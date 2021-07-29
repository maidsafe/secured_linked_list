// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod block;
mod branch;
mod deserialized;
pub mod error;
#[cfg(test)]
pub(crate) mod tests;

use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    collections::HashSet,
    fmt::{self, Debug, Formatter},
    iter, mem,
};

use self::{block::Block, branch::Branch, deserialized::Deserialized, error::Error};

/// Chain of BLS keys where every key is proven (signed) by its parent key, except the
/// first one.
///
/// # CRDT
///
/// The operations that mutate the chain ([`insert`](Self::insert) and [`merge`](Self::merge)) are
/// commutative, associative and idempotent. This means the chain is a
/// [CRDT](https://en.wikipedia.org/wiki/Conflict-free_replicated_data_type).
///
/// # Forks
///
/// It's possible to insert multiple keys that all have the same parent key. This is called a
/// "fork". The chain implements automatic fork resolution which means that even in the presence of
/// forks the chain presents the blocks in a well-defined unique and deterministic order.
///
/// # Block order
///
/// Block are ordered primarily according to their parent-child relation (parents always precede
/// children) and forks are resolved by additionally ordering the sibling blocks according to the
/// `Ord` relation of their public key. That is, "lower" keys precede "higher" keys.
#[derive(Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(try_from = "Deserialized")]
pub struct SecuredLinkedList {
    root: bls::PublicKey,
    tree: Vec<Block>,
}

#[allow(clippy::len_without_is_empty)]
impl SecuredLinkedList {
    /// Creates a new chain consisting of only one block.
    pub fn new(root: bls::PublicKey) -> Self {
        Self {
            root,
            tree: Vec::new(),
        }
    }

    /// Insert new key into the chain. `parent_key` must exists in the chain and must validate
    /// `signature`, otherwise error is returned.
    pub fn insert(
        &mut self,
        parent_key: &bls::PublicKey,
        key: bls::PublicKey,
        signature: bls::Signature,
    ) -> Result<(), Error> {
        let parent_index = self.index_of(parent_key).ok_or(Error::KeyNotFound)?;
        let block = Block {
            key,
            signature,
            parent_index,
        };

        if block.verify(parent_key) {
            let _ = self.insert_block(block);
            Ok(())
        } else {
            Err(Error::FailedSignature)
        }
    }

    /// Merges two chains into one.
    ///
    /// This succeeds only if the root key of one of the chain is present in the other one.
    /// Otherwise it returns `Error::InvalidOperation`
    pub fn merge(&mut self, mut other: Self) -> Result<(), Error> {
        let root_index = if let Some(index) = self.index_of(other.root_key()) {
            index
        } else if let Some(index) = other.index_of(self.root_key()) {
            mem::swap(self, &mut other);
            index
        } else {
            return Err(Error::InvalidOperation);
        };

        let mut reindex_map = vec![0; other.len()];
        reindex_map[0] = root_index;

        for (other_index, mut other_block) in other
            .tree
            .into_iter()
            .enumerate()
            .map(|(index, block)| (index + 1, block))
        {
            other_block.parent_index = reindex_map[other_block.parent_index];
            reindex_map[other_index] = self.insert_block(other_block);
        }

        Ok(())
    }

    /// Creates a sub-chain from given `from` and `to` keys.
    /// Returns `Error::KeyNotFound` if the given keys are not present in the chain.
    pub fn get_proof_chain(
        &self,
        from_key: &bls::PublicKey,
        to_key: &bls::PublicKey,
    ) -> Result<Self, Error> {
        self.minimize(vec![from_key, to_key])
    }

    /// Creates a sub-chain from a given key to the end.
    /// Returns `Error::KeyNotFound` if the given from key is not present in the chain.
    pub fn get_proof_chain_to_current(&self, from_key: &bls::PublicKey) -> Result<Self, Error> {
        self.minimize(vec![from_key, self.last_key()])
    }

    /// Creates a minimal sub-chain of `self` that contains all `required_keys`.
    /// Returns `Error::KeyNotFound` if some of `required_keys` is not present in `self`.
    ///
    /// Note: "minimal" means it contains the fewest number of blocks of all such sub-chains.
    pub fn minimize<'a, I>(&self, required_keys: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = &'a bls::PublicKey>,
    {
        // Note: the returned chain is not always strictly minimal. Consider this chain:
        //
        //     0->1->3->4
        //        |
        //        +->2
        //
        // Then calling `minimize([1, 3])` currently returns
        //
        //     1->3
        //     |
        //     +->2
        //
        // Even though the truly minimal chain containing 1 and 3 is just
        //
        //     1->3
        //
        // This is because 2 lies between 1 and 3 in the underlying `tree` vector and so is
        // currently included.
        //
        // TODO: make this function return the truly minimal chain in all cases.

        let mut min_index = self.len() - 1;
        let mut max_index = 0;

        for key in required_keys {
            let index = self.index_of(key).ok_or(Error::KeyNotFound)?;
            min_index = min_index.min(index);
            max_index = max_index.max(index);
        }

        // To account for forks, we also need to include the closest common ancestors of all the
        // required keys. This is to maintain the invariant that for every key in the chain that is
        // not the root its parent key is also in the chain.
        min_index = self.closest_common_ancestor(min_index, max_index);

        let mut chain = Self::new(if min_index == 0 {
            self.root
        } else {
            self.tree[min_index - 1].key
        });

        for index in min_index..max_index {
            let block = &self.tree[index];

            chain.tree.push(Block {
                key: block.key,
                signature: block.signature.clone(),
                parent_index: block.parent_index - min_index,
            })
        }

        Ok(chain)
    }

    /// Returns a sub-chain of `self` truncated to the last `count` keys.
    /// NOTE: a chain must have at least 1 block, so if `count` is 0 it is treated the same as if
    /// it was 1.
    pub fn truncate(&self, count: usize) -> Self {
        let count = count.max(1);

        let mut tree: Vec<_> = self.branch(self.tree.len()).take(count).cloned().collect();

        let root = if tree.len() >= count {
            tree.pop().map(|block| block.key).unwrap_or(self.root)
        } else {
            self.root
        };

        tree.reverse();

        // Fix the parent indices.
        for (index, block) in tree.iter_mut().enumerate() {
            block.parent_index = index;
        }

        Self { root, tree }
    }

    /// Returns the smallest super-chain of `self` that would be trusted by a peer that trust
    /// `trusted_key`. Ensures that the last key of the resuling chain is the same as the last key
    /// of `self`.
    ///
    /// Returns `Error::KeyNotFound` if any of `trusted_key`, `self.root_key()` or `self.last_key()`
    /// is not present in `super_chain`.
    ///
    /// Returns `Error::InvalidOperation` if `trusted_key` is not reachable from `self.last_key()`.
    pub fn extend(&self, trusted_key: &bls::PublicKey, super_chain: &Self) -> Result<Self, Error> {
        let trusted_key_index = super_chain
            .index_of(trusted_key)
            .ok_or(Error::KeyNotFound)?;
        let last_key_index = super_chain
            .index_of(self.last_key())
            .ok_or(Error::KeyNotFound)?;

        if !super_chain.has_key(self.root_key()) {
            return Err(Error::KeyNotFound);
        }

        if super_chain.is_ancestor(trusted_key_index, last_key_index) {
            super_chain.minimize(vec![trusted_key, self.last_key()])
        } else {
            Err(Error::InvalidOperation)
        }
    }

    /// Iterator over all the keys in the chain in order.
    pub fn keys(&self) -> impl DoubleEndedIterator<Item = &bls::PublicKey> {
        iter::once(&self.root).chain(self.tree.iter().map(|block| &block.key))
    }

    /// Returns the root key of this chain. This is the first key in the chain and is the only key
    /// that doesn't have a parent key.
    pub fn root_key(&self) -> &bls::PublicKey {
        &self.root
    }

    /// Returns the last key of this chain.
    pub fn last_key(&self) -> &bls::PublicKey {
        self.tree
            .last()
            .map(|block| &block.key)
            .unwrap_or(&self.root)
    }

    /// Returns the parent key of the last key or the root key if this chain has only one key.
    pub fn prev_key(&self) -> &bls::PublicKey {
        self.branch(self.tree.len())
            .nth(1)
            .map(|block| &block.key)
            .unwrap_or(&self.root)
    }

    /// Returns whether `key` is present in this chain.
    pub fn has_key(&self, key: &bls::PublicKey) -> bool {
        self.keys().any(|existing_key| existing_key == key)
    }

    /// Verify every BLS key in this chain is proven (signed) by its parent key,
    /// except the first one.
    pub fn self_verify(&self) -> bool {
        self.tree.iter().all(|block| {
            let parent_key = if block.parent_index > 0 {
                &self.tree[block.parent_index - 1].key
            } else {
                &self.root
            };

            block.verify(parent_key)
        })
    }

    /// Given a collection of keys that are already trusted, returns whether this chain is also
    /// trusted. A chain is considered trusted only if at least one of the `trusted_keys` is on its
    /// main branch.
    ///
    /// # Explanation
    ///
    /// Consider this chain that contains fork:
    ///
    /// ```ascii-art
    /// A->B->C
    ///    |
    ///    +->D
    /// ```
    ///
    /// Now if the only trusted key is `D`, then there is no way to prove the chain is trusted,
    /// because this chain would be indistinguishable in terms of trust from any other chain with
    /// the same general "shape", say:
    ///
    /// ```ascii-art
    /// W->X->Y->Z
    ///    |
    ///    +->D
    /// ```
    ///
    /// So an adversary is easily able to forge any such chain.
    ///
    /// When the trusted key is on the main branch, on the other hand:
    ///
    /// ```ascii-art
    /// D->E->F
    ///    |
    ///    +->G
    /// ```
    ///
    /// Then such chain is impossible to forge because the adversary would have to have access to
    /// the secret key corresponding to `D` in order to validly sign `E`. Thus such chain can be
    /// safely considered trusted.
    pub fn check_trust<'a, I>(&self, trusted_keys: I) -> bool
    where
        I: IntoIterator<Item = &'a bls::PublicKey>,
    {
        let trusted_keys: HashSet<_> = trusted_keys.into_iter().collect();
        self.branch(self.tree.len())
            .map(|block| &block.key)
            .chain(iter::once(&self.root))
            .any(|key| trusted_keys.contains(key))
    }

    /// Compare the two keys by their position in the chain. The key that is higher (closer to the
    /// last key) is considered `Greater`. If exactly one of the keys is not in the chain, the other
    /// one is implicitly considered `Greater`. If none are in the chain, they are considered
    /// `Equal`.
    pub fn cmp_by_position(&self, lhs: &bls::PublicKey, rhs: &bls::PublicKey) -> Ordering {
        match (self.index_of(lhs), self.index_of(rhs)) {
            (Some(lhs), Some(rhs)) => lhs.cmp(&rhs),
            (Some(_), None) => Ordering::Greater,
            (None, Some(_)) => Ordering::Less,
            (None, None) => Ordering::Equal,
        }
    }

    /// Returns the number of blocks in the chain. This is always >= 1.
    pub fn len(&self) -> usize {
        1 + self.tree.len()
    }

    /// Returns the number of block on the main branch of the chain - that is - the ones reachable
    /// from the last block.
    ///
    /// NOTE: this is a `O(n)` operation.
    pub fn main_branch_len(&self) -> usize {
        self.branch(self.tree.len()).count() + 1
    }

    fn insert_block(&mut self, new_block: Block) -> usize {
        // Find the index into `self.tree` to insert the new block at so that the block order as
        // described in the `SecuredLinkedList` doc comment is maintained.
        let insert_at = self
            .tree
            .iter()
            .enumerate()
            .skip(new_block.parent_index)
            .find(|(_, block)| {
                block.parent_index != new_block.parent_index || block.key >= new_block.key
            })
            .map(|(index, _)| index)
            .unwrap_or(self.tree.len());

        // If the key already exists in the chain, do nothing but still return success to make the
        // `insert` operation idempotent.
        if self.tree.get(insert_at).map(|block| &block.key) != Some(&new_block.key) {
            self.tree.insert(insert_at, new_block);

            // Adjust the parent indices of the keys whose parents are after the inserted key.
            for block in &mut self.tree[insert_at + 1..] {
                if block.parent_index > insert_at {
                    block.parent_index += 1;
                }
            }
        }

        insert_at + 1
    }

    /// Returns the index of the given key. Returns `None` if not present.
    pub fn index_of(&self, key: &bls::PublicKey) -> Option<usize> {
        self.keys()
            .rev()
            .position(|existing_key| existing_key == key)
            .map(|rev_position| self.len() - rev_position - 1)
    }

    fn parent_index_at(&self, index: usize) -> Option<usize> {
        if index == 0 {
            None
        } else {
            self.tree.get(index - 1).map(|block| block.parent_index)
        }
    }

    // Is the key at `lhs` an ancestor of the key at `rhs`?
    fn is_ancestor(&self, lhs: usize, rhs: usize) -> bool {
        let mut index = rhs;
        loop {
            if index == lhs {
                return true;
            }

            if index < lhs {
                return false;
            }

            if let Some(parent_index) = self.parent_index_at(index) {
                index = parent_index;
            } else {
                return false;
            }
        }
    }

    // Returns the index of the closest common ancestor of the keys in the *closed* interval
    // [min_index, max_index].
    fn closest_common_ancestor(&self, mut min_index: usize, mut max_index: usize) -> usize {
        loop {
            if max_index == 0 || min_index == 0 {
                return 0;
            }

            if max_index <= min_index {
                return min_index;
            }

            if let Some(parent_index) = self.parent_index_at(max_index) {
                min_index = min_index.min(parent_index);
            } else {
                return 0;
            }

            max_index -= 1;
        }
    }

    // Iterator over the blocks on the branch that ends at `index` in reverse order.
    // Does not include the root block.
    fn branch(&self, index: usize) -> Branch {
        Branch { chain: self, index }
    }
}

impl Debug for SecuredLinkedList {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:?}", self.keys().format("->"))
    }
}
