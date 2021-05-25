// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{block::Block, error::IntegrityError, SecuredLinkedList};
use serde::Deserialize;
use std::convert::TryFrom;

// `SecuredLinkedList` is deserialized by first deserializing it into this intermediate structure and
// then converting it into `SecuredLinkedList` using `try_from` which fails when the chain is invalid.
// This makes it impossible to obtain invalid `SecuredLinkedList` from malformed serialized data, thus
// making `SecuredLinkedList` "correct by deserialization".
#[derive(Deserialize)]
#[serde(rename = "SecuredLinkedList")]
pub(crate) struct Deserialized {
    pub(crate) root: bls::PublicKey,
    pub(crate) tree: Vec<Block>,
}

impl TryFrom<Deserialized> for SecuredLinkedList {
    type Error = IntegrityError;

    fn try_from(src: Deserialized) -> Result<Self, Self::Error> {
        let mut prev_block: Option<&Block> = None;

        for (tree_index, block) in src.tree.iter().enumerate() {
            let parent_key = if block.parent_index == 0 {
                &src.root
            } else if block.parent_index > tree_index {
                return Err(IntegrityError::WrongBlockOrder);
            } else if let Some(key) = src.tree.get(block.parent_index - 1).map(|block| &block.key) {
                key
            } else {
                return Err(IntegrityError::ParentNotFound);
            };

            if !block.verify(parent_key) {
                // Invalid signature
                return Err(IntegrityError::FailedSignature);
            }

            if let Some(prev_block) = prev_block {
                if block.parent_index < prev_block.parent_index {
                    // Wrong order of block that have neither parent-child, not sibling relation.
                    return Err(IntegrityError::WrongBlockOrder);
                }

                if block.parent_index == prev_block.parent_index && block <= prev_block {
                    // Wrong sibling order
                    return Err(IntegrityError::WrongBlockOrder);
                }
            }

            prev_block = Some(block);
        }

        Ok(Self {
            root: src.root,
            tree: src.tree,
        })
    }
}
