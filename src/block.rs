// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub(crate) struct Block {
    pub(crate) key: bls::PublicKey,
    pub(crate) signature: bls::Signature,
    pub(crate) parent_index: usize,
}

impl Block {
    pub(crate) fn verify(&self, parent_key: &bls::PublicKey) -> bool {
        bincode::serialize(&self.key)
            .map(|bytes| parent_key.verify(&self.signature, &bytes))
            .unwrap_or(false)
    }
}

// Define a total order on block, to resolve forks.
impl Ord for Block {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key.cmp(&other.key)
    }
}

impl PartialOrd for Block {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
