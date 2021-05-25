// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{block::Block, SecuredLinkedList};

// Iterator over the blocks on a single branch of the chain in reverse order.
// Does not include the root block.
pub(crate) struct Branch<'a> {
    pub(crate) chain: &'a SecuredLinkedList,
    pub(crate) index: usize,
}

impl<'a> Iterator for Branch<'a> {
    type Item = &'a Block;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index == 0 {
            None
        } else {
            let block = self.chain.tree.get(self.index - 1)?;
            self.index = block.parent_index;
            Some(block)
        }
    }
}
