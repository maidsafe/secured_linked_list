// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use thiserror::Error;

/// Error resulting from operations on `SecuredLinkedList`.
#[allow(missing_docs)]
#[derive(Error, Debug, PartialEq, Eq)]
pub enum Error {
    #[error("signature check failed")]
    FailedSignature,
    #[error("key not found in the chain")]
    KeyNotFound,
    #[error("no sub-chain was found in the chain")]
    SubChainNotFound,
    #[error("chain doesn't contain any trusted keys")]
    Untrusted,
    #[error("attempted operation is invalid")]
    InvalidOperation,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub(crate) enum IntegrityError {
    #[error("signature check failed")]
    FailedSignature,
    #[error("parent key not found in the chain")]
    ParentNotFound,
    #[error("chain blocks are in a wrong order")]
    WrongBlockOrder,
}
