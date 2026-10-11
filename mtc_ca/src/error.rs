//! Error types for certificate-authority operations.

use mtc_tree::error::TreeError;
use thiserror::Error;

/// Errors that can occur during certificate authority operations.
#[derive(Error, Debug)]
pub enum CertificateAuthorityError {
    /// A memory allocation failed while preparing or storing certificate data.
    #[error("Failed to allocate memory for certificate storage.")]
    MemoryAllocationError,

    /// An operation on the underlying Merkle tree failed.
    #[error(transparent)]
    Tree(#[from] TreeError),
}
