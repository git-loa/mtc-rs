//! Error types for Merkle tree operations.

use mtc_crypto::error::CryptoError;
use thiserror::Error;

/// Errors that can occur during Merkle tree operations.
#[derive(Debug, Error)]
pub enum TreeError {
    /// The requested leaf index is outside the tree.
    #[error("Leaf index is out of bounds.")]
    InvalidLeafIndex,

    /// The inclusion proof has an unexpected number of sibling hashes.
    #[error("Invalid inclusion proof length.")]
    InvalidProofLength,

    /// The tree size is invalid for the requested operation.
    #[error("Tree size must be greater than zero.")]
    InvalidTreeSize,

    /// An underlying cryptographic operation failed.
    #[error("Cryptographic error: {0:?}")]
    Crypto(#[from] CryptoError),
}
