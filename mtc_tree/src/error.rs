//! Error types for Merkle tree operations.

use thiserror::Error;
use mtc_crypto::error::CryptoError;

/// Errors that can occur during Merkle tree operations.
#[derive(Debug, Error)]
pub enum TreeError {
    /// An underlying cryptographic operation failed.
    #[error("Cryptographic error: {0:?}")]
    Crypto(#[from] CryptoError),
}
