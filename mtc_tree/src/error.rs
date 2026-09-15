use thiserror::Error;
use mtc_crypto::error::CryptoError;


/// Errors that can occur during Merkle tree construction and proof handling.
#[derive(Debug, Error)]
pub enum TreeError {
    /// No leaf nodes were provided for tree construction.
    #[error("No leaf nodes provided for tree construction.")]
    NoLeafNodes,

    /// Error occurred during cryptographic operations - using hash function
    #[error("Cryptographic error: {0:?}")]
    CryptoError(#[from] CryptoError),
}