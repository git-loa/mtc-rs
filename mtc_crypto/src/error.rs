//! Error types for cryptographic operations in the MTC system.

use thiserror::Error;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum CryptoError {
    /// Leaf data must not be empty.
    #[error("Leaf data must not be empty.")]
    EmptyLeafData,

    /// Two has values use different algorithms.
    #[error("Hash algorithms do not match.")]
    HashAlgorithmMismatch,

    /// A hsh value has an invalid length.
    #[error("Invalid hash length.")]
    InvalidHashLength,
}