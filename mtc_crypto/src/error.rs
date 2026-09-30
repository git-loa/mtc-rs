//! Error types for cryptographic operations in the MTC system.
//!
//! These errors are used by the cryptographic abstraction layer to report
//! invalid hash values and incompatible hash algorithms.

use thiserror::Error;

/// Errors that can occur during cryptographic operations.
#[derive(Debug, PartialEq, Eq, Error)]
pub enum CryptoError {
    /// Two hash values use different algorithms.
    #[error("Hash algorithms do not match.")]
    HashAlgorithmMismatch,

    /// A hash value has an invalid length.
    #[error("Invalid hash length.")]
    InvalidHashLength,
}