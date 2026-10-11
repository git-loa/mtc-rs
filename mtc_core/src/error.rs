//! Error types for shared MTC data structures.

use thiserror::Error;

/// Errors that can occur when constructing or validating a [`crate::types::HashValue`].
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HashValueError {
    /// The digest length does not match the selected hash algorithm.
    #[error("Invalid hash length for {algorithm:?}: expected {expected} bytes, got {actual} bytes")]
    InvalidLength {
        /// Hash algorithm associated with the digest.
        algorithm: crate::types::HashAlgorithm,

        /// Required digest length in bytes.
        expected: usize,

        /// Actual digest length in bytes.
        actual: usize,
    },
}
