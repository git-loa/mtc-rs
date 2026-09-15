//! Error types for cryptographic operations in the MTC system.

/// This module defines the `CryptoError` enum, which represents 
/// various error conditions that can occur during cryptographic 
/// operations, such as hashing and Merkle tree construction.

/// Hashing itself is infallible but invalid inputs must be rejected:
/// - empty leaf data (for leaf hashing)
/// - incorrect node lengths (for internal node hashing)

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    /// Leaf data must not be empty.
    #[error("Leaf data must not be empty.")]
    EmptyLeafData,

    /// Merkle tree node inputs must be exactly 32 bytes each.
    #[error("Merkle tree node inputs must be exactly 32 bytes each.")]
    InvalidNodeLength,
}