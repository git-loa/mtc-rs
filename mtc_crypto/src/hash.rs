//! Abstraction for hash functions used in Merkle trees.
//!
//! This module defines the interface that concrete hash
//! implementations must provide.

use crate::error::CryptoError;
use mtc_core::types::{HashValue, HashAlgorithm};

/// Abstraction over cryptographic hash functions.
///
/// Implementations provide hashing operations for:
/// - leaf data
/// - internal Merkle tree nodes
pub trait HashFn{
    /// Returns the algorithm implemented by this hash function.
    fn algorithm(&self) -> HashAlgorithm;

    /// Hashes leaf data.
    fn hash_leaf(&self, data: &[u8]) -> Result<HashValue, CryptoError>;

    /// Hashes two child nodes to produce a parent node.
    fn hash_two_children(&self, left: &HashValue, right: &HashValue) -> Result<HashValue, CryptoError>;
}


