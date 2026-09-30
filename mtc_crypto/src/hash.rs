//! Abstraction for hash functions used by Merkle trees.
//!
//! This module defines the interface implemented by concrete hash
//! functions used by the Merkle tree.

use crate::error::CryptoError;
use mtc_core::types::{HashValue, HashAlgorithm};

/// Abstraction over cryptographic hash functions.
///
/// Implementations provide hashing operations for empty trees,
/// leaf data, and internal Merkle tree nodes.
pub trait HashFn{
    /// Returns the algorithm implemented by this hash function.
    fn algorithm(&self) -> HashAlgorithm;

    /// Computes the hash for an empty tree.
    fn hash_empty(&self) -> Result<HashValue, CryptoError>;

    /// Computes the hash for leaf data.
    fn hash_leaf(&self, data: &[u8]) -> Result<HashValue, CryptoError>;

    /// Computes a parent hash from two child hashes.
    fn hash_two_children(
        &self, 
        left: &HashValue, 
        right: &HashValue
    ) -> Result<HashValue, CryptoError>;
}


