//! Abstraction for hash functions used by Merkle trees.
//!
//! This module defines the [`HashFn`] trait, which separates Merkle tree
//! operations from concrete hash implementations.

use crate::error::CryptoError;
use mtc_core::types::{HashAlgorithm, HashValue};

/// Defines the hashing operations required by a Merkle tree.
///
/// Implementations provide operations for hashing an empty tree, leaf data,
/// and internal nodes. The [`HashAlgorithm`] identifier describes the
/// algorithm associated with the implementation.
///
/// Implementations must use consistent hashing rules so that the same
/// inputs produce the same hash values under the same algorithm and
/// configuration.
///
/// # Errors
///
/// Hashing methods return [`CryptoError`] when an operation cannot be
/// completed, such as when child hashes use an incompatible algorithm.
pub trait HashFn {
    /// Returns the identifier of the hash algorithm used by this implementation.
    fn algorithm(&self) -> HashAlgorithm;

    /// Computes the hash representing an empty Merkle tree.
    ///
    /// The empty-tree hash is distinct from the hash of an empty leaf.
    fn hash_empty(&self) -> Result<HashValue, CryptoError>;

    /// Computes the hash of leaf data.
    ///
    /// The input is the data associated with one leaf. The implementation
    /// defines the hashing rules used to distinguish leaf data from
    /// internal-node inputs.
    fn hash_leaf(&self, data: &[u8]) -> Result<HashValue, CryptoError>;

    /// Computes the hash of an internal node from its two child hashes.
    ///
    /// `left` is the left child's hash, and `right` is the right child's
    /// hash. Implementations must preserve this ordering when constructing
    /// the parent hash.
    ///
    /// # Errors
    ///
    /// Returns a [`CryptoError`] if either child hash uses an incompatible
    /// algorithm or if the parent hash cannot be constructed.
    fn hash_two_children(
        &self,
        left: &HashValue,
        right: &HashValue,
    ) -> Result<HashValue, CryptoError>;
}
