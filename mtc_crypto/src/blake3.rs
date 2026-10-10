//! BLAKE3 implementation of the [`HashFn`] trait.
//!
//! This module computes hashes for empty trees, leaf data, and internal
//! Merkle tree nodes.
//!
//! Domain separation distinguishes leaf data from internal nodes:
//!
//! - `0x00` prefixes leaf data.
//! - `0x01` prefixes the concatenated child hashes of an internal node.
//!
//! These prefixes are part of this implementation's hashing convention.
//! Protocol interoperability requires agreement on the complete hashing
//! rules, including the hash algorithm and input encoding.

use blake3;

use crate::error::CryptoError;
use crate::hash::HashFn;
use mtc_core::types::{HashAlgorithm, HashValue};

/// BLAKE3 hash implementation for Merkle tree operations.
///
/// Leaf and internal-node inputs use distinct domain-separation prefixes.
#[derive(Debug)]
pub struct Blake3Hash;

impl HashFn for Blake3Hash {
    /// Returns `Blake3` as the algorithm identifier.
    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Blake3
    }

    /// Computes the hash representing an empty Merkle tree.
    ///
    /// The empty-tree hash is BLAKE3 applied to an empty byte string.
    /// It is distinct from the hash of an empty leaf, which includes
    /// the leaf domain-separation prefix.
    fn hash_empty(&self) -> Result<HashValue, CryptoError> {
        let digest: [u8; 32] = blake3::hash(b"").into();

        HashValue::new(HashAlgorithm::Blake3, digest.to_vec())
            .map_err(|_| CryptoError::InvalidHashLength)
    }

    /// Computes the hash of a Merkle tree leaf.
    ///
    /// The input is prefixed with `0x00` before BLAKE3 hashing, separating
    /// leaf hashing from internal-node hashing.
    ///
    /// # Errors
    ///
    /// Returns a [`CryptoError`] if constructing the resulting [`HashValue`]
    /// fails validation.
    fn hash_leaf(&self, data: &[u8]) -> Result<HashValue, CryptoError> {
        // Domain separation: 0x00 || data
        let mut buffer = Vec::with_capacity(1 + data.len());
        buffer.push(0x00);
        buffer.extend_from_slice(data);

        let digest: [u8; 32] = blake3::hash(&buffer).into();

        HashValue::new(HashAlgorithm::Blake3, digest.to_vec())
            .map_err(|_| CryptoError::InvalidHashLength)
    }

    /// Computes the hash of an internal Merkle tree node.
    ///
    /// The input is constructed by prefixing `0x01` to the concatenated
    /// bytes of the left and right child hashes, in that order.
    ///
    /// Both child hashes must use BLAKE3.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::HashAlgorithmMismatch`] if either child hash
    /// uses an algorithm other than BLAKE3.
    ///
    /// Returns [`CryptoError::InvalidHashLength`] if constructing the
    /// resulting [`HashValue`] fails validation.
    fn hash_two_children(
        &self,
        left: &HashValue,
        right: &HashValue,
    ) -> Result<HashValue, CryptoError> {
        // Ensure both child hashes use the configured algorithm.
        if left.algorithm() != self.algorithm() || right.algorithm() != self.algorithm() {
            return Err(CryptoError::HashAlgorithmMismatch);
        }

        // Domain separation: 0x01 || left || right
        let mut buffer = Vec::with_capacity(1 + 32 + 32);
        buffer.push(0x01);
        buffer.extend_from_slice(left.bytes());
        buffer.extend_from_slice(right.bytes());

        let digest: [u8; 32] = blake3::hash(&buffer).into();

        HashValue::new(HashAlgorithm::Blake3, digest.to_vec())
            .map_err(|_| CryptoError::InvalidHashLength)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn same_input_produces_same_hash() {
        let hasher = Blake3Hash;

        let data = b"hello world";
        let hash1 = hasher.hash_leaf(data).unwrap();
        let hash2 = hasher.hash_leaf(data).unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn different_inputs_produce_differen_hashes() {
        let hasher = Blake3Hash;

        let data1 = b"hello world";
        let data2 = b"hello rust";

        let hash1 = hasher.hash_leaf(data1).unwrap();
        let hash2 = hasher.hash_leaf(data2).unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn rejects_hash_with_wrong_algorithm() {
        let hasher = Blake3Hash;

        let sha256_hash = HashValue::new(HashAlgorithm::Sha256, vec![0u8; 32]).unwrap();

        let result = hasher.hash_two_children(&sha256_hash, &sha256_hash);

        assert_eq!(result, Err(CryptoError::HashAlgorithmMismatch));
    }

    #[test]
    fn leaf_and_node_hashes_are_different() {
        let hasher = Blake3Hash;
        let data = b"hello world";
        let leafhash = hasher.hash_leaf(data).unwrap();
        let left = hasher.hash_leaf(b"left").unwrap();
        let right = hasher.hash_leaf(b"right").unwrap();
        let node_hash = hasher.hash_two_children(&left, &right).unwrap();

        assert_ne!(leafhash, node_hash);
    }

    #[test]
    fn empty_tree_hash_differs_from_empty_leaf() {
        let hasher = Blake3Hash;

        let empty_tree = hasher.hash_empty().unwrap();

        let empty_leaf = hasher.hash_leaf(b"").unwrap();

        assert_ne!(empty_tree, empty_leaf);
        assert_eq!(empty_leaf.algorithm(), HashAlgorithm::Blake3);
        assert_eq!(empty_tree.algorithm(), HashAlgorithm::Blake3);
    }
}
