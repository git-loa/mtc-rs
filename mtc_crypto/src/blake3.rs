//! BLAKE3 implementation of the `HashFn` trait.
//!
//! Leaf and internal-node inputs use domain separation:
//! - `0x00` for leaf data.
//! - `0x01` for internal nodes.

use blake3;

use crate::error::CryptoError;
use crate::hash::HashFn;
use mtc_core::types::{HashAlgorithm, HashValue};

///BLAKE3 hash function with domain separation for Merlke tree nodes.
#[derive(Debug)]
pub struct Blake3Hash;

impl HashFn for Blake3Hash {
    /// Returns `Blake3` as the algorithm identifier.
    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Blake3
    }

    /// Computes the hash representing an empty tree.
    fn hash_empty(&self) -> Result<HashValue, CryptoError> {
        let digest: [u8; 32] = blake3::hash(b"").into();

        HashValue::new(HashAlgorithm::Blake3, digest.to_vec())
            .map_err(|_| CryptoError::InvalidHashLength)
    }

    /// Computes a leaf hash using `0x00 || data`
    fn hash_leaf(&self, data: &[u8]) -> Result<HashValue, CryptoError> {
        // Domain separation: 0x00 || data
        let mut buffer = Vec::with_capacity(1 + data.len());
        buffer.push(0x00);
        buffer.extend_from_slice(data);

        let digest: [u8; 32] = blake3::hash(&buffer).into();

        HashValue::new(HashAlgorithm::Blake3, digest.to_vec())
            .map_err(|_| CryptoError::InvalidHashLength)
    }

    /// Computes an internal-node hash using `0x01 || left || right`.
    ///
    /// Both child hashes must use BLAKE3.
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

// #######################################
// ############## Testing ################
// #######################################

#[cfg(test)]
mod tests {

    use super::*;

    // Testing determinism.
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
