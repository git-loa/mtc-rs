//! BLAKE3 implementation of the `HashFn` trait.
//! 
//! Domain separation:
//! - Leaves are prefixed with 0x00.
//! - Internal nodes are prefixed with 0x01.

use blake3;

use crate::error::CryptoError;
use crate::hash::HashFn;
use mtc_core::types::{HashAlgorithm, HashValue};

///BLAKE3 hash function with domain separation
/// for leaves and internal nodes.
pub struct Blake3Hash;

// Three interfaces: algorithm hash_leaf, hash_two_children
impl HashFn for Blake3Hash {

    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Blake3
    }

    fn hash_leaf(&self, data: &[u8]) -> Result<HashValue, CryptoError> {
        if data.is_empty() {
            return  Err(CryptoError::EmptyLeafData);
        }

        // Domain separation: 0x00 || data
        let mut buffer =Vec::with_capacity(1 + data.len());
        buffer.push(0x00);
        buffer.extend_from_slice(data);

        let digest: [u8; 32] = blake3::hash(&buffer).into();

        // Throws and error if arguments are wrong.
        HashValue::new(
            HashAlgorithm::Blake3, 
            digest.to_vec()
        ).map_err(|_| CryptoError::InvalidHashLength)
    }


    fn hash_two_children(
        &self, 
        left: &HashValue, 
        right: &HashValue,
    ) -> Result<HashValue, CryptoError> {
        
        // Check that left and right algorightms match.
        if left.algorithm() != self.algorithm() || right.algorithm() != self.algorithm()
        { 
            return Err(CryptoError::HashAlgorithmMismatch);
        }

        // Domain separation: 0x01 || left || right
        let mut buffer = Vec::with_capacity(1 + 32 + 32);
        buffer.push(0x01);
        buffer.extend_from_slice(left.bytes());
        buffer.extend_from_slice(right.bytes());

        let digest: [u8; 32] = blake3::hash(&buffer).into();


        // Check for errors
        HashValue::new(
            HashAlgorithm::Blake3,
            digest.to_vec(),
        ).map_err(|_| CryptoError::InvalidHashLength)
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
    fn empty_leaf_data_returns_error(){
        let hasher = Blake3Hash;
        let result = hasher.hash_leaf(b"");
        assert_eq!(result, Err(CryptoError::EmptyLeafData));
    }

    #[test]
    fn rejects_hash_with_wrong_algorithm() {
        let hasher = Blake3Hash;

        let sha256_hash = HashValue::new(
            HashAlgorithm::Sha256,
            vec![0u8; 32],
        ).unwrap();

        let result = hasher.hash_two_children(
            &sha256_hash, 
            &sha256_hash,
        );

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
}