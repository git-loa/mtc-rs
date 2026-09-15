//! BLAKE3-based implementation of the 'HashFn' trait.
//! Domain separation:
//! - Leaves are prefixed with 0x00
//! - Internal nodes are prefixed with 0x01

use blake3::hash;


use crate::error::CryptoError;
use crate::hash::HashFn;

/// BLAKE3 hash function with domain separation for leaves and nodes.
pub struct Blake3Hash;

// Implementation of the 'HashFn' trait for BLAKE3.
impl HashFn for Blake3Hash{
    fn hash_leaf(data: &[u8]) -> Result<[u8; 32], CryptoError> {
        // Implementation for hashing leaf data
        if data.is_empty() {
            return Err(CryptoError::EmptyLeafData);
        }

        // Domain separation: 0x00 || data
        let mut buffer = Vec::with_capacity(1 + data.len());
        buffer.push(0x00); // Domain separation prefix for leaves
        buffer.extend_from_slice(data);

        Ok(hash(&buffer).into()) // Returns a 32-byte hash [u8; 32].
    }

    fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
        // Implementation for hashing internal nodes
        if left.len() != 32 || right.len() != 32 {
            return Err(CryptoError::InvalidNodeLength);
        }

        // Domain separation: 0x01 || left || right
        let mut buffer = Vec::with_capacity(1 + 32  + 32);
        buffer.push(0x01); // Domain separation prefix for internal nodes
        buffer.extend_from_slice(left);
        buffer.extend_from_slice(right);

        Ok(hash(&buffer).into()) // Returns a 32-byte hash [u8; 32].
    }
}


// Unit tests for the BLAKE3 hash function implementation.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leaf_hash_is_deterministic() {
        let data = b"test leaf data";
        let hash1 = Blake3Hash::hash_leaf(data).expect("Hashing leaf data should not fail");
        let hash2 = Blake3Hash::hash_leaf(data).expect("Hashing leaf data should not fail");
        assert_eq!(hash1, hash2);
    }

}
