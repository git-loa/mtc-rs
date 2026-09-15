//! Abstraction for hash functions used in Merkle trees.
//! This trait defines the interface for hashing leaf nodes 
//! and internal nodes in a Merkle tree.
//!
//! Implementations must provide:
//! - `hash_leaf`: A method to hash leaf data, returning a 32-byte hash.
//! - `hash_node`: A method to hash two child node hashes, returning a 32

use crate::error::CryptoError;

pub trait HashFn{
    /// Hashes the given leaf data (certificate body) and returns a 32-byte hash.
    /// Returns an error if the input data is empty.
    fn hash_leaf(data: &[u8]) -> Result<[u8; 32], CryptoError>;

    /// Hashes the given left and right child node hashes and returns a 32-byte hash.
    /// Returns an error if the input node hashes are not exactly 32 bytes each.
    fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> Result<[u8; 32], CryptoError>;
}


