//! Merkle tree construction.
//!
//! This module provides the core Merkle tree structure used by MTC.
//! The tree uses a configurable cryptographic hash function and follows
//! the recursive Merkle Tree Hash construction.

use crate::error::TreeError;
use mtc_core::types::HashValue;
use mtc_crypto::hash::HashFn;

/// Returns the largest power of two strictly less than `n`.
///
/// This value determines the split point for the recursive Merkle Tree
/// Hash construction when the tree contains two or more leaves.
pub(crate) fn largest_power_of_two_less_than(n: usize) -> usize {
    assert!(n >= 2);

    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }

    k
}

/// A Merkle tree parameterized by a cryptographic hash function.
///
/// `H` is the Rust type that implements the [`HashFn`] trait and provides
/// the hashing operations used by the tree. For example, `H` can be
/// [`Blake3Hash`] when the tree is constructed with `Blake3Hash`.
///
/// The `H: HashFn` constraint requires the supplied type to implement
/// the `HashFn` trait.
///
/// The tree stores the configured hash function and the hashes of its
/// leaf records.
pub struct MerkleTree<H: HashFn> {
    /// Cryptographic hash function used by the tree.
    hasher: H,

    /// Hashes of the leaves stored in the tree.
    leaves: Vec<HashValue>,
}

impl<H: HashFn> MerkleTree<H> {
    /// Creates an empty Merke tree using the given hash function.
    pub fn new(hasher: H) -> Self {
        Self {
            hasher,
            leaves: Vec::new(),
        }
    }

    // Adds a new leaf to the Merkle tree.
    ///
    /// The input is hashed using the configured hash function before
    /// the resulting hash is stored. Empty leaf data is valid.
    pub fn append(&mut self, data: &[u8]) -> Result<(), TreeError> {
        let leaf_hash = self.hasher.hash_leaf(data)?;
        self.leaves.push(leaf_hash);

        Ok(())
    }

    /// Returns the number of leaves currently stored in the tree.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Returns `true` if the tree contains no leaves.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Returns a read-only view of the stored leaf hashes.
    pub(crate) fn leaves(&self) -> &[HashValue] {
        &self.leaves
    }

    /// Computes the Merkle root of the tree.
    ///
    /// Empty trees use the empty-tree hash. Multiple leaves are split
    /// according to the recursive Merkle Tree Hash construction.
    pub fn root(&self) -> Result<HashValue, TreeError> {
        self.root_for_slice(&self.leaves)
    }

    /// Recursively computes the Merkle root of a slice of leaf hashes.
    ///
    /// Empty and single-leaf slices are base cases. Multiple leaves are
    /// split according to the Merkle Tree Hash construction.
    pub(crate) fn root_for_slice(&self, leaves: &[HashValue]) -> Result<HashValue, TreeError> {
        if leaves.is_empty() {
            return Ok(self.hasher.hash_empty()?);
        }

        if leaves.len() == 1 {
            return Ok(leaves[0].clone());
        }

        let n = leaves.len();
        let k = largest_power_of_two_less_than(n);

        // Left and Right Slices
        let left = &leaves[..k];
        let right = &leaves[k..];

        let left_root = self.root_for_slice(left)?;
        let right_root = self.root_for_slice(right)?;

        // Compute the root
        let root = self.hasher.hash_two_children(&left_root, &right_root)?;

        Ok(root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mtc_core::types::HashAlgorithm;
    use mtc_crypto::blake3::Blake3Hash;

    #[test]
    fn new_tree_is_empty() {
        let tree = MerkleTree::new(Blake3Hash);

        assert!(tree.is_empty());
        assert_eq!(tree.len(), 0);
    }

    #[test]
    fn tree_is_not_empty_after_append() {
        let mut tree = MerkleTree::new(Blake3Hash);

        tree.append(b"hello").unwrap();

        assert!(!tree.is_empty());
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn append_adds_leaf_to_tree() {
        let mut tree = MerkleTree::new(Blake3Hash);
        tree.append(b"Certificate").unwrap();

        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn empty_tree_has_root() {
        let tree = MerkleTree::new(Blake3Hash);
        let root = tree.root().unwrap();
        assert_eq!(root.algorithm(), HashAlgorithm::Blake3);
    }

    #[test]
    fn single_leaf_is_root() {
        let mut tree = MerkleTree::new(Blake3Hash);

        tree.append(b"hello").unwrap();

        let root = tree.root().unwrap();
        let leaf = tree.leaves()[0].clone();

        assert_eq!(root, leaf);
    }

    #[test]
    fn largest_power_of_two_less_than_works() {
        assert_eq!(largest_power_of_two_less_than(2), 1);
        assert_eq!(largest_power_of_two_less_than(3), 2);
        assert_eq!(largest_power_of_two_less_than(4), 2);
        assert_eq!(largest_power_of_two_less_than(5), 4);
        assert_eq!(largest_power_of_two_less_than(8), 4);
        assert_eq!(largest_power_of_two_less_than(9), 8);
    }

    #[test]
    fn two_leaves_have_expected_root() {
        let mut tree = MerkleTree::new(Blake3Hash);

        tree.append(b"a").unwrap();
        tree.append(b"b").unwrap();

        let root = tree.root().unwrap();

        let left = &tree.leaves()[0];
        let right = &tree.leaves()[1];

        let expected = Blake3Hash.hash_two_children(left, right).unwrap();

        assert_eq!(root, expected);
    }

    #[test]
    fn three_leaves_use_correct_split() {
        let mut tree = MerkleTree::new(Blake3Hash);

        tree.append(b"a").unwrap();
        tree.append(b"b").unwrap();
        tree.append(b"c").unwrap();

        let root = tree.root().unwrap();

        let left = Blake3Hash
            .hash_two_children(&tree.leaves()[0], &tree.leaves()[1])
            .unwrap();

        let expected = Blake3Hash
            .hash_two_children(&left, &tree.leaves()[2])
            .unwrap();

        assert_eq!(root, expected);
    }

    #[test]
    fn four_leaves_use_correct_split() {
        let mut tree = MerkleTree::new(Blake3Hash);

        tree.append(b"a").unwrap();
        tree.append(b"b").unwrap();
        tree.append(b"c").unwrap();
        tree.append(b"d").unwrap();

        let root = tree.root().unwrap();

        let left = Blake3Hash
            .hash_two_children(&tree.leaves()[0], &tree.leaves()[1])
            .unwrap();

        let right = Blake3Hash
            .hash_two_children(&tree.leaves()[2], &tree.leaves()[3])
            .unwrap();

        let expected = Blake3Hash.hash_two_children(&left, &right).unwrap();

        assert_eq!(root, expected);
    }

    #[test]
    fn five_leaves_use_correct_recursive_structure() {
        let mut tree = MerkleTree::new(Blake3Hash);

        tree.append(b"a").unwrap();
        tree.append(b"b").unwrap();
        tree.append(b"c").unwrap();
        tree.append(b"d").unwrap();
        tree.append(b"e").unwrap();

        let root = tree.root().unwrap();

        let left_left = Blake3Hash
            .hash_two_children(&tree.leaves()[0], &tree.leaves()[1])
            .unwrap();

        let left_right = Blake3Hash
            .hash_two_children(&tree.leaves()[2], &tree.leaves()[3])
            .unwrap();

        let left = Blake3Hash
            .hash_two_children(&left_left, &left_right)
            .unwrap();

        let expected = Blake3Hash
            .hash_two_children(&left, &tree.leaves()[4])
            .unwrap();

        assert_eq!(root, expected);
    }

    #[test]
    fn empty_leaf_is_different_from_empty_tree() {
        let empty_tree = MerkleTree::new(Blake3Hash);

        let mut one_empty_leaf = MerkleTree::new(Blake3Hash);
        one_empty_leaf.append(b"").unwrap();

        let empty_tree_root = empty_tree.root().unwrap();
        let empty_leaf_root = one_empty_leaf.root().unwrap();

        assert_ne!(empty_leaf_root, empty_tree_root);
    }
}
