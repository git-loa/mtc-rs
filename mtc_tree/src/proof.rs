//! Merkle tree inclusion-proof generation and verification.
//!
//! This module generates inclusion proofs for leaves in a Merkle tree
//! and verifies those proofs against an expected root hash.
//!
//! The tree structure and hashing rules must be consistent between
//! proof generation and verification.

use crate::error::TreeError;
use crate::tree::{MerkleTree, largest_power_of_two_less_than};
use mtc_core::types::HashValue;
use mtc_crypto::hash::HashFn;

#[derive(Debug, PartialEq, Eq)]
enum Direction {
    Left,
    Right,
}

/// Generates an inclusion proof for the leaf at `leaf_index`.
///
/// The returned proof contains sibling subtree hashes in leaf-to-root
/// order. The proof can be used to verify the leaf against the root of
/// the same tree, provided the corresponding leaf data is available.
///
/// # Errors
///
/// Returns [`TreeError::InvalidLeafIndex`] if `leaf_index` is outside
/// the tree's valid leaf indices.
///
/// Returns a [`TreeError`] if a cryptographic operation required to
/// generate the proof fails.
pub fn generate_inclusion_proof<H: HashFn>(
    tree: &MerkleTree<H>,
    leaf_index: usize,
) -> Result<Vec<HashValue>, TreeError> {
    if leaf_index >= tree.len() {
        return Err(TreeError::InvalidLeafIndex);
    }

    // Single-leaf case
    if tree.len() == 1 {
        return Ok(Vec::new());
    }

    // Two-leaf base case
    if tree.len() == 2 {
        if leaf_index == 0 {
            return Ok(vec![tree.leaves()[1].clone()]);
        }

        return Ok(vec![tree.leaves()[0].clone()]);
    }

    generate_proof(tree, tree.leaves(), leaf_index)
}

/// Recursively generates an inclusion proof within a subtree.
fn generate_proof<H: HashFn>(
    tree: &MerkleTree<H>,
    leaves: &[HashValue],
    leaf_index: usize,
) -> Result<Vec<HashValue>, TreeError> {
    if leaves.len() == 1 {
        return Ok(Vec::new());
    }
    let n = leaves.len();
    let k = largest_power_of_two_less_than(n);

    // Left Subtree: recurse left
    if leaf_index < k {
        let left = &leaves[..k];
        let right = &leaves[k..];

        let mut proof = generate_proof(tree, left, leaf_index)?;

        let right_root = tree.root_for_slice(right)?;
        proof.push(right_root);

        return Ok(proof);
    }

    // Right Subtree: recurse right
    let left = &leaves[..k];
    let right = &leaves[k..];

    let mut proof = generate_proof(tree, right, leaf_index - k)?;

    let left_root = tree.root_for_slice(left)?;
    proof.push(left_root);

    Ok(proof)
}

/// Determines the left/right traversal path for a leaf.
///
/// The returned directions are ordered from leaf to root so that
/// `path[i]` corresponds to `proof[i]`.
fn determine_proof_path(leaf_index: usize, tree_size: usize) -> Result<Vec<Direction>, TreeError> {
    if tree_size == 0 {
        return Err(TreeError::InvalidTreeSize);
    }

    if leaf_index >= tree_size {
        return Err(TreeError::InvalidLeafIndex);
    }

    let mut subtree_size = tree_size;
    let mut current_index = leaf_index;
    let mut path = Vec::new();

    while subtree_size > 1 {
        let k = largest_power_of_two_less_than(subtree_size);

        if current_index < k {
            path.push(Direction::Left);
            subtree_size = k;
        } else {
            path.push(Direction::Right);
            current_index -= k;
            subtree_size -= k;
        }
    }
    path.reverse();

    Ok(path)
}

/// Verifies an inclusion proof for leaf data against an expected Merkle root.
///
/// The verifier hashes `leaf_data` and combines the resulting hash with
/// the sibling hashes in `proof`, following the tree path determined by
/// `leaf_index` and `tree_size`.
///
/// Returns `Ok(true)` if the reconstructed root equals `expected_root`,
/// or `Ok(false)` if the roots differ. A successful result establishes
/// consistency with the supplied root; it does not establish that the
/// root itself is trustworthy.
///
/// # Errors
///
/// Returns [`TreeError::InvalidTreeSize`] if `tree_size` is zero.
///
/// Returns [`TreeError::InvalidLeafIndex`] if `leaf_index` is outside
/// the tree's valid leaf indices.
///
/// Returns [`TreeError::InvalidProofLength`] if the proof contains an
/// unexpected number of sibling hashes.
///
/// Returns a [`TreeError`] if a cryptographic operation fails.
pub fn verify_inclusion_proof<H: HashFn>(
    hasher: &H,
    leaf_data: &[u8],
    leaf_index: usize,
    tree_size: usize,
    proof: &[HashValue],
    expected_root: &HashValue,
) -> Result<bool, TreeError> {
    let mut current = hasher.hash_leaf(leaf_data)?;

    let path = determine_proof_path(leaf_index, tree_size)?;

    if proof.len() != path.len() {
        return Err(TreeError::InvalidProofLength);
    }

    for (direction, sibling) in path.iter().zip(proof.iter()) {
        current = match direction {
            Direction::Left => hasher.hash_two_children(&current, sibling)?,
            Direction::Right => hasher.hash_two_children(sibling, &current)?,
        };
    }
    Ok(current == *expected_root)
}

// ########################
// ###### Testing #########
// ########################
#[cfg(test)]
mod tests {

    use super::*;
    use mtc_crypto::blake3::Blake3Hash;

    #[test]
    fn single_leaf_has_empty_inclusion_proof() {
        let mut tree = MerkleTree::new(Blake3Hash);
        tree.append(b"hello").unwrap();

        let proof = generate_inclusion_proof(&tree, 0).unwrap();
        assert!(proof.is_empty());
    }

    #[test]
    fn two_leaf_proof_for_first_leaf_contains_second_leaf_hash() {
        let mut tree = MerkleTree::new(Blake3Hash);
        tree.append(b"hello").unwrap();
        tree.append(b"world").unwrap();

        let proof = generate_inclusion_proof(&tree, 0).unwrap();

        assert_eq!(proof.len(), 1);
        assert_eq!(proof[0], tree.leaves()[1]);
    }

    #[test]
    fn two_leaf_proof_for_second_leaf_contains_first_leaf_hash() {
        let mut tree = MerkleTree::new(Blake3Hash);
        tree.append(b"hello").unwrap();
        tree.append(b"world").unwrap();

        let proof = generate_inclusion_proof(&tree, 1).unwrap();

        assert_eq!(proof.len(), 1);
        assert_eq!(proof[0], tree.leaves()[0]);
    }

    #[test]
    fn generate_inclusion_proof_for_leaf() {
        let mut tree = MerkleTree::new(Blake3Hash);

        tree.append(b"d0").unwrap();
        tree.append(b"d1").unwrap();
        tree.append(b"d2").unwrap();
        tree.append(b"d3").unwrap();
        tree.append(b"d4").unwrap();
        tree.append(b"d5").unwrap();

        let proof = generate_inclusion_proof(&tree, 2).unwrap();
        assert_eq!(proof.len(), 3);

        let hasher = Blake3Hash;

        let d3_hash = hasher.hash_leaf(b"d3").unwrap();

        let d0_hash = hasher.hash_leaf(b"d0").unwrap();
        let d1_hash = hasher.hash_leaf(b"d1").unwrap();
        let d0_d1_root = hasher.hash_two_children(&d0_hash, &d1_hash).unwrap();

        let d4_hash = hasher.hash_leaf(b"d4").unwrap();
        let d5_hash = hasher.hash_leaf(b"d5").unwrap();
        let d4_d5_root = hasher.hash_two_children(&d4_hash, &d5_hash).unwrap();

        assert_eq!(proof[0], d3_hash);
        assert_eq!(proof[1], d0_d1_root);
        assert_eq!(proof[2], d4_d5_root);
    }

    #[test]
    fn generates_inclusion_proof_for_rightmost_leaf() {
        let mut tree = MerkleTree::new(Blake3Hash);

        tree.append(b"d0").unwrap();
        tree.append(b"d1").unwrap();
        tree.append(b"d2").unwrap();
        tree.append(b"d3").unwrap();
        tree.append(b"d4").unwrap();
        tree.append(b"d5").unwrap();

        let proof = generate_inclusion_proof(&tree, 5).unwrap();

        assert_eq!(proof.len(), 2);

        let hasher = Blake3Hash;

        let d4_hash = hasher.hash_leaf(b"d4").unwrap();

        let d0_hash = hasher.hash_leaf(b"d0").unwrap();
        let d1_hash = hasher.hash_leaf(b"d1").unwrap();
        let d2_hash = hasher.hash_leaf(b"d2").unwrap();
        let d3_hash = hasher.hash_leaf(b"d3").unwrap();

        let d0_d1_root = hasher.hash_two_children(&d0_hash, &d1_hash).unwrap();

        let d2_d3_root = hasher.hash_two_children(&d2_hash, &d3_hash).unwrap();

        let d0_d1_d2_d3_root = hasher.hash_two_children(&d0_d1_root, &d2_d3_root).unwrap();

        assert_eq!(proof[0], d4_hash);
        assert_eq!(proof[1], d0_d1_d2_d3_root);
    }

    #[test]
    fn rejects_invalid_leaf_index() {
        let mut tree = MerkleTree::new(Blake3Hash);

        tree.append(b"d0").unwrap();
        tree.append(b"d1").unwrap();
        tree.append(b"d2").unwrap();

        let result = generate_inclusion_proof(&tree, 3);

        assert!(matches!(result, Err(TreeError::InvalidLeafIndex)));
    }

    #[test]
    fn generates_inclusion_proof_for_leftmost_leaf() {
        let mut tree = MerkleTree::new(Blake3Hash);

        tree.append(b"d0").unwrap();
        tree.append(b"d1").unwrap();
        tree.append(b"d2").unwrap();
        tree.append(b"d3").unwrap();
        tree.append(b"d4").unwrap();
        tree.append(b"d5").unwrap();

        let proof = generate_inclusion_proof(&tree, 0).unwrap();

        assert_eq!(proof.len(), 3);

        let hasher = Blake3Hash;

        let d1_hash = hasher.hash_leaf(b"d1").unwrap();

        let d2_hash = hasher.hash_leaf(b"d2").unwrap();
        let d3_hash = hasher.hash_leaf(b"d3").unwrap();
        let d2_d3_root = hasher.hash_two_children(&d2_hash, &d3_hash).unwrap();

        let d4_hash = hasher.hash_leaf(b"d4").unwrap();
        let d5_hash = hasher.hash_leaf(b"d5").unwrap();
        let d4_d5_root = hasher.hash_two_children(&d4_hash, &d5_hash).unwrap();

        assert_eq!(proof[0], d1_hash);
        assert_eq!(proof[1], d2_d3_root);
        assert_eq!(proof[2], d4_d5_root);
    }

    #[test]
    fn determines_path_for_d2_in_six_leaf_tree() {
        let path = determine_proof_path(2, 6).unwrap();

        assert_eq!(
            path,
            vec![Direction::Left, Direction::Right, Direction::Left,]
        );
    }

    #[test]
    fn determines_path_for_d1_in_six_leaf_tree() {
        let path = determine_proof_path(1, 6).unwrap();

        assert_eq!(
            path,
            vec![Direction::Right, Direction::Left, Direction::Left,]
        );
    }

    #[test]
    fn verifies_single_leaf_proof() {
        let hasher = Blake3Hash;

        let leaf_data = b"d0";
        let expected_root = hasher.hash_leaf(leaf_data).unwrap();

        let proof = Vec::new();

        let result =
            verify_inclusion_proof(&hasher, leaf_data, 0, 1, &proof, &expected_root).unwrap();

        assert!(result);
    }

    #[test]
    fn verifies_two_leaf_proof_for_first_leaf() {
        let hasher = Blake3Hash;

        let mut tree = MerkleTree::new(Blake3Hash);
        tree.append(b"d0").unwrap();
        tree.append(b"d1").unwrap();

        let proof = generate_inclusion_proof(&tree, 0).unwrap();
        let expected_root = tree.root().unwrap();

        let result = verify_inclusion_proof(&hasher, b"d0", 0, 2, &proof, &expected_root).unwrap();

        assert!(result);
    }

    #[test]
    fn verifies_six_leaf_proof_for_d2() {
        let hasher = Blake3Hash;

        let mut tree = MerkleTree::new(Blake3Hash);

        tree.append(b"d0").unwrap();
        tree.append(b"d1").unwrap();
        tree.append(b"d2").unwrap();
        tree.append(b"d3").unwrap();
        tree.append(b"d4").unwrap();
        tree.append(b"d5").unwrap();

        let proof = generate_inclusion_proof(&tree, 2).unwrap();
        let expected_root = tree.root().unwrap();

        let d3 = hasher.hash_leaf(b"d3").unwrap();
        assert_eq!(proof[0], d3);

        let d0 = hasher.hash_leaf(b"d0").unwrap();
        let d1 = hasher.hash_leaf(b"d1").unwrap();
        let d01 = hasher.hash_two_children(&d0, &d1).unwrap();
        assert_eq!(proof[1], d01);

        let d4 = hasher.hash_leaf(b"d4").unwrap();
        let d5 = hasher.hash_leaf(b"d5").unwrap();
        let d45 = hasher.hash_two_children(&d4, &d5).unwrap();
        assert_eq!(proof[2], d45);

        let result = verify_inclusion_proof(&hasher, b"d2", 2, 6, &proof, &expected_root).unwrap();

        assert!(result);
    }

    #[test]
    fn verifies_six_leaf_proof_for_d5() {
        let hasher = Blake3Hash;

        let mut tree = MerkleTree::new(Blake3Hash);

        tree.append(b"d0").unwrap();
        tree.append(b"d1").unwrap();
        tree.append(b"d2").unwrap();
        tree.append(b"d3").unwrap();
        tree.append(b"d4").unwrap();
        tree.append(b"d5").unwrap();

        let proof = generate_inclusion_proof(&tree, 5).unwrap();
        let expected_root = tree.root().unwrap();

        let result = verify_inclusion_proof(&hasher, b"d5", 5, 6, &proof, &expected_root).unwrap();

        assert!(result);
    }
}
