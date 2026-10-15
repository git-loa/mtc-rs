//! Integration tests for MTC certificate inclusion verification.
//!
//! These tests cover valid inclusion proofs, modified certificate bodies,
//! invalid leaf indices, incorrect Merkle roots, and mismatched leaf indices.
//! They test inclusion verification only; signed tree head signatures
//! are not verified by the current client implementation.

use mtc_client::verification::verify_certificate;
use mtc_core::types::{MtcCertificate, Signature, SignatureAlgorithm, SignedTreeHead, TreeHead};
use mtc_crypto::blake3::Blake3Hash;
use mtc_crypto::hash::HashFn;
use mtc_tree::proof::generate_inclusion_proof;
use mtc_tree::tree::MerkleTree;

/// Verifies that a certificate with a valid inclusion proof is accepted.
#[test]
fn verifies_certificate_with_valid_inclusion_proof() {
    // Arrange: Create a Merkle tree containing three certificates.
    let hasher = Blake3Hash;
    let mut tree = MerkleTree::new(Blake3Hash);

    tree.append(b"certificate-0").unwrap();
    tree.append(b"certificate-1").unwrap();
    tree.append(b"certificate-2").unwrap();

    // Generate an inclusion proof for the second certificate (index 1).
    let leaf_index = 1;
    let proof = generate_inclusion_proof(&tree, leaf_index).unwrap();
    let root = tree.root().unwrap();

    // Construct the tree head.
    let tree_head = TreeHead::new(root, u64::try_from(tree.len()).unwrap(), 1_760_000_000);

    // Use a placeholder signature because signature verification is outside
    // the scope of this inclusion-verification test.
    let signature = Signature::new(SignatureAlgorithm::MlDsa, Vec::new());
    let signed_tree_head = SignedTreeHead::new(tree_head, signature);

    // Construct the MTC certificate.
    let certificate = MtcCertificate::new(
        b"certificate-1".to_vec(),
        u64::try_from(leaf_index).unwrap(),
        proof,
        signed_tree_head,
    );

    // Act: Verify the certificate's inclusion.
    let result = verify_certificate(&hasher, &certificate).unwrap();

    // Assert: The inclusion proof should be valid.
    assert!(result);
}

/// Rejects a certificate whose body differs from the data in the Merkle tree.
#[test]
fn rejects_certificate_with_modified_body() {
    // Arrange: Construct a Merkle tree containing three certificates.
    let hasher = Blake3Hash;
    let mut tree = MerkleTree::new(Blake3Hash);

    tree.append(b"certificate-0").unwrap();
    tree.append(b"certificate-1").unwrap();
    tree.append(b"certificate-2").unwrap();

    // Generate a valid proof for the second certificate (index 1).
    let leaf_index = 1;
    let proof = generate_inclusion_proof(&tree, leaf_index).unwrap();
    let root = tree.root().unwrap();

    // Construct the tree head.
    let tree_head = TreeHead::new(root, u64::try_from(tree.len()).unwrap(), 1_760_000_000);

    // Use a placeholder signature; signature verification is not tested here.
    let signature = Signature::new(SignatureAlgorithm::MlDsa, Vec::new());
    let signed_tree_head = SignedTreeHead::new(tree_head, signature);

    // Construct a certificate with a modified body.
    let certificate = MtcCertificate::new(
        b"modified-certificate-1".to_vec(),
        u64::try_from(leaf_index).unwrap(),
        proof,
        signed_tree_head,
    );

    // Act: Verify the certificate's inclusion.
    let result = verify_certificate(&hasher, &certificate).unwrap();

    // Assert: The modified body must not match the original Merkle root.
    assert!(!result);
}

/// Rejects a certificate whose leaf index lies outside the tree's valid range.
#[test]
fn rejects_certificate_with_invalid_leaf_index() {
    // Arrange: Construct a Merkle tree containing three certificates.
    let hasher = Blake3Hash;
    let mut tree = MerkleTree::new(Blake3Hash);

    tree.append(b"certificate-0").unwrap();
    tree.append(b"certificate-1").unwrap();
    tree.append(b"certificate-2").unwrap();

    // Generate a valid proof for index 1 and obtain the tree root.
    let proof = generate_inclusion_proof(&tree, 1).unwrap();
    let root = tree.root().unwrap();
    let tree_head = TreeHead::new(root, u64::try_from(tree.len()).unwrap(), 1_760_000_000);

    // Construct a signed tree head with a placeholder signature.
    let signature = Signature::new(SignatureAlgorithm::MlDsa, Vec::new());
    let signed_tree_head = SignedTreeHead::new(tree_head, signature);

    // Construct a certificate using index 3, which is invalid for this tree.
    let certificate = MtcCertificate::new(
        b"certificate-1".to_vec(),
        3,
        proof,
        signed_tree_head,
    );

    // Act: Verify the certificate's inclusion.
    let result = verify_certificate(&hasher, &certificate);

    // Assert: The invalid leaf index must produce an error.
    assert!(result.is_err());
}

/// Rejects a certificate when the expected Merkle root is incorrect.
#[test]
fn rejects_certificate_with_incorrect_merkle_root() {
    // Arrange: Construct a Merkle tree containing three certificates.
    let hasher = Blake3Hash;
    let mut tree = MerkleTree::new(Blake3Hash);

    tree.append(b"certificate-0").unwrap();
    tree.append(b"certificate-1").unwrap();
    tree.append(b"certificate-2").unwrap();

    let leaf_index = 1;
    let proof = generate_inclusion_proof(&tree, leaf_index).unwrap();

    // Deliberately create an incorrect expected root.
    let incorrect_root = hasher.hash_leaf(b"incorrect-root").unwrap();

    let tree_head = TreeHead::new(
        incorrect_root,
        u64::try_from(tree.len()).unwrap(),
        1_760_000_000,
    );

    // Use a placeholder signature because signature verification is not tested.
    let signature = Signature::new(SignatureAlgorithm::MlDsa, Vec::new());
    let signed_tree_head = SignedTreeHead::new(tree_head, signature);

    // Construct the certificate using the original body and proof.
    let certificate = MtcCertificate::new(
        b"certificate-1".to_vec(),
        u64::try_from(leaf_index).unwrap(),
        proof,
        signed_tree_head,
    );

    // Act: Verify the certificate's inclusion.
    let result = verify_certificate(&hasher, &certificate);

    // Assert: Verification succeeds operationally but rejects the inclusion claim.
    assert!(matches!(result, Ok(false)));
}

/// Rejects a certificate whose proof does not match its claimed leaf index.
#[test]
fn rejects_certificate_with_mismatched_leaf_index() {
    // Arrange: Construct a Merkle tree containing three certificates.
    let hasher = Blake3Hash;
    let mut tree = MerkleTree::new(Blake3Hash);

    tree.append(b"certificate-0").unwrap();
    tree.append(b"certificate-1").unwrap();
    tree.append(b"certificate-2").unwrap();

    // Generate a proof for certificate-1 at index 1.
    let proof = generate_inclusion_proof(&tree, 1).unwrap();
    let root = tree.root().unwrap();

    let tree_head = TreeHead::new(root, u64::try_from(tree.len()).unwrap(), 1_760_000_000);

    // Construct a signed tree head with a placeholder signature.
    let signature = Signature::new(SignatureAlgorithm::MlDsa, Vec::new());
    let signed_tree_head = SignedTreeHead::new(tree_head, signature);

    // The body and proof belong to index 1, but the certificate claims index 0.
    let certificate = MtcCertificate::new(
        b"certificate-1".to_vec(),
        0,
        proof,
        signed_tree_head,
    );

    // Act: Verify the certificate's inclusion.
    let result = verify_certificate(&hasher, &certificate);

    // Assert: The mismatched index must not verify successfully.
    assert!(matches!(result, Ok(false)));
}