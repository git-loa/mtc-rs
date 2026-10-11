use mtc_ca::certificate_authority::CertificateAuthority;
use mtc_crypto::blake3::Blake3Hash;
use mtc_crypto::hash::HashFn;
use mtc_tree::proof::verify_inclusion_proof;

#[test]
fn add_certificate_returns_sequential_indices() {
    let mut ca = CertificateAuthority::new(Blake3Hash);

    let cert1 = ca.add_certificate(b"Certificate A").unwrap();
    let cert2 = ca.add_certificate(b"Certificate B").unwrap();
    let cert3 = ca.add_certificate(b"Certificate C").unwrap();

    assert_eq!(cert1, 0);
    assert_eq!(cert2, 1);
    assert_eq!(cert3, 2);
}

#[test]
fn add_certificate_returns_correct_index() {
    let mut ca = CertificateAuthority::new(Blake3Hash);
    let cert1 = b"Certificate A";
    let cert2 = b"Certificate B";

    let index1 = ca.add_certificate(cert1).unwrap();
    let index2 = ca.add_certificate(cert2).unwrap();

    assert_eq!(index1, 0);
    assert_eq!(index2, 1);
}

#[test]
fn get_certificate_returns_original_certificate() {
    let mut ca = CertificateAuthority::new(Blake3Hash);
    let cert1 = b"Certificate A";
    let cert2 = b"Certificate B";

    let index1 = ca.add_certificate(cert1).unwrap();
    let index2 = ca.add_certificate(cert2).unwrap();

    assert_eq!(ca.get_certificate(index1), Some(&cert1[..]));
    assert_eq!(ca.get_certificate(index2), Some(&cert2[..]));
}

#[test]
fn get_certificate_returns_none_for_invalid_index() {
    let ca = CertificateAuthority::new(Blake3Hash);
    assert!(ca.get_certificate(1).is_none());
}

#[test]
fn new_certificate_authority_is_empty() {
    let ca = CertificateAuthority::new(Blake3Hash);
    assert!(ca.is_empty());
    assert_eq!(ca.len(), 0);
}

#[test]
fn empty_certificate_authority_returns_empty_tree_root() {
    let ca = CertificateAuthority::new(Blake3Hash);
    let hasher = Blake3Hash;

    let root = ca.root_hash().unwrap();
    let expected_empty_tree_hash = hasher.hash_empty().unwrap();

    assert_eq!(root, expected_empty_tree_hash);
}

#[test]
fn simple_adding_certificate_updates_root_hash() {
    let mut ca = CertificateAuthority::new(Blake3Hash);

    let root_before = ca.root_hash().unwrap();

    ca.add_certificate(b"Certificate A").unwrap();

    let root_after = ca.root_hash().unwrap();

    assert_ne!(root_before, root_after);
}

#[test]
fn adding_certificates_updates_root_hash() {
    let mut ca = CertificateAuthority::new(Blake3Hash);
    let hasher = Blake3Hash;

    let cert1 = b"Certificate A";
    let cert2 = b"Certificate B";

    ca.add_certificate(cert1).unwrap();
    let root_after_first = ca.root_hash().unwrap();

    ca.add_certificate(cert2).unwrap();
    let root_after_second = ca.root_hash().unwrap();

    assert_ne!(root_after_first, root_after_second);

    // Verify that the root hash matches the expected Merkle tree root
    let leaf1_hash = hasher.hash_leaf(cert1).unwrap();
    let leaf2_hash = hasher.hash_leaf(cert2).unwrap();
    let expected_root = hasher.hash_two_children(&leaf1_hash, &leaf2_hash).unwrap();

    assert_eq!(root_after_second, expected_root);
}

#[test]
fn get_inclusion_proof_returns_proof_for_valid_index() {
    let mut ca = CertificateAuthority::new(Blake3Hash);
    let cert1 = b"Certificate A";
    let cert2 = b"Certificate B";

    let index1 = ca.add_certificate(cert1).unwrap();
    let index2 = ca.add_certificate(cert2).unwrap();

    let proof1 = ca.get_inclusion_proof(index1).unwrap();
    let proof2 = ca.get_inclusion_proof(index2).unwrap();

    assert!(!proof1.siblings().is_empty());
    assert!(!proof2.siblings().is_empty());
    assert!(proof1 != proof2);
    assert_eq!(proof1.siblings().len(), 1);
    assert_eq!(proof2.siblings().len(), 1);
}

#[test]
fn get_inclusion_proof_returns_error_for_invalid_index() {
    let ca = CertificateAuthority::new(Blake3Hash);
    let result = ca.get_inclusion_proof(0);
    assert!(result.is_err());
}

#[test]
fn two_leaf_inclusion_proofs_contain_the_other_leaf_hash() {
    let mut ca = CertificateAuthority::new(Blake3Hash);
    let cert1 = b"Certificate A";
    let cert2 = b"Certificate B";

    let index1 = ca.add_certificate(cert1).unwrap();
    let index2 = ca.add_certificate(cert2).unwrap();

    let proof1 = ca.get_inclusion_proof(index1).unwrap();
    let proof2 = ca.get_inclusion_proof(index2).unwrap();

    let leaf1_hash = Blake3Hash.hash_leaf(cert1).unwrap();
    let leaf2_hash = Blake3Hash.hash_leaf(cert2).unwrap();

    assert!(proof1.siblings().contains(&leaf2_hash));
    assert!(proof2.siblings().contains(&leaf1_hash));
    assert!(proof1.siblings()[0] == leaf2_hash);
    assert!(proof2.siblings()[0] == leaf1_hash);
}

#[test]
fn inclusion_proof_verifies_against_authority_root() {
    let mut ca = CertificateAuthority::new(Blake3Hash);
    let hasher = Blake3Hash;

    let cert_a = b"Certificate A";
    let cert_b = b"Certificate B";

    ca.add_certificate(cert_a).unwrap();
    ca.add_certificate(cert_b).unwrap();

    let root = ca.root_hash().unwrap();
    let proof = ca.get_inclusion_proof(0).unwrap();

    let result = verify_inclusion_proof(&hasher, cert_a, 0, ca.len(), &proof, &root).unwrap();

    assert!(result);
}

#[test]
fn inclusion_proof_rejects_altered_certificate() {
    let mut ca = CertificateAuthority::new(Blake3Hash);
    let hasher = Blake3Hash;

    ca.add_certificate(b"Certificate A").unwrap();
    ca.add_certificate(b"Certificate B").unwrap();

    let root = ca.root_hash().unwrap();
    let proof = ca.get_inclusion_proof(0).unwrap();

    let result =
        verify_inclusion_proof(&hasher, b"Altered Certificate", 0, ca.len(), &proof, &root)
            .unwrap();

    assert!(!result);
}
