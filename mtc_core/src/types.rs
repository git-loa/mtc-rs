//! Core data structures shared across the MTC system.
//!
//! These types represent Merkle tree metadata, signed tree heads,
//! and full MTC certificates used for verification.


/// Represents the Merkle tree root and associated metadata.
///
/// A `TreeHead` is the canonical summary of a Merkle tree:
/// - `root`: the 32-byte Merkle root hash
/// - `size`: number of leaves in the tree
/// - `timestamp`: when the tree was constructed (UNIX time)
#[derive(Debug, Clone)]
pub struct Treehead {
    pub root: [u8; 32],
    pub size: u64,
    pub timestamp: u64,
}

/// A signed version of a `TreeHead`.
///
/// This structure contains:
/// - the original `TreeHead`
/// - a digital signature produced by the CA
///
/// The signature is typically generated using a post-quantum
/// signature scheme (e.g., ML-DSA or ML-KEM hybrid).
#[derive(Debug, Clone)]
pub struct SignedTreehead {
    pub treehead: Treehead,
    pub signature: Vec<u8>,
}



/// A complete MTC certificate.
///
/// Contains:
/// - the raw certificate body (`body`)
/// - the Merkle inclusion proof (`proof`)
/// - the signed tree head (`signed_tree_head`)
///
/// This is the object clients receive and verify.
#[derive(Debug, Clone)]
pub struct MtcCertificate {
    pub body: Vec<u8>,
    pub proof: Vec<[u8; 32]>,
    pub signed_treehead: SignedTreehead,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test to ensure that the Treehead struct fields 
    // are correctly assigned and accessible.

    #[test]
    fn test_treehead_fields_are_correct() {
        let root = [0u8; 32];
        let size = 100;
        let timestamp = 123456;

        let th = Treehead {
            root,
            size,
            timestamp,
        };

        assert_eq!(th.root, root);
        assert_eq!(th.size, size);
        assert_eq!(th.timestamp, timestamp);
    }


    // Test to ensure that the SignedTreehead struct fields
    // are correctly assigned and accessible.
    // This test checks that the treehead and signature are correctly stored
    // and can be retrieved.
    #[test]
    fn test_signed_treehead_clones_correctly() {
        let root = [2u8; 32];
        let size = 100;
        let timestamp = 123456;
        let signature = vec![0xAA, 0xBB];

        let treehead = Treehead {
            root,
            size,
            timestamp,
        };

        let signed_treehead = SignedTreehead {
            treehead: treehead.clone(),
            signature: signature.clone(),
        };

        let cloned_signed_treehead = signed_treehead.clone();

        assert_eq!(cloned_signed_treehead.treehead.root, root);
        assert_eq!(cloned_signed_treehead.treehead.size, size);
        assert_eq!(cloned_signed_treehead.treehead.timestamp, timestamp);
        assert_eq!(cloned_signed_treehead.signature, signature);
    }

    // Test to ensure that the MtcCertificate struct fields
    // are correctly assigned and accessible.
    // This test checks that the certificate, proof, and signed treehead
    // are correctly stored and can be retrieved.
    #[test]
    fn test_mtc_certificate_holds_data() {
        let body = vec![0x01, 0x02, 0x03];
        let proof = vec![[0u8; 32], [1u8; 32]];
        let root = [3u8; 32];
        let size = 200;
        let timestamp = 654321;
        let signature = vec![0xCC, 0xDD];

        let treehead = Treehead {
            root,
            size,
            timestamp,
        };

        let signed_treehead = SignedTreehead {
            treehead: treehead.clone(),
            signature: signature.clone(),
        };

        let mtc_certificate = MtcCertificate {
            body: body.clone(),
            proof: proof.clone(),
            signed_treehead: signed_treehead.clone(),
        };

        assert_eq!(mtc_certificate.body, body);
        assert_eq!(mtc_certificate.proof, proof);
        assert_eq!(mtc_certificate.proof.len(), proof.len());
        assert_eq!(mtc_certificate.signed_treehead.treehead.root, root);
        assert_eq!(mtc_certificate.signed_treehead.treehead.size, size);
        assert_eq!(mtc_certificate.signed_treehead.treehead.timestamp, timestamp);
        assert_eq!(mtc_certificate.signed_treehead.signature, signature);
    }
}