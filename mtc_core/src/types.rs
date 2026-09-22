//! Core data structures shared across the MTC system.
//!
//! These types represent Merkle tree metadata an MTC
//!  structures used throughout the system.


/// Identifies  the hash algorithm used to produce a digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

/// A cryptographic hash value together with the algorithm
/// that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashValue {
    algorithm: HashAlgorithm,
    bytes: Vec<u8>,
}



impl HashValue{ 
    pub fn new(
        algorithm: HashAlgorithm,
        bytes: Vec<u8>,
    ) -> Result<Self, String> {

        //Validating the HashAlgorithm construction.
        // Matching HashAlgorithms with expected hash values.
        let expected_length = match algorithm {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
        };


        // Failure
        if bytes.len() != expected_length {
            return Err(
                format!("Invalid hash length: expected {}, got {}", 
                expected_length,
                bytes.len()
            ));
        }

        Ok(Self {
            algorithm,
            bytes,
        })
    }


    // ####### ENCAPSULATION ########

    // Returns the hash algorithm used to produce this value.
    pub fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    // Returns a borrowed view of the hash bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}


///Represents the root and metadata of a Merkle tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeHead {
    root: HashValue,
    size: u64,
    timestamp: u64,
}


impl TreeHead {
    pub fn root(&self) -> &HashValue {
        &self.root
    }

    // ###### ENCAPSULATION ######

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
}


/// Identifies the signature algorithm used to produce a signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    Ecdsa,
    MlDsa,
    SlhDsa,
}


/// A cryptographic signature together with the algorithm
/// that produced it.
/// #[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    algorithm: SignatureAlgorithm,
    bytes: Vec<u8>,
}


impl Signature {
    pub fn new(
        algorithm: SignatureAlgorithm,
        bytes: Vec<u8>,
    ) -> Self {
        Self {
        algorithm,
        bytes,
        }
    }


    // ###### ENCAPSULATION ######

    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
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
    pub treehead: TreeHead,
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


//###############################
//######## UNIT TESTING #########
//###############################

#[cfg(test)]
mod tests {
    use super::*;

    // Testing that hash algorithm is Sha256 with 
    //digest size equal to 23.
    #[test]
    fn sha256_hash_with32_bytes_is_valid() {
        let bytes = vec![0u8; 32];

        let result = HashValue::new(
            HashAlgorithm::Sha256,
            bytes,
        );
        
        //println!("result = {:?}", result);
        assert!(result.is_ok());
    }


    #[test]
    fn sha256_hash_with_wrong_length_is_rejected() {
        let bytes = vec![0u8; 10];

        let result = HashValue::new(
            HashAlgorithm::Sha256,
            bytes,
        );

        assert!(result.is_err());
    }

    // Testing attirbute-hiding (Encapsulation)
    #[test]
    fn hash_value_exposes_algorithm_and_bytes() {
        let bytes = vec![0u8; 32];

        let hash = HashValue::new(
            HashAlgorithm::Sha256,
            bytes.clone(),
        ).unwrap();
        
        assert_eq!(hash.algorithm(), HashAlgorithm::Sha256);
        assert_eq!(hash.bytes(), bytes.as_slice());

    }
    //###################################################
    //######### Testing Units for TreeHead ##############
    //###################################################
    #[test]
    fn tree_head_holds_hash_and_metadata() {
        let hash = HashValue::new(
            HashAlgorithm::Sha256,
            vec![0u8; 32],
        ).unwrap();

        let tree_head = TreeHead {
            root: hash.clone(),
            size: 100,
            timestamp: 1_757_000_000,
        };

        assert_eq!(tree_head.root, hash);
        assert_eq!(tree_head.size, 100);
        assert_eq!(tree_head.timestamp, 1_757_000_000);
    }


    // Testing Encapsulation.
    #[test]
    fn tree_head_exposes_root_size_timestamp() {
        let hash = HashValue::new(
            HashAlgorithm::Sha256,
            vec![0u8; 32],
        ).unwrap();

        let tree_head = TreeHead {
            root: hash.clone(),
            size: 100,
            timestamp: 1_757_000_000,
        };

        assert_eq!(tree_head.root(), &hash);
        assert_eq!(tree_head.size(), 100);
        assert_eq!(tree_head.timestamp(), 1_757_000_000);
    }


    //#######################################
    //################ Signature ############
    //#######################################

    // Testing signature algorithm
    #[test]
    fn signature_algorithm_can_be_identified() {
        let algorithm = SignatureAlgorithm::MlDsa;

        assert_eq!(algorithm, SignatureAlgorithm::MlDsa);
    }


    #[test]
    fn signature_exposes_algorithm_and_bytes() {
        let bytes = vec![0u8; 100];
        let signature = Signature::new(
            SignatureAlgorithm::MlDsa,
            bytes.clone(),
        );

        assert_eq!(signature.algorithm(), SignatureAlgorithm::MlDsa);
        assert_eq!(signature.bytes(), bytes.as_slice());
    }

//     // Test to ensure that the Treehead struct fields 
//     // are correctly assigned and accessible.

//     #[test]
//     fn test_treehead_fields_are_correct() {
//         let root = [0u8; 32];
//         let size = 100;
//         let timestamp = 123456;

//         let th = TreeHead {
//             root,
//             size,
//             timestamp,
//         };

//         assert_eq!(th.root, root);
//         assert_eq!(th.size, size);
//         assert_eq!(th.timestamp, timestamp);
//     }


//     // Test to ensure that the SignedTreehead struct fields
//     // are correctly assigned and accessible.
//     // This test checks that the treehead and signature are correctly stored
//     // and can be retrieved.
//     #[test]
//     fn test_signed_treehead_clones_correctly() {
//         let root = [2u8; 32];
//         let size = 100;
//         let timestamp = 123456;
//         let signature = vec![0xAA, 0xBB];

//         let treehead = TreeHead {
//             root,
//             size,
//             timestamp,
//         };

//         let signed_treehead = SignedTreehead {
//             treehead: treehead.clone(),
//             signature: signature.clone(),
//         };

//         let cloned_signed_treehead = signed_treehead.clone();

//         assert_eq!(cloned_signed_treehead.treehead.root, root);
//         assert_eq!(cloned_signed_treehead.treehead.size, size);
//         assert_eq!(cloned_signed_treehead.treehead.timestamp, timestamp);
//         assert_eq!(cloned_signed_treehead.signature, signature);
//     }

//     // Test to ensure that the MtcCertificate struct fields
//     // are correctly assigned and accessible.
//     // This test checks that the certificate, proof, and signed treehead
//     // are correctly stored and can be retrieved.
//     #[test]
//     fn test_mtc_certificate_holds_data() {
//         let body = vec![0x01, 0x02, 0x03];
//         let proof = vec![[0u8; 32], [1u8; 32]];
//         let root = [3u8; 32];
//         let size = 200;
//         let timestamp = 654321;
//         let signature = vec![0xCC, 0xDD];

//         let treehead = Treehead {
//             root,
//             size,
//             timestamp,
//         };

//         let signed_treehead = SignedTreehead {
//             treehead: treehead.clone(),
//             signature: signature.clone(),
//         };

//         let mtc_certificate = MtcCertificate {
//             body: body.clone(),
//             proof: proof.clone(),
//             signed_treehead: signed_treehead.clone(),
//         };

//         assert_eq!(mtc_certificate.body, body);
//         assert_eq!(mtc_certificate.proof, proof);
//         assert_eq!(mtc_certificate.proof.len(), proof.len());
//         assert_eq!(mtc_certificate.signed_treehead.treehead.root, root);
//         assert_eq!(mtc_certificate.signed_treehead.treehead.size, size);
//         assert_eq!(mtc_certificate.signed_treehead.treehead.timestamp, timestamp);
//         assert_eq!(mtc_certificate.signed_treehead.signature, signature);
//     }
}