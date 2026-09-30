//! Core data structures shared across the MTC system.
//!
//! This module defines types for cryptographic values, Merkle tree state,
//! signatures, and MTC certificate data.
//!
//! The types are independent of concrete cryptographic implementations.
//! Cryptographic operations are provided by higher-level crates such as
//! `mtc_crypto`.

/// Identifies the cryptographic hash algorithm associated with a hash value.
///
/// The enum records the algorithm used to produce a [`HashValue`].
/// Concrete hash implementations are provided through the `HashFn`
/// abstraction in the `mtc_crypto` crate. Currently, BLAKE3 is implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-256.
    Sha256,
    
    /// SHA-384.
    Sha384,
    
    /// SHA-512.
    Sha512,
    
    /// BLAKE3.
    Blake3,
}

/// A cryptographic hash value and the algorithm that produced it.
///
/// The digest length is validated when the value is created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashValue {
    /// Algorithm used to produce the digest.
    algorithm: HashAlgorithm,

    /// Raw digest bytes.
    bytes: Vec<u8>,
}

impl HashValue{ 
    /// Creates a hash value and validates its digest length.
    ///
    /// Returns an error if the length does not match the selected algorithm.
    pub fn new(
        algorithm: HashAlgorithm,
        bytes: Vec<u8>,
    ) -> Result<Self, String> {

        // Validates the digest length for the selected algorithm.
        let expected_length = match algorithm {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
            HashAlgorithm::Blake3 => 32,
        };

        // Failure
        if bytes.len() != expected_length {
            return Err(
                format!("Invalid hash length: expected {}, got {}", 
                expected_length,
                bytes.len()
            ));
        }

        Ok(Self { algorithm, bytes})
    }

    /// Returns the algorithm associated with the hash value.
    pub fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    /// Returns a read-only view of the hash bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}


///Represents the root and metadata of a Merkle tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeHead {
    /// Merkle tree root hash.
    root: HashValue,

    /// Number of leaves represented by the tree.
    size: u64,

    /// Timestamp associated with the tree state.
    timestamp: u64,
}


impl TreeHead {
    /// Returns the Merkle tree root.
    pub fn root(&self) -> &HashValue {
        &self.root
    }

    /// Returns the number of leaves in the tree.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the timestamp associated with the tree state.
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
}


/// Identifies the signature algorithm associated with a signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// ECDSA.
    Ecdsa,

    /// ML-DSA.
    MlDsa,

    /// SLH-DSA.
    SlhDsa,
}


/// A cryptographic signature and the algorithm that produced it.
///
/// Signature validation is handled by the cryptographic layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    algorithm: SignatureAlgorithm,
    bytes: Vec<u8>,
}

impl Signature {
    /// Creates a signature from an algorithm and its raw bytes.
    pub fn new(
        algorithm: SignatureAlgorithm,
        bytes: Vec<u8>,
    ) -> Self {
        Self { algorithm, bytes, }
    }


    /// Returns the algorithm associated with the signature.
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

     /// Returns a read-only view of the signature bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}


/// A Merkle tree head together with its cryptographic signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTreeHead {
    /// Merkle tree state being authenticated.
    tree_head: TreeHead,

    /// Signature associated with the tree head.
    signature: Signature,
}


impl SignedTreeHead {
    /// Creates a signed tree head from a tree head and signature.
    pub fn new (
        tree_head: TreeHead,
        signature: Signature,
    ) -> Self {
        Self { tree_head, signature, }
    }

    /// Returns the authenticated tree head.
    pub  fn tree_head(&self) -> &TreeHead {
        &self.tree_head
    }

    /// Returns the signature associated with the tree head.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }
}


/// An MTC certificate containing certificate data,
/// a Merkle inclusion proof, and a signed tree head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtcCertificate {
    /// Certificate data represented by the Merkle tree.
    body: Vec<u8>,

    /// Hash values used for Merkle inclusion verification.
    proof: Vec<HashValue>,

    /// Authenticated tree state associated with the certificate.
    signed_tree_head: SignedTreeHead,
}

impl MtcCertificate {
    /// Creates an MTC certificate from its components.
    pub fn new (
        body: Vec<u8>,
        proof: Vec<HashValue>,
        signed_tree_head: SignedTreeHead, 
    ) -> Self {
        Self { body, proof, signed_tree_head }
    }

    /// Returns a read-only view of the certificate body.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Returns a read-only view of the Merkle proof.
    pub fn proof(&self) -> &[HashValue] {
        &self.proof
    }

    /// Returns the signed tree head.
    pub fn signed_tree_head(&self) -> &SignedTreeHead {
        &self.signed_tree_head
    }
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

    #[test]
    fn signed_tree_head_exposes_tree_head_and_signature() {
        let hash = HashValue::new(
            HashAlgorithm::Sha256, 
            vec![0u8; 32]
        ).unwrap();

        let tree_head = TreeHead {
            root: hash,
            size: 100,
            timestamp: 1_757_000_000,
        };
        let signature = Signature::new(SignatureAlgorithm::MlDsa, vec![0u8, 100]);

        let signed_tree_head = SignedTreeHead::new(
            tree_head.clone(),
            signature.clone(),
        );

        assert_eq!(signed_tree_head.tree_head(), &tree_head);
        assert_eq!(signed_tree_head.signature(), &signature);
    }




    //####### MtcCertificate ##########
    #[test]
    fn mtc_certificate_exposes_body_proof_and_signed_tree_head() {
        let body = vec![1u8, 2u8, 3u8];

        let proof_hash = HashValue::new(
            HashAlgorithm::Sha256,
            vec![0u8; 32],
        )
        .unwrap();

        let proof = vec![proof_hash.clone()];

        let hash = HashValue::new(
            HashAlgorithm::Sha256,
            vec![0u8; 32],
        )
        .unwrap();

        let tree_head = TreeHead {
            root: hash,
            size: 100,
            timestamp: 1_757_000_000,
        };

        let signature = Signature::new(
            SignatureAlgorithm::MlDsa,
            vec![0u8; 100],
        );

        let signed_tree_head = SignedTreeHead::new(
            tree_head,
            signature,
        );

        let certificate = MtcCertificate::new(
            body.clone(),
            proof.clone(),
            signed_tree_head.clone(),
        );

        assert_eq!(
            certificate.body(),
            body.as_slice()
        );

        assert_eq!(
            certificate.proof(),
            proof.as_slice()
        );

        assert_eq!(
            certificate.signed_tree_head(),
            &signed_tree_head
        );
    }

}