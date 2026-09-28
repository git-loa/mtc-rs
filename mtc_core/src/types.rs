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
    Blake3,
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    algorithm: SignatureAlgorithm,
    bytes: Vec<u8>,
}

impl Signature {
    pub fn new(
        algorithm: SignatureAlgorithm,
        bytes: Vec<u8>,
    ) -> Self {
        Self { algorithm, bytes, }
    }


    // ###### ENCAPSULATION ######

    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}


/// A TreeHead together with a cryptographic signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTreeHead {
    tree_head: TreeHead,
    signature: Signature,
}


impl SignedTreeHead {
    pub fn new (
        tree_head: TreeHead,
        signature: Signature,
    ) -> Self {
        Self { tree_head, signature, }
    }

    // Accessors
    pub  fn tree_head(&self) -> &TreeHead {
        &self.tree_head
    }

    pub fn signature(&self) -> &Signature {
        &self.signature
    }
}






/// An MTC certificate containing certificate data,
/// a Merkle inclusion proof, and the authenticated tree state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtcCertificate {
    body: Vec<u8>,
    proof: Vec<HashValue>,
    signed_tree_head: SignedTreeHead,
}

impl MtcCertificate {
    pub fn new (
        body: Vec<u8>,
        proof: Vec<HashValue>,
        signed_tree_head: SignedTreeHead, 
    ) -> Self {
        Self { body, proof, signed_tree_head }
    }

    // Accessors
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn proof(&self) -> &[HashValue] {
        &self.proof
    }

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