//! Shared data structures for cryptographic values and MTC certificate data.
//!
//! This module defines hash values, Merkle tree heads, signature-related
//! types, and MTC certificate data. These types are independent of concrete
//! cryptographic implementations; cryptographic operations are provided by
//! other components.

/// Identifies the hash algorithm associated with a [`HashValue`].
///
/// This enum records an algorithm identifier; it does not implement the
/// algorithm. The `mtc_crypto` crate currently provides a BLAKE3 implementation.
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

/// Stores a digest and the identifier of the hash algorithm associated with it.
///
/// The digest length is checked when a value is constructed. This check does
/// not establish that the bytes were actually produced by the identified algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashValue {
    /// Algorithm used to produce the digest.
    algorithm: HashAlgorithm,

    /// Raw digest bytes.
    bytes: Vec<u8>,
}

impl HashValue {
    /// Creates a hash value after validating the digest length.
    ///
    /// `algorithm` identifies the hash algorithm associated with `bytes`.
    /// The bytes are stored as supplied if their length matches the expected
    /// digest length; this constructor does not recompute or authenticate the digest.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` has a length different from the expected
    /// digest length for `algorithm`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use mtc_core::types::{HashAlgorithm, HashValue};
    ///
    /// let digest = vec![0_u8; 32];
    /// let value = HashValue::new(HashAlgorithm::Sha256, digest);
    /// assert!(value.is_ok());
    /// ```
    pub fn new(algorithm: HashAlgorithm, bytes: Vec<u8>) -> Result<Self, String> {
        // Validates the digest length for the selected algorithm.
        let expected_length = match algorithm {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
            HashAlgorithm::Blake3 => 32,
        };

        // Failure
        if bytes.len() != expected_length {
            return Err(format!(
                "Invalid hash length: expected {}, got {}",
                expected_length,
                bytes.len()
            ));
        }

        Ok(Self { algorithm, bytes })
    }

    /// Returns the algorithm identifier associated with the hash value.
    pub fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    /// Returns the digest bytes as a borrowed slice.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Represents the root hash and metadata of a Merkle tree.
///
/// The timestamp's unit and interpretation are defined by the surrounding
/// protocol or application; this type does not enforce them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeHead {
    /// Root hash representing the tree contents.
    root: HashValue,

    /// Number of leaves represented by this tree head.
    size: u64,

    //// Timestamp associated with this tree state, in the unit chosen by the caller.
    timestamp: u64,
}

impl TreeHead {
    /// Returns a reference to the Merkle tree root hash.
    pub fn root(&self) -> &HashValue {
        &self.root
    }

    /// Returns the number of leaves represented by this tree head.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the timestamp associated with this tree head.
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
}

/// Identifies the signature algorithm associated with a [`Signature`].
///
/// These variants are identifiers only; they do not provide signing or
/// verification implementations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// ECDSA.
    Ecdsa,

    /// ML-DSA.
    MlDsa,

    /// SLH-DSA.
    SlhDsa,
}

/// Stores signature bytes and the identifier of the associated algorithm.
///
/// This type represents signature data; it does not validate the signature
/// or establish its authenticity. Signature verification is performed by a
/// component that implements the relevant cryptographic algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// Algorithm identified as having produced the signature.
    algorithm: SignatureAlgorithm,

    /// Raw signature bytes.
    bytes: Vec<u8>,
}

impl Signature {
    /// Creates a signature value from an algorithm identifier and raw bytes.
    ///
    /// The supplied bytes are stored without checking whether they form a
    /// valid signature for the selected algorithm.
    pub fn new(algorithm: SignatureAlgorithm, bytes: Vec<u8>) -> Self {
        Self { algorithm, bytes }
    }

    /// Returns the signature algorithm identifier.
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    /// Returns the raw signature bytes as a borrowed slice.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A Merkle tree head together with its associated signature.
///
/// This type groups the tree head and signature; it does not verify the
/// signature or establish trust in the tree head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTreeHead {
    /// Merkle tree state associated with the signature.
    tree_head: TreeHead,

    /// Signature associated with the tree head.
    signature: Signature,
}

impl SignedTreeHead {
    /// Creates a signed tree head from a tree head and signature.
    ///
    /// This signature does not verify the signature; it simply stores the provided values.
    pub fn new(tree_head: TreeHead, signature: Signature) -> Self {
        Self {
            tree_head,
            signature,
        }
    }

    /// Returns the tree head associated with the signature.
    pub fn tree_head(&self) -> &TreeHead {
        &self.tree_head
    }

    /// Returns the signature associated with the tree head.
    pub fn signature(&self) -> &Signature {
        &self.signature
    }
}

/// Groups certificate data, a Merkle inclusion proof, and a signed tree head.
///
/// This type does not verify the inclusion proof, verify the tree-head
/// signature, or establish trust in the supplied tree head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtcCertificate {
    /// Certificate data represented by the Merkle tree.
    body: Vec<u8>,

    /// Sibling hashes used to reconstruct a Merkle root during inclusion verification.
    proof: Vec<HashValue>,

    /// Tree head and its associated signature; neither is verified by this type.
    signed_tree_head: SignedTreeHead,
}

impl MtcCertificate {
    /// Creates an MTC certificate value from its components.
    ///
    /// The supplied data is stored without verifying the inclusion proof or
    /// the signature associated with the tree head.
    pub fn new(body: Vec<u8>, proof: Vec<HashValue>, signed_tree_head: SignedTreeHead) -> Self {
        Self {
            body,
            proof,
            signed_tree_head,
        }
    }

    /// Returns the certificate body as a borrowed byte slice.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Returns the inclusion proof as a borrowed slice of sibling hashes.
    pub fn proof(&self) -> &[HashValue] {
        &self.proof
    }

    /// Returns the tree head and associated signature.
    pub fn signed_tree_head(&self) -> &SignedTreeHead {
        &self.signed_tree_head
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hash_with32_bytes_is_valid() {
        let bytes = vec![0u8; 32];

        let result = HashValue::new(HashAlgorithm::Sha256, bytes);

        //println!("result = {:?}", result);
        assert!(result.is_ok());
    }

    #[test]
    fn sha256_hash_with_wrong_length_is_rejected() {
        let bytes = vec![0u8; 10];

        let result = HashValue::new(HashAlgorithm::Sha256, bytes);

        assert!(result.is_err());
    }

    #[test]
    fn hash_value_exposes_algorithm_and_bytes() {
        let bytes = vec![0u8; 32];

        let hash = HashValue::new(HashAlgorithm::Sha256, bytes.clone()).unwrap();

        assert_eq!(hash.algorithm(), HashAlgorithm::Sha256);
        assert_eq!(hash.bytes(), bytes.as_slice());
    }

    #[test]
    fn tree_head_holds_hash_and_metadata() {
        let hash = HashValue::new(HashAlgorithm::Sha256, vec![0u8; 32]).unwrap();

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
        let hash = HashValue::new(HashAlgorithm::Sha256, vec![0u8; 32]).unwrap();

        let tree_head = TreeHead {
            root: hash.clone(),
            size: 100,
            timestamp: 1_757_000_000,
        };

        assert_eq!(tree_head.root(), &hash);
        assert_eq!(tree_head.size(), 100);
        assert_eq!(tree_head.timestamp(), 1_757_000_000);
    }

    #[test]
    fn signature_algorithm_can_be_identified() {
        let algorithm = SignatureAlgorithm::MlDsa;

        assert_eq!(algorithm, SignatureAlgorithm::MlDsa);
    }

    #[test]
    fn signature_exposes_algorithm_and_bytes() {
        let bytes = vec![0u8; 100];
        let signature = Signature::new(SignatureAlgorithm::MlDsa, bytes.clone());

        assert_eq!(signature.algorithm(), SignatureAlgorithm::MlDsa);
        assert_eq!(signature.bytes(), bytes.as_slice());
    }

    #[test]
    fn signed_tree_head_exposes_tree_head_and_signature() {
        let hash = HashValue::new(HashAlgorithm::Sha256, vec![0u8; 32]).unwrap();

        let tree_head = TreeHead {
            root: hash,
            size: 100,
            timestamp: 1_757_000_000,
        };
        let signature = Signature::new(SignatureAlgorithm::MlDsa, vec![0u8, 100]);

        let signed_tree_head = SignedTreeHead::new(tree_head.clone(), signature.clone());

        assert_eq!(signed_tree_head.tree_head(), &tree_head);
        assert_eq!(signed_tree_head.signature(), &signature);
    }

    #[test]
    fn mtc_certificate_exposes_body_proof_and_signed_tree_head() {
        let body = vec![1u8, 2u8, 3u8];

        let proof_hash = HashValue::new(HashAlgorithm::Sha256, vec![0u8; 32]).unwrap();

        let proof = vec![proof_hash.clone()];

        let hash = HashValue::new(HashAlgorithm::Sha256, vec![0u8; 32]).unwrap();

        let tree_head = TreeHead {
            root: hash,
            size: 100,
            timestamp: 1_757_000_000,
        };

        let signature = Signature::new(SignatureAlgorithm::MlDsa, vec![0u8; 100]);

        let signed_tree_head = SignedTreeHead::new(tree_head, signature);

        let certificate =
            MtcCertificate::new(body.clone(), proof.clone(), signed_tree_head.clone());

        assert_eq!(certificate.body(), body.as_slice());

        assert_eq!(certificate.proof(), proof.as_slice());

        assert_eq!(certificate.signed_tree_head(), &signed_tree_head);
    }
}
