//! Certificate storage and Merkle-tree integration for the MTC system.

use crate::error::CertificateAuthorityError;
use mtc_core::types::HashValue;
use mtc_crypto::hash::HashFn;
use mtc_tree::proof::generate_inclusion_proof;
use mtc_tree::tree::MerkleTree;

/// Manages certificate records and their inclusion in a Merkle tree.
///
/// The certificate authority stores the original certificate bytes and
/// maintains a Merkle tree containing the certificates in insertion order.
/// Each certificate is associated with an index corresponding to its
/// position in the tree.
///
/// The generic parameter `H` specifies the hash implementation used by
/// the underlying Merkle tree.
///
/// # Examples
///
/// ```
/// use mtc_ca::certificate_authority::CertificateAuthority;
/// use mtc_crypto::blake3::Blake3Hash;
///
/// let mut ca = CertificateAuthority::new(Blake3Hash);
///
/// let index = ca.add_certificate(b"example certificate")?;
///
/// assert_eq!(index, 0);
/// assert_eq!(ca.len(), 1);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```

pub struct CertificateAuthority<H: HashFn> {
    tree: MerkleTree<H>,
    certificates: Vec<Vec<u8>>,
}

/// Manages certificate records and their inclusion in the Merkle tree.
impl<H: HashFn> CertificateAuthority<H> {
    /// Creates a new certificate authority with an empty Merkle tree.
    ///
    /// # Arguments
    ///
    /// * `hasher` - Hash implementation used by the underlying Merkle tree.
    ///
    /// # Returns
    ///
    /// A new certificate authority with no stored certificates.
    pub fn new(hasher: H) -> Self {
        Self {
            tree: MerkleTree::new(hasher),
            certificates: Vec::new(),
        }
    }

    /// Stores a certificate and appends it to the Merkle tree.
    ///
    /// The certificate bytes are retained so that the original certificate
    /// can be retrieved later. The returned index identifies the certificate's
    /// position in the tree.
    ///
    /// # Arguments
    ///
    /// * `certificate` - Certificate data to store.
    ///
    /// # Returns
    ///
    /// The index assigned to the newly stored certificate.
    ///
    /// # Errors
    ///
    /// Returns [`CertificateAuthorityError::MemoryAllocationError`] if
    /// memory allocation fails while preparing or storing the certificate.
    /// Returns [`CertificateAuthorityError::Tree`] if the underlying
    /// Merkle-tree operation fails.
    pub fn add_certificate(
        &mut self,
        certificate: &[u8],
    ) -> Result<usize, CertificateAuthorityError> {
        let index = self.certificates.len();

        let mut certificate_bytes = Vec::new();

        certificate_bytes
            .try_reserve_exact(certificate.len())
            .map_err(|_| CertificateAuthorityError::MemoryAllocationError)?;

        certificate_bytes.extend_from_slice(certificate);

        self.certificates
            .try_reserve(1)
            .map_err(|_| CertificateAuthorityError::MemoryAllocationError)?;

        // Hash and append the certificate to the Merkle tree first.
        self.tree.append(certificate)?;

        // Store the original certificate bytes after append succeeds.
        self.certificates.push(certificate_bytes);

        Ok(index)
    }

    /// Returns the certificate stored at the specified index.
    ///
    /// # Arguments
    ///
    /// * `index` - Zero-based index of the certificate.
    ///
    /// # Returns
    ///
    /// A reference to the certificate bytes, or `None` if the index
    /// is out of bounds.
    pub fn get_certificate(&self, index: usize) -> Option<&[u8]> {
        self.certificates.get(index).map(|cert| cert.as_slice())
    }

    /// Returns the number of certificates stored by the authority.
    pub fn len(&self) -> usize {
        self.certificates.len()
    }

    /// Returns `true` if the authority contains no certificates.
    pub fn is_empty(&self) -> bool {
        self.certificates.is_empty()
    }

    /// Returns the current Merkle-tree root hash.
    ///
    /// The root represents the certificates currently stored in the tree.
    /// An empty authority returns the hash defined for an empty tree by
    /// the configured hash implementation.
    ///
    /// # Errors
    ///
    /// Returns [`CertificateAuthorityError::Tree`] if computing the
    /// Merkle-tree root fails.
    pub fn root_hash(&self) -> Result<HashValue, CertificateAuthorityError> {
        Ok(self.tree.root()?)
    }

    /// Generates an inclusion proof for the certificate at the specified index.
    ///
    /// The proof contains the sibling hashes required to reconstruct the
    /// Merkle-tree root for the selected certificate.
    ///
    /// # Arguments
    ///
    /// * `index` - Zero-based index of the certificate in the tree.
    ///
    /// # Returns
    ///
    /// The sibling hashes forming the inclusion proof.
    ///
    /// # Errors
    ///
    /// Returns [`CertificateAuthorityError::Tree`] if the index is invalid
    /// or if proof generation fails.
    ///
    /// # Note
    ///
    /// Generating a proof does not verify it or establish that the root
    /// is trustworthy. A verifier must independently verify the proof
    /// against an expected root.
    pub fn get_inclusion_proof(
        &self,
        index: usize,
    ) -> Result<Vec<HashValue>, CertificateAuthorityError> {
        Ok(generate_inclusion_proof(&self.tree, index)?)
    }
}

// ################################
// ###### Testing #########
// ################################
#[cfg(test)]
mod tests {
    use super::*;
    use mtc_crypto::blake3::Blake3Hash;

    #[test]
    fn new_certificate_authority_private_is_empty() {
        let ca = CertificateAuthority::new(Blake3Hash);

        assert!(ca.certificates.is_empty());
        assert!(ca.tree.is_empty());
    }

    #[test]
    fn add_certificate_stores_original_bytes() {
        let mut ca = CertificateAuthority::new(Blake3Hash);
        let certificate = b"example certificate";

        ca.add_certificate(certificate).unwrap();

        assert_eq!(ca.certificates.len(), 1);
        assert_eq!(ca.certificates[0], certificate);
        assert_eq!(ca.tree.len(), 1);
    }
}
