//! Certificate authority operations for the MTC system.

use mtc_core::types::HashValue;
use mtc_crypto::hash::HashFn;
use mtc_tree::error::TreeError;
use mtc_tree::proof::generate_inclusion_proof;
use mtc_tree::tree::MerkleTree;

/// Coordintes certificate storage nad Merkle tree opreations.
pub struct CertificateAuthority<H: HashFn> {
    tree: MerkleTree<H>,
    certificate: Vec<Vec<u8>>,
}

impl<H: HashFn> CertificateAuthority<H> {
    pub fn new(hasher: H) -> Self {
        Self {
            tree: MerkleTree::new(hasher),
            certificate: Vec::new(),
        }
    }
}
