//! Certificate inclusion verification for MTC clients.
//!
//! This module provides functionality for verifying that a certificate
//! is included in a Merkle tree represented by a signed tree head.
//!
//! Inclusion verification does not establish trust in the tree head.
//! The signature on the signed tree head must be verified separately.

use mtc_core::types::MtcCertificate;
use mtc_crypto::hash::HashFn;
use mtc_tree::proof::verify_inclusion_proof;

use crate::error::ClientError;

/// Verifies that a certificate is included in the Merkle tree
/// represented by its signed tree head.
///
/// The function uses the certificate body, leaf index, inclusion proof,
/// and the root and size contained in the signed tree head.
///
/// # Arguments
///
/// * `hasher` - The hash implementation used to verify the Merkle proof.
/// * `certificate` - The certificate and its associated inclusion evidence.
///
/// # Returns
///
/// Returns `Ok(true)` if the inclusion proof is valid, or `Ok(false)`
/// if the proof does not establish inclusion at the specified index.
///
/// # Errors
///
/// Returns [`ClientError::LeafIndexConversion`] if the certificate's
/// leaf index cannot be represented as a `usize`.
///
/// Returns [`ClientError::TreeSizeConversion`] if the tree size cannot
/// be represented as a `usize`.
///
/// Returns [`ClientError::Tree`] if Merkle proof verification returns
/// a tree verification error.
///
/// # Security Considerations
///
/// This function verifies inclusion only. It does not verify the
/// signed tree head's signature, establish trust in the expected root,
/// or determine whether the certificate itself is valid.
pub fn verify_certificate<H: HashFn>(
    hasher: &H,
    certificate: &MtcCertificate,
) -> Result<bool, ClientError> {
    let leaf_index =
        usize::try_from(certificate.leaf_index()).map_err(|_| ClientError::LeafIndexConversion)?;

    let tree_head = certificate.signed_tree_head().tree_head();

    let tree_size =
        usize::try_from(tree_head.size()).map_err(|_| ClientError::TreeSizeConversion)?;

    verify_inclusion_proof(
        hasher,
        certificate.body(),
        leaf_index,
        tree_size,
        certificate.proof(),
        tree_head.root(),
    )
    .map_err(ClientError::from)
}