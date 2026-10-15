//! Error types returned by the MTC client.

use thiserror::Error;

/// Represents errors that can occur during certificate verification.
#[derive(Debug, Error)]
pub enum ClientError {
    /// The certificate's leaf index cannot be represented as a `usize`
    /// on the current platform.
    #[error("Leaf index cannot be represented on this platform")]
    LeafIndexConversion,

    /// The Merkle tree size cannot be represented as a `usize`
    /// on the current platform.
    #[error("Tree size cannot be represented on this platform")]
    TreeSizeConversion,

    /// An error occurred during Merkle tree inclusion-proof verification.
    #[error("Merkle tree verification failed: {0}")]
    Tree(#[from] mtc_tree::error::TreeError),
}