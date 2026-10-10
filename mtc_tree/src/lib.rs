//! Merkle tree construction and inclusion proofs for the MTC system.
//!
//! This crate provides the [`tree::MerkleTree`] type for storing leaf hashes
//! and computing Merkle roots, along with functions for generating and
//! verifying inclusion proofs.
//!
//! The tree uses the [`mtc_crypto::hash::HashFn`] trait to support different
//! hash implementations without coupling tree operations to a particular
//! algorithm.
//!
//! ## Tree construction
//!
//! The tree follows a recursive Merkle Tree Hash construction. For a
//! subtree containing more than one leaf, the leaves are split at the
//! largest power of two strictly smaller than the subtree size.
//!
//! Inclusion proofs contain sibling subtree hashes in leaf-to-root order.
//! Verification uses the leaf index and tree size to determine the order
//! in which sibling hashes are combined.
//!
//! ## Security boundaries
//!
//! This crate implements Merkle tree operations and inclusion proofs.
//! It does not issue certificates, generate digital signatures, or
//! establish trust in a supplied Merkle root or signed tree head.
//!
//! Successful inclusion-proof verification establishes that the supplied
//! leaf data is consistent with the expected root under the configured
//! hashing rules. It does not establish that the root itself is trustworthy.
//!
//! See `docs/MATH.md` for the mathematical definition of the tree structure
//! and the reasoning behind inclusion-proof verification.

pub mod error;
pub mod proof;
pub mod tree;
