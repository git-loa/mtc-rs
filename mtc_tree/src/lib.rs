//! # mtc_tree
//!
//! ## Purpose
//!
//! Provides Merkle tree construction, root computation, and inclusion-proof
//! operations for the MTC system.
//!
//! ## Responsibilities
//!
//! - Store the hashes of certificate records added to a Merkle tree.
//! - Compute Merkle roots using a configurable hash implementation.
//! - Generate inclusion proofs for individual leaves.
//! - Verify inclusion proofs against an expected Merkle root.
//! - Report errors arising from tree operations and underlying hash operations.
//!
//! ## Design
//!
//! The `MerkleTree<H>` type uses the `HashFn` trait from `mtc_crypto`,
//! separating tree logic from a particular hash implementation.
//!
//! Tree construction uses a recursive Merkle Tree Hash structure. For a
//! subtree containing more than one leaf, the leaves are divided at the
//! largest power of two strictly smaller than the subtree size.
//!
//! Inclusion proofs contain sibling subtree hashes in leaf-to-root order.
//! During verification, the leaf index and tree size determine how each
//! sibling hash is combined with the running hash.
//!
//! ## Boundaries
//!
//! This crate handles Merkle tree operations and inclusion proofs. It does
//! not issue certificates, generate digital signatures, or determine whether
//! a signed tree head is trusted.
//!
//! ## Status
//!
//! Merkle tree construction, root computation, inclusion-proof generation,
//! and inclusion-proof verification are implemented.
//!
//! Unit tests cover empty and non-empty trees, recursive tree structures,
//! proof generation, invalid leaf indices, and proof verification.
//!
//! ## Future extensions
//!
//! Consistency proofs, additional proof types, and integration with the
//! certificate-authority and client components may be considered as the
//! MTC architecture develops.
//!
//! See `docs/MATH.md` for the mathematical definition of the tree structure
//! and the reasoning behind inclusion-proof verification.

pub mod error;
pub mod proof;
pub mod tree;