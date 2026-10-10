//! # mtc_crypto
//!
//! ## Purpose
//!
//! Provides cryptographic abstractions and hash implementations for the
//! MTC system.
//!
//! ## Responsibilities
//!
//! - Define a common interface for Merkle-tree hash operations.
//! - Provide a BLAKE3 implementation of the `HashFn` trait.
//! - Apply domain separation to distinguish leaf and internal-node hashing.
//! - Represent errors arising from hash operations.
//!
//! ## Design
//!
//! The `HashFn` trait separates Merkle-tree logic from a specific hash
//! implementation. Tree operations can use this interface without being
//! directly coupled to BLAKE3.
//!
//! The current BLAKE3 implementation uses `0x00` for leaf inputs and
//! `0x01` for internal-node inputs.
//!
//! ## Boundaries
//!
//! This crate provides hash-related abstractions and implementations.
//! Shared cryptographic data types belong in `mtc_core`, while Merkle-tree
//! construction and inclusion-proof handling belong in `mtc_tree`.
//!
//! This crate currently does not implement digital-signature generation
//! or verification.
//!
//! ## Status
//!
//! The hash interface, BLAKE3 implementation, and cryptographic error
//! types are implemented. Unit tests cover determinism, differing inputs,
//! algorithm mismatch rejection, and distinctions between leaf, node,
//! and empty-tree hashing.
//!
//! ## Future extensions
//!
//! Additional hash implementations and digital-signature operations may
//! be considered as the MTC system's requirements develop.
//!
//! A common interface supports implementation flexibility, but does not
//! by itself guarantee protocol compatibility or security against
//! quantum-capable attackers.

pub mod blake3;
pub mod error;
pub mod hash;