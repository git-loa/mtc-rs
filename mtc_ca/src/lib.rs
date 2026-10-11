//! Certificate-authority functionality for the Merkle Tree Certificate (MTC) system.
//!
//! This crate coordinates certificate storage and integration with the
//! MTC transparency tree. It connects shared data structures, cryptographic
//! hashing, and Merkle-tree operations without reimplementing their
//! underlying functionality.
//!
//! # Architecture
//!
//! The crate depends on the following components:
//!
//! - `mtc_core` provides shared data structures, including `HashValue`.
//! - `mtc_crypto` provides hashing abstractions and hash implementations.
//! - `mtc_tree` provides Merkle-tree operations and inclusion proofs.
//!
//! The [`certificate_authority`] module manages certificate records and
//! coordinates their inclusion in the Merkle tree. The [`error`] module
//! defines errors returned by certificate-authority operations.
//!
//! # Current capabilities
//!
//! The crate supports:
//!
//! - Storing certificate data and retrieving certificates by index.
//! - Maintaining a Merkle tree containing the stored certificates.
//! - Retrieving the current Merkle-tree root hash.
//! - Generating inclusion proofs for stored certificates.
//!
//! Inclusion-proof verification is provided by `mtc_tree`. Verification of
//! digital signatures and other certificate-management operations are
//! outside the scope of the current implementation.

pub mod certificate_authority;
pub mod error;
