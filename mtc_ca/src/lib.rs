//! # mtc_ca
//!
//! Certificate-authority functionality for the MTC system.
//!
//! ## Purpose
//!
//! Coordinates certificate records and their inclusion in the MTC
//! transparency tree.
//!
//! ## Responsibilities
//!
//! - Manage certificate records.
//! - Coordinate insertion of records into the Merkle tree.
//! - Generate inclusion proofs for certificate records.
//! - Coordinate tree-head creation as the implementation develops.
//!
//! ## Dependencies
//!
//! - `mtc_core` provides shared MTC data structures.
//! - `mtc_crypto` provides cryptographic abstractions and implementations.
//! - `mtc_tree` provides Merkle tree operations and inclusion proofs.
//!
//! ## Boundaries
//!
//! This crate coordinates certificate-related operations. Merkle tree
//! construction belongs in `mtc_tree`, while hashing operations belong
//! in `mtc_crypto`.
//!
//! Digital-signature generation and verification are not yet implemented.
//!
//! ## Status
//!
//! The crate's dependencies are configured. Certificate management and
//! integration with the Merkle tree remain to be implemented.

pub mod certificate_authority;
