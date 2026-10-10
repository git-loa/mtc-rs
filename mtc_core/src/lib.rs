//! # mtc_core
//!
//! ## Purpose
//!
//! Defines the shared data structures used across the MTC system.
//!
//! ## Responsibilities
//!
//! - Represent hash values and hash algorithm identifiers.
//! - Represent Merkle tree heads and signed tree heads.
//! - Define shared signature-related data types.
//! - Represent MTC certificate data.
//!
//! ## Design
//!
//! This crate provides common data structures for the cryptographic,
//! Merkle-tree, certificate-authority, and client components.
//! Fields are encapsulated where appropriate, with accessors providing
//! read-only access to internal data.
//!
//! ## Boundaries
//!
//! This crate defines shared types. It does not construct Merkle trees,
//! implement hash algorithms, generate digital signatures, or verify
//! certificates.
//!
//! ## Status
//!
//! The core data structures are implemented. Additional types or metadata
//! may be introduced as the architecture develops.
//!
//! ## Future extensions
//!
//! Serialization support, protocol-specific metadata, and additional
//! algorithm identifiers may be considered when justified by the design.

pub mod types;
