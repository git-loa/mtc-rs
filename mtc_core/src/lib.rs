//! Shared data structures for the Merkle Tree Certificate (MTC) system.
//!
//! This crate defines common types for hash values, Merkle tree heads,
//! signatures, and MTC certificate data. These types are shared across
//! the system's cryptographic, tree, certificate-authority, and client
//! components.
//!
//! Fields are encapsulated where appropriate, with accessors providing
//! read-only access to internal data.
//!
//! This crate defines data structures rather than implementing
//! cryptographic operations. Hashing, signature generation, signature
//! verification, and Merkle tree construction are handled by other
//! components.
//!
//! Serialization support, protocol-specific metadata, and additional
//! algorithm identifiers may be introduced as the architecture develops.

pub mod types;
