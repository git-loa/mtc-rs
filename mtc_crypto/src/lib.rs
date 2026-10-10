//! Cryptographic abstractions and hash implementations for the MTC system.
//!
//! This crate defines the [`hash::HashFn`] trait, which separates Merkle tree
//! operations from specific hash implementations. It currently provides a
//! BLAKE3 implementation and the [`error::CryptoError`] type for reporting
//! errors during hash operations.
//!
//! The BLAKE3 implementation uses domain separation to distinguish leaf
//! data from internal-node inputs:
//!
//! - `0x00` prefixes leaf data.
//! - `0x01` prefixes the concatenated child hashes of an internal node.
//!
//! This crate provides hashing functionality, not Merkle tree construction
//! or inclusion-proof verification. Those responsibilities belong to
//! `mtc_tree`. Shared cryptographic data types are defined in `mtc_core`.
//!
//! Digital-signature generation and verification are not yet implemented.
//! Supporting multiple hash algorithms through a common interface does not,
//! by itself, guarantee protocol interoperability or post-quantum security.

pub mod blake3;
pub mod error;
pub mod hash;
