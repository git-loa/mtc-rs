//! Merkle tree construction and proof handling for the MTC system.
//!
//! This crate depends on:
//! - `mtc_core` for shared types such as `HashValue` and `TreeHead`.
//! - `mtc_crypto` for cryptographic primitives.

pub mod error;
pub mod proof;
pub mod tree;
