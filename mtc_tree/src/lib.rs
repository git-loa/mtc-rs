//! Merkle tree construction and proof handling for MTC system.
//!
//! This module depends on:
//! - `mtc-core` for shared types(e.g., certificate bodies, TreeHead)
//! - `mtc-cryto` for cryptographic primitives.

pub mod error;
pub mod tree;
pub mod proof;