//! Client functionality for verifying Merkle Tree Certificate inclusion.
//!
//! This crate provides certificate inclusion verification and associated
//! error types. It does not currently verify signed tree head signatures
//! or establish trust in a tree's root.

/// Error types returned by the MTC client.
pub mod error;

/// Certificate inclusion verification functionality.
pub mod verification;