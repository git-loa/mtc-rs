//! Cryptographic primitives for the MTC system.
//!
//! This crate defines the implementation of the hashing abstraction ('HashFn') and
//! concrete implemetation such as `Blake3Hash`. 

pub mod error;
pub mod hash;
pub mod blake3;