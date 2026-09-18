# Merkle Tree Certificates (MTC) — Rust

A modular Rust implementation of **Merkle Tree Certificates (MTCs)**, focused on cryptographic verification, Merkle trees, certificate transparency, and interoperability with Python and TLS tooling.

## Overview

This project is a hands-on implementation of Merkle Tree Certificates.

The goal is to build an end-to-end system that can:

* represent certificates
* hash certificate data
* build Merkle trees
* generate and verify inclusion proofs
* create and verify TreeHeads
* support certificate authority / log workflows
* test interoperability with Python
* explore integration with TLS 1.3 certificate analysis

The project is also a way for me to develop practical **Rust systems-programming and cryptographic engineering** skills.

## Project Structure

The project is organized as a Rust workspace.

### `mtc-core` — Core Types

**Status: Complete**

Defines the main data structures:

* `TreeHead`
* `SignedTreeHead`
* `MtcCertificate`

### `mtc-crypto` — Cryptographic Layer

**Status: Complete**

Provides:

* `HashFn` trait
* BLAKE3 hashing
* domain separation
* input validation
* structured cryptographic errors

### `mtc-tree` — Merkle Tree

**Status: In Progress**

Currently implements:

* Merkle tree construction
* leaf hashing
* internal-node hashing
* inclusion-proof generation
* inclusion-proof verification
* error handling

Next:

* TreeHead integration
* additional testing
* documentation

### `mtc-ca` — Certificate Authority / Log

**Status: Planned**

Will handle:

* certificate batching
* Merkle tree construction
* TreeHead creation
* TreeHead signing
* proof bundles

### `mtc-client` — Client Verification

**Status: Planned**

Will verify:

* certificate data
* Merkle inclusion proofs
* signed TreeHeads
* consistency rules
* timestamps

### `mtc-cli` — Command Line Interface

**Status: Planned**

A CLI for creating, inspecting, and verifying MTC objects and proofs.

## Testing

Testing focuses on both individual examples and general properties.

Properties being tested include:

* valid proofs should verify
* changing a leaf should invalidate its proof
* changing a proof should cause verification to fail
* changing the root should cause verification to fail
* the same input should produce the same result
* serialization and deserialization should preserve the object

These properties are closely related to the idea of **invariants** in mathematics: define what must remain true, then test those properties across many inputs.

Property-based testing will be expanded as the implementation develops.

## Python Interoperability

The project will include Python-based testing to verify interoperability with the Rust implementation.

Planned tests include:

* Rust → Python proof verification
* Python → Rust test vectors
* cross-language serialization
* deterministic hashing
* cross-language Merkle tree construction

This will help verify that the implementation behaves consistently across languages.

## TLS 1.3

MTC does **not replace TLS 1.3 or modify the TLS handshake**.

The planned integration is focused on certificate analysis.

The system will be tested alongside TLS connections to:

1. obtain certificate chains
2. extract certificate information
3. process certificates through the MTC system
4. generate or verify transparency proofs

Python's `ssl` module and Rust's `rustls` ecosystem will be used for experimentation.

This may later be integrated with TLS certificate inventory and analysis tooling.

## Development Status

Current focus:

* [x] Core data structures
* [x] Cryptographic hashing layer
* [x] Merkle tree construction
* [x] Inclusion proof generation
* [x] Inclusion proof verification
* [ ] TreeHead integration
* [ ] Expanded property-based testing
* [ ] CA / log implementation
* [ ] Client implementation
* [ ] Python interoperability
* [ ] TLS certificate integration
* [ ] End-to-end demonstration

## Goals

This project combines my interests in:

* cryptographic engineering
* post-quantum security
* certificate infrastructure
* Rust systems programming
* TLS security
* mathematical invariants and computational verification

The goal is to build a practical, testable cryptographic system while developing deeper experience with Rust and security engineering.

