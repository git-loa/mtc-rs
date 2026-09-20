# Merkle Tree Certificates (MTC)

**Cryptographically agile certificate infrastructure in Rust, with a focus on verifiable transparency and post-quantum migration.**

> **Status:** Early development. The current implementation focuses on the Merkle-tree and cryptographic foundations.

## Overview

This project explores **Merkle Tree Certificates (MTCs)** as a mechanism for verifiable certificate transparency.

The central engineering question is:

> **How can certificate and transparency infrastructure evolve as cryptographic algorithms are replaced or deprecated without redesigning the underlying transparency mechanism?**

The project uses Rust to investigate this problem through:

- authenticated Merkle trees;
- certificate and transparency data structures;
- cryptographic hashing and domain separation;
- inclusion proofs and verification;
- cryptographic algorithm agility;
- classical-to-post-quantum migration;
- independent verification; and
- reproducible testing and interoperability.

The Merkle tree is treated as part of a larger verification infrastructure rather than as an isolated data structure.

---

## Architecture

The project separates the transparency mechanism from the cryptographic mechanisms used to authenticate it:

```text
                 Certificate Infrastructure
                           │
                           ▼
                    Merkle Transparency
                           │
                 ┌─────────┴─────────┐
                 │                   │
          Certificate Entry      Merkle Root
                 │                   │
                 ▼                   │
        Authentication Layer         │
          ┌───────────┐              │
          │           │              │
      Classical       PQC            │
          │           │              │
          └─────┬─────┘              │
                │                    │
                └────────┬───────────┘
                         ▼
                Independent Verification
                         │
                         ▼
                   Crypto Agility
                         │
                         ▼
                    TLS / PKI
```

The current repository implements the lower-level foundation. Higher-level issuance, distributed trust, policy, migration, and TLS integration are planned.

---

## Repository Structure

```text
mtc-rs/
├── mtc-core/       # Core MTC data structures
├── mtc-crypto/     # Hashing and cryptographic abstractions
├── mtc-tree/       # Merkle trees and inclusion proofs
├── mtc-ca/         # Planned MTC issuance/log component
├── mtc-client/     # Planned independent verifier
├── mtc-cli/        # Planned command-line interface
├── tests/           # Integration and property-oriented tests
└── docs/            # Detailed protocol, security, and migration documentation
```

The project is being developed incrementally; planned components are not represented as completed functionality.

---

## Current Implementation

### `mtc-core`

Defines the core MTC data structures, including tree-head and certificate-related types.

### `mtc-crypto`

Provides the cryptographic foundation currently used by the Merkle layer:

- hash abstraction;
- leaf and internal-node hashing;
- domain separation;
- deterministic hashing;
- validation; and
- cryptographic error handling.

### `mtc-tree`

Implements the authenticated Merkle-tree layer:

- tree construction;
- root computation;
- inclusion-proof generation; and
- inclusion-proof verification.

Higher-level components such as certificate issuance and independent client verification remain under development.

---

## Merkle Tree Model

The implementation uses domain-separated hashing:

\[
L(x) = H(0x00 \parallel x)
\]

\[
N(L,R) = H(0x01 \parallel L \parallel R)
\]

The distinct domains separate leaf hashing from internal-node hashing.

For a tree containing \(N\) leaves, the construction recursively divides the tree using the largest power-of-two subtree smaller than \(N\), without padding or duplicating leaves.

An inclusion proof contains the sibling hashes required to reconstruct the path from a leaf to the authenticated root. Its size is \(O(\log N)\).

---

## Cryptographic Agility

Cryptographic algorithms are intended to be explicit protocol parameters rather than implementation details hidden inside the Merkle layer.

The longer-term design separates:

```text
Hash Algorithm
Signature Algorithm
Key / Certificate Algorithm
Algorithm Identifier
Verification Policy
```

This separation allows the project to investigate algorithm transitions without coupling the Merkle-tree construction to a particular authentication algorithm.

The intended migration model is:

```text
Classical
    │
    ▼
  Hybrid
    │
    ▼
Post-Quantum
```

Historical verification is also an intended capability: a future verifier should be able to distinguish current cryptographic policy from the policy that applied when evidence was originally produced.

---

## Post-Quantum Cryptography

This project studies PQC primarily as an **infrastructure and migration problem**, rather than as an attempt to design new post-quantum primitives.

Areas of investigation include:

- classical/PQC hybrid authentication;
- PQC certificate and signature overhead;
- cryptographic policy and algorithm deprecation;
- historical verification;
- migration-related storage and bandwidth costs; and
- TLS integration.

The Merkle tree itself is **not a post-quantum cryptographic algorithm**. It is a transparency mechanism whose security depends on its cryptographic components and the authentication mechanisms protecting associated data.

---

## Security and Verification

The implementation is being developed around explicit security properties, including:

- deterministic root computation;
- domain-separated hashing;
- proof correctness;
- tamper detection;
- explicit algorithm identification; and
- independent verification.

The threat model and detailed security analysis will be documented separately. The Merkle mechanism does not by itself establish issuer trust, protect compromised signing keys, or make an insecure cryptographic primitive secure.

---

## Testing

Testing focuses on cryptographic properties as well as ordinary software correctness.

Current and planned testing includes:

- valid and invalid inclusion proofs;
- modified leaves, proofs, and roots;
- deterministic hashing;
- serialization round trips;
- property-based testing;
- fuzz testing;
- malformed-input testing; and
- interoperability test vectors.

The goal is to test mathematical and protocol invariants rather than only individual examples.

---

## Documentation

The README intentionally provides the project overview rather than the complete protocol specification.

Detailed material will be maintained in:

```text
docs/
├── architecture.md
├── protocol.md
├── threat-model.md
├── security.md
├── crypto-agility.md
├── migration.md
└── experiments.md
```

These documents will contain the detailed architecture, threat model, protocol definitions, migration analysis, and experimental results.

---

## Roadmap

### Phase 1 — Merkle Foundation
- [x] Hash abstraction
- [x] Domain-separated hashing
- [x] Merkle construction
- [x] Inclusion proofs
- [ ] Expanded property testing

### Phase 2 — MTC Data Model
- [x] Core certificate structures
- [x] Tree-head structures
- [ ] Canonical serialization
- [ ] Signed tree heads

### Phase 3 — Independent Verification
- [ ] Client verification
- [ ] Consistency proofs
- [ ] Verification test vectors
- [ ] Interoperability testing

### Phase 4 — Cryptographic Agility
- [ ] Explicit algorithm identifiers
- [ ] Signature abstraction
- [ ] Verification policies
- [ ] Historical verification

### Phase 5 — PQC Migration
- [ ] Classical baseline
- [ ] Hybrid authentication
- [ ] Post-quantum authentication
- [ ] Migration experiments
- [ ] Performance evaluation

### Phase 6 — Distributed Trust and TLS
- [ ] Cosigner/checkpoint support
- [ ] Standalone and landmark MTCs
- [ ] TLS-facing integration
- [ ] End-to-end verification

MTC is intended to operate **alongside TLS rather than replace TLS**.

---

## Research Questions

The project is organized around several engineering questions:

1. Can Merkle-based certificate transparency accommodate cryptographic algorithm replacement without redesigning the transparency mechanism?
2. How should algorithm identifiers and verification policies be represented to support crypto agility?
3. How can historical cryptographic evidence remain independently verifiable after algorithm transitions?
4. What are the storage, bandwidth, and computational costs of PQC authentication in certificate infrastructure?
5. How should classical and post-quantum authentication coexist during migration?

---

## Development Philosophy

The implementation is developed incrementally with an emphasis on **correctness, explicit security properties, and independent verification**.

Rust is also the systems-programming environment used to develop the project. This provides practical experience with ownership and borrowing, traits, generics, error handling, serialization, testing, and modular crate design while working on a substantive cryptographic engineering problem.

---

## References

- *Merkle Tree Certificates* — research paper motivating the implementation.
- RFC 9162 — Certificate Transparency Version 2.0.
- NIST Post-Quantum Cryptography standards and related standardization materials.
- Rust documentation and relevant cryptographic libraries.

## Status

This is an active experimental cryptographic-engineering project. The current implementation focuses on the Merkle-tree and cryptographic foundations; certificate issuance, independent verification, cryptographic agility, PQC migration, distributed trust, and TLS integration are being developed incrementally.
