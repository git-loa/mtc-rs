# Merkle Tree Certificates (MTC) — Rust

A modular Rust implementation of the cryptographic and Merkle-tree foundations of **Merkle Tree Certificates (MTCs)**.

The project follows the Merkle-tree and certificate-authentication architecture described in the MTC paper, with the current implementation focused on the foundational components required for MTCs: certificate data structures, cryptographic hashing, domain separation, Merkle-tree construction, and inclusion-proof generation and verification.

The implementation is being developed incrementally toward the broader MTC architecture, including certificate issuance, TreeHeads and checkpoints, consistency proofs, cosigners, landmark certificates, client-side verification, and TLS/PQC integration.

---

## Overview

Merkle Tree Certificates use authenticated Merkle-tree structures to provide compact proofs that certificate information is included in an authenticated certificate log.

At the core of the system is a binary Merkle tree:

```text
                    Root / TreeHead
                         │
                ┌────────┴────────┐
                │                 │
              Hash              Hash
             /    \            /    \
           ...    ...         ...    ...
          / \     / \        / \     / \
        Leaf     Leaf      Leaf     Leaf
```

A certificate entry is converted into a leaf hash. Internal nodes are computed from their child hashes using domain-separated hashing. An inclusion proof then allows a verifier to reconstruct the root without receiving the entire tree.

The current repository implements this lower-level Merkle-tree machinery and provides the foundation for the higher-level MTC components.

---

## Relationship to the MTC Architecture

The full MTC architecture contains several components that build on the Merkle-tree foundation:

```text
                    Full MTC Architecture
                             │
                             ▼
                  ┌─────────────────────┐
                  │ MTCA / Certificate  │
                  │      Issuance        │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │ Certificate Entries │
                  └──────────┬──────────┘
                             │
                             ▼
        ┌─────────────────────────────────────────┐
        │       CURRENT IMPLEMENTATION            │
        │                                         │
        │  ┌───────────────────────────────────┐  │
        │  │ mtc-core                          │  │
        │  │ Certificate + TreeHead structures │  │
        │  └────────────────┬──────────────────┘  │
        │                   │                     │
        │  ┌────────────────▼──────────────────┐  │
        │  │ mtc-crypto                        │  │
        │  │ Hashing + domain separation       │  │
        │  └────────────────┬──────────────────┘  │
        │                   │                     │
        │  ┌────────────────▼──────────────────┐  │
        │  │ mtc-tree                          │  │
        │  │ Merkle trees + inclusion proofs   │  │
        │  └───────────────────────────────────┘  │
        │                                         │
        └───────────────────┬─────────────────────┘
                            │
                            ▼
                  ┌─────────────────────┐
                  │ Signed TreeHeads /  │
                  │    Checkpoints      │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │ Consistency Proofs  │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │     Cosigners       │
                  └──────────┬──────────┘
                             │
                    ┌────────┴────────┐
                    ▼                 ▼
             Standalone MTC      Landmark MTC
              Certificates       Certificates
                    │                 │
                    └────────┬────────┘
                             ▼
                  ┌─────────────────────┐
                  │    MTC Client       │
                  │     Verification    │
                  └──────────┬──────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │     TLS / PQC       │
                  └─────────────────────┘
```

**The current project occupies the Merkle-tree and cryptographic foundation of this architecture.**

Higher-level components will be added incrementally.

---

## Project Structure

```text
mtc-rs/
│
├── mtc-core/
│   └── Core MTC data structures
│
├── mtc-crypto/
│   └── Cryptographic hashing and domain separation
│
├── mtc-tree/
│   └── Merkle-tree construction and inclusion proofs
│
├── mtc-ca/
│   └── MTC Certificate Authority
│
├── mtc-client/
│   └── Client-side MTC verification
│
└── mtc-cli/
    └── Command-line interface
```

### `mtc-core`

Provides the core data structures used by the MTC system.

Current components include:

* `TreeHead`
* `SignedTreeHead`
* `MtcCertificate`
* Certificate-related structures

The crate provides the data model on which the higher-level MTC components will build.

### `mtc-crypto`

Provides the cryptographic primitives used by the Merkle-tree implementation.

Current components include:

* Hash function abstraction
* Leaf hashing
* Internal-node hashing
* Domain separation
* Deterministic hashing
* Input validation
* Cryptographic error handling

The hashing layer is intentionally separated from the tree implementation so that cryptographic operations can be tested and evolved independently.

### `mtc-tree`

Implements the Merkle-tree layer.

Current development includes:

* Merkle-tree construction
* Leaf hashing
* Internal-node hashing
* Inclusion-proof generation
* Inclusion-proof verification
* Deterministic tree construction
* Tree-related error handling

This crate represents the central Merkle-tree component of the current implementation.

### `mtc-ca`

Planned higher-level component for MTC certificate issuance.

Planned functionality includes:

* Certificate batching
* Certificate-log management
* Merkle-tree generation
* TreeHeads
* Signed TreeHeads
* Certificate/proof bundles

### `mtc-client`

Planned client-side verification layer.

Planned functionality includes:

* Certificate parsing
* Leaf verification
* Inclusion-proof verification
* TreeHead verification
* Consistency verification
* Timestamp and validity checks

### `mtc-cli`

Planned command-line interface for interacting with the MTC implementation.

---

## Merkle Tree Model

The Merkle-tree construction follows the authenticated binary Merkle-tree model used by Certificate Transparency.

Leaf and internal-node hashing use domain separation:

```text
LeafHash(x) = H(0x00 || x)

NodeHash(L, R) = H(0x01 || L || R)
```

The different prefixes distinguish leaf data from internal-node data.

For a tree containing `N` leaves, the tree is recursively divided using the largest power-of-two subtree that is smaller than `N`.

For example, a nine-leaf tree is divided as:

```text
                 Root
              /       \
          8 leaves    1 leaf
         /   ...  \      \
       L0          L7     L8
```

This allows non-power-of-two trees to be constructed without padding the tree or duplicating leaves.

---

## Inclusion Proofs

An inclusion proof demonstrates that a particular leaf belongs to a Merkle tree without requiring the verifier to receive the complete tree.

For a leaf at index `i`, the verifier uses the sibling hash at each level:

```text
                    Root
                     ▲
                     │
                 sibling
                     ▲
                     │
                 sibling
                     ▲
                     │
                 sibling
                     ▲
                     │
                   Leaf
```

The proof therefore requires approximately `O(log N)` sibling hashes.

During verification, the ordering of the hashes is determined by the position of the current node:

```text
if index is even:

    parent = H(0x01 || current || sibling)

if index is odd:

    parent = H(0x01 || sibling || current)
```

The process continues upward until the calculated root is obtained.

The proof is valid when the calculated root matches the expected authenticated tree root.

---

## Cryptographic Properties

Testing focuses on both concrete examples and general properties of the implementation.

Important properties include:

* A valid inclusion proof verifies against the correct root.
* Changing a leaf invalidates the corresponding proof.
* Changing a proof causes verification to fail.
* Changing the expected root causes verification to fail.
* Deterministic operations produce consistent results.
* Serialization and deserialization preserve the logical object.

These properties connect naturally to the mathematical notion of invariants: rather than checking only individual examples, the implementation tests whether important relationships remain true under different inputs and transformations.

Property-oriented and fuzz testing will be expanded as the implementation develops.

---

## Development Status

| Component                    | Status                                    |
| ---------------------------- | ----------------------------------------- |
| `mtc-core`                   | 🟡 In progress                            |
| `mtc-crypto`                 | 🟢 Implemented                            |
| `mtc-tree`                   | 🟡 In progress                            |
| Merkle-tree construction     | 🟡 In progress                            |
| Inclusion-proof generation   | 🟡 In progress                            |
| Inclusion-proof verification | 🟡 In progress                            |
| TreeHead                     | 🟡 In progress                            |
| SignedTreeHead structure     | 🟡 Structure implemented; signing planned |
| `mtc-ca`                     | 🔵 Planned                                |
| Consistency proofs           | 🔵 Planned                                |
| Cosigner support             | 🔵 Planned                                |
| Standalone MTC certificates  | 🔵 Planned                                |
| Landmark certificates        | 🔵 Planned                                |
| `mtc-client`                 | 🔵 Planned                                |
| TLS integration              | 🔵 Planned                                |
| PQC signature integration    | 🔵 Planned                                |
| Python interoperability      | 🔵 Planned                                |

**Legend**

* 🟢 Implemented
* 🟡 In progress
* 🔵 Planned

---

## Python Interoperability

A future goal is interoperability between the Rust implementation and Python-based tooling.

Potential applications include:

* Python-based certificate processing
* Test-vector generation
* Cross-language verification
* Integration with existing TLS and security analysis tools

The Rust implementation provides the cryptographic and systems-oriented foundation, while Python can be used for higher-level tooling and experimentation.

---

## TLS 1.3 Integration

MTC is intended to operate **alongside TLS rather than replace TLS**.

A future integration will investigate:

```text
TLS 1.3
   │
   ├── Certificate
   │
   ├── MTC proof
   │
   └── PQC authentication
```

The goal is to connect certificate transparency-style verification with modern TLS and post-quantum cryptographic workflows.

---

## Post-Quantum Cryptography

The project is being developed in the context of the transition to post-quantum cryptography.

Areas of interest include:

* Post-quantum certificate management
* Cryptographic agility
* Large PQC certificate and signature overhead
* MTC-based certificate authentication
* TLS 1.3
* NIST-standardized post-quantum algorithms

PQC signature integration is a future layer of the project. The Merkle-tree itself should not be interpreted as a post-quantum cryptographic algorithm; rather, MTC provides certificate-authentication infrastructure that can be used in PQC-era systems.

---

## Development Roadmap

The implementation is planned to progress from the cryptographic foundation toward the complete MTC architecture.

### Phase 1 — Merkle Foundation

* Complete `mtc-tree`
* Complete inclusion-proof generation
* Complete inclusion-proof verification
* Expand unit and property-oriented tests
* Document tree and proof algorithms

### Phase 2 — MTC Data Model

* Complete `TreeHead`
* Complete `SignedTreeHead`
* Define MTC proof structures
* Add serialization and deserialization
* Add test vectors

### Phase 3 — MTC Certificate Authority

* Implement `mtc-ca`
* Certificate-entry generation
* Certificate-log management
* TreeHead/checkpoint generation
* Certificate/proof bundles

### Phase 4 — Verification

* Implement `mtc-client`
* Inclusion-proof verification
* TreeHead verification
* Consistency-proof verification
* Certificate validity and timestamp checks

### Phase 5 — Distributed Trust

* Implement cosigner support
* Checkpoint signatures
* Cosigner quorum verification
* Standalone MTC certificates
* Landmark certificates

### Phase 6 — TLS and PQC

* TLS certificate extraction
* MTC verification alongside TLS
* Python/Rust interoperability
* PQC authentication experiments
* Integration with post-quantum TLS workflows

---

## Project Goals

The project has four primary goals:

1. **Understand MTC architecture** by implementing its cryptographic foundations from the bottom up.
2. **Develop practical Rust systems-programming skills** through a modular cryptographic software project.
3. **Build verifiable cryptographic software** with explicit invariants, deterministic behavior, and systematic testing.
4. **Progress toward an end-to-end MTC implementation** capable of interacting with certificate and TLS/PQC infrastructure.

---

## References

* *Merkle Tree Certificates* — research paper motivating this implementation.
* RFC 9162 — Certificate Transparency Version 2.0.
* NIST Post-Quantum Cryptography standards, including ML-KEM and ML-DSA.

---

## License

This project is currently under development. See the repository license for details.
