# MTC System Diagrams

This document provides visual summaries of the MTC components and their intended roles.

**Status note:** `mtc_core`, `mtc_crypto`, and `mtc_tree` provide the current foundation. The `mtc_ca`, `mtc_client`, and `mtc_cli` diagrams describe intended workflows; they do not imply that those workflows are already implemented. These are conceptual diagrams, not a definitive Cargo dependency graph.

## 1. System Overview

This diagram summarizes the intended roles of the six crates.

```mermaid
flowchart TB
    CLI["mtc_cli<br/>Command-line interface"]
    CA["mtc_ca<br/>Certificate and record management"]
    Client["mtc_client<br/>Independent verification"]
    Tree["mtc_tree<br/>Merkle tree and inclusion proofs"]
    Crypto["mtc_crypto<br/>Hashing abstractions and implementations"]
    Core["mtc_core<br/>Shared data types"]

    CLI --> CA
    CLI --> Client
    CA --> Tree
    Client --> Tree
    Tree --> Crypto

    Core -. "Shared types" .-> CA
    Core -. "Shared types" .-> Client
    Core -. "Shared types" .-> Tree
    Core -. "Shared types" .-> Crypto
```

The arrows show conceptual interactions and use of shared types. Check the crate manifests before treating this as the exact dependency graph.

## 2. `mtc_core` — Shared Data Types

`mtc_core` defines data structures used by other components. It does not perform hashing, signing, or verification itself.

```mermaid
flowchart TD
    HA["HashAlgorithm"]
    HV["HashValue<br/>algorithm + digest bytes"]
    TH["TreeHead<br/>root + size + timestamp"]
    SA["SignatureAlgorithm"]
    Sig["Signature<br/>algorithm + signature bytes"]
    STH["SignedTreeHead<br/>tree head + signature"]
    Cert["MtcCertificate<br/>body + proof + signed tree head"]

    HA --> HV
    HV --> TH
    SA --> Sig
    TH --> STH
    Sig --> STH
    STH --> Cert
    HV -. "Proof hashes" .-> Cert
```

The types carry cryptographic metadata explicitly. Their existence does not mean that signature generation or verification has been implemented.

## 3. `mtc_crypto` — Hashing Abstraction

The `HashFn` trait separates Merkle-tree operations from a particular hash implementation. BLAKE3 is the current concrete implementation.

```mermaid
flowchart TD
    Data["Input data"]
    Trait["HashFn interface"]
    Empty["hash_empty()"]
    Leaf["hash_leaf(data)<br/>0x00 || data"]
    Node["hash_two_children(left, right)<br/>0x01 || left || right"]
    Impl["Blake3Hash"]
    Result["HashValue"]
    Error["CryptoError<br/>e.g. algorithm mismatch"]

    Data --> Trait
    Trait --> Empty
    Trait --> Leaf
    Trait --> Node
    Empty --> Impl
    Leaf --> Impl
    Node --> Impl
    Impl --> Result
    Impl -. "On invalid input" .-> Error
```

The `0x00` and `0x01` prefixes separate leaf inputs from internal-node inputs. This is the current implementation's hashing design; it does not, by itself, establish compatibility with a particular transparency protocol.

## 4. `mtc_tree` — Merkle Tree and Inclusion Proofs

The tree hashes appended data, computes a root, and generates proofs. A verifier reconstructs the root from the leaf data and proof hashes.

```mermaid
flowchart TD
    A["Leaf data"] --> B["hash_leaf(data)"]
    B --> C["Store leaf hash"]
    C --> D["MerkleTree"]
    D --> E["Compute root recursively"]
    D --> F["Generate inclusion proof"]
    F --> G["Sibling hashes<br/>leaf-to-root order"]

    H["Verifier inputs:<br/>leaf data, leaf index, tree size, proof, expected root"]
    H --> I["Hash leaf"]
    G --> J["Use index and tree size<br/>to determine hash order"]
    I --> J
    J --> K["Reconstruct root"]
    K --> L{"Equals expected root?"}
    L -->|Yes| M["Inclusion verified against that root"]
    L -->|No| N["Inclusion not verified"]
```

A matching root does not prove that the root is trusted. Trust in a signed tree head, and consistency between different tree views, require additional mechanisms.

## 5. `mtc_ca` — Intended Certificate-Authority Workflow

The CA component is planned to retain original record bytes and coordinate their inclusion in the Merkle tree. This workflow is **planned**, not yet implemented.

```mermaid
flowchart TD
    A["Certificate or record bytes"] --> B["mtc_ca"]
    B --> C["Retain original record"]
    B --> D["Append record to mtc_tree"]
    D --> E["Hash record and update tree"]
    E --> F["Compute Merkle root"]
    D --> G["Generate inclusion proof"]
    F --> H["Transparency evidence"]
    G --> H
    H --> I["Future: assemble MTC certificate"]
    I --> J["Future: sign tree head when signing is implemented"]
```

The CA should not duplicate Merkle-tree or hashing logic. Signing and complete MTC certificate issuance depend on interfaces that still need to be designed and implemented.

## 6. `mtc_client` — Intended Independent Verification

The client is intended to verify inclusion and, once signature verification exists, evaluate signed tree heads and the associated trust policy.

```mermaid
flowchart TD
    A["MTC certificate / record"] --> C["mtc_client"]
    B["Inclusion proof"] --> C
    D["Expected tree root"] --> C
    C --> E["Verify inclusion proof"]
    E --> F{"Proof valid?"}
    F -->|No| G["Reject inclusion claim"]
    F -->|Yes| H["Inclusion established relative to root"]
    I["Signed tree head"] --> J["Future: verify signature"]
    J --> K["Future: apply trust policy"]
    H --> L["Overall verification decision"]
    K --> L
```

Inclusion verification and trust evaluation are distinct. A valid inclusion proof alone does not establish that the expected root is authentic or trustworthy.

## 7. `mtc_cli` — Intended Command-Line Entry Point

The CLI is intended to expose selected application operations. Its commands should be defined after the CA and client interfaces are established.

```mermaid
flowchart TD
    User["User / script"] --> CLI["mtc_cli"]
    CLI --> CA["mtc_ca operations<br/>(planned)"]
    CLI --> Client["mtc_client verification<br/>(planned)"]
    CA --> Output["Structured result or error"]
    Client --> Output
    Output --> User
```

This is a conceptual view of the planned command-line workflow, not a description of implemented CLI commands.

## 8. End-to-End Vision

The following diagram summarizes the broader project direction, including work that remains future development.

```mermaid
flowchart LR
    Record["Certificate record"] --> CA["Issuance / record management"]
    CA --> Tree["Merkle transparency tree"]
    Tree --> Evidence["Root + inclusion proof"]
    Evidence --> Auth["Authenticate associated evidence"]
    Auth --> Verify["Independent verification"]
    Verify --> Policy["Apply trust and algorithm policy"]
    Policy --> TLS["Potential TLS / PKI integration"]

    Classical["Classical algorithms"] -. "Migration path" .-> Hybrid["Hybrid authentication"]
    Hybrid -. "Migration path" .-> PQC["Post-quantum authentication"]
    Auth --- Classical
    Auth --- Hybrid
    Auth --- PQC
```

The migration path is a research direction. The current project does not yet implement the full issuance, signing, verification, hybrid-authentication, PQC-migration, or TLS-integration workflow.
