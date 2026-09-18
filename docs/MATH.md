# Mathematical Model

This document describes the mathematical model used in the Merkle Tree Certificate (MTC) implementation.

The implementation follows the **Certificate Transparency (CT) Merkle-tree construction model**, while using its own configurable cryptographic hashing layer.

## 1. Leaf Hashing

Each certificate body is converted into a leaf hash:

$$
\operatorname{LeafHash}(x)=H(0x00\parallel x)
$$

where:

* \(H\) is the configured hash function
* \(0x00\) is the leaf domain-separation prefix
* \(\parallel\) denotes byte concatenation

The separate prefix distinguishes leaf hashing from internal-node hashing.

## 2. Internal Node Hashing

Two child hashes are combined as:

$$
\operatorname{NodeHash}(L,R)
=
H(0x01\parallel L\parallel R)
$$

where \(L\) and \(R\) are the left and right child hashes.

The different prefixes provide domain separation between leaves and internal nodes.

## 3. Merkle Tree Construction

For \(N\) leaves, the tree is constructed recursively.

If \(N=1\), the single leaf is the root.

For \(N>1\), let

$$
k=2^{\lfloor\log_2(N)\rfloor}
$$

where \(k\) is the largest power of two strictly less than \(N\).

The leaves are divided into:

$$
L = [0,\ldots,k-1]
$$

and

$$
R = [k,\ldots,N-1].
$$

The left and right subtrees are constructed recursively, and their roots are combined:

$$
R_{\text{root}}
=
\operatorname{NodeHash}(L_{\text{root}},R_{\text{root}}).
$$

This produces a deterministic tree without padding or duplicating leaves.

### Example: 9 Leaves

For nine leaves:

$$
k=2^{\lfloor\log_2(9)\rfloor}=8.
$$

Therefore:

```text
                    Root
                   /    \
                  /      \
             8-leaf      L8
             subtree
```

The left side contains leaves \(L0\) through \(L7\), while \(L8\) forms the right subtree.

## 4. Inclusion Proofs

An inclusion proof contains the sibling hashes needed to reconstruct the path from a leaf to the root.

For a leaf at index \(i\), the sibling position within a complete binary level is:

$$
\operatorname{sibling}(i)=
\begin{cases}
i+1 & i\text{ even}\\
i-1 & i\text{ odd}
\end{cases}
$$

The parent position is:

$$
\operatorname{parent}(i)=
\left\lfloor\frac{i}{2}\right\rfloor.
$$

These operations are applied while moving upward through the tree.

The proof requires logarithmic space:

$$
O(\log N).
$$

## 5. Example: Proof for L5 in a 9-Leaf Tree

The relevant portion of the tree is:

```text
                         Root
                        /    \
                       /      \
                     Node      L8
                    /    \
                  B0      B1
                        /   \
                       A2   A3
                           /  \
                         L4    L5
```

For \(L5\), the starting index is:

$$
i=5.
$$

### Step 1 — Leaf Level

Since \(5\) is odd, its sibling is \(4\):

$$
\operatorname{sibling}(5)=4.
$$

Sibling: \(L4\)

Parent:

$$
\left\lfloor\frac{5}{2}\right\rfloor=2.
$$

### Step 2 — A-Level

The new index is \(2\).

Its sibling is \(3\):

$$
\operatorname{sibling}(2)=3.
$$

Sibling: \(A3\)

Parent:

$$
\left\lfloor\frac{2}{2}\right\rfloor=1.
$$

### Step 3 — B-Level

The new index is \(1\).

Its sibling is \(0\):

$$
\operatorname{sibling}(1)=0.
$$

Sibling: \(B0\)

Parent:

$$
\left\lfloor\frac{1}{2}\right\rfloor=0.
$$

### Step 4 — Root Level

The remaining sibling is the right subtree containing \(L8\).

Therefore the proof consists of:

$$
[L4,A3,B0,L8].
$$

## 6. Proof Verification

Given:

* certificate data \(x\)
* inclusion proof \([s_1,\ldots,s_k]\)
* leaf index \(i\)
* expected root \(R\)

First compute:

$$
h_0=\operatorname{LeafHash}(x).
$$

For each sibling \(s_j\):

If \(i\) is even:

$$
h_j
=
H(0x01\parallel h_{j-1}\parallel s_j)
$$

If \(i\) is odd:

$$
h_j
=
H(0x01\parallel s_j\parallel h_{j-1})
$$

Then update:

$$
i=
\left\lfloor\frac{i}{2}\right\rfloor.
$$

The proof is valid when:

$$
h_k=R.
$$

## 7. Testing Properties

The implementation is being developed around properties that should hold for valid Merkle trees and proofs.

Examples include:

* a valid proof verifies
* modifying the certificate invalidates the proof
* modifying a proof element causes verification to fail
* modifying the expected root causes verification to fail
* identical inputs produce identical outputs
* serialization and deserialization preserve the logical object

These properties are closely related to the concept of **invariants** in mathematics: rather than checking only individual examples, we identify properties that should remain true and test them across many inputs.

Property-based testing will be expanded as the implementation develops.

## 8. Current and Planned Pipeline

The intended end-to-end system is:

```text
Certificate
     │
     ▼
Leaf Hash
     │
     ▼
Merkle Tree
     │
     ▼
TreeHead
     │
     ├── Certificate
     ├── Inclusion Proof
     └── Signed TreeHead
              │
              ▼
        Client Verification
```

The current implementation focuses on the cryptographic and Merkle-tree layers.

Future components will add TreeHead signing, certificate-authority/log functionality, client verification, Python interoperability, and TLS certificate integration.

## 9. Relationship to TLS and PQC

MTC is intended to operate **alongside TLS rather than replace TLS 1.3**.

The planned integration uses TLS tooling to obtain certificate information and then processes that information through the MTC system.

Post-quantum signatures may be incorporated into future TreeHead-signing functionality as the project develops. This is separate from the Merkle-tree construction itself.

---

### Implementation Note

The mathematical model and the Rust implementation are developed together. The purpose is not only to reproduce the tree structure, but to make the cryptographic assumptions, invariants, and verification rules explicit enough that they can be tested independently.
