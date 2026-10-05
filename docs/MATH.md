# Mathematical Foundations

This document describes the mathematical foundations of the Merkle tree used by `mtc-rs`.

The tree structure and proof model follow the recursive **Merkle Tree Hash (MTH)** construction defined in [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162). The project currently uses a generic hash-function interface so that different hash algorithms can be supported.

The mathematical construction is intentionally separated from the concrete cryptographic implementation.

---

## 1. Notation

Let the ordered sequence of leaf data be

$$
D = (d_0, d_1, \ldots, d_{n-1})
$$

where \(n\) is the number of leaves.

For a range of leaves, \(D[a:b]\) denotes

$$
D[a:b] = (d_a, d_{a+1}, \ldots, d_{b-1}).
$$

The symbol \(\Vert\) denotes byte-string concatenation.

Let \(H\) denote the selected cryptographic hash function.

The empty byte string is denoted by \(\epsilon\).

---

## 2. Domain-Separated Hashing

The Merkle tree uses distinct hash inputs for leaves and internal nodes.

### Leaf

A leaf containing data \(d\) is hashed as

$$
H(0x00 \Vert d).
$$

The leaf data \(d\) may itself be empty.

Therefore, a leaf containing an empty byte string is still a leaf and is distinct from an empty tree.

### Internal Node

An internal node with left hash \(L\) and right hash \(R\) is hashed as

$$
H(0x01 \Vert L \Vert R).
$$

The distinct prefixes provide domain separation between leaf hashing and internal-node hashing.

Thus, the hash input for a leaf cannot be confused with the hash input for an internal node.

---

## 3. Merkle Tree Hash

The root of a Merkle tree is computed recursively using the Merkle Tree Hash function \(MTH\).

### Empty Tree

For an empty tree containing no leaves,

$$
MTH(\emptyset) = H(\epsilon).
$$

An empty tree therefore has zero leaves and is represented by a hash of the empty byte string.

### Single Leaf

For a tree containing one leaf whose data is \(d_0\),

$$
MTH((d_0)) = H(0x00 \Vert d_0).
$$

If the leaf data is itself empty, \(d_0=\epsilon\), then

$$
MTH((\epsilon)) = H(0x00 \Vert \epsilon).
$$

This is different from the empty-tree case:

$$
MTH(\emptyset) = H(\epsilon).
$$

Therefore, an empty tree and a tree containing one empty leaf are different tree states and have different hash inputs.

### Multiple Leaves

For \(n > 1\), choose \(k\) as the largest power of two that is strictly less than \(n\).

The sequence is divided into

$$
D[0:k]
$$

and

$$
D[k:n].
$$

The root is then computed as

$$
MTH(D) = H\left(0x01 \Vert MTH(D[0:k])\Vert MTH(D[k:n])\right).
$$

The same rule is applied recursively to each subtree until every subtree contains either zero or one leaf.

The recursive split determines the shape of the tree.

In particular, the tree is **not** constructed by simply pairing adjacent leaves at every level, and it does not require padding or duplication of leaves.

---

## 4. Example: Six Leaves

Consider six leaves:

$$
D=(d_0,d_1,d_2,d_3,d_4,d_5).
$$

The largest power of two strictly less than \(6\) is \(4\).

Therefore, the first split is

$$
D[0:4]
$$

and

$$
D[4:6].
$$

The resulting structure is:

```text
                    Root
                   /    \
                0..4    4..6
                /  \    /  \
             0..2 2..4 d4  d5
             / \   / \
            d0 d1 d2 d3
```

Therefore,

$$
MTH(D)=H\left(0x01\Vert MTH(D[0:4])\Vert MTH(D[4:6])\right).
$$

The same recursive rule is then applied to each subtree.

For example,

$$ 
MTH(D[0:4]) = H\left(0x01 \Vert MTH(D[0:2])\Vert MTH(D[2:4])\right).
$$

This recursive structure is important when generating and verifying inclusion proofs.

---

## 5. Inclusion Proofs

An inclusion proof allows a verifier to demonstrate that a particular leaf belongs to a tree without receiving the entire tree.

For leaf $d_i$, the verifier first computes the leaf hash

$$
H(0x00 \Vert d_i).
$$

The proof then supplies the hashes of the sibling subtrees required to reconstruct the path from that leaf to the tree root.

At each step, the verifier computes either

$$
H(0x01 \Vert current \Vert sibling)
$$

when the current subtree is the left child, or

$$
H(0x01 \Vert sibling \Vert current)
$$

when the current subtree is the right child.

The proof elements are processed in **leaf-to-root order**.

The orientation of each proof element is determined by the recursive tree structure and the leaf index within the current subtree.

It is therefore **not** determined by a simple even/odd leaf-index rule.

After all proof elements have been processed, the resulting hash is compared with the expected Merkle root.

If the reconstructed hash equals the expected root, the inclusion proof is valid for the supplied leaf, leaf index, and tree size.

---

## 6. Recursive Proof Structure

Let a tree contain \(n\) leaves and let the target leaf have index \(i\).

For \(n>1\), choose

$$
k = 2^{\lfloor \log_2(n-1) \rfloor},
$$

which is the largest power of two strictly less than \(n\).

There are two cases.

### Case 1: \(i < k\)

The target leaf lies in the left subtree:

$$
D[0:k].
$$

The proof recursively contains the sibling information required to reconstruct that subtree, followed by the root of the right subtree:

$$
MTH(D[k:n]).
$$

### Case 2: \(i \geq k\)

The target leaf lies in the right subtree:

$$
D[k:n].
$$

The local leaf index becomes

$$
i' = i-k.
$$

The proof recursively contains the sibling information required to reconstruct the right subtree, followed by the root of the left subtree:

$$
MTH(D[0:k]).
$$

The resulting proof is therefore naturally constructed from the leaf toward the root.

During verification, the corresponding path is processed in the same leaf-to-root order.

This relationship between recursive splitting, proof ordering, and left/right orientation is essential for correct verification.

---

## 7. Proof Size

At each level of the recursive construction, an inclusion proof contributes at most one sibling subtree hash.

Therefore, the number of proof elements grows logarithmically with the number of leaves.

The proof size is

$$
O(\log n).
$$

The verifier does not need the complete set of leaves to reconstruct the root; it needs the target leaf, its index, the tree size, the sibling hashes in the proof, and the expected root.

---

## 8. Merkle Subtrees in MTC

A subtree covering the leaves from `start` through `end - 1` has root

$$
MTH(D[start:end]).
$$

These subtree roots provide the mathematical building blocks for higher-level transparency mechanisms.

The MTC design builds on the Merkle Tree Hash construction and is intended to use authenticated subtrees and related proof mechanisms as part of its certificate-transparency infrastructure.

The MTC-specific protocol mechanisms are implemented separately from the basic Merkle tree construction in this project.

---

## 9. Implementation Notes

The mathematical definition is independent of the concrete hash algorithm.

The Rust implementation therefore uses the `HashFn` trait to separate:

* Merkle tree construction;
* hash-function selection; and
* concrete cryptographic hash implementation.

The current implementation provides BLAKE3 through this interface.

The use of a generic hash abstraction is an implementation design choice. The current BLAKE3 configuration does **not** claim wire-level compatibility with Certificate Transparency using the SHA-256 configuration specified by RFC 9162.

### Empty Tree versus Empty Leaf

The implementation keeps the empty-tree case conceptually separate from `hash_leaf`:

```text
hash_empty()
    → tree containing zero leaves

hash_leaf(b"")
    → tree containing one leaf whose data is empty
```

The corresponding hash inputs are different:

$$
H(\epsilon)
$$

versus

$$
H(0x00 \Vert \epsilon).
$$

This distinction is important because the number of leaves is part of the authenticated tree state.

### Algorithm Agility

The Merkle-tree implementation does not directly depend on BLAKE3.

Instead, the tree operates through the `HashFn` abstraction. This allows the tree construction to remain independent of the concrete hash implementation while retaining explicit algorithm metadata in the resulting hash values.

---

## 10. Relationship to the Implementation

The mathematical construction maps directly onto the current Rust implementation:

```text
Mathematical concept          Rust implementation

MTH(D)                        MerkleTree::root()
MTH(D[a:b])                   root_for_slice()
leaf hash                     HashFn::hash_leaf()
internal node hash            HashFn::hash_two_children()
empty tree                    HashFn::hash_empty()
inclusion proof               generate_inclusion_proof()
proof verification            verify_inclusion_proof()
recursive split               largest_power_of_two_less_than()
```

The implementation is intentionally kept modular so that the mathematical tree construction can evolve independently from higher-level MTC certificate, signing, and verification mechanisms.

---

## References

* RFC 9162 — *Certificate Transparency Version 2.0*
* IETF Internet-Draft — *Merkle Tree Certificates*
* Project implementation:

  * `mtc_core`
  * `mtc_crypto`
  * `mtc_tree`
