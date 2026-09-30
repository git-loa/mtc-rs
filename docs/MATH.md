# Mathematical Foundations

This document describes the mathematical foundations of the Merkle tree used by `mtc-rs`.

The tree structure and proof model follow the Merkle Tree Hash construction defined in [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162). The project currently uses a generic hash-function interface so that different hash algorithms can be supported.

## 1. Notation

Let the ordered set of leaf data be

$$
D = (d_0, d_1, \ldots, d_{n-1})
$$

where $n$ is the number of leaves.

For a range of leaves, $D[a:b]$ denotes

$$
(d_a, d_{a+1}, \ldots, d_{b-1}).
$$

The symbol $\Vert$ denotes concatenation.

Let $H$ denote the selected cryptographic hash function.

## 2. Domain-Separated Hashing

The Merkle tree uses different hash inputs for leaves and internal nodes.

### Leaf

A leaf containing data $d$ is hashed as

$$
H(0x00 \Vert d)
$$

The leaf data $d$ may be empty. An empty leaf is therefore still a leaf and is distinct from an empty tree.

### Internal node

An internal node with left hash $L$ and right hash $R$ is hashed as

$$
H(0x01 \Vert L \Vert R)
$$

The different prefixes provide domain separation between leaf hashing and internal-node hashing.

## 3. Merkle Tree Hash

The root of a Merkle tree is computed recursively using the Merkle Tree Hash function, $MTH$.

### Empty tree

For an empty tree containing no leaves,

$$
MTH(\emptyset) = H(\epsilon)
$$

where $\epsilon$ is the empty byte string.

An empty tree has zero leaves.

### Single leaf

For one leaf containing data $d_0$,

$$
MTH(D) = H(0x00 \Vert d_0)
$$

The leaf data may itself be empty. In that case,

$$
MTH(("")) = H(0x00)
$$

This is different from the empty-tree case:

$$
MTH(\emptyset) = H("")
$$

Thus, an empty tree and a tree containing one empty leaf are different tree states and produce different hash inputs.

### Multiple leaves

For $n > 1$, choose $k$ as the largest power of two that is strictly less than $n$.

Split the leaves into

$$
D[0:k]
$$

and

$$
D[k:n].
$$

The root is then

$$
MTH(D)
=
H
\left(
0x01
\Vert
MTH(D[0:k])
\Vert
MTH(D[k:n])
\right).
$$

This rule is applied recursively until every subtree contains either zero or one leaf.

The recursive split determines the shape of the tree. In particular, the tree is **not** constructed by simply pairing adjacent leaves at every level.

## 4. Example

Consider six leaves:

$$
D = (d_0,d_1,d_2,d_3,d_4,d_5).
$$

Because the largest power of two strictly less than $6$ is $4$, the first split is

$$
D[0:4] \quad\text{and}\quad D[4:6].
$$

The resulting structure is:

```text
                    Root
                   /    \
                0..4    4..6
                /  \     /  \
             0..2 2..4  d4  d5
             / \   / \
            d0 d1 d2 d3
```

Therefore,

$$
Root
=
H
\left(
0x01
\Vert
MTH(D[0:4])
\Vert
MTH(D[4:6])
\right).
$$

The same rule is then applied to each subtree.

## 5. Inclusion Proofs

An inclusion proof allows a verifier to demonstrate that a particular leaf belongs to a tree without receiving the entire tree.

For leaf $d_i$, the verifier first computes

$$
H(0x00 \Vert d_i).
$$

The proof then supplies the hashes of the sibling subtrees needed to reconstruct the root.

At each step, the verifier computes either

$$
H(0x01 \Vert current \Vert sibling)
$$

when the current subtree is on the left, or

$$
H(0x01 \Vert sibling \Vert current)
$$

when the current subtree is on the right.

After all proof elements have been processed, the resulting hash is compared with the expected tree root.

The ordering of the hashes is determined by the recursive tree structure. It is **not** determined by a simple even/odd leaf-index rule.

## 6. Merkle Subtrees in MTC

MTC builds on this Merkle Tree Hash construction.

A subtree covering the leaves from `start` through `end - 1` has root

$$
MTH(D[start:end]).
$$

MTC then uses these subtree roots as part of its certificate-transparency mechanisms, including subtree inclusion and consistency proofs.

The MTC-specific protocol mechanisms are implemented separately from the basic Merkle tree construction in this project.

## 7. Implementation Notes

The mathematical definition is independent of the concrete hash algorithm.

The Rust implementation therefore uses the `HashFn` trait to separate:

* Merkle tree construction
* hash-function selection
* cryptographic hash implementation

The current implementation provides BLAKE3 through this interface. This is a generic implementation choice and does not claim wire-level compatibility with Certificate Transparency using the SHA-256 configuration specified by RFC 9162.

The implementation keeps the empty-tree case conceptually separate from `hash_leaf`:

* `hash_empty()` represents a tree containing zero leaves.
* `hash_leaf(b"")` represents a tree containing one leaf whose data is empty.

These cases have different hash inputs and therefore produce different hash values.

## References

* RFC 9162 — Certificate Transparency Version 2.0
* IETF Internet-Draft — Merkle Tree Certificates
* Project implementation: `mtc_core`, `mtc_crypto`, and `mtc_tree`
