# Verkle Tree

Rust version of Verkle Tree.

Original Golang implementation is in
[crate-crypto/go-ipa](https://github.com/crate-crypto/go-ipa/tree/fe21866d2ad5c732d1529cc8c4ebcc715edcc4e1) and [gballet/go-verkle](https://github.com/gballet/go-verkle/tree/8cf71b342fb237a48fafba9fcb2f68240a0c9f43).

This library uses alt-BabyJubjub BN128 instead Bandersnatch as the elliptic curve for commitments.

## Environment

```sh
rustup override set nightly
cargo --version # >= 1.56.0
```

## API

`VerkleTreeWith32BytesKey` is the 32 bytes key-value storage with `G1Affine`-valued commitments.
See also [verkle_tree_tests](./src/verkle_tree/mod.rs) about how to use this library.

```rust
use franklin_crypto::bellman::bn256::{G1Affine};
use verkle_tree::verkle_tree::{bn256_verkle_tree::VerkleProof, trie::VerkleTree};
```

### Create an empty Verkle tree

`VerkleTreeWith32BytesKey::default()` returns a tree consisting of only one root node with no children.

```rust
let mut tree = VerkleTreeWith32BytesKey::default();
```

### Insert an entry in a Verkle tree

`VerkleTreeWith32BytesKey::insert()` inserts `(key, value)` entry in given Verkle tree.
This method updates the entry to the new value and returns the old value,
even if the tree already has a value corresponding to the key.

```rust
let old_value: Option<[u8; 32]> = VerkleTreeWith32BytesKey::insert(&mut tree, key, value);
```

### Remove an entry from a Verkle tree

`VerkleTreeWith32BytesKey::remove()` remove the entry corresponding to `key` in given Verkle tree.
If the tree does not have a value corresponding to the key, this method does not change the tree state.

```rust
let old_value: Option<[u8; 32]> = VerkleTreeWith32BytesKey::remove(&mut tree, &key);
```

### Get the value from a Verkle tree

`VerkleTreeWith32BytesKey::get()` fetch the value corresponding to `key` in given Verkle tree.
The maximum time it takes to search entries depends on the depth of given Verkle tree.

```rust
let value: Option<&[u8; 32]> = VerkleTreeWith32BytesKey::get(&tree, &key);
```

### Compute the commitment of a Verkle root

`VerkleTreeWith32BytesKey::compute_commitment()` computes the digest of given Verkle tree.

```rust
let commitment: G1Affine = VerkleTreeWith32BytesKey::compute_commitment(&mut tree)?;
```

### Compute the inclusion/exclusion proof of a Verkle tree

`VerkleProof::create()` returns the inclusion/exclusion proof and its auxiliary data.
`elements.zs` is a list of child indices of internal nodes along the path corresponding each key,
and `elements.ys` is a list of digests for those nodes.

```rust
let (proof, elements) = VerkleProof::create(&mut tree, &keys)?;
```

### Validate an inclusion/exclusion proof

`VerkleProof::check()` returns the validity of given inclusion/exclusion proof.

```rust
let is_valid: bool = VerkleProof::check(&proof, &elements.zs, &elements.ys, &tree.committer)?;
```

## Details

### Transcript

The **transcript** is the object storing all commitments which a prover should submits to a verifier and
generating challenges (pseudo-random variables) on behalf of the verifier.
Generating challenges uses [Poseidon hash function](https://github.com/filecoin-project/neptune).

### Elliptic Curve

To do the [inner product proof](https://eprint.iacr.org/2019/1177), We need an elliptic curve.
We choose Alt-BN128 (a.k.a. BN254) curve in our implementation for use with Ethereum Solidity.

### Verkle Tree

A **tree data structure** consists of the set called **nodes**.
Each node consist of a value and a list of reference to other nodes called **children**.
No reference is duplicated.
There is only one node in a tree that is not referenced by any other node. This is called the **root**.

**Verkle tree** is a type of prefix tree, whose nodes are key prefixes and reference is the next byte of the key.
There are two types of nodes in the case of Verkle trees: **internal** and **leaf**.
Each internal node has 256 children and the digest of its subtree.
Each leaf node has no children and consist of a digest of the **suffix tree**, which is a data structure storing multiple entries corresponding to a key prefix.

A similar data structure is **Merkle tree**, but the difference between these is in the way their inclusion/exclusion proofs are constructed.

If you would like to know more, please refer to [Vitalik Buterin's post](https://vitalik.ca/general/2021/06/18/verkle.html).
