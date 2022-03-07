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

`VerkleTreeWith32BytesKeyValue` is the 32 bytes key-value storage with `G1Affine`-valued commitments.
See also [sample code](./src/main.rs) about how to use this library.

```rust
use franklin_crypto::bellman::bn256::G1Affine;
use verkle_tree::bn256_verkle_tree::proof::VerkleProof;
use verkle_tree::bn256_verkle_tree::VerkleTreeWith32BytesKeyValue;
```

### Create an empty Verkle tree

`VerkleTreeWith32BytesKeyValue::new()` returns a tree consisting of only one root node with no children.

```rust
let domain_size = 256;
let committer = IpaConfig::new(domain_size);
let mut tree = VerkleTreeWith32BytesKeyValue::new(committer);
```

### Insert an entry in a Verkle tree

`VerkleTreeWith32BytesKeyValue::insert()` inserts `(key, value)` entry in given Verkle tree.
This method updates the entry to the new value and returns the old value,
even if the tree already has a value corresponding to the key.

```rust
let old_value: Option<[u8; 32]> = tree.insert(key, value);
```

### Remove an entry from a Verkle tree

`VerkleTreeWith32BytesKeyValue::remove()` remove the entry corresponding to `key` in given Verkle tree.
If the tree does not have a value corresponding to the key, this method does not change the tree state.

```rust
let old_value: Option<[u8; 32]> = tree.remove(&key);
```

### Get the value from a Verkle tree

`VerkleTreeWith32BytesKeyValue::get()` fetch the value corresponding to `key` in given Verkle tree.
The maximum time it takes to search entries depends on the depth of given Verkle tree.

```rust
let stored_value: Option<&[u8; 32]> = tree.get(&key);
```

### Compute the commitment of a Verkle root

`VerkleTreeWith32BytesKeyValue::compute_commitment()` computes the digest of given Verkle tree.

```rust
let commitment: G1Affine = tree.compute_commitment()?;
```

### Compute the inclusion/exclusion proof of a Verkle tree (Verkle proof)

`VerkleProof::create()` returns the inclusion/exclusion proof and its auxiliary data.
If `keys` includes one key, `elements.zs[i]` is a child index of the internal node
corresponding the key prefix of length `i`, and `elements.ys[i]` is the value of that child.
If `keys` includes two or more keys, compute `elements.zs` and `elements.ys` for each key,
and concatenate them.

```rust
let (proof, elements) = VerkleProof::create(&mut tree, &keys)?;
let zs = elements.zs;
let ys = elements.ys;
```

### Encode Verkle proof

**under development**

`EncodedVerkleProof::encode()` returns a Verkle proof in an serializable form.
It omits duplications and elements that can be calculated from other elements.

```rust
let encoded_proof = EncodedVerkleProof::encode(&proof);
```

### Decode Verkle proof

**under development**

`EncodedVerkleProof::decode()` returns a Verkle proof in an easy-to-calculate form.
`zs` and `ys` can be restored from `proof`.

```rust
let (proof, zs, ys) = encoded_proof.decode()?;
```

### Validate an inclusion/exclusion proof

`VerkleProof::check()` returns the validity of given inclusion/exclusion proof.
The verification does not use `elements.fs`, which has information on all child nodes.

```rust
let domain_size = 256;
let committer = IpaConfig::new(domain_size);
let is_valid: bool = VerkleProof::check(&proof, &zs, &ys, &committer)?;
```

## Details

### Transcript

The **transcript** is the object storing all commitments which a prover should submits to a verifier and
generating challenges (= pseudo-random variables) on behalf of the verifier.
Generating challenges uses [Poseidon hash function](https://github.com/filecoin-project/neptune) for low-cost PlonK proofs.

### Elliptic Curve

We choose Alt-BN128 (a.k.a. BN254) curve in our implementation for use with Ethereum Solidity.
We need this elliptic curve to do the [inner product proof](https://eprint.iacr.org/2019/1177).

### Verkle Tree

A **tree** data structure consists of the set called **nodes**.
Each node consist of a value and a list of reference to other nodes called **children**.
No reference is duplicated.
There is only one node in a tree that is not referenced by any other node. This is called the **root**.

**Verkle tree** is a type of prefix tree, where each node correspond to a key prefix, i.e. the first few bytes of the key, and refers to nodes corresponding to a prefix that is one character longer than its own prefix.
There are two types of nodes in the case of Verkle trees: **internal** and **leaf**.
Each internal node has 256 children and a digest of its subtree.
Each leaf node has no children and a digest of the **suffix tree**, which is a data structure storing multiple entries corresponding to a key prefix.

A similar data structure is **Merkle tree**, but the difference between these is in the way their commitments are computed.

If you would like to know more, please refer to [Vitalik Buterin's post](https://vitalik.ca/general/2021/06/18/verkle.html).
