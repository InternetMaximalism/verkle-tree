# Verkle Tree

Rust implementation of Verkle tree verifiable by PlonK.
The circuit implementation of Verkle tree verification is [here](https://github.com/InternetMaximalism/verkle-tree-circuit).

Original Golang implementation is in
[crate-crypto/go-ipa](https://github.com/crate-crypto/go-ipa/tree/fe21866d2ad5c732d1529cc8c4ebcc715edcc4e1) and [gballet/go-verkle](https://github.com/gballet/go-verkle/tree/8cf71b342fb237a48fafba9fcb2f68240a0c9f43).

This library uses alt-BabyJubjub BN128 instead Bandersnatch as the elliptic curve for commitments.

## What this is, and is not

This is not an attempt to further speed up the creation or verification of Verkle tree proofs. The project is positioned as a groundwork for constructing Verkle tree proofs verifiable by PlonK and for making verification of Layer 2 transactions more efficient.

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

`VerkleTreeWith32BytesKeyValue::compute_digest()` computes the digest of given Verkle tree.

```rust
let digest: Fr = tree.compute_digest()?;
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

### Encoded Verkle Proof

Example:

```sh
cargo test -- test_encode_verkle_proof --nocapture
cat test_cases/proof_case2.json
```

```json
{
  "multi_proof": {
    "ipa": {
      "l": [
        "0x373ae8f856e37542cda7561dc507ddf3a7ac666fb163e908d093fda016bd328a",
        "0x1d764657384e62b0e9b70d00d140cc13d885b8831355e7f3fb708f2b47be2604",
        "0x47ed7f94b6263630d585b4bb8070bb066aa74e9b1ee068d28c6b0dfef61b4d01",
        "0x363cf2f487193e12d57f5034b64a46dd7ce360b157b8c69cb39d5e9cde553714",
        "0xcab992777bd368c4fbb0372127f623dd803bf2830d69c620a6042b153e2d9727",
        "0xa9f01ce3441b121dc8bb75860eebac6a49b96001462a92a18e511c151501c6a8",
        "0xaddbaffbf6a28fad5f8d050be6d884aa68705421fdd345bb83296adc5ee2d602",
        "0x0d57a8821d9771380ef72b743304f3b0b960b59b7683f95a0434bf95d4cc6093"
      ],
      "r": [
        "0x2ff4547fface585e095bf1eae305fa07b5e2b6b1692d17c1d7f964b2b1794181",
        "0x447165ae6c16b23540c07d3f0a93d92be37e90030c3b80e7fce16f9671890aa8",
        "0x39625eb44c1b211eced15ba93f2c901eadb1a32e0b5a0d0c4987b8d7d60c9b2f",
        "0x572729372ccd211f3073a3535e5c5590e38173ce0071d9ce55f67fccbedb4415",
        "0x5ebcd74626a3923034ec66bd0b7f7908fb6a6ff3fb1aa9dde6273684ec13bb16",
        "0x8e859d69cc0e4cb297acf8ac8b3af292d3d9e1de3ddc5734400769565ce3d088",
        "0x0b474fd0dc097920ec9642f1dbcfa3f840b7da6fe25c496c05aa181fad2632aa",
        "0xd8f52ca54bf344b80d7b5268b46a49fa3b633b51ed1277d49da429d4176dd41e"
      ],
      "a": "0x1e7caca7461a0200b57594e57db4a4bc33526f80a2757a6f6d93bb2e54364059"
    },
    "d": "0x406cbde73c39a688977004d833d80105f19c058698f4e69c8b7427af1858e1a4"
  },
  "keys": [
    "0xfea400000000000000000000000000000000000000000000000000000000650d",
    "0x11a400000000000000000000000000000000000000000000000000000000670d",
    "0xfda400000000000000000000000000000000000000000000000000000000670d",
    "0xfea400000000000000000000000000000000000000000000000000000000670d",
    "0xff00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  ],
  "values": [
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x0000000000000000000000000000000000000000000000000000000000000000",
    "0x8800000000000000000000000000003cc10000000000000000000000000000eb",
    "0x0000000000000000000000000000000000000000000000000000000000000000"
  ],
  "extra_data_list": [
    "0x1000000000000000000000000000000000000000000000000000000000000000",
    "0x1200000000000000000000000000000000000000000000000000000000000000",
    "0x1300000000000000000000000000000000000000000000000000000000000000",
    "0x1400000000000000000000000000000000000000000000000000000000000000",
    "0x09ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  ],
  "commitments": [
    "0x548597525b0dcb2c046411b7f4d7ce5a2f89a5c2b74fd25de157034296e30ca2",
    "0x522a1a4b4989ba0d40f3087753aa85c29dce891816215036855c11b77362199c",
    "0x8d6606735e3b17c30992ec1646dbe6c01e37ed37b60cedfc19cb773d1c14890a",
    "0x421e3f1467b697029ce8b8ab9b50667233fa198d6df465364345b444feb12889",
    "0x421e3f1467b697029ce8b8ab9b50667233fa198d6df465364345b444feb12889",
    "0x9b9704755f28a84eca03566db4dbdf43f0a045e95df2fe400eee6cdcf9eaf227"
  ]
}
```

NOTE: This Verkle proof has 5 keys, but a capacity of about 32 keys
(to be precise, it can contain 256 commitments before encoding).
The size of `multi_proof` is constant within that capacity.
