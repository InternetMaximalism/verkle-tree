# Verkle Tree

Rust version of Verkle Tree.

Original Golang implementation is in
[crate-crypto/go-ipa](https://github.com/crate-crypto/go-ipa/tree/fe21866d2ad5c732d1529cc8c4ebcc715edcc4e1) and [gballet/go-verkle](https://github.com/gballet/go-verkle/tree/8cf71b342fb237a48fafba9fcb2f68240a0c9f43).

This library uses alt-BabyJubjub BN128 instead Bandersnatch as the elliptic curve for commitments.

## Structure

`crate::verkle_tree` -> `crate::batch_proof` -> `crate::ipa_fr`

## Details

### Transcript

The **transcript** is the object storing all commitments which a prover should submits to a verifier and
generating challenges (pseudo-random variables) on behalf of the verifier.
Generating challenges uses [Poseidon hash function](https://github.com/filecoin-project/neptune).

### Elliptic Curve

To do the [inner product proof](https://eprint.iacr.org/2019/1177), We need an elliptic curve.
We choose Alt-BN128 (a.k.a. BN254) curve in our implementation for use with Ethereum Solidity.
