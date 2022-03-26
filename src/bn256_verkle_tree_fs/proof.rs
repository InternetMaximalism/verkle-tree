use franklin_crypto::babyjubjub::{edwards, JubjubBn256, JubjubEngine, Unknown};
use franklin_crypto::bellman::pairing::bn256::Bn256;
use franklin_crypto::bellman::{Field, PrimeField, PrimeFieldRepr};
use serde::{Deserialize, Serialize};

use crate::batch_proof_fs::BatchProof;
use crate::ipa_fs::config::{Committer, IpaConfig};
use crate::ipa_fs::proof::IpaProof;
use crate::ipa_fs::transcript::{Bn256Transcript, PoseidonBn256Transcript};
use crate::ipa_fs::utils::{read_field_element_le, write_field_element_le};
use crate::verkle_tree::trie::{
    AbstractKey, AbstractPath, AbstractStem, ExtStatus, IntoFieldElement,
};
// use crate::verkle_tree::utils::{fill_leaf_tree_poly, leaf_to_commitments, point_to_field_element};
use crate::verkle_tree::witness::{Elements, ExtraProofData};
use crate::verkle_tree_fs::trie::{LeafNodeValue, VerkleNode, VerkleTree};
use crate::verkle_tree_fs::utils::{
    fill_leaf_tree_poly, leaf_to_commitments, point_to_field_element,
};
use crate::verkle_tree_fs::witness::{CommitmentElements, MultiProofWitnesses};

use super::leaf::{LeafNodeWith32BytesValue, LIMBS};

#[derive(Clone)]
pub struct VerkleProof<K, L, E, C>
where
    K: AbstractKey,
    L: LeafNodeValue<K, E>,
    E: JubjubEngine,
    C: Committer<E>,
{
    pub multi_proof: BatchProof<E>, // multi-point argument
    pub commitments: Vec<edwards::Point<E, Unknown>>, // commitments, sorted by their path in the tree
    pub extra_data_list: Vec<ExtraProofData<K>>,
    pub keys: Vec<K>,
    pub values: Vec<Option<L::Value>>,
    _width: std::marker::PhantomData<C>,
}

impl<'a, P, K> VerkleProof<K, LeafNodeWith32BytesValue<Bn256>, Bn256, IpaConfig<'a, Bn256>>
where
    P: Default + AbstractPath,
    K: AbstractKey<Path = P>,
    K::Stem: AbstractStem<Path = P> + IntoFieldElement<<Bn256 as JubjubEngine>::Fs>,
{
    /// Returns the inclusion/exclusion proof and its auxiliary data.
    /// If `keys` includes one key, `elements.zs[i]` is a child index of the internal node
    /// corresponding the key prefix of length `i`, and `elements.ys[i]` is the value of that child.
    /// If `keys` includes two or more keys, compute `elements.zs` and `elements.ys` for each key,
    /// and concatenate them.
    pub fn create(
        tree: &mut VerkleTree<K, LeafNodeWith32BytesValue<Bn256>, Bn256, IpaConfig<Bn256>>,
        keys: &[K],
    ) -> anyhow::Result<(Self, Elements<<Bn256 as JubjubEngine>::Fs>)> {
        let transcript = PoseidonBn256Transcript::with_bytes(b"multi_proof");
        let jubjub_params = &JubjubBn256::new();
        tree.compute_digest()?;

        let MultiProofWitnesses {
            commitment_elements,
            extra_data_list,
        } = tree.get_witnesses(keys)?;

        let CommitmentElements {
            commitments,
            elements,
        } = commitment_elements;

        let mut values: Vec<Option<[u8; 32]>> = vec![];
        for k in keys {
            let val = tree.get(k);
            values.push(val.map(|v| *v));
        }

        let (multi_proof, _) = BatchProof::<Bn256>::create(
            &commitments,
            &elements.fs,
            &elements.zs,
            transcript.into_params(),
            &tree.committer,
            jubjub_params,
        )?;
        let proof = VerkleProof {
            multi_proof,
            commitments,
            extra_data_list,
            keys: keys.to_vec(),
            values,
            _width: std::marker::PhantomData,
        };

        Ok((proof, elements))
    }

    /// Returns the validity of given inclusion/exclusion proof.
    pub fn check(
        &self,
        zs: &[usize],
        ys: &[<Bn256 as JubjubEngine>::Fs],
        ipa_conf: &IpaConfig<Bn256>,
    ) -> anyhow::Result<bool> {
        let transcript = PoseidonBn256Transcript::with_bytes(b"multi_proof");
        let jubjub_params = &JubjubBn256::new();
        self.multi_proof.check(
            &self.commitments.clone(),
            ys,
            zs,
            transcript.into_params(),
            ipa_conf,
            jubjub_params,
        )
    }
}

impl<P, K, E, C> VerkleTree<K, LeafNodeWith32BytesValue<E>, E, C>
where
    C: Committer<E>,
    P: Default + AbstractPath,
    K: AbstractKey<Path = P>,
    K::Stem: AbstractStem<Path = P> + IntoFieldElement<E::Fs>,
    E: JubjubEngine,
{
    pub fn get_witnesses(&self, keys: &[K]) -> anyhow::Result<MultiProofWitnesses<K, E>> {
        get_witnesses(&self.root, keys, &self.committer)
    }
}

pub fn get_witnesses<P, K, E, C>(
    node: &VerkleNode<K, LeafNodeWith32BytesValue<E>, E>,
    keys: &[K],
    committer: &C,
) -> anyhow::Result<MultiProofWitnesses<K, E>>
where
    C: Committer<E>,
    P: Default + AbstractPath,
    K: AbstractKey<Path = P>,
    K::Stem: AbstractStem<Path = P> + IntoFieldElement<E::Fs>,
    E: JubjubEngine,
{
    match node {
        VerkleNode::Leaf {
            path, stem, info, ..
        } => {
            let depth = path.len();
            let width = committer.get_domain_size();
            let value_size = 32; // The size of [u8; 32] in bytes.
            let limb_bits_size = value_size * 8 / LIMBS;
            debug_assert!(limb_bits_size < E::Fs::NUM_BITS as usize);

            let tmp_s_commitments = info
                .s_commitments
                .clone()
                .expect("Need to execute `compute commitment` in advance");
            let tmp_commitment = info
                .commitment
                .clone()
                .expect("Need to execute `compute commitment` in advance");

            let infinity_point_fs = point_to_field_element(&edwards::Point::<E, Unknown>::zero())?;
            let poly = {
                let poly_0 = E::Fs::from_raw_repr(<E::Fs as PrimeField>::Repr::from(1u64))?;
                let poly_1 = stem
                    .clone()
                    .into_field_element()
                    .map_err(|_| anyhow::anyhow!("unreachable code"))?;
                let mut poly = vec![poly_0, poly_1];
                for s_commitment in tmp_s_commitments.iter() {
                    poly.push(point_to_field_element(s_commitment)?);
                }
                poly.resize(width, infinity_point_fs);

                poly
            };

            let mut multi_proof_commitments = MultiProofWitnesses::default();
            for key in keys {
                if key.get_stem() != stem.clone() {
                    // Proof of absence: case of a differing stem.
                    //
                    // Return an unopened stem-level node.
                    multi_proof_commitments.merge(&mut MultiProofWitnesses {
                        commitment_elements: CommitmentElements {
                            commitments: vec![tmp_commitment.clone(), tmp_commitment.clone()],
                            elements: Elements {
                                zs: vec![0, 1],
                                ys: vec![poly[0], poly[1]],
                                fs: vec![poly.clone(), poly.clone()],
                            },
                        },
                        extra_data_list: vec![ExtraProofData {
                            depth,
                            status: ExtStatus::OtherStem,
                            poa_stem: stem.clone(),
                        }],
                    });
                    continue;
                }

                let suffix = key.get_suffix();
                debug_assert!(suffix < width);

                let slot = (LIMBS * suffix) % width;

                let zero = E::Fs::zero();
                let limb_index = suffix / limb_bits_size;
                let suffix_slot = 2 + limb_index;
                let mut s_poly = vec![zero; width];
                let start_index = limb_index * limb_bits_size;
                // let sub_leaves_array = leaves_array[start_index..(start_index + limb_bits_size)];
                let mut sub_leaves_array = vec![None; limb_bits_size];
                for (i, &v) in info.leaves.iter() {
                    if (start_index..(start_index + limb_bits_size)).contains(i) {
                        sub_leaves_array[i - start_index] = Some(v);
                    }
                }
                let count = fill_leaf_tree_poly(&mut s_poly, &sub_leaves_array)?;

                // Proof of absence: case of a missing suffix tree.
                //
                // The suffix tree for this value is missing, i.e. all
                // leaves in the extension-and-suffix tree are grouped
                // in the other suffix tree (e.g. C2 if we are looking
                // at C1).
                if count == 0 {
                    // TODO: maintain a count variable at LeafNode level
                    // so that we know not to build the polynomials in this case,
                    // as all the information is available before fill_leaf_tree_poly
                    // has to be called, save the count.
                    debug_assert_eq!(poly[suffix_slot], infinity_point_fs);
                    multi_proof_commitments.merge(&mut MultiProofWitnesses {
                        commitment_elements: CommitmentElements {
                            commitments: vec![
                                tmp_commitment.clone(),
                                tmp_commitment.clone(),
                                tmp_commitment.clone(),
                            ],
                            elements: Elements {
                                zs: vec![0usize, 1, suffix_slot],
                                ys: vec![poly[0], poly[1], infinity_point_fs],
                                fs: vec![poly.clone(), poly.clone(), poly.clone()],
                            },
                        },
                        extra_data_list: vec![ExtraProofData {
                            depth,
                            status: ExtStatus::EmptySuffixTree,
                            poa_stem: K::Stem::default(),
                        }],
                    });
                    continue;
                }

                let tmp_s_commitment = tmp_s_commitments[limb_index].clone();

                if info.leaves.get(&suffix).is_none() {
                    // Proof of absence: case of a missing value.
                    //
                    // Leaf tree is present as a child of the extension,
                    // but does not contain the requested suffix. This can
                    // only happen when the leaf has never been written to
                    // since after deletion the value would be set to zero
                    // but still contain the leaf marker 2^128.
                    if cfg!(debug_assertion) {
                        for i in 0..LIMBS {
                            assert_eq!(s_poly[slot + i], infinity_point_fs);
                        }
                    }
                    multi_proof_commitments.merge(&mut MultiProofWitnesses {
                        commitment_elements: CommitmentElements {
                            commitments: vec![
                                tmp_commitment.clone(),
                                tmp_commitment.clone(),
                                tmp_commitment.clone(),
                                tmp_s_commitment,
                            ],
                            elements: Elements {
                                zs: vec![0usize, 1, suffix_slot, slot],
                                ys: vec![poly[0], poly[1], poly[suffix_slot], infinity_point_fs],
                                fs: vec![poly.clone(), poly.clone(), poly.clone(), s_poly],
                            },
                        },
                        extra_data_list: vec![ExtraProofData {
                            depth,
                            status: ExtStatus::OtherKey, // present, since the stem is present
                            poa_stem: K::Stem::default(),
                        }],
                    });
                    continue;
                }

                let mut tmp_leaves = [zero; LIMBS];
                leaf_to_commitments(&mut tmp_leaves, *info.leaves.get(&suffix).unwrap())?;
                if cfg!(debug_assertion) {
                    for i in 0..LIMBS {
                        assert_eq!(s_poly[slot + i], tmp_leaves[i]);
                    }
                }

                multi_proof_commitments.merge(&mut MultiProofWitnesses {
                    commitment_elements: CommitmentElements {
                        commitments: vec![
                            tmp_commitment.clone(),
                            tmp_commitment.clone(),
                            tmp_commitment.clone(),
                            tmp_s_commitment.clone(),
                            tmp_s_commitment,
                        ],
                        elements: Elements {
                            zs: vec![0usize, 1, suffix_slot, slot, slot + 1],
                            ys: vec![
                                poly[0],
                                poly[1],
                                poly[suffix_slot],
                                tmp_leaves[0],
                                tmp_leaves[1],
                            ],
                            fs: vec![
                                poly.clone(),
                                poly.clone(),
                                poly.clone(),
                                s_poly.clone(),
                                s_poly,
                            ],
                        },
                    },
                    extra_data_list: vec![ExtraProofData {
                        depth,
                        status: ExtStatus::Present,
                        poa_stem: K::Stem::default(),
                    }],
                });
                continue;
            }

            Ok(multi_proof_commitments)
        }
        VerkleNode::Internal {
            path,
            children,
            info,
            ..
        } => {
            let depth = path.len();
            let groups = group_keys(keys, depth);
            let mut multi_proof_commitments = MultiProofWitnesses::default();

            // fill in the polynomial for this node
            let width = committer.get_domain_size();
            let mut fi = vec![E::Fs::zero(); width];
            for (&i, child) in children.iter() {
                fi[i] = *child.get_digest().unwrap();
            }

            let commitment = info.get_commitment().unwrap().clone();

            for group in groups.clone() {
                let zi = group[0].get_branch_at(depth);

                let yi = fi.clone()[zi];
                multi_proof_commitments
                    .commitment_elements
                    .merge(&mut CommitmentElements {
                        commitments: vec![commitment.clone()],
                        elements: Elements {
                            zs: vec![zi],
                            ys: vec![yi],
                            fs: vec![fi.clone()],
                        },
                    });
                // }

                // // Loop over again, collecting the children's proof elements
                // // This is because the order is breadth-first.
                // for group in groups {
                let zi = group[0].get_branch_at(depth);

                let child = children.get(&zi);
                if let Some(child) = child {
                    multi_proof_commitments.merge(&mut get_witnesses(child, &group, committer)?);
                } else {
                    // Special case of a proof of absence: empty node.
                    // The depth of the child node is `depth + 1`.
                    multi_proof_commitments
                        .extra_data_list
                        .push(ExtraProofData {
                            depth: depth + 1,
                            status: ExtStatus::Empty,
                            poa_stem: K::Stem::default(),
                        });
                }
            }

            Ok(multi_proof_commitments)
        }
    }
}

pub fn group_entries<T, F>(keys: &[T], get_branch: F) -> Vec<Vec<T>>
where
    T: Sized + Clone,
    F: Fn(&T) -> usize,
{
    // special case: only one key left
    if keys.len() == 1 {
        return vec![keys.to_vec()];
    }

    // there are at least two keys left in the list at this depth
    let mut groups = Vec::with_capacity(keys.len());
    let mut first_key = 0;
    for last_key in 1..keys.len() {
        let key = &keys[last_key];
        let key_idx = get_branch(key);
        let prev_idx = get_branch(&keys[last_key - 1]);

        if key_idx != prev_idx {
            groups.push(keys[first_key..last_key].to_vec());
            first_key = last_key
        }
    }

    groups.push(keys[first_key..keys.len()].to_vec());

    groups
}

/// `group_keys` groups a set of keys based on their byte at a given depth.
pub fn group_keys<P, K>(keys: &[K], depth: usize) -> Vec<Vec<K>>
where
    P: Default + AbstractPath,
    K: AbstractKey<Path = P>,
{
    group_entries(keys, |key| key.get_branch_at(depth))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncodedVerkleProof {
    pub multi_proof: EncodedBatchProof,
    pub keys: Vec<Encoded32Bytes>,
    pub values: Vec<Encoded32Bytes>, // None = 0
    pub extra_data_list: Vec<EncodedExtProofData>,
    pub commitments: Vec<EncodedEcPoint>,
}

impl EncodedVerkleProof {
    pub fn encode(
        verkle_proof: &VerkleProof<
            [u8; 32],
            LeafNodeWith32BytesValue<Bn256>,
            Bn256,
            IpaConfig<Bn256>,
        >,
    ) -> Self {
        let entries = verkle_proof
            .keys
            .iter()
            .zip(&verkle_proof.values)
            .zip(&verkle_proof.extra_data_list)
            .map(|((&key, &value), extra_data)| (key, value, extra_data.clone()))
            .collect::<Vec<_>>();
        let cs = &mut vec![];
        remove_duplicates(cs, &mut verkle_proof.commitments.iter(), &entries, 0).unwrap();

        Self {
            multi_proof: EncodedBatchProof::encode(&verkle_proof.multi_proof),
            keys: verkle_proof
                .keys
                .iter()
                .map(|k| Encoded32Bytes::encode(k))
                .collect::<Vec<_>>(),
            values: verkle_proof
                .values
                .iter()
                .map(|value| Encoded32Bytes::encode(&value.or_else(|| Some([0u8; 32])).unwrap()))
                .collect::<Vec<_>>(),
            extra_data_list: verkle_proof
                .extra_data_list
                .iter()
                .map(|extra_data| EncodedExtProofData::encode(extra_data))
                .collect::<Vec<_>>(),
            commitments: cs
                .iter()
                .map(|commitment| EncodedEcPoint::encode(commitment))
                .collect::<Vec<_>>(),
        }
    }

    pub fn decode(
        &self,
    ) -> anyhow::Result<(
        VerkleProof<[u8; 32], LeafNodeWith32BytesValue<Bn256>, Bn256, IpaConfig<Bn256>>,
        Vec<usize>,
        Vec<<Bn256 as JubjubEngine>::Fs>,
    )> {
        let commitments = self
            .commitments
            .iter()
            .map(|commitment| commitment.decode())
            .collect::<anyhow::Result<Vec<_>>>()?;
        let extra_data_list = self
            .extra_data_list
            .iter()
            .map(|extra_data| extra_data.decode())
            .collect::<anyhow::Result<Vec<_>>>()?;
        let keys = self
            .keys
            .iter()
            .map(|k| k.decode())
            .collect::<anyhow::Result<Vec<_>>>()?;
        let values = self
            .values
            .iter()
            .zip(&extra_data_list)
            .map(|(value, extra_data)| match extra_data.status {
                ExtStatus::Present => value.decode().and_then(|v| Ok(Some(v))),
                _ => Ok(None),
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let entries = keys
            .iter()
            .zip(&values)
            .zip(&extra_data_list)
            .map(|((&key, &value), extra_data)| (key, value, extra_data.clone()))
            .collect::<Vec<_>>();

        let rc = commitments[0].clone();

        let mut cs = vec![];
        let mut zs = vec![];
        let mut ys = vec![];
        recover_commitments(
            &mut cs,
            &mut zs,
            &mut ys,
            &mut commitments.iter().skip(1),
            &rc,
            &entries,
            0,
        )?;

        let verkle_proof = VerkleProof {
            commitments: cs,
            multi_proof: self.multi_proof.decode()?,
            keys,
            values,
            extra_data_list,
            _width: std::marker::PhantomData,
        };

        Ok((verkle_proof, zs, ys))
    }
}

fn remove_duplicates<'a, I: Iterator<Item = &'a edwards::Point<Bn256, Unknown>>>(
    cs: &mut Vec<edwards::Point<Bn256, Unknown>>,
    commitments: &mut I,
    entries: &[([u8; 32], Option<[u8; 32]>, ExtraProofData<[u8; 32]>)],
    depth: usize,
) -> anyhow::Result<()> {
    let groups = group_entries(entries, |(key, _, _)| key.get_branch_at(depth));

    let (first_key, _, first_extra_data) = &entries[0];
    let mut same_stem = true;
    for (key, _, _) in entries.iter().skip(1) {
        if key.get_stem() != first_key.get_stem() {
            same_stem = false;
        }
    }

    let first_entry_depth = first_extra_data.depth;
    if same_stem && depth == first_entry_depth {
        // leaf node
        match first_extra_data.status {
            ExtStatus::Empty => {}
            ExtStatus::OtherStem => {
                cs.push(commitments.next().unwrap().clone());
                commitments.next();
            }
            ExtStatus::EmptySuffixTree => {
                cs.push(commitments.next().unwrap().clone());
                commitments.next();
                commitments.next();
            }
            ExtStatus::OtherKey => {
                cs.push(commitments.next().unwrap().clone());
                commitments.next();
                commitments.next();
                cs.push(commitments.next().unwrap().clone());
            }
            ExtStatus::Present => {
                cs.push(commitments.next().unwrap().clone());
                commitments.next();
                commitments.next();
                cs.push(commitments.next().unwrap().clone());
                for _ in 0..(LIMBS - 1) {
                    commitments.next();
                }
            }
        }

        for (_, _, extra_data) in entries.iter().skip(1) {
            // leaf node
            match extra_data.status {
                ExtStatus::Empty => {
                    // NOTICE: A empty leaf does not have the same stem with a non-empty leaf.
                }
                ExtStatus::OtherStem => {
                    commitments.next();
                    commitments.next();
                }
                ExtStatus::EmptySuffixTree => {
                    commitments.next();
                    commitments.next();
                    commitments.next();
                }
                ExtStatus::OtherKey => {
                    commitments.next();
                    commitments.next();
                    commitments.next();
                    cs.push(commitments.next().unwrap().clone());
                }
                ExtStatus::Present => {
                    commitments.next();
                    commitments.next();
                    commitments.next();
                    cs.push(commitments.next().unwrap().clone());
                    for _ in 0..(LIMBS - 1) {
                        commitments.next();
                    }
                }
            }
        }
    } else {
        let cc = commitments.next().unwrap();
        cs.push(cc.clone());
        remove_duplicates(cs, commitments, &groups[0], depth + 1)?;
        for group in groups.iter().skip(1) {
            commitments.next();
            remove_duplicates(cs, commitments, &group, depth + 1)?;
        }
    }

    Ok(())
}

fn recover_commitments<'a, I: Iterator<Item = &'a edwards::Point<Bn256, Unknown>>>(
    cs: &mut Vec<edwards::Point<Bn256, Unknown>>,
    zs: &mut Vec<usize>,
    ys: &mut Vec<<Bn256 as JubjubEngine>::Fs>,
    commitments: &mut I,
    rc: &edwards::Point<Bn256, Unknown>,
    entries: &[([u8; 32], Option<[u8; 32]>, ExtraProofData<[u8; 32]>)],
    depth: usize,
) -> anyhow::Result<()> {
    type Fs = <Bn256 as JubjubEngine>::Fs;
    let groups = group_entries(entries, |(key, _, _)| key.get_branch_at(depth));

    let (first_key, _, first_extra_data) = &entries[0];
    let mut same_stem = true;
    for (key, _, _) in entries.iter().skip(1) {
        if key.get_stem() != first_key.get_stem() {
            same_stem = false;
        }
    }

    let width = 256;
    let first_entry_depth = first_extra_data.depth;
    if same_stem && depth == first_entry_depth {
        for (key, value, extra_data) in entries {
            // leaf node
            match extra_data.status {
                ExtStatus::Empty => {}
                ExtStatus::OtherStem => {
                    cs.push(rc.clone());
                    zs.push(0);
                    ys.push(Fs::one());
                    cs.push(rc.clone());
                    zs.push(1);
                    ys.push(read_field_element_le(&extra_data.poa_stem.unwrap())?);
                }
                ExtStatus::EmptySuffixTree => {
                    cs.push(rc.clone());
                    zs.push(0);
                    ys.push(Fs::one());
                    cs.push(rc.clone());
                    zs.push(1);
                    ys.push(read_field_element_le(&key.get_stem().unwrap())?);
                    cs.push(rc.clone());
                    let suffix = key.get_suffix();
                    let limb_index = (LIMBS * suffix) / width;
                    zs.push(2 + limb_index);
                    ys.push(Fs::zero());
                }
                ExtStatus::OtherKey => {
                    let cc = commitments.next().unwrap();
                    cs.push(rc.clone());
                    zs.push(0);
                    ys.push(Fs::one());
                    cs.push(rc.clone());
                    zs.push(1);
                    ys.push(read_field_element_le(&key.get_stem().unwrap())?);
                    cs.push(rc.clone());
                    let suffix = key.get_suffix();
                    let limb_index = (LIMBS * suffix) / width;
                    let slot = (LIMBS * suffix) % width;
                    zs.push(2 + limb_index);
                    ys.push(point_to_field_element(cc)?);
                    cs.push(cc.clone());
                    zs.push(slot);
                    ys.push(Fs::zero());
                }
                ExtStatus::Present => {
                    let cc = commitments.next().unwrap();
                    cs.push(rc.clone());
                    zs.push(0);
                    ys.push(Fs::one());
                    cs.push(rc.clone());
                    zs.push(1);
                    ys.push(read_field_element_le(&key.get_stem().unwrap())?);
                    cs.push(rc.clone());
                    let suffix = key.get_suffix();
                    let limb_index = (LIMBS * suffix) / width;
                    let slot = (LIMBS * suffix) % width;
                    zs.push(2 + limb_index);
                    ys.push(point_to_field_element(cc)?);
                    let mut tmp_leaves = [Fs::zero(); LIMBS];
                    leaf_to_commitments(&mut tmp_leaves, (*value).unwrap())?;
                    for i in 0..LIMBS {
                        cs.push(cc.clone());
                        zs.push(slot + i);
                        ys.push(tmp_leaves[i]);
                    }
                }
            }
        }
    } else {
        for group in groups.clone() {
            let (key, _, extra_data) = &group[0];
            let zi = key.get_branch_at(depth);
            zs.push(zi);
            cs.push(rc.clone());
            if extra_data.depth == depth + 1 && extra_data.status == ExtStatus::Empty {
                let yi = Fs::zero();
                ys.push(yi);
            } else {
                let cc = commitments.next().unwrap();
                let yi = point_to_field_element(cc).unwrap();
                ys.push(yi);
                recover_commitments(cs, zs, ys, commitments, cc, &group, depth + 1)?;
            }
        }
    }

    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncodedExtProofData(pub Encoded32Bytes);

impl EncodedExtProofData {
    pub fn encode(extra_proof_data: &ExtraProofData<[u8; 32]>) -> Self {
        let mut result = [0u8; 32];
        let status_depth = extra_proof_data.status.clone() as usize | (extra_proof_data.depth << 3);
        assert!(status_depth < 256);
        result[31] = status_depth as u8;
        if let Some(poa_stem) = extra_proof_data.poa_stem {
            for i in 0..31 {
                result[i] = poa_stem[i];
            }
        }

        Self(Encoded32Bytes::encode(&result))
    }

    pub fn decode(&self) -> anyhow::Result<ExtraProofData<[u8; 32]>> {
        let raw = self.0.decode()?;
        let status_depth = raw[31];
        let depth = (status_depth >> 3) as usize;
        let status = ExtStatus::from(status_depth % 8);
        let poa_stem = if status == ExtStatus::OtherStem {
            let mut poa_stem = [0u8; 31];
            for i in 0..31 {
                poa_stem[i] = raw[i];
            }

            Some(poa_stem)
        } else {
            None
        };

        Ok(ExtraProofData {
            depth,
            status,
            poa_stem,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncodedBatchProof {
    pub ipa: EncodedIpaProof,
    pub d: EncodedEcPoint,
}

impl EncodedBatchProof {
    pub fn encode(batch_proof: &BatchProof<Bn256>) -> Self {
        Self {
            ipa: EncodedIpaProof::encode(&batch_proof.ipa),
            d: EncodedEcPoint::encode(&batch_proof.d),
        }
    }

    pub fn decode(&self) -> anyhow::Result<BatchProof<Bn256>> {
        Ok(BatchProof {
            ipa: self.ipa.decode()?,
            d: self.d.decode()?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncodedElements {
    pub zs: Vec<u8>,
    pub ys: Vec<EncodedScalar>,
    pub fs: Vec<Vec<EncodedScalar>>,
}

impl EncodedElements {
    pub fn encode(elements: &Elements<<Bn256 as JubjubEngine>::Fs>) -> Self {
        Self {
            zs: elements.zs.iter().map(|&zi| zi as u8).collect::<Vec<_>>(),
            ys: elements
                .ys
                .iter()
                .map(|yi| EncodedScalar::encode(yi))
                .collect::<Vec<_>>(),
            fs: elements
                .fs
                .iter()
                .map(|fi| {
                    fi.iter()
                        .map(|f| EncodedScalar::encode(f))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>(),
        }
    }

    pub fn decode(&self) -> anyhow::Result<Elements<<Bn256 as JubjubEngine>::Fs>> {
        Ok(Elements {
            zs: self.zs.iter().map(|&zi| zi as usize).collect::<Vec<_>>(),
            ys: self
                .ys
                .iter()
                .map(|yi| yi.decode())
                .collect::<anyhow::Result<Vec<_>>>()?,
            fs: self
                .fs
                .iter()
                .map(|fi| {
                    fi.iter()
                        .map(|f| f.decode())
                        .collect::<anyhow::Result<Vec<_>>>()
                })
                .collect::<anyhow::Result<Vec<_>>>()?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncodedCommitmentElements {
    pub commitments: Vec<EncodedEcPoint>,
    pub elements: EncodedElements,
}

impl EncodedCommitmentElements {
    pub fn encode(elements: &CommitmentElements<Bn256>) -> Self {
        Self {
            commitments: elements
                .commitments
                .iter()
                .map(|commitment| EncodedEcPoint::encode(commitment))
                .collect::<Vec<_>>(),
            elements: EncodedElements::encode(&elements.elements),
        }
    }

    pub fn decode(&self) -> anyhow::Result<CommitmentElements<Bn256>> {
        Ok(CommitmentElements {
            commitments: self
                .commitments
                .iter()
                .map(|commitment| commitment.decode())
                .collect::<anyhow::Result<Vec<_>>>()?,
            elements: self.elements.decode()?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncodedIpaProof {
    pub l: Vec<EncodedEcPoint>,
    pub r: Vec<EncodedEcPoint>,
    pub a: EncodedScalar,
}

impl EncodedIpaProof {
    pub fn encode(ipa_proof: &IpaProof<Bn256>) -> Self {
        Self {
            l: ipa_proof
                .l
                .iter()
                .map(|li| EncodedEcPoint::encode(li))
                .collect::<Vec<_>>(),
            r: ipa_proof
                .r
                .iter()
                .map(|ri| EncodedEcPoint::encode(ri))
                .collect::<Vec<_>>(),
            a: EncodedScalar::encode(&ipa_proof.a),
        }
    }

    pub fn decode(&self) -> anyhow::Result<IpaProof<Bn256>> {
        Ok(IpaProof {
            l: self
                .l
                .iter()
                .map(|li| EncodedEcPoint::decode(li))
                .collect::<anyhow::Result<Vec<_>>>()?,
            r: self
                .r
                .iter()
                .map(|ri| EncodedEcPoint::decode(ri))
                .collect::<anyhow::Result<Vec<_>>>()?,
            a: self.a.decode()?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncodedEcPoint(pub Encoded32Bytes);

impl EncodedEcPoint {
    pub fn encode(point: &edwards::Point<Bn256, Unknown>) -> Self {
        let (x, y) = point.into_xy();
        let encoded = write_field_element_le(&y);
        let mut raw = [0u8; 32];
        for (i, v) in encoded.iter().enumerate() {
            raw[i] = *v;
        }

        if x.into_repr().is_odd() {
            raw[31] |= 0x80;
        }

        Self(Encoded32Bytes::encode(&raw))
    }

    pub fn decode(&self) -> anyhow::Result<edwards::Point<Bn256, Unknown>> {
        let jubjub_params = &JubjubBn256::new();
        let mut raw = self.0.decode()?;
        let sign = (raw[31] >> 7) == 1;
        raw[31] &= 0x7F;
        let y = read_field_element_le(&raw)?;
        let result = edwards::Point::get_for_y(y, sign, jubjub_params).unwrap();

        Ok(result)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncodedScalar(pub Encoded32Bytes);

impl EncodedScalar {
    pub fn encode(scalar: &<Bn256 as JubjubEngine>::Fs) -> Self {
        let encoded = write_field_element_le(scalar);
        let mut raw = [0u8; 32];
        for (i, v) in encoded.iter().enumerate() {
            raw[i] = *v;
        }

        Self(Encoded32Bytes::encode(&raw))
    }

    pub fn decode(&self) -> anyhow::Result<<Bn256 as JubjubEngine>::Fs> {
        let raw = self.0.decode()?;
        read_field_element_le::<<Bn256 as JubjubEngine>::Fs>(&raw)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Encoded32Bytes(pub String);

impl Encoded32Bytes {
    pub fn encode(bytes: &[u8; 32]) -> Self {
        let mut bytes_rev = bytes.to_vec();
        bytes_rev.reverse();
        Self("0x".to_string() + &hex::encode(&bytes_rev))
    }

    pub fn decode(&self) -> anyhow::Result<[u8; 32]> {
        let mut raw = hex::decode(&self.0[2..])?;
        raw.reverse();
        let mut bytes = [0u8; 32];
        for (i, v) in raw.iter().enumerate() {
            bytes[i] = *v;
        }

        Ok(bytes)
    }
}
