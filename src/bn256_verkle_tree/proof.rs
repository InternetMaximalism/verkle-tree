use franklin_crypto::bellman::pairing::bn256::{Bn256, Fq, Fr, G1Affine};
use franklin_crypto::bellman::{
    CurveAffine, Field, GroupDecodingError, PrimeField, PrimeFieldRepr, SqrtField,
};
use serde::{Deserialize, Serialize};

use crate::batch_proof_fr::BatchProof;
use crate::ipa_fr::config::{Committer, IpaConfig};
use crate::ipa_fr::proof::IpaProof;
use crate::ipa_fr::rns::BaseRnsParameters;
use crate::ipa_fr::transcript::{Bn256Transcript, PoseidonBn256Transcript};
use crate::ipa_fr::utils::{read_field_element_le, write_field_element_le};
use crate::verkle_tree::trie::{
    AbstractKey, AbstractPath, AbstractStem, ExtStatus, IntoFieldElement, LeafNodeValue, NodeValue,
    VerkleNode, VerkleTree,
};
use crate::verkle_tree::utils::{fill_leaf_tree_poly, leaf_to_commitments, point_to_field_element};
use crate::verkle_tree::witness::{
    CommitmentElements, Elements, ExtraProofData, MultiProofWitnesses,
};

use super::leaf::{LeafNodeWith32BytesValue, LIMBS};

#[derive(Clone, Debug)]
pub struct VerkleProof<K, L, GA, C>
where
    K: AbstractKey,
    L: LeafNodeValue<K, GA>,
    GA: CurveAffine,
    C: Committer<GA>,
{
    pub multi_proof: BatchProof<GA>, // multi-point argument
    pub commitments: Vec<GA>,        // commitments, sorted by their path in the tree
    pub extra_data_list: Vec<ExtraProofData<K>>,
    pub keys: Vec<K>,
    pub values: Vec<Option<L::Value>>,
    _width: std::marker::PhantomData<C>,
}

impl<P, K> VerkleProof<K, LeafNodeWith32BytesValue<G1Affine>, G1Affine, IpaConfig<G1Affine>>
where
    P: Default + AbstractPath,
    K: AbstractKey<Path = P>,
    K::Stem: AbstractStem<Path = P> + IntoFieldElement<Fr>,
{
    /// Returns the inclusion/exclusion proof and its auxiliary data.
    /// If `keys` includes one key, `elements.zs[i]` is a child index of the internal node
    /// corresponding the key prefix of length `i`, and `elements.ys[i]` is the value of that child.
    /// If `keys` includes two or more keys, compute `elements.zs` and `elements.ys` for each key,
    /// and concatenate them.
    pub fn create(
        tree: &mut VerkleTree<K, LeafNodeWith32BytesValue<G1Affine>, G1Affine, IpaConfig<G1Affine>>,
        keys: &[K],
    ) -> anyhow::Result<(Self, Elements<Fr>)> {
        let transcript = PoseidonBn256Transcript::with_bytes(b"multi_proof");
        let rns_params = &BaseRnsParameters::<Bn256>::new_for_field(68, 110, 4);
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

        let multi_proof = BatchProof::<G1Affine>::create(
            &commitments,
            &elements.fs,
            &elements.zs,
            transcript.into_params(),
            rns_params,
            &tree.committer,
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
        ys: &[Fr],
        ipa_conf: &IpaConfig<G1Affine>,
    ) -> anyhow::Result<bool> {
        let transcript = PoseidonBn256Transcript::with_bytes(b"multi_proof");
        let rns_params = &BaseRnsParameters::<Bn256>::new_for_field(68, 110, 4);
        self.multi_proof.check(
            &self.commitments.clone(),
            ys,
            zs,
            transcript.into_params(),
            rns_params,
            ipa_conf,
        )
    }
}

impl<P, K, GA, C> VerkleTree<K, LeafNodeWith32BytesValue<GA>, GA, C>
where
    C: Committer<GA>,
    P: Default + AbstractPath,
    K: AbstractKey<Path = P>,
    K::Stem: AbstractStem<Path = P> + IntoFieldElement<GA::Scalar>,
    GA: CurveAffine,
    GA::Base: PrimeField,
{
    pub fn get_witnesses(&self, keys: &[K]) -> anyhow::Result<MultiProofWitnesses<K, GA>> {
        get_witnesses(&self.root, keys, &self.committer)
    }
}

pub fn get_witnesses<P, K, GA, C>(
    node: &VerkleNode<K, LeafNodeWith32BytesValue<GA>, GA>,
    keys: &[K],
    committer: &C,
) -> anyhow::Result<MultiProofWitnesses<K, GA>>
where
    C: Committer<GA>,
    P: Default + AbstractPath,
    K: AbstractKey<Path = P>,
    K::Stem: AbstractStem<Path = P> + IntoFieldElement<GA::Scalar>,
    GA: CurveAffine,
    GA::Base: PrimeField,
{
    match node {
        VerkleNode::Leaf {
            path, stem, info, ..
        } => {
            let depth = path.len();
            let width = committer.get_domain_size();
            let value_size = 32; // The size of [u8; 32] in bytes.
            let limb_bits_size = value_size * 8 / LIMBS;
            debug_assert!(limb_bits_size < GA::Scalar::NUM_BITS as usize);

            let tmp_s_commitments = info
                .s_commitments
                .clone()
                .expect("Need to execute `compute commitment` in advance");
            let tmp_commitment = info
                .commitment
                .expect("Need to execute `compute commitment` in advance");

            let zero = GA::Scalar::zero();
            let poly = {
                let poly_0 = GA::Scalar::from_repr(<GA::Scalar as PrimeField>::Repr::from(1u64))?;
                let poly_1 = stem
                    .clone()
                    .into_field_element()
                    .map_err(|_| anyhow::anyhow!("unreachable code"))?;
                let mut poly = vec![poly_0, poly_1];
                for s_commitment in tmp_s_commitments.iter() {
                    poly.push(point_to_field_element(s_commitment)?);
                }
                poly.resize(width, zero);

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
                            commitments: vec![tmp_commitment, tmp_commitment],
                            elements: Elements {
                                zs: vec![0, 1],
                                ys: vec![poly[0], poly[1]],
                                fs: vec![poly.clone(), poly.clone()],
                            },
                        },
                        extra_data_list: vec![ExtraProofData {
                            ext_status: ExtStatus::OtherStem as usize | (depth << 3),
                            poa_stem: stem.clone(),
                        }],
                    });
                    continue;
                }

                let suffix = key.get_suffix();
                debug_assert!(suffix < width);

                let slot = (LIMBS * suffix) % width;

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
                    debug_assert_eq!(poly[suffix_slot], zero);
                    multi_proof_commitments.merge(&mut MultiProofWitnesses {
                        commitment_elements: CommitmentElements {
                            commitments: vec![tmp_commitment, tmp_commitment, tmp_commitment],
                            elements: Elements {
                                zs: vec![0usize, 1, suffix_slot],
                                ys: vec![poly[0], poly[1], zero],
                                fs: vec![poly.clone(), poly.clone(), poly.clone()],
                            },
                        },
                        extra_data_list: vec![ExtraProofData {
                            ext_status: ExtStatus::EmptySuffixTree as usize | (depth << 3),
                            poa_stem: K::Stem::default(),
                        }],
                    });
                    continue;
                }

                let tmp_s_commitment = tmp_s_commitments[limb_index];

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
                            assert_eq!(s_poly[slot + i], zero);
                        }
                    }
                    multi_proof_commitments.merge(&mut MultiProofWitnesses {
                        commitment_elements: CommitmentElements {
                            commitments: vec![
                                tmp_commitment,
                                tmp_commitment,
                                tmp_commitment,
                                tmp_s_commitment,
                            ],
                            elements: Elements {
                                zs: vec![0usize, 1, suffix_slot, slot],
                                ys: vec![poly[0], poly[1], poly[suffix_slot], zero],
                                fs: vec![poly.clone(), poly.clone(), poly.clone(), s_poly],
                            },
                        },
                        extra_data_list: vec![ExtraProofData {
                            ext_status: ExtStatus::OtherKey as usize | (depth << 3), // present, since the stem is present
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
                            tmp_commitment,
                            tmp_commitment,
                            tmp_commitment,
                            tmp_s_commitment,
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
                        ext_status: ExtStatus::Present as usize | (depth << 3),
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
            let mut fi = vec![GA::Scalar::zero(); width];
            for (&i, child) in children.iter() {
                fi[i] = *child.get_digest().unwrap();
            }

            let commitment = *info.get_commitment().unwrap();

            for group in groups.clone() {
                let zi = group[0].get_branch_at(depth);

                let yi = fi.clone()[zi];
                multi_proof_commitments
                    .commitment_elements
                    .merge(&mut CommitmentElements {
                        commitments: vec![commitment],
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
                            ext_status: ExtStatus::Empty as usize | ((depth + 1) << 3),
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
    pub keys: Vec<[u8; 32]>,
    pub values: Vec<[u8; 32]>, // None = 0
    pub extra_data_list: Vec<EncodedExtProofData>,
    pub commitments_list: Vec<EncodedEcPoint>,
}

impl EncodedVerkleProof {
    pub fn encode(
        verkle_proof: &VerkleProof<
            [u8; 32],
            LeafNodeWith32BytesValue<G1Affine>,
            G1Affine,
            IpaConfig<G1Affine>,
        >,
    ) -> Self {
        let commitments = verkle_proof
            .commitments
            .iter()
            .map(|commitment| EncodedEcPoint::encode(commitment))
            .collect::<Vec<_>>();
        println!("commitments: {:?}", commitments);
        let entries = verkle_proof
            .keys
            .iter()
            .zip(&verkle_proof.values)
            .zip(&verkle_proof.extra_data_list)
            .map(|((&key, &value), extra_data)| (key, value, extra_data.clone()))
            .collect::<Vec<_>>();
        let cs = &mut vec![];
        set_index(cs, &mut verkle_proof.commitments.iter(), &entries, 0).unwrap();
        let cs = cs
            .iter()
            .map(|commitment| EncodedEcPoint::encode(commitment))
            .collect::<Vec<_>>();

        EncodedVerkleProof {
            multi_proof: EncodedBatchProof::encode(&verkle_proof.multi_proof),
            keys: verkle_proof.keys.clone(),
            values: verkle_proof
                .values
                .iter()
                .map(|value| value.map_or([0u8; 32], |v| v))
                .collect::<Vec<_>>(),
            extra_data_list: verkle_proof
                .extra_data_list
                .iter()
                .map(|extra_data| EncodedExtProofData::encode(extra_data))
                .collect::<Vec<_>>(),
            commitments_list: cs,
        }
    }

    pub fn decode(
        &self,
    ) -> anyhow::Result<(
        VerkleProof<[u8; 32], LeafNodeWith32BytesValue<G1Affine>, G1Affine, IpaConfig<G1Affine>>,
        Vec<usize>,
        Vec<Fr>,
    )> {
        println!("commitments: {:?}", self.commitments_list);
        let commitments_list = self
            .commitments_list
            .iter()
            .map(|commitment| commitment.decode())
            .collect::<anyhow::Result<Vec<_>>>()?;
        let extra_data_list = self
            .extra_data_list
            .iter()
            .map(|extra_data| extra_data.decode())
            .collect::<Vec<_>>();

        let entries = self
            .keys
            .iter()
            .zip(&self.values)
            .zip(&extra_data_list)
            .map(|((&key, &value), extra_data)| (key, value, extra_data.clone()))
            .collect::<Vec<_>>();

        let rc = commitments_list[0];

        let (cs, zs, ys, ps) = get_index(&mut commitments_list.iter().skip(1), &rc, &entries, 0)?;
        println!(
            "ps: {:?}",
            ps.iter()
                .map(|&commitment| commitment.map(|v| EncodedEcPoint::encode(&v)))
                .collect::<Vec<_>>()
        );

        let values = self
            .values
            .iter()
            .zip(&extra_data_list)
            .map(
                |(value, extra_data)| match ExtStatus::from(extra_data.ext_status % 8) {
                    ExtStatus::Present => Some(*value),
                    _ => None,
                },
            )
            .collect::<Vec<_>>();
        let verkle_tree = VerkleProof {
            commitments: cs,
            multi_proof: self.multi_proof.decode()?,
            keys: self.keys.clone(),
            values,
            extra_data_list: extra_data_list.clone(),
            _width: std::marker::PhantomData,
        };
        Ok((verkle_tree, zs, ys))
    }
}

fn set_index<'a, I: Iterator<Item = &'a G1Affine>>(
    cs: &mut Vec<G1Affine>,
    commitments: &mut I,
    entries: &[([u8; 32], Option<[u8; 32]>, ExtraProofData<[u8; 32]>)],
    depth: usize,
) -> anyhow::Result<()> {
    let groups = group_entries(entries, |(key, _, _)| key.get_branch_at(depth));

    let mut same_stem = true;
    for (key, _, _) in entries.iter().skip(1) {
        if key.get_stem() != entries[0].0.get_stem() {
            same_stem = false;
        }
    }

    if same_stem && depth != 0 {
        // leaf node
        let (_, _, first_extra_data) = &entries[0];
        match ExtStatus::from(first_extra_data.ext_status % 8) {
            ExtStatus::Empty => {}
            ExtStatus::OtherStem => {
                cs.push(*commitments.next().unwrap());
                commitments.next();
            }
            ExtStatus::EmptySuffixTree => {
                cs.push(*commitments.next().unwrap());
                commitments.next();
                commitments.next();
            }
            ExtStatus::OtherKey => {
                cs.push(*commitments.next().unwrap());
                commitments.next();
                commitments.next();
                cs.push(*commitments.next().unwrap());
            }
            ExtStatus::Present => {
                cs.push(*commitments.next().unwrap());
                commitments.next();
                commitments.next();
                cs.push(*commitments.next().unwrap());
                for _ in 0..(LIMBS - 1) {
                    commitments.next();
                }
            }
        }

        for (_, _, extra_data) in entries.iter().skip(1) {
            // leaf node
            match ExtStatus::from(extra_data.ext_status % 8) {
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
                    cs.push(*commitments.next().unwrap());
                }
                ExtStatus::Present => {
                    commitments.next();
                    commitments.next();
                    commitments.next();
                    cs.push(*commitments.next().unwrap());
                    for _ in 0..(LIMBS - 1) {
                        commitments.next();
                    }
                }
            }
        }
    } else {
        let cc = commitments.next().unwrap();
        println!("cc: {:?}", EncodedEcPoint::encode(cc));
        cs.push(*cc);
        set_index(cs, commitments, &groups[0], depth + 1)?;
        for group in groups.iter().skip(1) {
            commitments.next();
            // }

            // for group in groups {
            set_index(cs, commitments, &group, depth + 1)?;
        }
    }

    Ok(())
}

fn get_index<'a, I: Iterator<Item = &'a G1Affine>>(
    commitments: &mut I,
    rc: &G1Affine,
    entries: &[([u8; 32], [u8; 32], ExtraProofData<[u8; 32]>)],
    depth: usize,
) -> anyhow::Result<(Vec<G1Affine>, Vec<usize>, Vec<Fr>, Vec<Option<G1Affine>>)> {
    let mut cs = vec![];
    let mut zs = vec![];
    let mut ys = vec![];
    let mut ps = vec![];

    let groups = group_entries(entries, |(key, _, _)| key.get_branch_at(depth));

    let mut same_stem = true;
    for (key, _, _) in entries.iter().skip(1) {
        if key.get_stem() != entries[0].0.get_stem() {
            same_stem = false;
        }
    }

    let width = 256;
    if same_stem && depth != 0 {
        for (key, value, extra_data) in entries {
            // leaf node
            match ExtStatus::from(extra_data.ext_status % 8) {
                ExtStatus::Empty => {
                    cs.push(*rc);
                    ps.push(None);
                    zs.push(key.get_branch_at(depth - 1));
                    ys.push(Fr::zero());
                }
                ExtStatus::OtherStem => {
                    cs.push(*rc);
                    ps.push(None);
                    zs.push(0);
                    ys.push(Fr::one());
                    cs.push(*rc);
                    ps.push(None);
                    zs.push(1);
                    ys.push(read_field_element_le(&extra_data.poa_stem.unwrap())?);
                }
                ExtStatus::EmptySuffixTree => {
                    cs.push(*rc);
                    ps.push(None);
                    zs.push(0);
                    ys.push(Fr::one());
                    cs.push(*rc);
                    ps.push(None);
                    zs.push(1);
                    ys.push(read_field_element_le(&key.get_stem().unwrap())?);
                    cs.push(*rc);
                    ps.push(None);
                    let suffix = key.get_suffix();
                    let limb_index = (LIMBS * suffix) / width;
                    zs.push(2 + limb_index);
                    ys.push(Fr::zero());
                }
                ExtStatus::OtherKey => {
                    let cc = commitments.next().unwrap();
                    cs.push(*rc);
                    ps.push(Some(*cc));
                    zs.push(0);
                    ys.push(Fr::one());
                    cs.push(*rc);
                    ps.push(Some(*cc));
                    zs.push(1);
                    ys.push(read_field_element_le(&key.get_stem().unwrap())?);
                    cs.push(*rc);
                    ps.push(Some(*cc));
                    let suffix = key.get_suffix();
                    let limb_index = (LIMBS * suffix) / width;
                    let slot = (LIMBS * suffix) % width;
                    zs.push(2 + limb_index);
                    ys.push(point_to_field_element(cc)?);
                    cs.push(*cc);
                    ps.push(None);
                    zs.push(slot);
                    ys.push(Fr::zero());
                }
                ExtStatus::Present => {
                    let cc = commitments.next().unwrap();
                    cs.push(*rc);
                    ps.push(Some(*cc));
                    zs.push(0);
                    ys.push(Fr::one());
                    cs.push(*rc);
                    ps.push(Some(*cc));
                    zs.push(1);
                    ys.push(read_field_element_le(&key.get_stem().unwrap())?);
                    cs.push(*rc);
                    ps.push(Some(*cc));
                    let suffix = key.get_suffix();
                    let limb_index = (LIMBS * suffix) / width;
                    let slot = (LIMBS * suffix) % width;
                    zs.push(2 + limb_index);
                    ys.push(point_to_field_element(cc)?);
                    let mut tmp_leaves = [Fr::zero(); LIMBS];
                    leaf_to_commitments(&mut tmp_leaves, *value)?;
                    for i in 0..LIMBS {
                        cs.push(*cc);
                        ps.push(None);
                        zs.push(slot + i);
                        ys.push(tmp_leaves[i]);
                    }
                }
            }
        }
    } else {
        let mut tmp_cc_list = vec![];

        for group in groups.clone() {
            let zi = group[0].0.get_branch_at(depth);
            let cc = commitments.next().unwrap();
            zs.push(zi);
            cs.push(*rc);
            tmp_cc_list.push(cc);
            // }

            // for (group, cc) in groups.iter().zip(tmp_cc_list) {
            let yi = point_to_field_element(cc).unwrap();
            ys.push(yi);
            ps.push(Some(*cc));
            let (mut children_cs, mut children_zs, mut children_ys, mut children_ps) =
                get_index(commitments, cc, &group, depth + 1)?;
            cs.append(&mut children_cs);
            zs.append(&mut children_zs);
            ys.append(&mut children_ys);
            ps.append(&mut children_ps);
        }
    }

    Ok((cs, zs, ys, ps))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncodedExtProofData {
    pub ext_status: u8,
    pub poa_stem: [u8; 31],
}

impl EncodedExtProofData {
    pub fn encode(extra_proof_data: &ExtraProofData<[u8; 32]>) -> Self {
        Self {
            ext_status: extra_proof_data.ext_status as u8,
            poa_stem: extra_proof_data.poa_stem.map_or([0u8; 31], |v| v),
        }
    }

    pub fn decode(&self) -> ExtraProofData<[u8; 32]> {
        ExtraProofData {
            ext_status: self.ext_status as usize,
            poa_stem: match ExtStatus::from(self.ext_status % 8) {
                ExtStatus::OtherStem => Some(self.poa_stem),
                _ => <[u8; 32] as AbstractKey>::Stem::default(),
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncodedBatchProof {
    pub ipa: EncodedIpaProof,
    pub d: EncodedEcPoint,
}

impl EncodedBatchProof {
    pub fn encode(batch_proof: &BatchProof<G1Affine>) -> Self {
        Self {
            ipa: EncodedIpaProof::encode(&batch_proof.ipa),
            d: EncodedEcPoint::encode(&batch_proof.d),
        }
    }

    pub fn decode(&self) -> anyhow::Result<BatchProof<G1Affine>> {
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
    pub fn encode(elements: &Elements<Fr>) -> Self {
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

    pub fn decode(&self) -> anyhow::Result<Elements<Fr>> {
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
    pub fn encode(elements: &CommitmentElements<G1Affine>) -> Self {
        Self {
            commitments: elements
                .commitments
                .iter()
                .map(|commitment| EncodedEcPoint::encode(commitment))
                .collect::<Vec<_>>(),
            elements: EncodedElements::encode(&elements.elements),
        }
    }

    pub fn decode(&self) -> anyhow::Result<CommitmentElements<G1Affine>> {
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
    pub fn encode(ipa_proof: &IpaProof<G1Affine>) -> Self {
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

    pub fn decode(&self) -> anyhow::Result<IpaProof<G1Affine>> {
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
pub struct EncodedEcPoint(Encoded32Bytes);

impl EncodedEcPoint {
    pub fn encode(point: &G1Affine) -> Self {
        let encoded = point.into_compressed();
        let mut raw = [0u8; 32];
        for (i, v) in encoded.as_ref().iter().enumerate() {
            raw[i] = *v;
        }

        Self(Encoded32Bytes::encode(&raw))
    }

    pub fn decode(&self) -> anyhow::Result<G1Affine> {
        let raw = self.0.decode()?;
        let result = into_affine_unchecked(raw)?;

        Ok(result)
    }
}

fn into_affine_unchecked(bytes: [u8; 32]) -> Result<G1Affine, GroupDecodingError> {
    // Create a copy of this representation.
    let mut copy = bytes;

    if copy[0] & (1 << 6) != 0 {
        // This is the point at infinity, which means that if we mask away
        // the first two bits, the entire representation should consist
        // of zeroes.
        copy[0] &= 0x3f;

        if copy.iter().all(|b| *b == 0) {
            Ok(G1Affine::zero())
        } else {
            Err(GroupDecodingError::UnexpectedInformation)
        }
    } else {
        // Determine if the intended y coordinate must be greater
        // lexicographically.
        let greatest = copy[0] & (1 << 7) != 0;

        // Unset the two most significant bits.
        copy[0] &= 0x3f;

        let mut x = <Fq as PrimeField>::Repr::default();

        {
            let mut reader = &copy[..];

            x.read_be(&mut reader).unwrap();
        }

        // Interpret as Fq element.
        let x = Fq::from_repr(x)
            .map_err(|e| GroupDecodingError::CoordinateDecodingError("x coordinate", e))?;

        get_point_from_x(x, greatest).ok_or(GroupDecodingError::NotOnCurve)
    }
}

fn get_point_from_x(x: Fq, greatest: bool) -> Option<G1Affine> {
    // let mut b_repr = <Fq as PrimeField>::Repr::default();
    // b_repr.0[0] = 0x7a17caa950ad28d7;
    // b_repr.0[1] = 0x1f6ac17ae15521b9;
    // b_repr.0[2] = 0x334bea4e696bd284;
    // b_repr.0[3] = 0x2a1f6744ce179d8e;
    // let b = Fq::from_repr(b_repr).unwrap();
    let b = G1Affine::b_coeff();

    // Compute x^3 + b
    let mut x3b = x;
    x3b.square();
    x3b.mul_assign(&x);
    x3b.add_assign(&b);

    x3b.sqrt().map(|y| {
        let mut negy = y;
        negy.negate();

        G1Affine::from_xy_unchecked(x, if (y < negy) ^ greatest { y } else { negy })
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncodedScalar(Encoded32Bytes);

impl EncodedScalar {
    pub fn encode(scalar: &Fr) -> Self {
        let encoded = write_field_element_le(scalar);
        let mut raw = [0u8; 32];
        for (i, v) in encoded.iter().enumerate() {
            raw[i] = *v;
        }

        Self(Encoded32Bytes::encode(&raw))
    }

    pub fn decode(&self) -> anyhow::Result<Fr> {
        let raw = self.0.decode()?;
        read_field_element_le::<Fr>(&raw)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Encoded32Bytes(String);

impl Encoded32Bytes {
    pub fn encode(bytes: &[u8; 32]) -> Self {
        Self(hex::encode(bytes))
    }

    pub fn decode(&self) -> anyhow::Result<[u8; 32]> {
        let raw = hex::decode(&self.0)?;
        let mut bytes = [0u8; 32];
        for (i, v) in raw.iter().enumerate() {
            bytes[i] = *v;
        }

        Ok(bytes)
    }
}
