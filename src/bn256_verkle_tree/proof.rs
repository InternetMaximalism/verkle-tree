use franklin_crypto::bellman::pairing::bn256::{Bn256, Fr, G1Affine};
use franklin_crypto::bellman::{CurveAffine, Field, PrimeField};

use crate::batch_proof_fr::BatchProof;
use crate::ipa_fr::config::{Committer, IpaConfig};
use crate::ipa_fr::rns::BaseRnsParameters;
use crate::ipa_fr::transcript::{Bn256Transcript, PoseidonBn256Transcript};
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
        tree.compute_commitment()?;

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
                            ext_status: ExtStatus::AbsentOther as usize | (depth << 3),
                            poa_stems: stem.clone(),
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
                            ext_status: ExtStatus::AbsentEmpty as usize | (depth << 3),
                            poa_stems: K::Stem::default(),
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
                    for i in 0..LIMBS {
                        debug_assert_eq!(s_poly[slot + i], zero);
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
                            ext_status: ExtStatus::Present as usize | (depth << 3), // present, since the stem is present
                            poa_stems: K::Stem::default(),
                        }],
                    });
                    continue;
                }

                let mut tmp_leaves = [zero; LIMBS];
                leaf_to_commitments(&mut tmp_leaves, *info.leaves.get(&suffix).unwrap())?;
                for i in 0..LIMBS {
                    debug_assert_eq!(s_poly[slot + i], tmp_leaves[i]);
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
                        poa_stems: K::Stem::default(),
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

                // Build the list of elements for this level
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
            }

            // Loop over again, collecting the children's proof elements
            // This is because the order is breadth-first.
            for group in groups {
                let child = children.get(&group[0].get_branch_at(depth));
                if let Some(child) = child {
                    multi_proof_commitments.merge(&mut get_witnesses(child, &group, committer)?);
                } else {
                    // Special case of a proof of absence: no children
                    // commitment, as the value is 0.
                    multi_proof_commitments
                        .extra_data_list
                        .push(ExtraProofData {
                            ext_status: ExtStatus::AbsentEmpty as usize | (depth << 3),
                            poa_stems: K::Stem::default(),
                        });
                }
            }

            Ok(multi_proof_commitments)
        }
    }
}

/// `group_keys` groups a set of keys based on their byte at a given depth.
pub fn group_keys<P, K>(keys: &[K], depth: usize) -> Vec<Vec<K>>
where
    P: Default + AbstractPath,
    K: AbstractKey<Path = P>,
{
    // special case: only one key left
    if keys.len() == 1 {
        return vec![keys.to_vec()];
    }

    // there are at least two keys left in the list at this depth
    let mut groups = Vec::with_capacity(keys.len());
    let mut first_key = 0;
    for last_key in 1..keys.len() {
        let key = keys[last_key];
        let key_idx = key.get_branch_at(depth);
        let prev_idx = keys[last_key - 1].get_branch_at(depth);

        if key_idx != prev_idx {
            groups.push(keys[first_key..last_key].to_vec());
            first_key = last_key
        }
    }

    groups.push(keys[first_key..keys.len()].to_vec());

    groups
}
