use franklin_crypto::bellman::pairing::bn256::{Bn256, Fr, G1Affine};
use franklin_crypto::bellman::{CurveAffine, Field, PrimeField};

use crate::batch_proof::BatchProof;
use crate::ipa_fr::config::{Committer, IpaConfig};
use crate::ipa_fr::rns::BaseRnsParameters;
use crate::ipa_fr::transcript::{Bn256Transcript, PoseidonBn256Transcript};

use super::leaf::{LeafNodeWith32BytesValue, LIMBS};
use super::proof::{CommitmentElements, Elements, ExtraProofData, MultiProofWitnesses};
use super::trie::{
    AbstractKey, AbstractPath, AbstractStem, ExtStatus, IntoFieldElement, LeafNodeValue, NodeValue,
    VerkleNode, VerkleTree,
};
use super::utils::{fill_leaf_tree_poly, leaf_to_commitments, point_to_field_element};

#[cfg(test)]
mod bn256_verkle_tree_tests {
    use franklin_crypto::bellman::bn256::Fr;
    use franklin_crypto::bellman::Field;

    use crate::ipa_fr::config::IpaConfig;
    use crate::verkle_tree::bn256_verkle_tree::VerkleProof;
    use crate::verkle_tree::trie::{AbstractKey, ExtStatus};

    use super::VerkleTreeWith32BytesKeyValue;

    #[test]
    fn test_verkle_verification_with_one_entry() {
        let domain_size = 256;
        let committer = IpaConfig::new(domain_size);
        let mut tree = VerkleTreeWith32BytesKeyValue::new(committer);
        let mut key = [0u8; 32];
        key[0] = 13;
        let mut value = [0u8; 32];
        value[0] = 27;
        tree.insert(key, value);
        tree.compute_commitment().unwrap();

        let result = tree.get_witnesses(&[key]).unwrap();
        println!("commitments: {:?}", result.commitment_elements.commitments);
        println!("zs: {:?}", result.commitment_elements.elements.zs);
        println!("ys: {:?}", result.commitment_elements.elements.ys);

        let (proof, elements) = VerkleProof::create(&mut tree, &[key]).unwrap();

        let success = proof
            .check(&elements.zs, &elements.ys, &tree.committer)
            .unwrap();

        assert!(
            success,
            "Fail to pass the verification of verkle proof circuit."
        );
    }

    #[test]
    fn test_verkle_tree_with_some_entries() {
        let domain_size = 256;
        let committer = IpaConfig::new(domain_size);
        let mut tree = VerkleTreeWith32BytesKeyValue::new(committer);
        let mut keys = vec![];
        {
            let mut key = [0u8; 32];
            key[0] = 13;
            key[1] = 2;
            key[2] = 32;
            key[30] = 164;
            key[31] = 254;
            let value = [255u8; 32];
            tree.insert(key, value);
            keys.push(key);
        }
        {
            let key = [255u8; 32];
            let mut value = [0u8; 32];
            value[0] = 28;
            value[15] = 193;
            value[16] = 60;
            value[31] = 27;
            tree.insert(key, value);
            keys.push(key);
        }
        {
            let mut key = [0u8; 32];
            key[0] = 13;
            key[1] = 3;
            key[30] = 164;
            key[31] = 255;
            let value = [0u8; 32];
            tree.insert(key, value);
            keys.push(key);
        }
        {
            let mut key = [0u8; 32];
            key[0] = 13;
            key[1] = 3;
            key[30] = 164;
            key[31] = 254;
            let mut value = [0u8; 32];
            value[0] = 235;
            value[15] = 193;
            value[16] = 60;
            value[31] = 136;
            tree.insert(key, value);
            keys.push(key);
        }

        tree.compute_commitment().unwrap();
        let data = tree.get(&keys[2]).unwrap();
        println!("entry[2]: {:?}", data);

        let result = tree.get_witnesses(&[keys[0]]).unwrap();
        println!("commitments: {:?}", result.commitment_elements.commitments);
        println!("zs: {:?}", result.commitment_elements.elements.zs);
        println!("ys: {:?}", result.commitment_elements.elements.ys);
        println!("extra_data_list: {:?}", result.extra_data_list);
        assert_eq!(
            result.commitment_elements.elements.zs,
            [13, 2, 0, 1, 3, 252, 253]
        );
        assert_eq!(result.commitment_elements.elements.ys.len(), 7);
        assert_eq!(result.commitment_elements.commitments.len(), 7);
        assert_eq!(result.extra_data_list.len(), 1);
        assert_eq!(
            result.extra_data_list[0].ext_status % 8,
            ExtStatus::Present as usize
        );
        assert_eq!(result.extra_data_list[0].ext_status >> 3, 2);
        assert!(result.extra_data_list[0].poa_stems.is_none());

        tree.remove(&keys[0]);

        tree.compute_commitment().unwrap();

        let key_present_stem = keys[0];

        let result = tree.get_witnesses(&[key_present_stem]).unwrap();
        println!("commitments: {:?}", result.commitment_elements.commitments);
        println!("ys: {:?}", result.commitment_elements.elements.ys);
        assert_eq!(result.commitment_elements.elements.zs, [13, 2]);
        assert_eq!(result.commitment_elements.elements.ys.len(), 2);
        assert_eq!(result.commitment_elements.commitments.len(), 2);
        assert_eq!(result.extra_data_list.len(), 1);
        assert_eq!(
            result.extra_data_list[0].ext_status % 8,
            ExtStatus::AbsentEmpty as usize
        );
        assert_eq!(result.extra_data_list[0].ext_status >> 3, 1);
        assert!(result.extra_data_list[0].poa_stems.is_none());

        let key_absent_other = {
            let mut key = [255u8; 32];
            key[30] = 0;

            key
        };

        let result = tree.get_witnesses(&[key_absent_other]).unwrap();
        println!("commitments: {:?}", result.commitment_elements.commitments);
        println!("ys: {:?}", result.commitment_elements.elements.ys);
        assert_eq!(result.commitment_elements.elements.zs, [255, 0, 1]);
        assert_eq!(result.commitment_elements.elements.ys.len(), 3);
        assert_eq!(result.commitment_elements.commitments.len(), 3);
        assert_eq!(result.extra_data_list[0].poa_stems, keys[1].get_stem());
        assert_eq!(result.extra_data_list.len(), 1);
        assert_eq!(
            result.extra_data_list[0].ext_status % 8,
            ExtStatus::AbsentOther as usize
        );
        assert_eq!(result.extra_data_list[0].ext_status >> 3, 1);
        assert!(result.extra_data_list[0].poa_stems.is_some());

        let key_absent_empty = {
            let mut key = [255u8; 32];
            key[0] = 5;

            key
        };

        let result = tree.get_witnesses(&[key_absent_empty]).unwrap();
        println!("commitments: {:?}", result.commitment_elements.commitments);
        assert_eq!(result.commitment_elements.elements.zs, [5]);
        assert_eq!(result.commitment_elements.elements.ys, [Fr::zero()]);
        assert_eq!(result.commitment_elements.commitments.len(), 1);
        assert_eq!(result.extra_data_list.len(), 1);
        assert_eq!(
            result.extra_data_list[0].ext_status % 8,
            ExtStatus::AbsentEmpty as usize
        );
        assert_eq!(result.extra_data_list[0].ext_status >> 3, 0);
        assert!(result.extra_data_list[0].poa_stems.is_none());
    }
}

pub type VerkleTreeWith32BytesKeyValue =
    VerkleTree<[u8; 32], LeafNodeWith32BytesValue<G1Affine>, G1Affine, IpaConfig<G1Affine>>;

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
    pub values: Vec<L::Value>,
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

        let mut values: Vec<[u8; 32]> = vec![];
        for k in keys {
            let val = tree
                .get(k)
                .ok_or_else(|| anyhow::anyhow!("key {:?} is not found in this tree", k))?;
            values.push(*val);
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
