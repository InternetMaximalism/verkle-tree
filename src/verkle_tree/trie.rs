use core::fmt::Debug;
use franklin_crypto::bellman::{CurveAffine, Field, PrimeField};
use generic_array::{ArrayLength, GenericArray};

use crate::ipa_fr::{config::IpaConfig, utils::read_field_element_le};

use super::{
    proof::{CommitmentElements, Elements, MultiProofCommitment, ProofCommitment},
    utils::{fill_suffix_tree_poly, leaf_to_commitments, point_to_field_element},
};

pub enum ExtStatus {
    AbsentEmpty, // path led to a node with a different stem
    AbsentOther, // missing child node along the path
    Present,     // stem was present
}

pub trait Committer<GA: CurveAffine> {
    type Err: Send + Sync + 'static;

    fn commit_to_poly(&self, polynomial: &[GA::Scalar], a: usize) -> Result<GA, Self::Err>;
}

impl<GA: CurveAffine> Committer<GA> for IpaConfig<GA::Projective> {
    type Err = anyhow::Error;

    fn commit_to_poly(&self, polynomial: &[GA::Scalar], _: usize) -> anyhow::Result<GA> {
        let result = self.commit(polynomial)?;

        Ok(result)
    }
}

pub trait AbstractKey: Clone + Copy + Debug + PartialEq + Eq {
    type Stem: AbstractAbsolutePath;
    type Path: AbstractRelativePath;

    fn into_stem(self) -> Self::Stem;

    fn encode(&self) -> Self::Path;
}

// 32 bytes key
impl AbstractKey for [u8; 32] {
    type Stem = Vec<u8>; // [u8; 31]
    type Path = Vec<u8>;

    fn into_stem(self) -> Vec<u8> {
        self[..31].to_vec()
    }

    fn encode(&self) -> Vec<u8> {
        self.to_vec()
    }
}

// 32 bytes value
pub trait AbstractValue: Clone + Copy + Debug + PartialEq + Eq {}

impl AbstractValue for [u8; 32] {}

pub trait AbstractRelativePath: IntoIterator {
    fn get_branch(&self) -> usize;

    fn get_suffix(&self) -> usize;

    /// Returns if `self` is a proper prefix of `full_path`.
    ///
    /// If `self` is non-empty, this function returns `true`.
    ///
    /// If `self` is equal to `full_path`, this function returns `false`.
    fn is_proper_prefix_of(&self, full_path: &Self) -> bool;
}

impl AbstractRelativePath for Vec<u8> {
    fn get_branch(&self) -> usize {
        self[0] as usize
    }

    fn get_suffix(&self) -> usize {
        let mut suffix_bytes = self[31..].to_vec();
        assert!(suffix_bytes.len() <= 8);
        suffix_bytes.resize(8, 0u8);

        usize::from_le_bytes(suffix_bytes.try_into().unwrap())
    }

    fn is_proper_prefix_of(&self, full_path: &Self) -> bool {
        if self.is_empty() {
            return true;
        }

        if self.len() >= full_path.len() {
            return false;
        }

        let base_path = full_path[..self.len()].to_vec();

        *self.clone() == base_path
    }
}

pub trait AbstractAbsolutePath {
    fn get_depth(&self) -> usize;
}

impl AbstractAbsolutePath for Vec<u8> {
    fn get_depth(&self) -> usize {
        self.len()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum TrieNode<K, V, W, GA>
where
    K: AbstractKey,
    V: AbstractValue,
    W: ArrayLength<Option<TrieNode<K, V, W, GA>>>,
    GA: CurveAffine,
{
    // Empty {
    //     key_fragments: K::Path,
    //     key: K::Stem,
    //     c1: Option<GA>,
    //     c2: Option<GA>,
    //     info: NodeInfo<GA>,
    // },
    Suffix {
        key_fragments: K::Path,
        key: K::Stem,
        leaves: Box<Vec<Option<V>>>,
        s_commitments: Option<Vec<GA>>,
        info: NodeInfo<GA>,
    },
    Internal {
        key_fragments: K::Path,
        key: K::Stem,
        children: Box<GenericArray<Option<TrieNode<K, V, W, GA>>, W>>,
        info: NodeInfo<GA>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeInfo<GA>
where
    GA: CurveAffine,
{
    /// The number of children which are `Some` rather than `None`.
    pub(crate) num_nonempty_children: usize,

    /// A helper function for computing commitment.
    // pub(crate) committer: C,

    /// The commitment of this node.
    /// If it has not computed yet, `commitment` set `None`.
    pub(crate) commitment: Option<GA>,

    /// The digest of `commitment`.
    /// If it has not computed yet, `digest` set `None`.
    pub(crate) digest: Option<GA::Scalar>,
}

impl<K, V, W, GA> TrieNode<K, V, W, GA>
where
    K: AbstractKey,
    V: AbstractValue,
    W: ArrayLength<Option<TrieNode<K, V, W, GA>>>,
    GA: CurveAffine,
    GA::Base: PrimeField,
{
    pub fn get_key(&self) -> &K::Stem {
        match self {
            // Self::Empty { key, .. } => key,
            Self::Suffix { key, .. } => key,
            Self::Internal { key, .. } => key,
        }
    }

    pub fn get_info(&self) -> &NodeInfo<GA> {
        match self {
            // Self::Empty { info, .. } => info,
            Self::Suffix { info, .. } => info,
            Self::Internal { info, .. } => info,
        }
    }

    pub fn get_key_fragments(&self) -> &K::Path {
        match self {
            // Self::Empty { key_fragments, .. } => key_fragments,
            Self::Suffix { key_fragments, .. } => key_fragments,
            Self::Internal { key_fragments, .. } => key_fragments,
        }
    }

    pub fn get_digest(&self) -> Option<GA::Scalar> {
        self.get_info().digest
    }
}

impl<U, K, V, W, GA> TrieNode<K, V, W, GA>
where
    U: PartialEq + Debug,
    K: AbstractKey<Stem = Vec<U>, Path = Vec<U>>,
    V: AbstractValue,
    W: ArrayLength<Option<TrieNode<K, V, W, GA>>>,
    GA: CurveAffine,
    <GA as CurveAffine>::Base: PrimeField,
{
    pub fn assert_valid_key(&self) {
        let key_fragments = &self.get_key_fragments()[..];
        let stem = self.get_key();
        let depth = stem.len();
        println!("depth: {:?}", depth);
        println!("key_fragments.len(): {:?}", key_fragments.len());
        assert_eq!(key_fragments, &stem[(depth - key_fragments.len())..]);
    }
}

impl<K, V, W, GA> TrieNode<K, V, W, GA>
where
    K: AbstractKey<Stem = Vec<u8>, Path = Vec<u8>>,
    V: AbstractValue,
    W: ArrayLength<Option<TrieNode<K, V, W, GA>>>,
    GA: CurveAffine,
    GA::Base: PrimeField,
{
    pub fn new_leaf_node(key: K, key_fragments: K::Path) -> Self {
        let node = Self::Suffix {
            key_fragments,
            key: key.into_stem(),
            leaves: Box::new(vec![None; W::to_usize()]),
            s_commitments: None,
            info: NodeInfo {
                num_nonempty_children: 0,
                commitment: None,
                digest: None,
            },
        };

        node.assert_valid_key();

        node
    }

    pub fn new_root_node() -> Self {
        let children = Box::new(GenericArray::default());

        Self::Internal {
            key_fragments: vec![],
            key: vec![],
            children,
            info: NodeInfo {
                num_nonempty_children: 0,
                commitment: None,
                digest: None,
            },
        }
    }
}

impl<K, V, W, GA> TrieNode<K, V, W, GA>
where
    K: AbstractKey<Stem = Vec<u8>, Path = Vec<u8>>,
    V: AbstractValue,
    W: ArrayLength<Option<TrieNode<K, V, W, GA>>>,
    GA: CurveAffine,
    <GA as CurveAffine>::Base: PrimeField,
{
    pub fn insert(&mut self, encoded_key: K::Path, key: K, value: V) -> anyhow::Result<()> {
        match self {
            // Self::Empty { .. } => {
            //     todo!();
            // }
            Self::Suffix {
                key_fragments,
                leaves,
                info: NodeInfo {
                    commitment, digest, ..
                },
                ..
            } => {
                // Sanity check: ensure the key header is the same:
                if !key_fragments.is_proper_prefix_of(&encoded_key) {
                    todo!();
                }

                let _ = commitment.take();
                let _ = digest.take();
                leaves[encoded_key.get_suffix()] = Some(value);
            }
            Self::Internal {
                key_fragments,
                children,
                info: NodeInfo {
                    commitment, digest, ..
                },
                ..
            } => {
                // Sanity check: ensure the key header is the same:
                if !key_fragments.is_proper_prefix_of(&encoded_key) {
                    anyhow::bail!("Should not split here.");
                }

                let _ = commitment.take();
                let _ = digest.take();
                if children[encoded_key.get_branch()].is_none() {
                    children[encoded_key.get_branch()] = Some(TrieNode::new_leaf_node(
                        key.clone(),
                        encoded_key[key_fragments.len()..(encoded_key.len() - 1)].to_vec(),
                    ));
                }

                match &mut children[encoded_key.get_branch()] {
                    Some(child) => {
                        child.insert(encoded_key[key_fragments.len()..].to_vec(), key, value)?;
                    }
                    None => {
                        panic!("unreachable code");
                    }
                }
            }
        }

        Ok(())
    }

    pub fn delete(&mut self, encoded_key: K::Path) -> anyhow::Result<()> {
        let key_fragments = self.get_key_fragments().clone();
        match self {
            // Self::Empty { .. } => {
            //     anyhow::bail!("Cannot remove an entry from `EmptyNode`");
            // }
            Self::Suffix {
                key: node_key,
                leaves,
                info: NodeInfo {
                    commitment, digest, ..
                },
                ..
            } => {
                // Sanity check: ensure the key header is the same:
                if !key_fragments.is_proper_prefix_of(&encoded_key) {
                    anyhow::bail!(
                        "Delete non-existent key. key: {:?}, {:?}",
                        node_key,
                        encoded_key
                    );
                }

                leaves[encoded_key.get_suffix()] = None;
                let _ = commitment.take();
                let _ = digest.take();
            }
            Self::Internal {
                key: node_key,
                key_fragments,
                children,
                info: NodeInfo {
                    commitment, digest, ..
                },
                ..
            } => {
                // Sanity check: ensure the key header is the same:
                if !key_fragments.is_proper_prefix_of(&encoded_key) {
                    anyhow::bail!(
                        "Delete non-existent key. key: {:?}, {:?}",
                        node_key,
                        encoded_key
                    );
                }

                let _ = commitment.take();
                let _ = digest.take();

                match &mut children[encoded_key.get_branch()] {
                    Some(child) => {
                        child.delete(encoded_key[key_fragments.len()..].to_vec())?;
                    }
                    None => {
                        anyhow::bail!(
                            "Delete non-existent key. key: {:?}, {:?}",
                            node_key,
                            encoded_key
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Get a value from this tree.
    pub fn get(&self, encoded_key: K::Path) -> anyhow::Result<Option<V>> {
        match &self {
            // Self::Empty { .. } => {
            //     anyhow::bail!("unreachable code");
            // }
            Self::Suffix {
                leaves,
                key_fragments,
                ..
            } => {
                // Sanity check: ensure the key header is the same:
                if key_fragments.is_proper_prefix_of(&encoded_key) {
                    // let mut suffix = encoded_key.get_suffix();
                    // let mut tmp = key_fragments.clone();
                    // tmp.append(&mut suffix);
                    // if cfg!(debug_assertions) {
                    //     println!("encoded_key: {:?}", encoded_key);
                    //     println!("key_fragments + suffix: {:?}", tmp);
                    // }
                    // if equal_paths(&encoded_key, &tmp) {
                    return Ok(leaves[encoded_key.get_suffix()]); // TODO: Is this correct?
                                                                 // } else {
                                                                 //     panic!(
                                                                 //         "There is an error in the key_fragments of the node whose key is {:?}.",
                                                                 //         encoded_key
                                                                 //     );
                                                                 // }
                } else {
                    todo!();
                }
            }
            Self::Internal {
                key: node_key,
                key_fragments,
                children,
                ..
            } => {
                // Sanity check: ensure the key header is the same:
                if !key_fragments.is_proper_prefix_of(&encoded_key) {
                    anyhow::bail!(
                        "Fetch non-existent key. key: {:?}, {:?}",
                        node_key,
                        encoded_key
                    );
                }

                let result = match &children[encoded_key.get_branch()] {
                    Some(child) => child.get(encoded_key[key_fragments.len()..].to_vec())?,
                    None => {
                        anyhow::bail!(
                            "Fetch non-existent key. key: {:?}, {:?}",
                            node_key,
                            encoded_key
                        );
                    }
                };

                Ok(result)
            }
        }
    }

    /// Returns witness of the existence or non-existence of
    /// an entry corresponding to the given key.
    /// If the entry exists, `witness` is the entry.
    /// If the entry does not exist,
    /// `witness` is an entry corresponding "the nearest" key to the given one.
    pub fn get_witness(&self, encoded_key: K::Path) -> anyhow::Result<(K::Path, V)> {
        match &self {
            // Self::Empty { .. } => {
            //     anyhow::bail!("unreachable code");
            // }
            Self::Suffix {
                leaves,
                key_fragments,
                ..
            } => {
                // Sanity check: ensure the key header is the same:
                if key_fragments.is_proper_prefix_of(&encoded_key) {
                    // let mut suffix = encoded_key.get_suffix();
                    // let mut tmp = key_fragments.clone();
                    // tmp.append(&mut suffix);
                    // if cfg!(debug_assertions) {
                    //     println!("encoded_key: {:?}", encoded_key);
                    //     println!("key_fragments + suffix: {:?}", tmp);
                    // }
                    // if equal_paths(&encoded_key, &tmp) {
                    if let Some(value) = leaves[encoded_key.get_suffix()] {
                        return Ok((encoded_key, value)); // TODO: Is this correct?
                    } else {
                        todo!();
                    }
                    // } else {
                    //     panic!(
                    //         "There is an error in the key_fragments of the node whose key is {:?}.",
                    //         encoded_key
                    //     );
                    // }
                } else {
                    todo!();
                }
            }
            Self::Internal { .. } => {
                todo!();
            }
        }
    }
}

fn compute_commitment_of_leaf<K, W, GA, C>(
    stem: &mut K::Stem,
    leaves: &mut Box<Vec<Option<[u8; 32]>>>,
    committer: &C,
) -> anyhow::Result<(Vec<GA>, GA, GA::Scalar)>
where
    K: AbstractKey<Stem = Vec<u8>, Path = Vec<u8>>,
    W: ArrayLength<Option<TrieNode<K, [u8; 32], W, GA>>>,
    GA: CurveAffine,
    GA::Base: PrimeField,
    C: Committer<GA>,
{
    let domain_size = W::to_usize();
    let value_size = 32;
    let limbs = 2;
    let limb_bits_size = value_size * 8 / limbs; // TODO: Is this correct? (If `domain_size` is 256, this is correct.)
    debug_assert!(limb_bits_size < GA::Scalar::NUM_BITS as usize);

    let poly_0 = GA::Scalar::from_repr(<GA::Scalar as PrimeField>::Repr::from(1u64))?;
    let poly_1 = read_field_element_le::<GA::Scalar>(stem)?;
    let mut poly = vec![poly_0, poly_1];

    let mut s_commitments = vec![];
    for limb in leaves.chunks(limb_bits_size) {
        let mut sub_poly = vec![GA::Scalar::zero(); domain_size];
        let count = fill_suffix_tree_poly(&mut sub_poly, &limb)?;
        let tmp_s_commitment = committer
            .commit_to_poly(&sub_poly, domain_size - count)
            .or_else(|_| anyhow::bail!("Fail to compute the commitment of the polynomial."))?;
        s_commitments.push(tmp_s_commitment);
        poly.push(point_to_field_element(&tmp_s_commitment)?);
    }

    poly.resize(domain_size, GA::Scalar::zero());

    let tmp_commitment = committer
        .commit_to_poly(&poly, domain_size - (2 + limbs))
        .or_else(|_| anyhow::bail!("Fail to compute the commitment of the polynomial."))?;
    let tmp_digest = point_to_field_element(&tmp_commitment)?;

    Ok((s_commitments, tmp_commitment, tmp_digest))
}

impl<K, W, GA> TrieNode<K, [u8; 32], W, GA>
where
    K: AbstractKey<Stem = Vec<u8>, Path = Vec<u8>>,
    W: ArrayLength<Option<TrieNode<K, [u8; 32], W, GA>>>,
    GA: CurveAffine,
    GA::Base: PrimeField,
{
    pub fn compute_commitment<C: Committer<GA>>(&mut self, committer: &C) -> anyhow::Result<GA> {
        if let Some(commitment) = self.get_info().commitment {
            return Ok(commitment);
        }

        match self {
            // Self::Empty {
            //     key,
            //     c1,
            //     c2,
            //     info: NodeInfo {
            //         commitment, digest, ..
            //     },
            //     ..
            // } => {
            //     let values = &mut Box::new([None; W::to_usize()]);
            //     let (tmp_c1, tmp_c2, tmp_commitment, tmp_digest) =
            //         compute_commitment_of_leaf::<K, _, _>(key, values, _committer)?;
            //     let _ = std::mem::replace(c1, Some(tmp_c1));
            //     let _ = std::mem::replace(c2, Some(tmp_c2));
            //     let _ = std::mem::replace(commitment, Some(tmp_commitment));
            //     let _ = std::mem::replace(digest, Some(tmp_digest));
            // }
            Self::Suffix {
                key,
                leaves,
                s_commitments,
                info: NodeInfo {
                    commitment, digest, ..
                },
                ..
            } => {
                let (tmp_s_commitments, tmp_commitment, tmp_digest) =
                    compute_commitment_of_leaf::<K, W, _, _>(key, leaves, committer)?;
                let _ = std::mem::replace(s_commitments, Some(tmp_s_commitments));
                let _ = std::mem::replace(commitment, Some(tmp_commitment));
                let _ = std::mem::replace(digest, Some(tmp_digest));

                return Ok(tmp_commitment);
            }
            Self::Internal {
                children,
                info: NodeInfo {
                    commitment, digest, ..
                },
                ..
            } => {
                let mut children_digests = vec![];
                for child in children.iter_mut() {
                    match child {
                        Some(x) => {
                            x.compute_commitment(committer)?;
                            let digest = x.get_digest();
                            children_digests.push(digest.unwrap());
                        }
                        None => {
                            children_digests.push(GA::Scalar::zero());
                        }
                    }
                }

                let tmp_commitment = committer
                    .commit_to_poly(&children_digests, 0)
                    .or_else(|_| anyhow::bail!("Fail to make a commitment of given polynomial."))?;
                let tmp_digest = point_to_field_element(&tmp_commitment)?;

                let _ = std::mem::replace(commitment, Some(tmp_commitment));
                let _ = std::mem::replace(digest, Some(tmp_digest));

                Ok(tmp_commitment)
            }
        }
    }

    pub fn get_commitments_along_path(
        &self,
        encoded_key: K::Path,
        key: K,
    ) -> anyhow::Result<ProofCommitment<GA>> {
        match self {
            // Self::Empty { .. } => {
            //     anyhow::bail!("unreachable code");
            // }
            Self::Suffix {
                key_fragments,
                leaves,
                s_commitments,
                info: NodeInfo { commitment, .. },
                ..
            } => {
                let domain_size = W::to_usize();
                let value_size = 32;
                let limbs = 2;
                let limb_bits_size = value_size * 8 / limbs;
                debug_assert!(limb_bits_size < GA::Scalar::NUM_BITS as usize);

                let stem = key.into_stem();

                let tmp_s_commitments = s_commitments
                    .clone()
                    .expect("Need to execute `compute commitment` in advance");
                let tmp_commitment = commitment
                    .clone()
                    .expect("Need to execute `compute commitment` in advance");

                let poly = {
                    let poly_0 =
                        GA::Scalar::from_repr(<GA::Scalar as PrimeField>::Repr::from(1u64))?;
                    let poly_1 = read_field_element_le(&stem)?;
                    let mut poly = vec![poly_0, poly_1];
                    for s_commitment in tmp_s_commitments.clone() {
                        poly.push(point_to_field_element(&s_commitment)?);
                    }
                    poly.resize(domain_size, GA::Scalar::zero());

                    poly
                };

                // Proof of absence: case of a differing stem.
                //
                // Return an unopened stem-level node.
                let depth = self.get_key().get_depth();
                if !key_fragments.is_proper_prefix_of(&encoded_key) {
                    return Ok(ProofCommitment {
                        commitment_elements: CommitmentElements {
                            commitments: vec![tmp_commitment, tmp_commitment],
                            elements: Elements {
                                zs: vec![0, 1],
                                ys: vec![poly[0], poly[1]],
                                fs: vec![poly.clone(), poly],
                            },
                        },
                        ext_status: ExtStatus::AbsentOther as usize | (depth << 3),
                        alt: stem.to_vec(),
                    });
                }

                let slot = key.encode().get_suffix();
                debug_assert!(slot < domain_size);

                let limb_index = slot / limb_bits_size;
                let suffix_slot = 2 + limb_index;
                let mut s_poly = vec![GA::Scalar::zero(); domain_size];
                let start_index = limb_index * limb_bits_size;
                let count = fill_suffix_tree_poly(
                    &mut s_poly,
                    &leaves[start_index..(start_index + limb_bits_size)],
                )?;

                // Proof of absence: case of a missing suffix tree.
                //
                // The suffix tree for this value is missing, i.e. all
                // leaves in the extension-and-suffix tree are grouped
                // in the other suffix tree (e.g. C2 if we are looking
                // at C1).
                if count == 0 {
                    // TODO: maintain a count variable at LeafNode level
                    // so that we know not to build the polynomials in this case,
                    // as all the information is available before fillSuffixTreePoly
                    // has to be called, save the count.
                    debug_assert_eq!(poly[suffix_slot], GA::Scalar::zero()); // poly[suffix_slot] = None
                    return Ok(ProofCommitment {
                        commitment_elements: CommitmentElements {
                            commitments: vec![tmp_commitment, tmp_commitment, tmp_commitment],
                            elements: Elements {
                                zs: vec![0usize, 1, suffix_slot],
                                ys: vec![poly[0], poly[1], GA::Scalar::zero()],
                                fs: vec![poly.clone(), poly.clone(), poly],
                            },
                        },
                        ext_status: ExtStatus::AbsentEmpty as usize | (depth << 3),
                        alt: vec![], // None
                    });
                }

                let tmp_s_commitment = tmp_s_commitments[limb_index];

                // Proof of absence: case of a missing value.
                //
                // Suffix tree is present as a child of the extension,
                // but does not contain the requested suffix. This can
                // only happen when the leaf has never been written to
                // since after deletion the value would be set to zero
                // but still contain the leaf marker 2^128.
                if leaves[slot].is_none() {
                    debug_assert_eq!(s_poly[slot], GA::Scalar::zero()); // s_poly[slot] = None
                    return Ok(ProofCommitment {
                        commitment_elements: CommitmentElements {
                            commitments: vec![
                                tmp_commitment,
                                tmp_commitment,
                                tmp_commitment,
                                tmp_s_commitment,
                            ],
                            elements: Elements {
                                zs: vec![0usize, 1, suffix_slot, slot],
                                ys: vec![poly[0], poly[1], poly[suffix_slot], GA::Scalar::zero()],
                                fs: vec![poly.clone(), poly.clone(), poly, s_poly],
                            },
                        },
                        ext_status: ExtStatus::Present as usize | (depth << 3), // present, since the stem is present
                        alt: vec![],                                            // None
                    });
                }

                let mut tmp_leaves = vec![GA::Scalar::zero(); 2];
                leaf_to_commitments(&mut tmp_leaves, leaves[slot].unwrap())?;
                // s_poly[2 * slot] = tmp_leaves[0]
                // s_poly[2 * slot + 1] = tmp_leaves[1]

                Ok(ProofCommitment {
                    commitment_elements: CommitmentElements {
                        commitments: vec![
                            tmp_commitment,
                            tmp_commitment,
                            tmp_commitment,
                            tmp_s_commitment,
                            tmp_s_commitment,
                        ],
                        elements: Elements {
                            zs: vec![0usize, 1, suffix_slot, 2 * slot, 2 * slot + 1],
                            ys: vec![
                                poly[0],
                                poly[1],
                                poly[suffix_slot],
                                tmp_leaves[0],
                                tmp_leaves[1],
                            ],
                            fs: vec![poly.clone(), poly.clone(), poly, s_poly.clone(), s_poly],
                        },
                    },
                    ext_status: ExtStatus::Present as usize | (depth << 3),
                    alt: vec![], // None
                })
            }
            Self::Internal {
                key_fragments,
                children,
                ..
            } => {
                // Sanity check: ensure the key header is the same:
                if !key_fragments.is_proper_prefix_of(&encoded_key) {
                    anyhow::bail!("Fetch non-existent key. key: {:?}", key);
                }

                let result = match &children[encoded_key.get_branch()] {
                    Some(child) => child.get_commitments_along_path(
                        encoded_key[key_fragments.len()..].to_vec(),
                        key,
                    )?,
                    None => {
                        anyhow::bail!("Fetch non-existent key. key: {:?}", key);
                    }
                };

                Ok(result)
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct VerkleTree<W, GA>
where
    W: ArrayLength<Option<TrieNode<[u8; 32], [u8; 32], W, GA>>>,
    GA: CurveAffine,
    GA::Base: PrimeField,
{
    pub root: TrieNode<[u8; 32], [u8; 32], W, GA>,
    pub(crate) committer: IpaConfig<GA::Projective>,
}

impl<W, GA> Default for VerkleTree<W, GA>
where
    W: ArrayLength<Option<TrieNode<[u8; 32], [u8; 32], W, GA>>>,
    GA: CurveAffine,
    GA::Base: PrimeField,
{
    fn default() -> Self {
        let domain_size = W::to_usize();
        Self {
            root: TrieNode::new_root_node(),
            committer: IpaConfig::new(domain_size),
        }
    }
}

impl<W, GA> VerkleTree<W, GA>
where
    W: ArrayLength<Option<TrieNode<[u8; 32], [u8; 32], W, GA>>>,
    GA: CurveAffine,
    GA::Base: PrimeField,
{
    pub fn insert(&mut self, key: [u8; 32], value: [u8; 32]) -> anyhow::Result<()> {
        self.root.insert(key.encode(), key, value)
    }

    pub fn delete(&mut self, key: [u8; 32]) -> anyhow::Result<()> {
        let encoded_key = key.encode();

        self.root.delete(encoded_key)
    }

    pub fn get(&self, key: [u8; 32]) -> anyhow::Result<Option<[u8; 32]>> {
        let encoded_key = key.encode();

        self.root.get(encoded_key)
    }

    pub fn compute_commitment(&mut self) -> anyhow::Result<GA> {
        self.root.compute_commitment(&self.committer)
    }

    pub fn get_commitments_along_path(&self, key: [u8; 32]) -> anyhow::Result<ProofCommitment<GA>> {
        self.root.get_commitments_along_path(key.encode(), key)
    }
}

pub fn get_commitments_for_multi_proof<W, GA>(
    tree: &VerkleTree<W, GA>,
    keys: &[[u8; 32]],
) -> anyhow::Result<MultiProofCommitment<GA>>
where
    W: ArrayLength<Option<TrieNode<[u8; 32], [u8; 32], W, GA>>>,
    GA: CurveAffine,
    GA::Base: PrimeField,
{
    let mut c = CommitmentElements::default();
    let mut ext_statuses = vec![];
    let mut poa_stems = vec![];

    for key in keys {
        let ProofCommitment {
            mut commitment_elements,
            ext_status,
            alt,
        } = tree.get_commitments_along_path(*key)?;
        c.merge(&mut commitment_elements);
        ext_statuses.push(ext_status);
        if !alt.is_empty() {
            poa_stems.push(alt);
        }
    }

    Ok(MultiProofCommitment {
        commitment_elements: c,
        ext_status: ext_statuses,
        alt: poa_stems,
    })
}
