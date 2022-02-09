use core::fmt::Debug;
use franklin_crypto::bellman::{CurveAffine, Field, PrimeField};

use crate::ipa_fr::{config::IpaConfig, utils::read_field_element_le};

use super::{
    proof::{CommitmentElements, Elements, MultiProofCommitment, ProofCommitment},
    utils::{equal_paths, fill_suffix_tree_poly, leaf_to_commitments, point_to_field_element},
};

pub enum ExtStatus {
    ExtStatusAbsentOther,
    ExtStatusAbsentEmpty,
    ExtStatusPresent,
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

impl AbstractKey for [u8; 32] {
    type Stem = Vec<u8>;
    type Path = Vec<u8>;

    fn into_stem(self) -> Vec<u8> {
        self[..31].to_vec()
    }

    fn encode(&self) -> Vec<u8> {
        self.to_vec()
    }
}

pub trait AbstractValue: Clone + Copy + Debug + PartialEq + Eq {}

impl AbstractValue for [u8; 32] {}

pub trait AbstractRelativePath: IntoIterator {
    type Suffix: AbstractSuffix;

    fn get_branch(&self) -> usize;

    fn get_suffix(&self) -> Self::Suffix;

    /// Returns if `self` is a proper prefix of `full_path`.
    ///
    /// If `self` is non-empty, this function returns `true`.
    ///
    /// If `self` is equal to `full_path`, this function returns `false`.
    fn is_proper_prefix_of(&self, full_path: &Self) -> bool;
}

impl AbstractRelativePath for Vec<u8> {
    type Suffix = Self;

    fn get_branch(&self) -> usize {
        self[0] as usize
    }

    fn get_suffix(&self) -> Self {
        self[31..].to_vec()
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

pub trait AbstractSuffix {
    fn to_usize(&self) -> usize;
}

impl AbstractSuffix for Vec<u8> {
    fn to_usize(&self) -> usize {
        assert!(self.len() <= 8);
        let mut tmp = self.clone();
        tmp.resize(8, 0u8);
        let index_bytes: [u8; 8] = tmp.try_into().unwrap();

        usize::from_le_bytes(index_bytes)
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
pub enum TrieNode<K, V, GA>
where
    K: AbstractKey,
    V: AbstractValue,
    GA: CurveAffine,
{
    Empty {
        key_fragments: K::Path,
        key: K::Stem,
        c1: Option<GA>,
        c2: Option<GA>,
        info: NodeInfo<GA>,
    },
    Suffix {
        key_fragments: K::Path,
        key: K::Stem,
        values: Box<[Option<V>; 256]>,
        c1: Option<GA>,
        c2: Option<GA>,
        info: NodeInfo<GA>,
    },
    Internal {
        key_fragments: K::Path,
        key: K::Stem,
        children: Box<[Option<TrieNode<K, V, GA>>; 256]>,
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

impl<K, V, GA> TrieNode<K, V, GA>
where
    K: AbstractKey<Stem = Vec<u8>, Path = Vec<u8>>,
    V: AbstractValue,
    GA: CurveAffine,
    <GA as CurveAffine>::Base: PrimeField,
{
    pub fn assert_valid_key_fragments(&self) {
        let width = 256usize;
        let key_fragments = self.get_key_fragments();
        // assert_eq!(key_fragments.len(), 1); // TODO: if InternalNode
        for key_fragment in key_fragments.iter() {
            assert!(width > *key_fragment as usize);
        }
    }

    pub fn assert_valid_entry_key(&self) {
        let key_fragments = &self.get_key_fragments()[..];
        let fragments = self.get_key();
        let depth = fragments.len();
        let fragments_suffix = &fragments[(depth - key_fragments.len())..];
        assert_eq!(fragments_suffix, key_fragments);
    }
}

impl<K, V, GA> TrieNode<K, V, GA>
where
    K: AbstractKey<Stem = Vec<u8>, Path = Vec<u8>>,
    V: AbstractValue,
    GA: CurveAffine,
    GA::Base: PrimeField,
{
    pub fn new_leaf_node(key: K::Stem, key_fragments: K::Path) -> Self {
        Self::Suffix {
            key_fragments,
            key,
            values: Box::new([None; 256]),
            c1: None,
            c2: None,
            info: NodeInfo {
                num_nonempty_children: 0,
                commitment: None,
                digest: None,
            },
        }
    }

    pub fn new_root_node() -> Self {
        let mut children = vec![];
        for _ in 0..256 {
            children.push(None);
        }

        let children = Box::new(children.try_into().unwrap());

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

    pub fn insert(&mut self, encoded_key: K::Path, key: K::Stem, value: V) -> anyhow::Result<()> {
        match self {
            Self::Empty { .. } => {
                todo!();
            }
            Self::Suffix {
                key_fragments,
                values,
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
                values[encoded_key.get_suffix().to_usize()] = Some(value);
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
                    let key_fragments = encoded_key[key_fragments.len()..].to_vec();
                    children[encoded_key.get_branch()] =
                        Some(TrieNode::new_leaf_node(key.clone(), key_fragments));
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
            Self::Empty { .. } => {
                anyhow::bail!("Cannot remove an entry from `EmptyNode`");
            }
            Self::Suffix {
                values,
                info: NodeInfo {
                    commitment, digest, ..
                },
                ..
            } => {
                assert_eq!(encoded_key.len(), 1);

                // Sanity check: ensure the key header is the same:
                if !equal_paths(&encoded_key, &key_fragments) {
                    anyhow::bail!("Delete non-existent key.");
                }

                values[encoded_key.get_suffix().to_usize()] = None;
                let _ = commitment.take();
                let _ = digest.take();
            }
            Self::Internal { .. } => {
                todo!();
            }
        }

        Ok(())
    }

    /// Get a value from this tree.
    pub fn get(&self, encoded_key: K::Path) -> anyhow::Result<Option<V>> {
        match &self {
            Self::Empty { .. } => {
                anyhow::bail!("unreachable code");
            }
            Self::Suffix {
                values,
                key_fragments,
                ..
            } => {
                assert_eq!(encoded_key.len(), 1);

                // Sanity check: ensure the key header is the same:
                if !equal_paths(&encoded_key, key_fragments) {
                    Ok(None)
                } else {
                    Ok(values[encoded_key.get_suffix().to_usize()])
                }
            }
            Self::Internal { .. } => {
                anyhow::bail!("unreachable code");
            }
        }
    }

    /// Returns witness of the existence or non-existence of
    /// an entry corresponding to the given key.
    /// If the entry exists, `witness` is the entry.
    /// If the entry does not exist,
    /// `witness` is an entry corresponding "the nearest" key to the given one.
    pub fn get_witness(&self, _encoded_key: K::Path) -> anyhow::Result<(K::Path, V)> {
        todo!();
    }
}

impl<K, V, GA> TrieNode<K, V, GA>
where
    K: AbstractKey<Stem = Vec<u8>, Path = Vec<u8>>,
    V: AbstractValue,
    GA: CurveAffine,
    GA::Base: PrimeField,
{
    pub fn get_key(&self) -> &K::Stem {
        match self {
            Self::Empty { key, .. } => key,
            Self::Suffix { key, .. } => key,
            Self::Internal { key, .. } => key,
        }
    }

    pub fn get_info(&self) -> &NodeInfo<GA> {
        match self {
            Self::Empty { info, .. } => info,
            Self::Suffix { info, .. } => info,
            Self::Internal { info, .. } => info,
        }
    }

    pub fn get_key_fragments(&self) -> &K::Path {
        match self {
            Self::Empty { key_fragments, .. } => key_fragments,
            Self::Suffix { key_fragments, .. } => key_fragments,
            Self::Internal { key_fragments, .. } => key_fragments,
        }
    }

    pub fn get_digest(&self) -> Option<GA::Scalar> {
        self.get_info().digest
    }
}

fn compute_commitment_of_leaf<K, GA, C>(
    key: &mut K::Stem,
    values: &mut Box<[Option<[u8; 32]>; 256]>,
    committer: &C,
) -> anyhow::Result<(GA, GA, GA, GA::Scalar)>
where
    K: AbstractKey<Stem = Vec<u8>, Path = Vec<u8>>,
    GA: CurveAffine,
    GA::Base: PrimeField,
    C: Committer<GA>,
{
    let mut poly = [GA::Scalar::zero(); 256];
    let mut c1_poly = [GA::Scalar::zero(); 256];
    let mut c2_poly = [GA::Scalar::zero(); 256];
    poly[0] = read_field_element_le::<GA::Scalar>(&[1])?;
    poly[1] = read_field_element_le::<GA::Scalar>(key)?;

    let count = fill_suffix_tree_poly(&mut c1_poly, &values[..128])?;
    let tmp_c1 = committer
        .commit_to_poly(&c1_poly, 256 - count)
        .or_else(|_| anyhow::bail!("Fail to compute the commitment of the polynomial."))?;
    poly[2] = point_to_field_element(&tmp_c1)?;
    let count = fill_suffix_tree_poly(&mut c2_poly, &values[128..])?;
    let tmp_c2 = committer
        .commit_to_poly(&c2_poly, 256 - count)
        .or_else(|_| anyhow::bail!("Fail to compute the commitment of the polynomial."))?;

    poly[3] = point_to_field_element(&tmp_c2)?;

    let tmp_commitment = committer
        .commit_to_poly(&poly, 252)
        .or_else(|_| anyhow::bail!("Fail to compute the commitment of the polynomial."))?;
    let tmp_digest = point_to_field_element(&tmp_commitment)?;

    Ok((tmp_c1, tmp_c2, tmp_commitment, tmp_digest))
}

impl<K, GA> TrieNode<K, [u8; 32], GA>
where
    K: AbstractKey<Stem = Vec<u8>, Path = Vec<u8>>,
    GA: CurveAffine,
    GA::Base: PrimeField,
{
    pub fn compute_commitment<C: Committer<GA>>(&mut self, _committer: &C) -> anyhow::Result<GA> {
        if let Some(commitment) = self.get_info().commitment {
            return Ok(commitment);
        }

        match self {
            Self::Empty {
                key,
                c1,
                c2,
                info: NodeInfo {
                    commitment, digest, ..
                },
                ..
            } => {
                let values = &mut Box::new([None; 256]);
                let (tmp_c1, tmp_c2, tmp_commitment, tmp_digest) =
                    compute_commitment_of_leaf::<K, _, _>(key, values, _committer)?;
                let _ = std::mem::replace(c1, Some(tmp_c1));
                let _ = std::mem::replace(c2, Some(tmp_c2));
                let _ = std::mem::replace(commitment, Some(tmp_commitment));
                let _ = std::mem::replace(digest, Some(tmp_digest));
            }
            Self::Suffix {
                key,
                values,
                c1,
                c2,
                info: NodeInfo {
                    commitment, digest, ..
                },
                ..
            } => {
                let (tmp_c1, tmp_c2, tmp_commitment, tmp_digest) =
                    compute_commitment_of_leaf::<K, _, _>(key, values, _committer)?;
                let _ = std::mem::replace(c1, Some(tmp_c1));
                let _ = std::mem::replace(c2, Some(tmp_c2));
                let _ = std::mem::replace(commitment, Some(tmp_commitment));
                let _ = std::mem::replace(digest, Some(tmp_digest));
            }
            Self::Internal { children, .. } => {
                for child in children.iter_mut() {
                    match child {
                        Some(x) => {
                            x.compute_commitment(_committer)?;
                        }
                        None => {}
                    }
                }
            }
        }

        if let Some(commitment) = self.get_info().commitment {
            Ok(commitment)
        } else {
            panic!("unreachable code");
        }
    }

    pub fn get_commitments_along_path(&self, key: K) -> anyhow::Result<ProofCommitment<GA>> {
        let encoded_key = key.encode();
        match self {
            Self::Empty { .. } => {
                anyhow::bail!("unreachable code");
            }
            Self::Suffix {
                key_fragments,
                values,
                c1,
                c2,
                info: NodeInfo { commitment, .. },
                ..
            } => {
                let stem = key.into_stem();

                // Proof of absence: case of a differing stem.
                //
                // Return an unopened stem-level node.
                if !equal_paths(&encoded_key, key_fragments) {
                    let mut poly = vec![GA::Scalar::zero(); 256];
                    poly[0] = GA::Scalar::from_repr(<GA::Scalar as PrimeField>::Repr::from(1u64))?;
                    poly[1] = read_field_element_le(&stem)?;
                    poly[2] = point_to_field_element(&c1.unwrap())?;
                    poly[3] = point_to_field_element(&c2.unwrap())?;

                    let depth = self.get_key().get_depth();
                    return Ok(ProofCommitment {
                        commitment_elements: CommitmentElements {
                            commitments: vec![commitment.unwrap(), commitment.unwrap()],
                            elements: Elements {
                                zs: vec![0usize, 1],
                                ys: vec![poly[0], poly[1]],
                                fs: vec![poly.clone(), poly],
                            },
                        },
                        ext_status: ExtStatus::ExtStatusAbsentOther as usize | (depth << 3),
                        alt: stem.to_vec(),
                    });
                }

                let slot = stem.to_usize();
                let suffix_slot = 2 + slot / 128;
                let mut poly = vec![GA::Scalar::zero(); 256];

                let count = if slot >= 128 {
                    fill_suffix_tree_poly(&mut poly, &values[128..])?
                } else {
                    fill_suffix_tree_poly(&mut poly, &values[..128])?
                };

                let mut ext_poly = vec![GA::Scalar::zero(); 256];
                ext_poly[0] = GA::Scalar::from_repr(<GA::Scalar as PrimeField>::Repr::from(1u64))?;
                ext_poly[1] = read_field_element_le(&stem)?;
                ext_poly[2] = point_to_field_element(&c1.unwrap())?;
                ext_poly[3] = point_to_field_element(&c2.unwrap())?;

                // Proof of absence: case of a missing suffix tree.
                //
                // The suffix tree for this value is missing, i.e. all
                // values in the extension-and-suffix tree are grouped
                // in the other suffix tree (e.g. C2 if we are looking
                // at C1).
                let depth = self.get_key().get_depth();
                if count == 0 {
                    // TODO: maintain a count variable at LeafNode level
                    // so that we know not to build the polynomials in this case,
                    // as all the information is available before fillSuffixTreePoly
                    // has to be called, save the count.
                    return Ok(ProofCommitment {
                        commitment_elements: CommitmentElements {
                            commitments: vec![
                                commitment.unwrap(),
                                commitment.unwrap(),
                                commitment.unwrap(),
                            ],
                            elements: Elements {
                                zs: vec![0usize, 1, suffix_slot],
                                ys: vec![ext_poly[0], ext_poly[1], GA::Scalar::zero()],
                                fs: vec![ext_poly.clone(), ext_poly.clone(), ext_poly],
                            },
                        },
                        ext_status: ExtStatus::ExtStatusAbsentEmpty as usize | (depth << 3),
                        alt: vec![], // None
                    });
                }

                let s_commitment = if slot < 128 { *c1 } else { *c2 };

                // Proof of absence: case of a missing value.
                //
                // Suffix tree is present as a child of the extension,
                // but does not contain the requested suffix. This can
                // only happen when the leaf has never been written to
                // since after deletion the value would be set to zero
                // but still contain the leaf marker 2^128.
                if values[slot].is_none() {
                    return Ok(ProofCommitment {
                        commitment_elements: CommitmentElements {
                            commitments: vec![
                                commitment.unwrap(),
                                commitment.unwrap(),
                                commitment.unwrap(),
                                s_commitment.unwrap(),
                            ],
                            elements: Elements {
                                zs: vec![0usize, 1, suffix_slot, slot],
                                ys: vec![
                                    ext_poly[0],
                                    ext_poly[1],
                                    ext_poly[2 + slot / 128],
                                    GA::Scalar::zero(),
                                ],
                                fs: vec![ext_poly.clone(), ext_poly.clone(), ext_poly, poly],
                            },
                        },
                        ext_status: ExtStatus::ExtStatusPresent as usize | (depth << 3), // present, since the stem is present
                        alt: vec![],                                                     // None
                    });
                }

                let mut leaves = vec![GA::Scalar::zero(); 2];
                leaf_to_commitments(&mut leaves, values[slot].unwrap())?;

                Ok(ProofCommitment {
                    commitment_elements: CommitmentElements {
                        commitments: vec![
                            commitment.unwrap(),
                            commitment.unwrap(),
                            commitment.unwrap(),
                            s_commitment.unwrap(),
                            s_commitment.unwrap(),
                        ],
                        elements: Elements {
                            zs: vec![0usize, 1, suffix_slot, 2 * slot, 2 * slot + 1],
                            ys: vec![
                                ext_poly[0],
                                ext_poly[1],
                                ext_poly[2 + slot / 128],
                                leaves[0],
                                leaves[1],
                            ],
                            fs: vec![
                                ext_poly.clone(),
                                ext_poly.clone(),
                                ext_poly,
                                poly.clone(),
                                poly,
                            ],
                        },
                    },
                    ext_status: ExtStatus::ExtStatusPresent as usize | (depth << 3),
                    alt: vec![], // None
                })
            }
            Self::Internal { .. } => {
                anyhow::bail!("unreachable code");
            }
        }
    }
}

pub struct VerkleTree<K, GA>
where
    K: AbstractKey<Stem = Vec<u8>, Path = Vec<u8>>,
    GA: CurveAffine,
    GA::Base: PrimeField,
{
    pub root: TrieNode<K, [u8; 32], GA>,
    pub committer: IpaConfig<GA::Projective>,
}

impl<K, GA> Default for VerkleTree<K, GA>
where
    K: AbstractKey<Stem = Vec<u8>, Path = Vec<u8>>,
    GA: CurveAffine,
    GA::Base: PrimeField,
{
    fn default() -> Self {
        Self {
            root: TrieNode::new_root_node(),
            committer: IpaConfig::new(256),
        }
    }
}

impl<K, GA> VerkleTree<K, GA>
where
    K: AbstractKey<Stem = Vec<u8>, Path = Vec<u8>>,
    GA: CurveAffine,
    GA::Base: PrimeField,
{
    pub fn compute_commitment(&mut self) -> anyhow::Result<GA> {
        self.root.compute_commitment(&self.committer)
    }

    pub fn get_commitments_along_path(&self, key: K) -> anyhow::Result<ProofCommitment<GA>> {
        self.root.get_commitments_along_path(key)
    }
}

pub fn get_commitments_for_multi_proof<K, GA>(
    tree: &VerkleTree<K, GA>,
    keys: &[K],
) -> anyhow::Result<MultiProofCommitment<GA>>
where
    K: AbstractKey<Stem = Vec<u8>, Path = Vec<u8>>,
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
