use core::fmt::Debug;
use franklin_crypto::bellman::{CurveAffine, Field, PrimeField};
use std::borrow::Borrow;
use std::collections::HashMap;

use crate::ipa_fr::config::{Committer, IpaConfig};
use crate::ipa_fr::utils::read_field_element_le;
use crate::verkle_tree::proof::ExtraProofData;

use super::path::TreePath;
use super::proof::{CommitmentElements, Elements, MultiProofCommitments};
use super::utils::{fill_leaf_tree_poly, leaf_to_commitments, point_to_field_element};

pub const WIDTH: usize = 256;
pub const LIMBS: usize = 2;

pub enum ExtStatus {
    AbsentEmpty, // path led to a node with a different stem
    AbsentOther, // missing child node along the path
    Present,     // stem was present
}

pub trait AbstractKey: Clone + Copy + Debug + PartialEq + Eq {
    type Stem: AbstractStem + Default;
    type Path: AbstractPath + Default;

    fn get_stem(&self) -> Self::Stem;

    fn get_suffix(&self) -> usize;

    fn to_path(&self) -> Self::Path;
}

// 32 bytes key
impl AbstractKey for [u8; 32] {
    type Stem = Option<[u8; 31]>;
    type Path = TreePath;

    fn get_stem(&self) -> Option<[u8; 31]> {
        let result: [u8; 31] = self[..31].to_vec().try_into().unwrap();

        Some(result)
    }

    fn get_suffix(&self) -> usize {
        usize::from(self[31])
    }

    fn to_path(&self) -> TreePath {
        TreePath::from(self.to_vec())
    }
}

pub trait AbstractValue: Clone + Copy + Debug + PartialEq + Eq {}

// 32 bytes value
impl AbstractValue for [u8; 32] {}

pub trait AbstractPath: Sized + Debug + PartialEq + Eq + IntoIterator {
    type RemovePrefixError: Send + Sync + 'static;

    fn get_next_branch(&self) -> usize;

    fn get_suffix(&self) -> usize;

    /// Returns if `self` is a proper prefix of `full_path`.
    ///
    /// If `self` is non-empty, this function returns `true`.
    ///
    /// If `self` is equal to `full_path`, this function returns `false`.
    fn is_proper_prefix_of(&self, full_path: &Self) -> bool;

    fn remove_prefix(&self, prefix: &Self) -> Result<Self, Self::RemovePrefixError>;
}

impl AbstractPath for TreePath {
    type RemovePrefixError = anyhow::Error;

    fn get_next_branch(&self) -> usize {
        let branch = self[0];
        assert!(branch < WIDTH);

        branch
    }

    fn get_suffix(&self) -> usize {
        let suffix = self[self.len() - 1];
        assert!(suffix < WIDTH);

        // let mut suffix_bytes = self[31..].to_vec();
        // assert!(suffix_bytes.len() <= 8);
        // suffix_bytes.resize(8, 0);

        // let suffix = usize::from_le_bytes(suffix_bytes.try_into().unwrap())

        suffix
    }

    fn is_proper_prefix_of(&self, full_path: &Self) -> bool {
        if self.is_empty() {
            return true;
        }

        if self.len() >= full_path.len() {
            return false;
        }

        let base_path = full_path[..self.len()].to_vec();

        self.inner == base_path
    }

    fn remove_prefix(&self, prefix: &Self) -> anyhow::Result<Self> {
        if !prefix.is_proper_prefix_of(self) {
            anyhow::bail!(
                "{:?} is not proper prefix of {:?}",
                prefix.inner,
                self.inner,
            );
        }

        let result = Self::from(&self[prefix.len()..]);

        Ok(result)
    }
}

pub trait AbstractStem: Clone + Debug + PartialEq + Eq {
    type Path: AbstractPath;

    fn to_path(&self) -> Self::Path;
}

impl AbstractStem for Option<[u8; 31]> {
    type Path = TreePath;

    fn to_path(&self) -> TreePath {
        let bytes = match self {
            Some(inner) => inner.to_vec(),
            None => vec![],
        };
        TreePath {
            inner: bytes.iter().map(|x| *x as usize).collect::<Vec<_>>(),
        }
    }
}

pub trait IntoFieldElement<F: PrimeField> {
    type Err: Send + Sync + 'static;

    fn into_field_element(self) -> Result<F, Self::Err>;
}

impl<F: PrimeField> IntoFieldElement<F> for Option<[u8; 31]> {
    type Err = anyhow::Error;

    fn into_field_element(self) -> anyhow::Result<F> {
        match self {
            Some(bytes) => read_field_element_le(&bytes),
            None => {
                anyhow::bail!("None is not converted into a field element.")
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum VerkleNode<K, V, GA>
where
    K: AbstractKey,
    V: AbstractValue,
    GA: CurveAffine,
{
    Leaf {
        path: K::Path,
        stem: K::Stem,
        leaves: HashMap<usize, V>,      // HashMap<u8, V>
        s_commitments: Option<Vec<GA>>, // Option<[GA; 2]>
        info: NodeInfo<GA>,
    },
    Internal {
        path: K::Path,
        children: HashMap<usize, VerkleNode<K, V, GA>>, // HashMap<u8, VerkleNode<K, V, GA>>
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

    /// The commitment of this node.
    /// If it has not computed yet, `commitment` set `None`.
    pub(crate) commitment: Option<GA>,

    /// The digest of `commitment`.
    /// If it has not computed yet, `digest` set `None`.
    pub(crate) digest: Option<GA::Scalar>,
}

impl<K, V, GA> VerkleNode<K, V, GA>
where
    K: AbstractKey,
    V: AbstractValue,
    GA: CurveAffine,
    GA::Base: PrimeField,
{
    pub fn new_leaf_node(path: K::Path, key: K, value: V) -> Self {
        let mut leaves = HashMap::new();
        leaves.insert(key.get_suffix(), value);
        Self::Leaf {
            stem: key.get_stem(),
            path,
            leaves,
            s_commitments: None,
            info: NodeInfo {
                num_nonempty_children: 1,
                commitment: None,
                digest: None,
            },
        }
    }

    pub fn new_root_node() -> Self {
        Self::Internal {
            path: K::Path::default(),
            children: HashMap::new(),
            info: NodeInfo {
                num_nonempty_children: 0,
                commitment: None,
                digest: None,
            },
        }
    }

    pub fn get_info(&self) -> &NodeInfo<GA> {
        match self {
            Self::Leaf { info, .. } => info,
            Self::Internal { info, .. } => info,
        }
    }

    pub fn get_path(&self) -> &K::Path {
        match self {
            Self::Leaf { path, .. } => path,
            Self::Internal { path, .. } => path,
        }
    }
}

impl<K, V, GA> Default for VerkleNode<K, V, GA>
where
    K: AbstractKey,
    V: AbstractValue,
    GA: CurveAffine,
    GA::Base: PrimeField,
{
    fn default() -> Self {
        Self::new_root_node()
    }
}

impl<K, V, GA> VerkleNode<K, V, GA>
where
    K: AbstractKey<Path = TreePath>,
    K::Stem: AbstractStem<Path = TreePath> + IntoFieldElement<GA::Scalar>,
    V: AbstractValue,
    GA: CurveAffine,
    <GA as CurveAffine>::Base: PrimeField,
{
    pub fn insert(&mut self, relative_path: K::Path, key: K, value: V) -> Option<V> {
        if relative_path.is_empty() {
            anyhow::anyhow!("`relative_path` must be non-empty.");
        }

        match self {
            VerkleNode::Leaf {
                stem,
                path,
                leaves,
                s_commitments,
                info:
                    NodeInfo {
                        commitment,
                        digest,
                        num_nonempty_children,
                    },
                ..
            } => {
                if key.get_stem() == stem.clone() || path.clone() == stem.to_path() {
                    let _ = commitment.take();
                    let _ = digest.take();
                    let old_leaf = leaves.insert(key.get_suffix(), value);
                    if old_leaf.is_some() {
                        *num_nonempty_children += 1;
                    }

                    return old_leaf;
                }

                // A new branch node has to be inserted. Depending
                // on the next branch in both keys, a recursion into
                // the moved leaf node can occur.
                let depth = path.len();
                let next_branch_of_existing_key =
                    TreePath::from(&stem.to_path()[depth..]).get_next_branch();
                let mut children = HashMap::new();
                let mut new_path = path.clone();
                new_path.inner.push(next_branch_of_existing_key);
                let moving_child = VerkleNode::Leaf {
                    stem: stem.clone(),
                    path: new_path,
                    leaves: leaves.clone(),
                    s_commitments: s_commitments.clone(),
                    info: NodeInfo {
                        commitment: *commitment,
                        digest: *digest,
                        num_nonempty_children: *num_nonempty_children,
                    },
                };
                children.insert(next_branch_of_existing_key, moving_child);

                let mut new_branch = VerkleNode::Internal {
                    path: path.clone(),
                    children,
                    info: NodeInfo {
                        commitment: None,
                        digest: None,
                        num_nonempty_children: 1,
                    },
                };

                let next_branch_of_inserting_key = relative_path.get_next_branch();
                if next_branch_of_inserting_key != next_branch_of_existing_key {
                    // Next branch differs, so this was the last level.
                    // Insert it directly into its suffix.
                    let mut leaves = HashMap::new();
                    leaves.insert(key.get_suffix(), value);
                    let mut new_path = path.clone();
                    new_path.inner.push(next_branch_of_inserting_key);
                    let leaf_node = VerkleNode::Leaf {
                        stem: key.get_stem(),
                        path: new_path,
                        leaves,
                        s_commitments: s_commitments.clone(),
                        info: NodeInfo {
                            commitment: *commitment,
                            digest: *digest,
                            num_nonempty_children: 1,
                        },
                    };

                    match &mut new_branch {
                        VerkleNode::Internal {
                            children,
                            info:
                                NodeInfo {
                                    num_nonempty_children,
                                    ..
                                },
                            ..
                        } => {
                            children.insert(next_branch_of_inserting_key, leaf_node);
                            *num_nonempty_children += 1;
                        }
                        VerkleNode::Leaf { .. } => {
                            panic!("unreachable code");
                        }
                    }
                    let _ = std::mem::replace(self, new_branch);

                    return None;
                }

                let _ = std::mem::replace(self, new_branch);

                self.insert(relative_path, key, value)
            }
            VerkleNode::Internal {
                path,
                children,
                info: NodeInfo {
                    commitment, digest, ..
                },
                ..
            } => {
                let _ = commitment.take();
                let _ = digest.take();

                let next_relative_path = TreePath::from(&relative_path[1..]);
                if next_relative_path.is_empty() {
                    anyhow::anyhow!("`relative_path` must be non-empty.");
                }

                let next_branch_of_inserting_key = relative_path.get_next_branch();
                if let Some(child) = children.get_mut(&next_branch_of_inserting_key) {
                    child.insert(next_relative_path, key, value)
                } else {
                    let mut new_path = path.clone();
                    new_path.inner.push(next_branch_of_inserting_key);
                    children.insert(
                        next_branch_of_inserting_key,
                        VerkleNode::new_leaf_node(new_path, key, value),
                    );

                    None
                }
            }
        }
    }

    pub fn remove(&mut self, relative_path: K::Path, key: &K) -> Option<V> {
        match self {
            Self::Leaf {
                leaves,
                info:
                    NodeInfo {
                        commitment,
                        digest,
                        num_nonempty_children,
                    },
                ..
            } => {
                let old_leaf = leaves.remove(&key.borrow().get_suffix());
                if old_leaf.is_some() {
                    let _ = commitment.take();
                    let _ = digest.take();
                    *num_nonempty_children -= 1;
                }

                old_leaf
            }
            Self::Internal {
                children,
                info: NodeInfo {
                    commitment, digest, ..
                },
                ..
            } => {
                let _ = commitment.take();
                let _ = digest.take();

                let next_branch = relative_path.get_next_branch();
                if let Some(child) = children.get_mut(&next_branch) {
                    let old_value = child.remove(TreePath::from(&relative_path[1..]), key);

                    // Remove a empty node if any.
                    if child.get_info().num_nonempty_children == 0 {
                        let _ = children.remove(&next_branch);
                    }

                    old_value
                } else {
                    None
                }
            }
        }
    }

    /// Get a value from this tree.
    pub fn get(&self, relative_path: K::Path, key: &K) -> Option<&V> {
        match &self {
            Self::Leaf { stem, leaves, .. } => {
                if key.get_stem() != stem.clone() {
                    None
                } else {
                    leaves.get(&key.get_suffix())
                }
            }
            Self::Internal { children, .. } => {
                if let Some(child) = children.get(&relative_path.get_next_branch()) {
                    child.get(TreePath::from(&relative_path[1..]), key)
                } else {
                    None
                }
            }
        }
    }

    /// Returns witness of the existence or non-existence of
    /// an entry corresponding to the given key.
    /// If the entry exists, `witness` is the entry.
    /// If the entry does not exist,
    /// `witness` is an entry corresponding "the nearest" key to the given one.
    pub fn get_witness(&self, relative_path: K::Path, key: K) -> anyhow::Result<(K::Path, V)> {
        match &self {
            Self::Leaf { stem, leaves, .. } => {
                if key.get_stem() != stem.clone() {
                    todo!();
                }

                match leaves.get(&key.get_suffix()) {
                    Some(&value) => Ok((key.to_path(), value)),
                    None => {
                        todo!()
                    }
                }
            }
            Self::Internal { children, .. } => {
                if let Some(child) = children.get(&relative_path.get_next_branch()) {
                    child.get_witness(TreePath::from(&relative_path[1..]), key)
                } else {
                    todo!()
                }
            }
        }
    }
}

pub fn compute_commitment_of_leaf_node<K, GA, C>(
    committer: &C,
    stem: &mut K::Stem,
    leaves: &mut HashMap<usize, [u8; 32]>,
) -> anyhow::Result<(Vec<GA>, GA)>
where
    K: AbstractKey,
    K::Stem: IntoFieldElement<GA::Scalar>,
    GA: CurveAffine,
    GA::Base: PrimeField,
    C: Committer<GA>,
{
    let value_size = 32;
    let limb_bits_size = value_size * 8 / LIMBS;
    debug_assert!(limb_bits_size < GA::Scalar::NUM_BITS as usize);

    let poly_0 = GA::Scalar::from_repr(<GA::Scalar as PrimeField>::Repr::from(1u64))?;
    let poly_1 = stem
        .clone()
        .into_field_element()
        .map_err(|_| anyhow::anyhow!("unreachable code"))?;
    let mut poly = vec![poly_0, poly_1];

    let mut leaves_array = [None; WIDTH];
    for (&i, &v) in leaves.iter() {
        leaves_array[i] = Some(v);
    }
    let mut s_commitments = vec![];
    for limb in leaves_array.chunks(limb_bits_size) {
        let mut sub_poly = [GA::Scalar::zero(); WIDTH];
        let _count = fill_leaf_tree_poly(&mut sub_poly, limb)?;
        let tmp_s_commitment = committer
            .commit(&sub_poly)
            .or_else(|_| anyhow::bail!("Fail to compute the commitment of the polynomial."))?;
        s_commitments.push(tmp_s_commitment);
        poly.push(point_to_field_element(&tmp_s_commitment)?);
    }

    poly.resize(WIDTH, GA::Scalar::zero());

    let tmp_commitment = committer
        .commit(&poly)
        .or_else(|_| anyhow::bail!("Fail to compute the commitment of the polynomial."))?;

    Ok((s_commitments, tmp_commitment))
}

pub fn compute_commitment_of_internal_node<GA: CurveAffine, C: Committer<GA>>(
    committer: &C,
    children_digests: Vec<GA::Scalar>,
) -> anyhow::Result<GA> {
    committer
        .commit(&children_digests)
        .or_else(|_| anyhow::bail!("Fail to make a commitment of given polynomial."))
}

impl<K, GA> VerkleNode<K, [u8; 32], GA>
where
    K: AbstractKey<Path = TreePath>,
    K::Stem: AbstractStem<Path = TreePath> + IntoFieldElement<GA::Scalar>,
    GA: CurveAffine,
    GA::Base: PrimeField,
{
    pub fn compute_commitment<C: Committer<GA>>(&mut self, committer: &C) -> anyhow::Result<GA> {
        if let Some(commitment) = self.get_info().commitment {
            return Ok(commitment);
        }

        match self {
            Self::Leaf {
                stem,
                leaves,
                s_commitments,
                info: NodeInfo {
                    commitment, digest, ..
                },
                ..
            } => {
                let (tmp_s_commitments, tmp_commitment) =
                    compute_commitment_of_leaf_node::<K, _, _>(committer, stem, leaves)?;
                let tmp_digest = point_to_field_element(&tmp_commitment)?;

                let _ = std::mem::replace(s_commitments, Some(tmp_s_commitments));
                let _ = std::mem::replace(commitment, Some(tmp_commitment));
                let _ = std::mem::replace(digest, Some(tmp_digest));

                Ok(tmp_commitment)
            }
            Self::Internal {
                children,
                info: NodeInfo {
                    commitment, digest, ..
                },
                ..
            } => {
                let mut children_digests = vec![GA::Scalar::zero(); WIDTH];
                for (&i, child) in children.iter_mut() {
                    child.compute_commitment(committer)?;
                    children_digests[i] = child.get_info().digest.unwrap();
                }

                let tmp_commitment =
                    compute_commitment_of_internal_node(committer, children_digests)?;
                let tmp_digest = point_to_field_element(&tmp_commitment)?;

                let _ = std::mem::replace(commitment, Some(tmp_commitment));
                let _ = std::mem::replace(digest, Some(tmp_digest));

                Ok(tmp_commitment)
            }
        }
    }

    pub fn get_commitments_along_path(
        &self,
        keys: &[K],
    ) -> anyhow::Result<MultiProofCommitments<K, GA>> {
        match self {
            Self::Leaf {
                path,
                stem,
                leaves,
                s_commitments,
                info: NodeInfo { commitment, .. },
                ..
            } => {
                let value_size = 32;
                let limb_bits_size = value_size * 8 / LIMBS;
                debug_assert!(limb_bits_size < GA::Scalar::NUM_BITS as usize);

                let tmp_s_commitments = s_commitments
                    .clone()
                    .expect("Need to execute `compute commitment` in advance");
                let tmp_commitment =
                    (*commitment).expect("Need to execute `compute commitment` in advance");

                let zero = GA::Scalar::zero();
                let poly = {
                    let poly_0 =
                        GA::Scalar::from_repr(<GA::Scalar as PrimeField>::Repr::from(1u64))?;
                    let poly_1 = stem
                        .clone()
                        .into_field_element()
                        .map_err(|_| anyhow::anyhow!("unreachable code"))?;
                    let mut poly = vec![poly_0, poly_1];
                    for s_commitment in tmp_s_commitments.clone() {
                        poly.push(point_to_field_element(&s_commitment)?);
                    }
                    poly.resize(WIDTH, zero);

                    poly
                };

                let mut multi_proof_commitments = MultiProofCommitments::default();
                for key in keys {
                    let depth = path.len();
                    if key.get_stem() != stem.clone() {
                        // Proof of absence: case of a differing stem.
                        //
                        // Return an unopened stem-level node.
                        multi_proof_commitments.merge(&mut MultiProofCommitments {
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
                    debug_assert!(suffix < WIDTH);

                    let slot = (LIMBS * suffix) % WIDTH;

                    let limb_index = suffix / limb_bits_size;
                    let suffix_slot = 2 + limb_index;
                    let mut s_poly = vec![zero; WIDTH];
                    let start_index = limb_index * limb_bits_size;
                    // let sub_leaves_array = leaves_array[start_index..(start_index + limb_bits_size)];
                    let mut sub_leaves_array = vec![None; limb_bits_size];
                    for (i, &v) in leaves.iter() {
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
                        multi_proof_commitments.merge(&mut MultiProofCommitments {
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

                    if leaves.get(&suffix).is_none() {
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
                        multi_proof_commitments.merge(&mut MultiProofCommitments {
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
                    leaf_to_commitments(&mut tmp_leaves, *leaves.get(&suffix).unwrap())?;
                    for i in 0..LIMBS {
                        debug_assert_eq!(s_poly[slot + i], tmp_leaves[i]);
                    }

                    multi_proof_commitments.merge(&mut MultiProofCommitments {
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
            Self::Internal {
                path,
                children,
                info: NodeInfo { commitment, .. },
                ..
            } => {
                let depth = path.len();
                let groups = group_keys(keys, depth);
                let mut multi_proof_commitments = MultiProofCommitments::default();

                // fill in the polynomial for this node
                let mut fi = vec![GA::Scalar::zero(); WIDTH];
                for (&i, child) in children.iter() {
                    fi[i] = child.get_info().digest.unwrap();
                }

                for group in groups.clone() {
                    let zi = group[0].to_path()[depth];

                    // Build the list of elements for this level
                    let yi = fi.clone()[zi];
                    multi_proof_commitments
                        .commitment_elements
                        .merge(&mut CommitmentElements {
                            commitments: vec![commitment.unwrap()],
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
                    let child = children.get(&group[0].to_path()[depth]);
                    if let Some(child) = child {
                        multi_proof_commitments
                            .merge(&mut child.get_commitments_along_path(&group)?);
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
}

// groupKeys groups a set of keys based on their byte at a given depth.
fn group_keys<K: AbstractKey<Path = TreePath>>(keys: &[K], depth: usize) -> Vec<Vec<K>> {
    // special case: only one key left
    if keys.len() == 1 {
        return vec![keys.to_vec()];
    }

    // there are at least two keys left in the list at this depth
    let mut groups = Vec::with_capacity(keys.len());
    let mut first_key = 0;
    for last_key in 1..keys.len() {
        let key = keys[last_key];
        let key_idx = key.to_path()[depth];
        let prev_idx = keys[last_key - 1].to_path()[depth];

        if key_idx != prev_idx {
            groups.push(keys[first_key..last_key].to_vec());
            first_key = last_key
        }
    }

    groups.push(keys[first_key..keys.len()].to_vec());

    groups
}

#[derive(Debug, PartialEq, Eq)]
pub struct VerkleTree<GA>
where
    GA: CurveAffine,
    GA::Base: PrimeField,
{
    pub root: VerkleNode<[u8; 32], [u8; 32], GA>,
    pub(crate) committer: IpaConfig<GA::Projective>,
}

impl<GA> Default for VerkleTree<GA>
where
    GA: CurveAffine,
    GA::Base: PrimeField,
{
    fn default() -> Self {
        Self {
            root: VerkleNode::new_root_node(),
            committer: IpaConfig::new(WIDTH),
        }
    }
}

impl<GA> VerkleTree<GA>
where
    GA: CurveAffine,
    GA::Base: PrimeField,
{
    pub fn insert(&mut self, key: [u8; 32], value: [u8; 32]) -> Option<[u8; 32]> {
        self.root.insert(key.to_path(), key, value)
    }

    pub fn remove(&mut self, key: &[u8; 32]) -> Option<[u8; 32]> {
        self.root.remove(key.to_path(), key)
    }

    pub fn get(&self, key: &[u8; 32]) -> Option<&[u8; 32]> {
        self.root.get(key.to_path(), key)
    }
}

// pub trait AbstractMerkleTree<K, V>
// where
//     K: AbstractKey,
//     V: AbstractValue,
// {
//     type Err: Send + Sync + 'static;
//     type Commitment: PartialEq + Eq;
//     type ProofCommitments: PartialEq + Eq;

//     fn compute_commitment(&mut self) -> Result<Self::Commitment, Self::Err>;

//     fn get_commitments_along_path(&self, keys: &[K]) -> Result<Self::ProofCommitments, Self::Err>;
// }

impl<GA> VerkleTree<GA>
where
    GA: CurveAffine,
    GA::Base: PrimeField,
{
    pub fn compute_commitment(&mut self) -> anyhow::Result<GA> {
        self.root.compute_commitment(&self.committer)
    }

    pub fn get_commitments_along_path(
        &self,
        keys: &[[u8; 32]],
    ) -> anyhow::Result<MultiProofCommitments<[u8; 32], GA>> {
        self.root.get_commitments_along_path(keys)
    }
}
