use core::fmt::Debug;
use franklin_crypto::bellman::{CurveAffine, Field, PrimeField};

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
    type Path: AbstractPath;

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
        self[31] as usize
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
        leaves: Box<[Option<V>; WIDTH]>,
        s_commitments: Option<Vec<GA>>, // Option<[GA; 2]>
        info: NodeInfo<GA>,
    },
    Internal {
        path: K::Path,
        children: Box<[Option<VerkleNode<K, V, GA>>; WIDTH]>,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry<K, V> {
    pub key: K,
    pub value: V,
}

impl<K, V, GA> VerkleNode<K, V, GA>
where
    K: AbstractKey,
    V: AbstractValue,
    GA: CurveAffine,
    GA::Base: PrimeField,
{
    pub fn get_info(&self) -> &NodeInfo<GA> {
        match self {
            Self::Leaf { info, .. } => info,
            Self::Internal { info, .. } => info,
        }
    }
}

impl<K, V, GA> VerkleNode<K, V, GA>
where
    K: AbstractKey<Path = TreePath>,
    K::Stem: AbstractStem<Path = TreePath> + IntoFieldElement<GA::Scalar>,
    V: AbstractValue,
    GA: CurveAffine,
    GA::Base: PrimeField,
{
    pub fn new_leaf_node(path: K::Path, entry: Entry<K, V>) -> Self {
        let Entry { key, value } = entry;
        let mut leaves = [None; WIDTH];
        leaves[key.get_suffix()] = Some(value);
        Self::Leaf {
            stem: key.get_stem(),
            path,
            leaves: Box::new(leaves),
            s_commitments: None,
            info: NodeInfo {
                num_nonempty_children: 1,
                commitment: None,
                digest: None,
            },
        }
    }

    pub fn new_root_node() -> Self {
        let mut children = vec![];
        for _ in 0..WIDTH {
            children.push(None);
        }

        let children = Box::new(children.try_into().unwrap()); // = [None; WIDTH]
        Self::Internal {
            path: K::Path::default(),
            children,
            info: NodeInfo {
                num_nonempty_children: 0,
                commitment: None,
                digest: None,
            },
        }
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
    pub fn insert(&mut self, encoded_key: K::Path, entry: Entry<K, V>) -> anyhow::Result<()> {
        let Entry { key, value } = entry;
        match self {
            Self::Leaf {
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
                if key.get_stem() == stem.clone() {
                    let _ = commitment.take();
                    let _ = digest.take();
                    let old_leaf =
                        std::mem::replace(&mut leaves[encoded_key.get_suffix()], Some(value));
                    if old_leaf.is_some() {
                        *num_nonempty_children += 1;
                    }

                    return Ok(());
                }

                // A new branch node has to be inserted. Depending
                // on the next branch in both keys, a recursion into
                // the moved leaf node can occur.
                let depth = path.len();
                let next_branch_of_existing_key =
                    TreePath::from(&stem.to_path()[depth..]).get_next_branch();
                let mut children = vec![];
                for i in 0..WIDTH {
                    if i == next_branch_of_existing_key {
                        let mut new_path = path.clone();
                        new_path.inner.push(next_branch_of_existing_key);
                        let moving_child = Self::Leaf {
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
                        children.push(Some(moving_child));
                    } else {
                        children.push(None);
                    }
                }

                let children = children.try_into().unwrap(); // = [None; WIDTH]
                let mut new_branch = Self::Internal {
                    path: path.clone(),
                    children: Box::new(children),
                    info: NodeInfo {
                        commitment: None,
                        digest: None,
                        num_nonempty_children: 1,
                    },
                };

                let next_branch_of_inserting_key = encoded_key.get_next_branch();
                if next_branch_of_inserting_key != next_branch_of_existing_key {
                    // Next branch differs, so this was the last level.
                    // Insert it directly into its suffix.
                    let mut leaves = Box::new([None; WIDTH]);
                    leaves[key.get_suffix()] = Some(value);
                    let mut new_path = path.clone();
                    new_path.inner.push(next_branch_of_inserting_key);
                    let leaf_node = Self::Leaf {
                        stem: stem.clone(),
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
                        Self::Internal {
                            children,
                            info:
                                NodeInfo {
                                    num_nonempty_children,
                                    ..
                                },
                            ..
                        } => {
                            let _ = std::mem::replace(
                                &mut children[next_branch_of_inserting_key],
                                Some(leaf_node),
                            );
                            *num_nonempty_children += 1;
                        }
                        Self::Leaf { .. } => {
                            panic!("unreachable code");
                        }
                    }
                    let _ = std::mem::replace(self, new_branch);

                    return Ok(());
                }

                let _ = std::mem::replace(self, new_branch);

                self.insert(TreePath::from(&encoded_key[1..]), entry)
            }
            Self::Internal {
                path,
                children,
                info: NodeInfo {
                    commitment, digest, ..
                },
                ..
            } => {
                let _ = commitment.take();
                let _ = digest.take();
                let next_branch = encoded_key.get_next_branch();
                if children[next_branch].is_none() {
                    let entry = Entry { key, value };
                    let mut new_path = path.clone();
                    new_path.inner.push(next_branch);
                    children[next_branch] = Some(VerkleNode::new_leaf_node(new_path, entry));
                }

                if let Some(child) = &mut children[next_branch] {
                    child.insert(TreePath::from(&encoded_key[1..]), entry)
                } else {
                    Ok(())
                }
            }
        }
    }

    pub fn remove(&mut self, encoded_key: K::Path, key: K) -> anyhow::Result<()> {
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
                let old_leaf = std::mem::replace(&mut leaves[key.get_suffix()], None);
                if old_leaf.is_none() {
                    anyhow::bail!("Delete non-existent key. key: {:?}", key);
                }

                let _ = commitment.take();
                let _ = digest.take();
                *num_nonempty_children -= 1;
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

                let next_branch = encoded_key.get_next_branch();
                match &mut children[next_branch] {
                    Some(child) => {
                        child.remove(TreePath::from(&encoded_key[1..]), key)?;

                        // Remove a empty node if any.
                        if child.get_info().num_nonempty_children == 0 {
                            let _ = children[next_branch].take();
                        }
                    }
                    None => {
                        anyhow::bail!("Delete non-existent stem. key: {:?}", key);
                    }
                }
            }
        }

        Ok(())
    }

    /// Get a value from this tree.
    pub fn get_value(&self, encoded_key: K::Path, key: K) -> anyhow::Result<Option<V>> {
        match &self {
            Self::Leaf { stem, leaves, .. } => {
                if key.get_stem() != stem.clone() {
                    Ok(None)
                } else {
                    Ok(leaves[key.get_suffix()])
                }
            }
            Self::Internal { children, .. } => match &children[encoded_key.get_next_branch()] {
                Some(child) => child.get_value(TreePath::from(&encoded_key[1..]), key),
                None => Ok(None),
            },
        }
    }

    /// Returns witness of the existence or non-existence of
    /// an entry corresponding to the given key.
    /// If the entry exists, `witness` is the entry.
    /// If the entry does not exist,
    /// `witness` is an entry corresponding "the nearest" key to the given one.
    fn _get_witness(&self, encoded_key: K::Path, key: K) -> anyhow::Result<(K::Path, V)> {
        match &self {
            Self::Leaf { stem, leaves, .. } => {
                if key.get_stem() != stem.clone() {
                    todo!();
                }

                match leaves[key.get_suffix()] {
                    Some(value) => Ok((key.to_path(), value)),
                    None => {
                        todo!()
                    }
                }
            }
            Self::Internal { children, .. } => match &children[encoded_key.get_next_branch()] {
                Some(child) => child._get_witness(TreePath::from(&encoded_key[1..]), key),
                None => {
                    todo!()
                }
            },
        }
    }
}

pub fn compute_commitment_of_leaf_node<K, GA, C>(
    committer: &C,
    stem: &mut K::Stem,
    leaves: &mut Box<[Option<[u8; 32]>; WIDTH]>,
) -> anyhow::Result<(Vec<GA>, GA)>
where
    K: AbstractKey,
    K::Stem: IntoFieldElement<GA::Scalar>,
    GA: CurveAffine,
    GA::Base: PrimeField,
    C: Committer<GA>,
{
    let width = WIDTH;
    let value_size = 32;
    let limbs = LIMBS;
    let limb_bits_size = value_size * 8 / limbs;
    debug_assert!(limb_bits_size < GA::Scalar::NUM_BITS as usize);

    let poly_0 = GA::Scalar::from_repr(<GA::Scalar as PrimeField>::Repr::from(1u64))?;
    let poly_1 = stem
        .clone()
        .into_field_element()
        .map_err(|_| anyhow::anyhow!("unreachable code"))?;
    let mut poly = vec![poly_0, poly_1];

    let mut s_commitments = vec![];
    for limb in leaves.chunks(limb_bits_size) {
        let mut sub_poly = vec![GA::Scalar::zero(); width];
        let _count = fill_leaf_tree_poly(&mut sub_poly, limb)?;
        let tmp_s_commitment = committer
            .commit(&sub_poly /* , width - count */)
            .or_else(|_| anyhow::bail!("Fail to compute the commitment of the polynomial."))?;
        s_commitments.push(tmp_s_commitment);
        poly.push(point_to_field_element(&tmp_s_commitment)?);
    }

    poly.resize(width, GA::Scalar::zero());

    let tmp_commitment = committer
        .commit(&poly /* , width - (2 + limbs) */)
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
                let mut children_digests = vec![];
                for child in children.iter_mut() {
                    match child {
                        Some(x) => {
                            x.compute_commitment(committer)?;
                            children_digests.push(x.get_info().digest.unwrap());
                        }
                        None => {
                            children_digests.push(GA::Scalar::zero());
                        }
                    }
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
        encoded_key: K::Path,
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
                let width = WIDTH;
                let value_size = 32;
                let limbs = LIMBS;
                let limb_bits_size = value_size * 8 / limbs;
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
                    poly.resize(width, zero);

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
                    debug_assert!(suffix < width);

                    let slot = (limbs * suffix) % width;

                    let limb_index = suffix / limb_bits_size;
                    let suffix_slot = 2 + limb_index;
                    let mut s_poly = vec![zero; width];
                    let start_index = limb_index * limb_bits_size;
                    let count = fill_leaf_tree_poly(
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

                    if leaves[suffix].is_none() {
                        // Proof of absence: case of a missing value.
                        //
                        // Leaf tree is present as a child of the extension,
                        // but does not contain the requested suffix. This can
                        // only happen when the leaf has never been written to
                        // since after deletion the value would be set to zero
                        // but still contain the leaf marker 2^128.
                        for i in 0..limbs {
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

                    let mut tmp_leaves: Vec<GA::Scalar> = vec![zero; limbs];
                    leaf_to_commitments(&mut tmp_leaves, leaves[suffix].unwrap())?;
                    for i in 0..limbs {
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
                for (i, child) in children.iter().enumerate() {
                    match child {
                        Some(c) => {
                            fi[i] = c.get_info().digest.unwrap();
                        }
                        None => {}
                    }
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
                    let child_idx = group[0].to_path()[depth];

                    // Special case of a proof of absence: no children
                    // commitment, as the value is 0.
                    if children[child_idx].is_none() {
                        multi_proof_commitments
                            .extra_data_list
                            .push(ExtraProofData {
                                ext_status: ExtStatus::AbsentEmpty as usize | (depth << 3),
                                poa_stems: K::Stem::default(),
                            });
                        continue;
                    }

                    match &children[child_idx] {
                        Some(child) => {
                            multi_proof_commitments.merge(&mut child.get_commitments_along_path(
                                TreePath::from(&encoded_key[1..]),
                                &group,
                            )?);
                        }
                        None => {}
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

pub trait AbstractMerkleTree {
    type Err: Send + Sync + 'static;
    type Key: AbstractKey;
    type Value: AbstractValue;
    type Commitment: PartialEq + Eq;
    type ProofCommitments: PartialEq + Eq;

    fn insert(&mut self, key: Self::Key, value: Self::Value) -> Result<(), Self::Err>;

    fn remove(&mut self, key: Self::Key) -> Result<(), Self::Err>;

    fn get_value(&self, key: Self::Key) -> Result<Option<Self::Value>, Self::Err>;

    fn compute_commitment(&mut self) -> Result<Self::Commitment, Self::Err>;

    fn get_commitments_along_path(
        &self,
        key: Self::Key,
    ) -> Result<Self::ProofCommitments, Self::Err>;
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

impl<GA> AbstractMerkleTree for VerkleTree<GA>
where
    GA: CurveAffine,
    GA::Base: PrimeField,
{
    type Err = anyhow::Error;
    type Key = [u8; 32];
    type Value = [u8; 32];
    type Commitment = GA;
    type ProofCommitments = MultiProofCommitments<Self::Key, GA>;

    fn insert(&mut self, key: Self::Key, value: Self::Value) -> anyhow::Result<()> {
        let entry = Entry { key, value };
        self.root.insert(key.to_path(), entry)
    }

    fn remove(&mut self, key: Self::Key) -> anyhow::Result<()> {
        self.root.remove(key.to_path(), key)
    }

    fn get_value(&self, key: Self::Key) -> anyhow::Result<Option<Self::Value>> {
        self.root.get_value(key.to_path(), key)
    }

    fn compute_commitment(&mut self) -> anyhow::Result<Self::Commitment> {
        self.root.compute_commitment(&self.committer)
    }

    fn get_commitments_along_path(&self, key: Self::Key) -> anyhow::Result<Self::ProofCommitments> {
        self.root.get_commitments_along_path(key.to_path(), &[key])
    }
}
