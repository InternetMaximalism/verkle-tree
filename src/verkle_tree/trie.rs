use core::fmt::Debug;
use franklin_crypto::bellman::{CurveAffine, Field, PrimeField};
use std::borrow::Borrow;
use std::collections::HashMap;

use crate::ipa_fr::config::Committer;

use super::utils::point_to_field_element;

#[derive(Debug, PartialEq, Eq)]
pub struct VerkleTree<K, L, GA, C>
where
    K: AbstractKey,
    L: LeafNodeValue<K, GA>,
    GA: CurveAffine,
    C: Committer<GA>,
{
    pub root: VerkleNode<K, L, GA>,
    pub(crate) committer: C,
}

// impl<K, L, GA> Default for VerkleTree<K, L, GA>
// where
//     K: AbstractKey,
//     L: LeafNodeValue<K, GA>,
//     GA: CurveAffine,
//     GA::Base: PrimeField,
// {
//     fn default() -> Self {
//         Self {
//             root: VerkleNode::default(),
//             committer: IpaConfig::new(WIDTH),
//         }
//     }
// }

impl<K, L, GA, C> VerkleTree<K, L, GA, C>
where
    C: Committer<GA>,
    K: AbstractKey,
    L: LeafNodeValue<K, GA>,
    GA: CurveAffine,
    GA::Base: PrimeField,
{
    pub fn new(committer: C) -> Self {
        let num_limbs = L::num_limbs();
        assert!(
            committer.get_domain_size() >= num_limbs + 2,
            "domain size must be larger than or equal to {}",
            num_limbs + 2
        );
        Self {
            root: VerkleNode::default(),
            committer,
        }
    }

    pub fn get_width(&mut self) -> usize {
        self.committer.get_domain_size()
    }
}

impl<P, K, L, GA, C> VerkleTree<K, L, GA, C>
where
    C: Committer<GA>,
    P: Default + AbstractPath,
    K: AbstractKey<Path = P>,
    K::Stem: AbstractStem<Path = P> + IntoFieldElement<GA::Scalar>,
    L: LeafNodeValue<K, GA>,
    GA: CurveAffine,
    GA::Base: PrimeField,
{
    /// Inserts `(key, value)` entry in given Verkle tree.
    /// This method updates the entry to the new value and returns the old value,
    /// even if the tree already has a value corresponding to the key.
    pub fn insert(&mut self, key: K, value: L::Value) -> Option<L::Value> {
        self.root.insert(key.to_path(), key, value)
    }

    /// Remove the entry corresponding to `key` in given Verkle tree.
    /// If the tree does not have a value corresponding to the key, this method does not change the tree state.
    pub fn remove(&mut self, key: &K) -> Option<L::Value> {
        self.root.remove(key.to_path(), key)
    }

    /// Fetch the value corresponding to `key` in given Verkle tree.
    /// The maximum time it takes to search entries depends on the depth of given Verkle tree.
    pub fn get(&self, key: &K) -> Option<&L::Value> {
        self.root.get(key.to_path(), key)
    }
}

// pub trait AbstractMerkleTree<K, V>
// where
//     K: AbstractKey,
//     V: AbstractValue,
// {
//     type Err: Send + Sync + 'static;
//     type Digest: PartialEq + Eq;
//     type ProofCommitments: PartialEq + Eq;

//     fn compute_digest(&mut self) -> Result<Self::Digest, Self::Err>;
// }

impl<P, K, L, GA, C> VerkleTree<K, L, GA, C>
where
    C: Committer<GA>,
    P: Default + AbstractPath,
    K: AbstractKey<Path = P>,
    K::Stem: AbstractStem<Path = P> + IntoFieldElement<GA::Scalar>,
    L: LeafNodeValue<K, GA>,
    GA: CurveAffine,
    GA::Base: PrimeField,
{
    /// Computes the digest of given Verkle tree.
    pub fn compute_digest(&mut self) -> anyhow::Result<GA::Scalar> {
        self.root.compute_digest(&self.committer)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExtStatus {
    Empty,           // path led to a empty node
    OtherStem,       // path led to a node with a different stem
    EmptySuffixTree, // stem is present, but suffix tree is not present
    OtherKey,        // stem and suffix tree is present
    Present,         // key is present
}

impl From<u8> for ExtStatus {
    fn from(value: u8) -> Self {
        if value == 0 {
            ExtStatus::Empty
        } else if value == 1 {
            ExtStatus::OtherStem
        } else if value == 2 {
            ExtStatus::EmptySuffixTree
        } else if value == 3 {
            ExtStatus::OtherKey
        } else if value == 4 {
            ExtStatus::Present
        } else {
            panic!("fail to convert");
        }
    }
}

impl From<usize> for ExtStatus {
    fn from(value: usize) -> Self {
        if value == 0 {
            ExtStatus::Empty
        } else if value == 1 {
            ExtStatus::OtherStem
        } else if value == 2 {
            ExtStatus::EmptySuffixTree
        } else if value == 3 {
            ExtStatus::OtherKey
        } else if value == 4 {
            ExtStatus::Present
        } else {
            panic!("fail to convert");
        }
    }
}

pub trait AbstractKey: Clone + Copy + Debug + Ord {
    type Stem: AbstractStem + Default;
    type Path: AbstractPath + Default;

    fn get_stem(&self) -> Self::Stem;

    fn get_suffix(&self) -> usize;

    fn to_path(&self) -> Self::Path;

    fn get_branch_at(&self, depth: usize) -> usize;
}

pub trait AbstractValue: Clone + Copy + Debug + Eq {}

pub trait AbstractPath: Sized + Clone + Debug + Default + Eq + IntoIterator<Item = usize> {
    type RemovePrefixError: Debug + Send + Sync + 'static;

    fn get_next_path_and_branch(&self) -> (Self, usize);

    fn get_suffix(&self) -> usize;

    /// Returns if `self` is a proper prefix of `full_path`.
    ///
    /// If `self` is non-empty, this function returns `true`.
    ///
    /// If `self` is equal to `full_path`, this function returns `false`.
    fn is_proper_prefix_of(&self, full_path: &Self) -> bool;

    fn remove_prefix(&self, prefix: &Self) -> Result<Self, Self::RemovePrefixError>;

    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn push(&mut self, value: usize);
}

pub trait AbstractStem: Clone + Debug + Eq {
    type Path: AbstractPath;

    fn to_path(&self) -> Self::Path;
}

pub trait IntoFieldElement<F: PrimeField> {
    type Err: Send + Sync + 'static;

    fn into_field_element(self) -> Result<F, Self::Err>;
}

pub trait NodeValue<GA>
where
    GA: CurveAffine,
{
    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn get_digest_mut(&mut self) -> &mut Option<GA::Scalar>;

    fn get_digest(&self) -> Option<&GA::Scalar>;
}

pub trait LeafNodeValue<K, GA>: Clone + Default + NodeValue<GA>
where
    K: AbstractKey,
    GA: CurveAffine,
{
    type Value: AbstractValue;

    fn new() -> Self;

    fn insert(&mut self, key: usize, value: Self::Value) -> Option<Self::Value>;

    fn get(&self, key: &usize) -> Option<&Self::Value>;

    fn remove(&mut self, key: &usize) -> Option<Self::Value>;

    fn compute_digest<C: Committer<GA>>(
        &mut self,
        stem: &mut K::Stem,
        committer: &C,
    ) -> anyhow::Result<GA::Scalar>;

    // fn get_witnesses<C: Committer<GA>>(
    //     &self,
    //     keys: &[K],
    //     stem: K::Stem,
    //     depth: usize,
    //     committer: &C,
    // ) -> anyhow::Result<MultiProofWitnesses<K, GA>>;

    fn bits_of_value() -> usize;

    fn num_limbs() -> usize;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InternalNodeValue<GA>
where
    GA: CurveAffine,
{
    /// The number of children which are `Some` rather than `None`.
    num_nonempty_children: usize,

    /// The commitment of this node.
    /// If it has not computed yet, `commitment` set `None`.
    commitment: Option<GA>,

    /// The digest of `commitment`.
    /// If it has not computed yet, `digest` set `None`.
    digest: Option<GA::Scalar>,
}

impl<GA> NodeValue<GA> for InternalNodeValue<GA>
where
    GA: CurveAffine,
{
    fn len(&self) -> usize {
        self.num_nonempty_children
    }

    fn get_digest_mut(&mut self) -> &mut Option<GA::Scalar> {
        &mut self.digest
    }

    fn get_digest(&self) -> Option<&GA::Scalar> {
        let digest = &self.digest;

        digest.into()
    }
}

impl<GA> InternalNodeValue<GA>
where
    GA: CurveAffine,
{
    pub fn get_commitment_mut(&mut self) -> &mut Option<GA> {
        &mut self.commitment
    }

    pub fn get_commitment(&self) -> Option<&GA> {
        let commitment = &self.commitment;

        commitment.into()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum VerkleNode<K, L, GA>
where
    K: AbstractKey,
    L: LeafNodeValue<K, GA>,
    GA: CurveAffine,
{
    Leaf {
        path: K::Path,
        stem: K::Stem,
        info: L,
    },
    Internal {
        path: K::Path,
        children: HashMap<usize, VerkleNode<K, L, GA>>, // HashMap<u8, VerkleNode<K, V, GA>>
        info: InternalNodeValue<GA>,
    },
}

impl<K, L, GA> VerkleNode<K, L, GA>
where
    K: AbstractKey,
    L: LeafNodeValue<K, GA>,
    GA: CurveAffine,
    GA::Base: PrimeField,
{
    pub fn new_leaf_node_with_entry(path: K::Path, key: K, value: L::Value) -> Self {
        // let mut leaves = HashMap::new();
        // leaves.insert(key.get_suffix(), value);
        let mut info = L::new();
        info.insert(key.get_suffix(), value);
        Self::Leaf {
            stem: key.get_stem(),
            path,
            info,
        }
    }

    pub fn new_internal_node_with_children(
        path: K::Path,
        children: HashMap<usize, VerkleNode<K, L, GA>>,
    ) -> Self {
        let num_nonempty_children = children.len();
        Self::Internal {
            path,
            children,
            info: InternalNodeValue {
                num_nonempty_children,
                commitment: None,
                digest: None,
            },
        }
    }

    pub fn get_path(&self) -> &K::Path {
        match self {
            Self::Leaf { path, .. } => path,
            Self::Internal { path, .. } => path,
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::Leaf { info, .. } => info.is_empty(),
            Self::Internal { info, .. } => info.is_empty(),
        }
    }

    // pub fn get_commitment(&self) -> Option<&GA> {
    //     match self {
    //         Self::Leaf { info, .. } => info.get_commitment(),
    //         Self::Internal { info, .. } => info.get_commitment(),
    //     }
    // }

    pub fn get_digest(&self) -> Option<&GA::Scalar> {
        match self {
            Self::Leaf { info, .. } => info.get_digest(),
            Self::Internal { info, .. } => info.get_digest(),
        }
    }
}

impl<K, L, GA> Default for VerkleNode<K, L, GA>
where
    K: AbstractKey,
    L: LeafNodeValue<K, GA>,
    GA: CurveAffine,
    GA::Base: PrimeField,
{
    fn default() -> Self {
        Self::new_internal_node_with_children(K::Path::default(), HashMap::new())
    }
}

impl<P, K, L, GA> VerkleNode<K, L, GA>
where
    P: Default + AbstractPath,
    K: AbstractKey<Path = P>,
    K::Stem: AbstractStem<Path = P> + IntoFieldElement<GA::Scalar>,
    L: LeafNodeValue<K, GA>,
    GA: CurveAffine,
    <GA as CurveAffine>::Base: PrimeField,
{
    pub fn insert(&mut self, relative_path: K::Path, key: K, value: L::Value) -> Option<L::Value> {
        if relative_path.is_empty() {
            panic!("`relative_path` must be non-empty.");
        }

        match self {
            VerkleNode::Leaf {
                stem, path, info, ..
            } => {
                let stem_relative_path = stem
                    .to_path()
                    .remove_prefix(path)
                    .expect("unreachable code");
                if stem_relative_path.is_empty() {
                    panic!("`relative_path` must be non-empty.");
                }
                if key.get_stem().eq(stem) {
                    return info.insert(key.get_suffix(), value);
                }

                // A new branch node has to be inserted. Depending
                // on the next branch in both keys, a recursion into
                // the moved leaf node can occur.
                let (_, next_branch_of_existing_key) =
                    stem_relative_path.get_next_path_and_branch();
                // assert!(next_branch_of_existing_key < WIDTH);

                let mut new_branch = {
                    let mut children = HashMap::new();
                    let mut new_path = path.clone();
                    new_path.push(next_branch_of_existing_key);
                    let moving_child = VerkleNode::Leaf {
                        stem: stem.clone(),
                        path: new_path,
                        info: info.clone(),
                    };
                    children.insert(next_branch_of_existing_key, moving_child);

                    VerkleNode::new_internal_node_with_children(path.clone(), children)
                };

                let (_, next_branch_of_inserting_key) = relative_path.get_next_path_and_branch();
                // assert!(next_branch_of_inserting_key < WIDTH);

                if next_branch_of_inserting_key != next_branch_of_existing_key {
                    // Next branch differs, so this was the last level.
                    // Insert it directly into its suffix.
                    let mut info = L::new();
                    info.insert(key.get_suffix(), value);
                    let mut new_path = path.clone();
                    new_path.push(next_branch_of_inserting_key);
                    let leaf_node = VerkleNode::Leaf {
                        stem: key.get_stem(),
                        path: new_path,
                        info,
                    };

                    match &mut new_branch {
                        VerkleNode::Internal { children, info, .. } => {
                            children.insert(next_branch_of_inserting_key, leaf_node);
                            info.num_nonempty_children += 1;
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
                info,
                ..
            } => {
                let _ = info.commitment.take();
                let _ = info.digest.take();

                let (next_relative_path, next_branch_of_inserting_key) =
                    relative_path.get_next_path_and_branch();
                // assert!(next_branch_of_inserting_key < WIDTH);

                if let Some(child) = children.get_mut(&next_branch_of_inserting_key) {
                    child.insert(next_relative_path, key, value)
                } else {
                    let mut new_path = path.clone();
                    new_path.push(next_branch_of_inserting_key);
                    children.insert(
                        next_branch_of_inserting_key,
                        VerkleNode::new_leaf_node_with_entry(new_path, key, value),
                    );

                    None
                }
            }
        }
    }

    pub fn remove(&mut self, relative_path: K::Path, key: &K) -> Option<L::Value> {
        match self {
            Self::Leaf { info, .. } => info.remove(&key.borrow().get_suffix()),
            Self::Internal {
                children,
                info:
                    InternalNodeValue {
                        commitment, digest, ..
                    },
                ..
            } => {
                let _ = commitment.take();
                let _ = digest.take();

                let (next_path, next_branch) = relative_path.get_next_path_and_branch();
                // assert!(next_branch < WIDTH);

                if let Some(child) = children.get_mut(&next_branch) {
                    let old_value = child.remove(next_path, key);

                    // Remove a empty node if any.
                    if child.is_empty() {
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
    pub fn get(&self, relative_path: K::Path, key: &K) -> Option<&L::Value> {
        match &self {
            Self::Leaf { stem, info, .. } => {
                if key.get_stem() != stem.clone() {
                    None
                } else {
                    info.get(&key.get_suffix())
                }
            }
            Self::Internal { children, .. } => {
                let (next_path, next_branch) = relative_path.get_next_path_and_branch();
                // assert!(next_branch < WIDTH);

                children
                    .get(&next_branch)
                    .and_then(|child| child.get(next_path, key))
            }
        }
    }

    // Returns witness of the existence or non-existence of
    // an entry corresponding to the given key.
    // If the entry exists, `witness` is the entry.
    // If the entry does not exist,
    // `witness` is an entry corresponding "the nearest" key to the given one.
    // pub fn get_witness(
    //     &self,
    //     relative_path: K::Path,
    //     key: K,
    // ) -> anyhow::Result<(K::Path, L::Value)> {
    //     match &self {
    //         Self::Leaf { .. } => {
    //             todo!();
    //             // if key.get_stem() != stem.clone() {
    //             //     todo!();
    //             // }

    //             // match leaves.get(&key.get_suffix()) {
    //             //     Some(&value) => Ok((key.to_path(), value)),
    //             //     None => {
    //             //         todo!()
    //             //     }
    //             // }
    //         }
    //         Self::Internal { children, .. } => {
    //             let (next_path, next_branch) = relative_path.get_next_path_and_branch();
    //             // assert!(next_branch < WIDTH);

    //             if let Some(child) = children.get(&next_branch) {
    //                 child.get_witness(next_path, key)
    //             } else {
    //                 todo!()
    //             }
    //         }
    //     }
    // }
}

pub fn compute_commitment_of_internal_node<GA: CurveAffine, C: Committer<GA>>(
    committer: &C,
    children_digests: Vec<GA::Scalar>,
) -> anyhow::Result<GA> {
    committer
        .commit(&children_digests)
        .or_else(|_| anyhow::bail!("Fail to make a commitment of given polynomial."))
}

impl<P, K, L, GA> VerkleNode<K, L, GA>
where
    P: Default + AbstractPath,
    K: AbstractKey<Path = P>,
    K::Stem: AbstractStem<Path = P> + IntoFieldElement<GA::Scalar>,
    L: LeafNodeValue<K, GA>,
    GA: CurveAffine,
    GA::Base: PrimeField,
{
    pub fn compute_digest<C: Committer<GA>>(
        &mut self,
        committer: &C,
    ) -> anyhow::Result<GA::Scalar> {
        if let Some(d) = self.get_digest() {
            return Ok(*d);
        }

        match self {
            VerkleNode::Leaf { stem, info, .. } => info.compute_digest::<C>(stem, committer),
            VerkleNode::Internal { children, info, .. } => {
                // TODO: info.compute_digest::<C>(children, committer)
                let width = committer.get_domain_size();
                let mut children_digests = vec![GA::Scalar::zero(); width];
                for (&i, child) in children.iter_mut() {
                    children_digests[i] = child.compute_digest(committer)?;
                }

                let tmp_commitment =
                    compute_commitment_of_internal_node(committer, children_digests)?;
                let tmp_digest = point_to_field_element(&tmp_commitment)?;

                let _ = std::mem::replace(&mut info.commitment, Some(tmp_commitment));
                let _ = std::mem::replace(&mut info.digest, Some(tmp_digest));

                Ok(tmp_digest)
            }
        }
    }
}
