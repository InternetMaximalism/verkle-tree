use core::fmt::Debug;
use franklin_crypto::bellman::bn256::{Fr, G1Affine};
use franklin_crypto::bellman::{CurveAffine, Field, PrimeField};

use crate::ipa_fr::config::Committer;
use crate::verkle_tree::trie::{
    AbstractKey, AbstractPath, AbstractStem, AbstractValue, IntoFieldElement, LeafNodeValue,
    NodeValue,
};

pub(crate) const LIMBS: usize = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafNodeWithFrValue<GA>
where
    GA: CurveAffine,
{
    /// The number of leaves which are `Some` rather than `None`.
    /// The value allows 0 or 1 in F_r-value case.
    pub(crate) num_nonempty_children: usize,

    pub(crate) value: Option<GA::Scalar>,

    /// The commitment of this node.
    /// If it has not computed yet, `commitment` set `None`.
    pub(crate) commitment: Option<GA>,

    /// The digest of `commitment`.
    /// If it has not computed yet, `digest` set `None`.
    pub(crate) digest: Option<GA::Scalar>,
}

impl<GA> Default for LeafNodeWithFrValue<GA>
where
    GA: CurveAffine,
{
    fn default() -> Self {
        Self {
            num_nonempty_children: 0,
            commitment: None,
            digest: None,
            value: None,
        }
    }
}

impl<GA> NodeValue<GA> for LeafNodeWithFrValue<GA>
where
    GA: CurveAffine,
{
    fn len(&self) -> usize {
        self.num_nonempty_children
    }

    fn get_commitment_mut(&mut self) -> &mut Option<GA> {
        &mut self.commitment
    }

    fn get_commitment(&self) -> Option<&GA> {
        (&self.commitment).into()
    }

    fn get_digest_mut(&mut self) -> &mut Option<GA::Scalar> {
        &mut self.digest
    }

    fn get_digest(&self) -> Option<&GA::Scalar> {
        (&self.digest).into()
    }
}

// 32 bytes value
impl AbstractValue for Fr {}

pub fn compute_commitment_of_leaf_node<K, C>(
    _committer: &C,
    _stem: &mut K::Stem,
    info: &mut LeafNodeWithFrValue<G1Affine>,
) -> anyhow::Result<G1Affine>
where
    K: AbstractKey,
    K::Stem: IntoFieldElement<Fr>,
    C: Committer<G1Affine>,
{
    let value_size = 32;
    let limb_bits_size = value_size * 8 / LIMBS;
    debug_assert!(limb_bits_size < Fr::NUM_BITS as usize);

    let zero = <Fr as Field>::zero();
    let tmp_commitment = G1Affine::zero();
    let tmp_digest = info.value.map_or(zero, |v| v);

    let _ = std::mem::replace(&mut info.digest, Some(tmp_digest));

    Ok(tmp_commitment)
}

impl<P, K> LeafNodeValue<K, G1Affine> for LeafNodeWithFrValue<G1Affine>
where
    P: Default + AbstractPath,
    K: AbstractKey<Path = P>,
    K::Stem: AbstractStem<Path = P> + IntoFieldElement<Fr>,
{
    type Value = Fr;

    fn new() -> Self {
        Self::default()
    }

    fn insert(&mut self, key: usize, value: Fr) -> Option<Fr> {
        assert_eq!(key, 0);
        let _ = self.commitment.take();
        let _ = self.digest.take();
        let old_leaf = self.value.replace(value);
        if old_leaf.is_none() {
            self.num_nonempty_children += 1;
        }

        old_leaf
    }

    fn get(&self, key: &usize) -> Option<&Fr> {
        assert_eq!(*key, 0);

        self.value.as_ref()
    }

    fn remove(&mut self, key: &usize) -> Option<Fr> {
        assert_eq!(*key, 0);

        let old_leaf = self.value.take();
        if old_leaf.is_some() {
            let _ = self.commitment.take();
            let _ = self.digest.take();
            self.num_nonempty_children -= 1;
        }

        old_leaf
    }

    fn compute_commitment<C: Committer<G1Affine>>(
        &mut self,
        stem: &mut K::Stem,
        committer: &C,
    ) -> anyhow::Result<G1Affine> {
        compute_commitment_of_leaf_node::<K, _>(committer, stem, self)
    }
}
