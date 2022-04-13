use core::fmt::Debug;
use franklin_crypto::bellman::{CurveAffine, Field, PrimeField};
use std::collections::HashMap;

use crate::ipa_fr::config::Committer;
use crate::verkle_tree::trie::{
    AbstractKey, AbstractPath, AbstractStem, AbstractValue, IntoFieldElement, LeafNodeValue,
    NodeValue,
};
use crate::verkle_tree::utils::{fill_leaf_tree_poly, point_to_field_element};

pub(crate) const LIMBS: usize = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafNodeWith32BytesValue<GA>
where
    GA: CurveAffine,
{
    /// The number of leaves which are `Some` rather than `None`.
    pub(crate) num_nonempty_children: usize,

    pub(crate) leaves: HashMap<usize, [u8; 32]>, // HashMap<u8, V>

    pub(crate) s_commitments: Option<Vec<GA>>, // Option<[GA; 2]>

    /// The commitment of this node.
    /// If it has not computed yet, `commitment` set `None`.
    pub(crate) commitment: Option<GA>,

    /// The digest of `commitment`.
    /// If it has not computed yet, `digest` set `None`.
    pub(crate) digest: Option<GA::Scalar>,
}

impl<GA> Default for LeafNodeWith32BytesValue<GA>
where
    GA: CurveAffine,
{
    fn default() -> Self {
        Self {
            num_nonempty_children: 0,
            leaves: HashMap::new(),
            s_commitments: None,
            commitment: None,
            digest: None,
        }
    }
}

impl<GA> NodeValue<GA> for LeafNodeWith32BytesValue<GA>
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

impl<GA> LeafNodeWith32BytesValue<GA>
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

// 32 bytes value
impl AbstractValue for [u8; 32] {}

pub fn compute_commitment_of_leaf_node<K, GA, C>(
    committer: &C,
    stem: &mut K::Stem,
    info: &mut LeafNodeWith32BytesValue<GA>,
) -> anyhow::Result<GA::Scalar>
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

    let poly_0 = GA::Scalar::one();
    let poly_1 = stem
        .clone()
        .into_field_element()
        .map_err(|_| anyhow::anyhow!("unreachable code"))?;
    let mut poly = vec![poly_0, poly_1];

    let width = committer.get_domain_size();
    let mut leaves_array = vec![None; width];
    for (&i, &v) in info.leaves.iter() {
        leaves_array[i] = Some(v);
    }
    let mut s_commitments = vec![];
    for limb in leaves_array.chunks(limb_bits_size) {
        let mut sub_poly = vec![GA::Scalar::zero(); width];
        let _count = fill_leaf_tree_poly(&mut sub_poly, limb)?;
        let tmp_s_commitment = committer
            .commit(&sub_poly)
            .or_else(|_| anyhow::bail!("Fail to compute the commitment of the polynomial."))?;
        s_commitments.push(tmp_s_commitment);
        poly.push(point_to_field_element(&tmp_s_commitment)?);
    }

    // let infinity_point_fs = point_to_field_element(&GA::zero())?;
    poly.resize(width, GA::Scalar::zero());

    let tmp_commitment = committer
        .commit(&poly)
        .or_else(|_| anyhow::bail!("Fail to compute the commitment of the polynomial."))?;

    let tmp_digest = point_to_field_element(&tmp_commitment)?;

    let _ = std::mem::replace(&mut info.s_commitments, Some(s_commitments));
    let _ = std::mem::replace(&mut info.commitment, Some(tmp_commitment));
    let _ = std::mem::replace(&mut info.digest, Some(tmp_digest));

    Ok(tmp_digest)
}

impl<P, K, GA> LeafNodeValue<K, GA> for LeafNodeWith32BytesValue<GA>
where
    P: Default + AbstractPath,
    K: AbstractKey<Path = P>,
    K::Stem: AbstractStem<Path = P> + IntoFieldElement<GA::Scalar>,
    GA: CurveAffine,
    GA::Base: PrimeField,
{
    type Value = [u8; 32];

    fn new() -> Self {
        Self::default()
    }

    fn insert(&mut self, key: usize, value: [u8; 32]) -> Option<[u8; 32]> {
        let _ = self.commitment.take();
        let _ = self.digest.take();
        let old_leaf = self.leaves.insert(key, value);
        if old_leaf.is_none() {
            self.num_nonempty_children += 1;
        }

        old_leaf
    }

    fn get(&self, key: &usize) -> Option<&[u8; 32]> {
        self.leaves.get(key)
    }

    fn remove(&mut self, key: &usize) -> Option<[u8; 32]> {
        let old_leaf = self.leaves.remove(key);
        if old_leaf.is_some() {
            let _ = self.commitment.take();
            let _ = self.digest.take();
            self.num_nonempty_children -= 1;
        }

        old_leaf
    }

    fn compute_digest<C: Committer<GA>>(
        &mut self,
        stem: &mut K::Stem,
        committer: &C,
    ) -> anyhow::Result<GA::Scalar> {
        compute_commitment_of_leaf_node::<K, _, _>(committer, stem, self)
    }
}
