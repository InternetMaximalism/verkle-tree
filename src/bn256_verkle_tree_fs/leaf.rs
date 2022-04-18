use franklin_crypto::babyjubjub::{edwards, JubjubEngine, Unknown};
use franklin_crypto::bellman::{Field, PrimeField};
use std::collections::HashMap;

use crate::ipa_fs::config::Committer;
use crate::verkle_tree::trie::{AbstractKey, AbstractPath, AbstractStem, IntoFieldElement};
use crate::verkle_tree_fs::trie::{LeafNodeValue, NodeValue};
use crate::verkle_tree_fs::utils::{fill_leaf_tree_poly, point_to_field_element};

#[derive(Clone, PartialEq)]
pub struct LeafNodeWith32BytesValue<E>
where
    E: JubjubEngine,
{
    /// The number of leaves which are `Some` rather than `None`.
    pub(crate) num_nonempty_children: usize,

    pub(crate) leaves: HashMap<usize, [u8; 32]>, // HashMap<u8, V>

    pub(crate) s_commitments: Option<Vec<edwards::Point<E, Unknown>>>, // Option<[GA; 2]>

    /// The commitment of this node.
    /// If it has not computed yet, `commitment` set `None`.
    pub(crate) commitment: Option<edwards::Point<E, Unknown>>,

    /// The digest of `commitment`.
    /// If it has not computed yet, `digest` set `None`.
    pub(crate) digest: Option<E::Fs>,
}

impl<E> Default for LeafNodeWith32BytesValue<E>
where
    E: JubjubEngine,
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

impl<E> NodeValue<E> for LeafNodeWith32BytesValue<E>
where
    E: JubjubEngine,
{
    fn len(&self) -> usize {
        self.num_nonempty_children
    }

    fn get_digest_mut(&mut self) -> &mut Option<E::Fs> {
        &mut self.digest
    }

    fn get_digest(&self) -> Option<&E::Fs> {
        let digest = &self.digest;

        digest.into()
    }
}

impl<E> LeafNodeWith32BytesValue<E>
where
    E: JubjubEngine,
{
    pub fn get_commitment_mut(&mut self) -> &mut Option<edwards::Point<E, Unknown>> {
        &mut self.commitment
    }

    pub fn get_commitment(&self) -> Option<&edwards::Point<E, Unknown>> {
        let commitment = &self.commitment;

        commitment.into()
    }
}

pub fn compute_commitment_of_leaf_node<P, K, E, C>(
    committer: &C,
    stem: &mut K::Stem,
    info: &mut LeafNodeWith32BytesValue<E>,
) -> anyhow::Result<E::Fs>
where
    P: Default + AbstractPath,
    K: AbstractKey<Path = P>,
    K::Stem: AbstractStem<Path = P> + IntoFieldElement<E::Fs>,
    E: JubjubEngine,
    C: Committer<E>,
{
    let width = committer.get_domain_size();
    let num_limbs = <LeafNodeWith32BytesValue<E> as LeafNodeValue<K, E>>::num_limbs();
    let bits_of_value = <LeafNodeWith32BytesValue<E> as LeafNodeValue<K, E>>::bits_of_value();
    // let bits_of_value = width;
    let limb_bits_size = bits_of_value / num_limbs;
    debug_assert!(limb_bits_size < E::Fs::NUM_BITS as usize);

    let poly_0 = E::Fs::one();
    let poly_1 = stem
        .clone()
        .into_field_element()
        .map_err(|_| anyhow::anyhow!("unreachable code"))?;
    let mut poly = vec![poly_0, poly_1];

    let mut leaves_array = vec![None; width];
    for (&i, &v) in info.leaves.iter() {
        leaves_array[i] = Some(v);
    }
    let mut s_commitments = vec![];
    for limb in leaves_array.chunks(limb_bits_size) {
        let mut sub_poly = vec![E::Fs::zero(); width];
        let _count = fill_leaf_tree_poly(&mut sub_poly, limb, num_limbs)?;
        let tmp_s_commitment = committer
            .commit(&sub_poly)
            .or_else(|_| anyhow::bail!("Fail to compute the commitment of the polynomial."))?;
        poly.push(point_to_field_element(&tmp_s_commitment)?);
        s_commitments.push(tmp_s_commitment);
    }

    // let infinity_point_fs = point_to_field_element(&edwards::Point::<E, Unknown>::zero())?;
    poly.resize(width, E::Fs::zero());

    let tmp_commitment = committer
        .commit(&poly)
        .or_else(|_| anyhow::bail!("Fail to compute the commitment of the polynomial."))?;

    let tmp_digest = point_to_field_element(&tmp_commitment)?;

    let _ = std::mem::replace(&mut info.s_commitments, Some(s_commitments));
    let _ = std::mem::replace(&mut info.commitment, Some(tmp_commitment));
    let _ = std::mem::replace(&mut info.digest, Some(tmp_digest));

    Ok(tmp_digest)
}

impl<P, K, E> LeafNodeValue<K, E> for LeafNodeWith32BytesValue<E>
where
    P: Default + AbstractPath,
    K: AbstractKey<Path = P>,
    K::Stem: AbstractStem<Path = P> + IntoFieldElement<E::Fs>,
    E: JubjubEngine,
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

    fn compute_digest<C: Committer<E>>(
        &mut self,
        stem: &mut K::Stem,
        committer: &C,
    ) -> anyhow::Result<E::Fs> {
        compute_commitment_of_leaf_node::<_, K, _, _>(committer, stem, self)
    }

    fn bits_of_value() -> usize {
        256
    }

    fn num_limbs() -> usize {
        2
    }
}
