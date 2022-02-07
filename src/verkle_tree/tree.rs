use franklin_crypto::bellman::CurveProjective;
use generic_array::{ArrayLength, GenericArray};
// use franklin_crypto::bellman::Field;

use super::proof::ProofCommitment;

pub trait MerkleNode<G: CurveProjective> {
    type Key: Clone + PartialEq + Eq;
    type Value: Clone + PartialEq + Eq;
    type Err: Send + Sync + 'static;

    fn insert<Fn: FnOnce(Vec<u8>) -> Vec<u8>>(
        &mut self,
        key: Self::Key,
        value: Self::Value,
        setter: Fn,
    ) -> Result<(), Self::Err>;

    fn delete(&mut self, key: Self::Key) -> Result<(), Self::Err>;

    /// Get a value from this tree.
    fn get<Fn: FnOnce(Vec<u8>) -> Vec<u8>>(
        &self,
        key: Self::Key,
        getter: Fn,
    ) -> Result<Self::Value, Self::Err>;

    /// This method follows the path that one key
    /// traces through the tree, and collects the various
    /// elements needed to build a proof. The order of elements
    /// is from the bottom of the tree, up to the root. It also
    /// returns the extension status.
    fn get_commitments_along_path(&self, key: Self::Key) -> Result<ProofCommitment<G>, Self::Err>;
}

pub trait VerkleNode<G: CurveProjective>: MerkleNode<G> {
    /// Finalize commitment (digest) of this tree.
    fn compute_verkle_commitment(&self) -> anyhow::Result<()> {
        todo!()
    }
}

pub trait Committer<G: CurveProjective>: PartialEq + Eq {
    fn commit_to_poly(poly: &[G::Scalar], eval_point: G::Scalar) -> G;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InternalNode<G: CurveProjective, N: VerkleNode<G>, W: ArrayLength<N>, C: Committer<G>> {
    pub children: GenericArray<N, W>,
    pub depth: usize,
    pub count: usize,
    pub hash: G::Scalar,
    pub commitment: G,
    pub committer: C,
}

impl<
        Err: std::error::Error + Send + Sync + 'static,
        G: CurveProjective,
        N: VerkleNode<G, Key = Vec<u8>, Value = Vec<u8>, Err = Err>,
        W: ArrayLength<N> + Eq,
        C: Committer<G>,
    > MerkleNode<G> for InternalNode<G, N, W, C>
{
    type Key = Vec<u8>;
    type Value = Vec<u8>;
    type Err = anyhow::Error;

    fn insert<Fn: FnOnce(Vec<u8>) -> Vec<u8>>(
        &mut self,
        _key: Self::Key,
        _value: Self::Value,
        _setter: Fn,
    ) -> Result<(), Self::Err> {
        todo!()
    }

    fn delete(&mut self, _key: Self::Key) -> Result<(), Self::Err> {
        todo!()
    }

    /// Get a value from this tree.
    fn get<Fn: FnOnce(Vec<u8>) -> Vec<u8>>(
        &self,
        _key: Self::Key,
        _getter: Fn,
    ) -> Result<Self::Value, Self::Err> {
        todo!()
    }

    fn get_commitments_along_path(&self, _key: Self::Key) -> anyhow::Result<ProofCommitment<G>> {
        todo!()
    }
}

pub enum Node {
    InternalNode,
}
