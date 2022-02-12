use franklin_crypto::bellman::pairing::bn256::{Fr, G1Affine, G1};
use franklin_crypto::bellman::{CurveAffine, CurveProjective, PrimeField};
use generic_array::ArrayLength;
// use franklin_crypto::bellman::Field;

use crate::batch_proof::{BatchProof, Bn256BatchProof, MultiProof};
use crate::ipa_fr::config::IpaConfig;
use crate::ipa_fr::transcript::{Bn256Transcript, PoseidonBn256Transcript};

use super::proof::{
    CommitmentElements, Elements, ExtraProofData, MultiProofCommitments, ProofCommitments,
};
use super::trie::{AbstractMerkleTree, VerkleNode, VerkleTree};

#[derive(Clone, Debug)]
pub struct VerkleProof<G: CurveProjective> {
    pub multi_proof: MultiProof<G>,  // multipoint argument
    pub commitments: Vec<G::Affine>, // commitments, sorted by their path in the tree
    pub extra_data_list: Vec<ExtraProofData<[u8; 32]>>,
    pub keys: Vec<[u8; 32]>,
    pub values: Vec<[u8; 32]>,
}

pub trait VerkleTreeZkp<W, G, T>
where
    W: ArrayLength<Option<VerkleNode<[u8; 32], [u8; 32], G::Affine>>>,
    G: CurveProjective,
    <G::Affine as CurveAffine>::Base: PrimeField,
    T: Bn256Transcript,
{
    type Err: Send + Sync + 'static;

    #[allow(clippy::type_complexity)]
    fn create_proof(
        tree: &VerkleTree<G::Affine>,
        keys: &[[u8; 32]],
        ipa_conf: &IpaConfig<G>,
    ) -> Result<(VerkleProof<G>, Elements<G::Scalar>), Self::Err>;

    fn check_proof(
        proof: VerkleProof<G>,
        zs: &[usize],
        ys: &[Fr],
        ipa_conf: &IpaConfig<G>,
    ) -> Result<bool, Self::Err>;
}

pub struct Bn256VerkleTree<W: ArrayLength<Option<VerkleNode<[u8; 32], [u8; 32], G1Affine>>>> {
    _width: std::marker::PhantomData<W>,
}

impl<W> VerkleTreeZkp<W, G1, PoseidonBn256Transcript> for Bn256VerkleTree<W>
where
    W: ArrayLength<Option<VerkleNode<[u8; 32], [u8; 32], G1Affine>>>,
{
    type Err = anyhow::Error;

    fn create_proof(
        tree: &VerkleTree<G1Affine>,
        keys: &[[u8; 32]],
        ipa_conf: &IpaConfig<G1>,
    ) -> anyhow::Result<(VerkleProof<G1>, Elements<Fr>)> {
        let transcript = PoseidonBn256Transcript::with_bytes(b"multi_proof");
        if tree.root.get_digest().is_none() {
            anyhow::bail!("Please execute `tree.compute_commitment()` before creating proof.")
        }

        let MultiProofCommitments {
            commitment_elements,
            extra_data_list,
        } = get_commitments_for_multi_proof(tree, keys)?;

        let CommitmentElements {
            commitments,
            elements,
        } = commitment_elements;

        let mut values: Vec<[u8; 32]> = vec![];
        for k in keys {
            let val = tree
                .get_value(*k)
                .map_err(|_| anyhow::anyhow!("key {:?} is not found in this tree", k))?
                .unwrap();
            values.push(val);
        }

        let multi_proof = Bn256BatchProof::create_proof(
            &commitments,
            &elements.fs,
            &elements.zs,
            transcript.into_params(),
            ipa_conf,
        )?;
        let proof = VerkleProof {
            multi_proof,
            commitments,
            extra_data_list,
            keys: keys.to_vec(),
            values,
        };

        Ok((proof, elements))
    }

    fn check_proof(
        proof: VerkleProof<G1>,
        zs: &[usize],
        ys: &[Fr],
        ipa_conf: &IpaConfig<G1>,
    ) -> anyhow::Result<bool> {
        let transcript = PoseidonBn256Transcript::with_bytes(b"multi_proof");
        Bn256BatchProof::check_proof(
            proof.multi_proof,
            &proof.commitments,
            ys,
            zs,
            transcript.into_params(),
            ipa_conf,
        )
    }
}

pub fn get_commitments_for_multi_proof<GA>(
    tree: &VerkleTree<GA>,
    keys: &[[u8; 32]],
) -> anyhow::Result<MultiProofCommitments<[u8; 32], GA>>
where
    GA: CurveAffine,
    GA::Base: PrimeField,
{
    let mut c = CommitmentElements::default();
    let mut extra_data_list = vec![];

    for key in keys {
        let ProofCommitments {
            mut commitment_elements,
            extra_data,
        } = tree.get_commitments_along_path(*key)?;
        c.merge(&mut commitment_elements);
        extra_data_list.push(extra_data);
    }

    Ok(MultiProofCommitments {
        commitment_elements: c,
        extra_data_list,
    })
}
