use franklin_crypto::bellman::pairing::bn256::{Fr, G1Affine, G1};
use franklin_crypto::bellman::CurveProjective;
// use franklin_crypto::bellman::Field;

use crate::batch_proof::{BatchProof, Bn256BatchProof, MultiProof};
use crate::ipa_fr::config::IpaConfig;
use crate::ipa_fr::transcript::{Bn256Transcript, PoseidonBn256Transcript};

use super::proof::{
    get_commitments_for_multi_proof, CommitmentElements, Elements, MultiProofCommitment,
};
use super::tree::VerkleNode;

#[derive(Clone)]
pub struct VerkleProof<G: CurveProjective> {
    pub multi_proof: MultiProof<G>,  // multipoint argument
    pub commitments: Vec<G::Affine>, // commitments, sorted by their path in the tree
    pub ext_status: Vec<usize>,      // the extension status of each stem
    pub poa_stems: Vec<Vec<u8>>,     // stems proving another stem is absent
    pub keys: Vec<Vec<u8>>,
    pub values: Vec<Vec<u8>>,
}

pub trait VerkleTree<G: CurveProjective, T: Bn256Transcript, N: VerkleNode<G>> {
    type Err: Send + Sync + 'static;

    #[allow(clippy::type_complexity)]
    fn create_proof(
        root: &N,
        keys: &[N::Key],
        ipa_conf: &IpaConfig<G>,
    ) -> Result<(VerkleProof<G>, Elements<G::Scalar>), Self::Err>;

    fn check_proof(
        proof: VerkleProof<G>,
        commitments: &[G::Affine],
        zs: &[usize],
        ys: &[Fr],
        ipa_conf: &IpaConfig<G>,
    ) -> Result<bool, Self::Err>;
}

pub struct Bn256VerkleTree;

impl<
        Err: std::error::Error + Send + Sync + 'static,
        N: VerkleNode<G1, Key = Vec<u8>, Value = Vec<u8>, Err = Err>,
    > VerkleTree<G1, PoseidonBn256Transcript, N> for Bn256VerkleTree
{
    type Err = anyhow::Error;

    fn create_proof(
        root: &N,
        keys: &[N::Key],
        ipa_conf: &IpaConfig<G1>,
    ) -> anyhow::Result<(VerkleProof<G1>, Elements<Fr>)> {
        let transcript = PoseidonBn256Transcript::with_bytes(b"multi_proof");
        root.compute_verkle_commitment()?;

        let MultiProofCommitment {
            commitment_elements,
            ext_status,
            alt: poa_stems,
        } = get_commitments_for_multi_proof(root, keys)?;

        let CommitmentElements {
            commitments,
            elements,
        } = commitment_elements;

        let mut values: Vec<Vec<u8>> = vec![];
        for k in keys {
            let val = root
                .get(k.clone(), |x| x)
                .map_err(|_| anyhow::anyhow!("key {:?} is not found in this tree", k))?;
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
            ext_status,
            poa_stems,
            keys: keys.to_vec(),
            values,
        };

        Ok((proof, elements))
    }

    fn check_proof(
        proof: VerkleProof<G1>,
        commitments: &[G1Affine],
        zs: &[usize],
        ys: &[Fr],
        ipa_conf: &IpaConfig<G1>,
    ) -> anyhow::Result<bool> {
        let transcript = PoseidonBn256Transcript::with_bytes(b"multi_proof");
        Bn256BatchProof::check_proof(
            proof.multi_proof,
            commitments,
            ys,
            zs,
            transcript.into_params(),
            ipa_conf,
        )
    }
}
