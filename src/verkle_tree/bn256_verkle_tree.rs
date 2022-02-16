use franklin_crypto::bellman::pairing::bn256::{Fr, G1Affine, G1};
use franklin_crypto::bellman::CurveProjective;
// use franklin_crypto::bellman::Field;

use crate::batch_proof::{BatchProof, Bn256BatchProof, MultiProof};
use crate::ipa_fr::config::IpaConfig;
use crate::ipa_fr::transcript::{Bn256Transcript, PoseidonBn256Transcript};

use super::proof::{CommitmentElements, Elements, ExtraProofData, MultiProofCommitments};
use super::trie::VerkleTree;

#[derive(Clone, Debug)]
pub struct VerkleProof<G: CurveProjective> {
    pub multi_proof: MultiProof<G>,  // multipoint argument
    pub commitments: Vec<G::Affine>, // commitments, sorted by their path in the tree
    pub extra_data_list: Vec<ExtraProofData<[u8; 32]>>,
    pub keys: Vec<[u8; 32]>,
    pub values: Vec<[u8; 32]>,
}

impl VerkleProof<G1> {
    pub fn create(
        tree: &mut VerkleTree<G1Affine>,
        keys: &[[u8; 32]],
    ) -> anyhow::Result<(Self, Elements<Fr>)> {
        let transcript = PoseidonBn256Transcript::with_bytes(b"multi_proof");
        tree.compute_commitment()?;

        let MultiProofCommitments {
            commitment_elements,
            extra_data_list,
        } = tree.get_commitments_along_path(keys)?;

        let CommitmentElements {
            commitments,
            elements,
        } = commitment_elements;

        let mut values: Vec<[u8; 32]> = vec![];
        for k in keys {
            let val = tree
                .get(k)
                .ok_or_else(|| anyhow::anyhow!("key {:?} is not found in this tree", k))?;
            values.push(*val);
        }

        let multi_proof = Bn256BatchProof::create_proof(
            &commitments,
            &elements.fs,
            &elements.zs,
            transcript.into_params(),
            &tree.committer,
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

    pub fn check(&self, zs: &[usize], ys: &[Fr], ipa_conf: &IpaConfig<G1>) -> anyhow::Result<bool> {
        let transcript = PoseidonBn256Transcript::with_bytes(b"multi_proof");
        Bn256BatchProof::check_proof(
            self.multi_proof.clone(),
            &self.commitments.clone(),
            ys,
            zs,
            transcript.into_params(),
            ipa_conf,
        )
    }
}
