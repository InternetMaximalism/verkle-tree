use franklin_crypto::bellman::pairing::bn256::G1;
use franklin_crypto::bellman::{CurveProjective, PrimeField, SqrtField};
// use franklin_crypto::bellman::Field;

use super::tree::VerkleNode;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Elements<F: PrimeField + SqrtField> {
    pub zs: Vec<usize>,
    pub ys: Vec<F>,
    pub fs: Vec<Vec<F>>,
}

impl<F: PrimeField + SqrtField> Default for Elements<F> {
    fn default() -> Self {
        Self {
            zs: vec![],
            ys: vec![],
            fs: vec![],
        }
    }
}

impl<F: PrimeField + SqrtField> Elements<F> {
    pub fn merge(&mut self, other: &mut Self) {
        self.zs.append(&mut other.zs);
        self.ys.append(&mut other.ys);
        self.fs.append(&mut other.fs);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentElements<G: CurveProjective> {
    pub commitments: Vec<G::Affine>,
    pub elements: Elements<G::Scalar>,
}

impl<G: CurveProjective> Default for CommitmentElements<G> {
    fn default() -> Self {
        Self {
            commitments: vec![],
            elements: Elements::default(),
        }
    }
}

impl<G: CurveProjective> CommitmentElements<G> {
    pub fn merge(&mut self, other: &mut Self) {
        self.commitments.append(&mut other.commitments);
        self.elements.merge(&mut other.elements);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofCommitment<G: CurveProjective> {
    pub commitment_elements: CommitmentElements<G>,
    pub ext_status: usize,
    pub alt: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultiProofCommitment<G: CurveProjective> {
    pub commitment_elements: CommitmentElements<G>,
    pub ext_status: Vec<usize>,
    pub alt: Vec<Vec<u8>>,
}

pub fn get_commitments_for_multi_proof<
    Err: std::error::Error + Send + Sync + 'static,
    N: VerkleNode<G1, Key = Vec<u8>, Value = Vec<u8>, Err = Err>,
>(
    root: &N,
    keys: &[N::Key],
) -> anyhow::Result<MultiProofCommitment<G1>> {
    let mut c = CommitmentElements::default();
    let mut ext_statuses = vec![];
    let mut poa_stems = vec![];

    for key in keys {
        let ProofCommitment {
            mut commitment_elements,
            ext_status,
            alt,
        } = root.get_commitments_along_path(key.clone())?;
        c.merge(&mut commitment_elements);
        ext_statuses.push(ext_status);
        if !alt.is_empty() {
            poa_stems.push(alt);
        }
    }

    Ok(MultiProofCommitment {
        commitment_elements: c,
        ext_status: ext_statuses,
        alt: poa_stems,
    })
}
