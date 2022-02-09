use franklin_crypto::bellman::{CurveAffine, PrimeField, SqrtField};

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
pub struct CommitmentElements<GA: CurveAffine> {
    pub commitments: Vec<GA>,
    pub elements: Elements<GA::Scalar>,
}

impl<GA: CurveAffine> Default for CommitmentElements<GA> {
    fn default() -> Self {
        Self {
            commitments: vec![],
            elements: Elements::default(),
        }
    }
}

impl<GA: CurveAffine> CommitmentElements<GA> {
    pub fn merge(&mut self, other: &mut Self) {
        self.commitments.append(&mut other.commitments);
        self.elements.merge(&mut other.elements);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofCommitment<GA: CurveAffine> {
    pub commitment_elements: CommitmentElements<GA>,
    pub ext_status: usize,
    pub alt: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultiProofCommitment<GA: CurveAffine> {
    pub commitment_elements: CommitmentElements<GA>,
    pub ext_status: Vec<usize>,
    pub alt: Vec<Vec<u8>>,
}
