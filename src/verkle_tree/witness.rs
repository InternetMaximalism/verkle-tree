use franklin_crypto::bellman::{CurveAffine, PrimeField, SqrtField};
use serde::{Deserialize, Serialize};

use super::trie::{AbstractKey, ExtStatus};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
pub struct ExtraProofData<K: AbstractKey> {
    pub depth: usize,
    pub status: ExtStatus, // the extension status of each stem
    pub poa_stem: K::Stem, // stems proving another stem is absent
}

// #[derive(Clone, Debug, PartialEq, Eq)]
// pub struct ProofCommitments<K: AbstractKey, GA: CurveAffine> {
//     pub commitment_elements: CommitmentElements<GA>,
//     pub extra_data: ExtraProofData<K>,
// }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultiProofWitnesses<K: AbstractKey, GA: CurveAffine> {
    pub commitment_elements: CommitmentElements<GA>,
    pub extra_data_list: Vec<ExtraProofData<K>>,
}

impl<K: AbstractKey, GA: CurveAffine> Default for MultiProofWitnesses<K, GA> {
    fn default() -> Self {
        Self {
            commitment_elements: CommitmentElements::default(),
            extra_data_list: vec![],
        }
    }
}

impl<K: AbstractKey, GA: CurveAffine> MultiProofWitnesses<K, GA> {
    pub fn merge(&mut self, other: &mut Self) {
        self.commitment_elements
            .merge(&mut other.commitment_elements);
        self.extra_data_list.append(&mut other.extra_data_list);
    }
}
