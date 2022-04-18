use franklin_crypto::babyjubjub::{edwards, JubjubEngine, Unknown};

use crate::verkle_tree::{
    trie::AbstractKey,
    witness::{Elements, ExtraProofData},
};

// #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
// pub struct Elements<F: PrimeField + SqrtField> {
//     pub zs: Vec<usize>,
//     pub ys: Vec<F>,
//     pub fs: Vec<Vec<F>>,
// }

// impl<F: PrimeField + SqrtField> Default for Elements<F> {
//     fn default() -> Self {
//         Self {
//             zs: vec![],
//             ys: vec![],
//             fs: vec![],
//         }
//     }
// }

// impl<F: PrimeField + SqrtField> Elements<F> {
//     pub fn merge(&mut self, other: &mut Self) {
//         self.zs.append(&mut other.zs);
//         self.ys.append(&mut other.ys);
//         self.fs.append(&mut other.fs);
//     }
// }

#[derive(Clone, PartialEq)]
pub struct CommitmentElements<E: JubjubEngine> {
    pub commitments: Vec<edwards::Point<E, Unknown>>,
    pub elements: Elements<E::Fs>,
}

impl<E: JubjubEngine> Default for CommitmentElements<E> {
    fn default() -> Self {
        Self {
            commitments: vec![],
            elements: Elements::default(),
        }
    }
}

impl<E: JubjubEngine> CommitmentElements<E> {
    pub fn merge(&mut self, other: &mut Self) {
        self.commitments.append(&mut other.commitments);
        self.elements.merge(&mut other.elements);
    }
}

// #[derive(Clone, Debug, PartialEq, Eq)]
// pub struct ExtraProofData<K: AbstractKey> {
//     pub depth: usize,
//     pub status: ExtStatus, // the extension status of each stem
//     pub poa_stem: K::Stem, // stems proving another stem is absent
// }

// #[derive(Clone, Debug, PartialEq, Eq)]
// pub struct ProofCommitments<K: AbstractKey, E: JubjubEngine> {
//     pub commitment_elements: CommitmentElements<GA>,
//     pub extra_data: ExtraProofData<K>,
// }

#[derive(Clone, PartialEq)]
pub struct MultiProofWitnesses<K: AbstractKey, E: JubjubEngine> {
    pub commitment_elements: CommitmentElements<E>,
    pub extra_data_list: Vec<ExtraProofData<K>>,
}

impl<K: AbstractKey, E: JubjubEngine> Default for MultiProofWitnesses<K, E> {
    fn default() -> Self {
        Self {
            commitment_elements: CommitmentElements::default(),
            extra_data_list: vec![],
        }
    }
}

impl<K: AbstractKey, E: JubjubEngine> MultiProofWitnesses<K, E> {
    pub fn merge(&mut self, other: &mut Self) {
        self.commitment_elements
            .merge(&mut other.commitment_elements);
        self.extra_data_list.append(&mut other.extra_data_list);
    }
}
