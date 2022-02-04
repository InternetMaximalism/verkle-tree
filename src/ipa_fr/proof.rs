use franklin_crypto::bellman::pairing::bn256::{Fr, G1};
use franklin_crypto::bellman::CurveProjective;

use super::transcript::Bn256Transcript;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpaProof<G: CurveProjective> {
    pub l: Vec<G>,
    pub r: Vec<G>,
    pub a: G::Scalar,
}

pub fn generate_challenges<T: Bn256Transcript>(
    ipa_proof: &IpaProof<G1>,
    transcript: &mut T,
) -> anyhow::Result<Vec<Fr>> {
    let mut challenges: Vec<Fr> = Vec::with_capacity(ipa_proof.l.len());
    for (l, r) in ipa_proof.l.iter().zip(&ipa_proof.r) {
        transcript.commit_point(&l)?; // L[i]
        transcript.commit_point(&r)?; // R[i]

        let c = transcript.get_challenge();
        challenges.push(c);
    }

    Ok(challenges)
}
