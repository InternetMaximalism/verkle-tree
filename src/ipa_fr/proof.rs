use super::transcript::Bn256Transcript;
use franklin_crypto::bellman::pairing::bn256::{Fr, G1Affine};
use franklin_crypto::bellman::CurveAffine;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpaProof<GA: CurveAffine> {
    pub l: Vec<GA>,
    pub r: Vec<GA>,
    pub a: GA::Scalar,
}

pub fn generate_challenges<T: Bn256Transcript>(
    ipa_proof: &IpaProof<G1Affine>,
    transcript: &mut T,
) -> anyhow::Result<Vec<Fr>> {
    let mut challenges: Vec<Fr> = Vec::with_capacity(ipa_proof.l.len());
    for (l, r) in ipa_proof.l.iter().zip(&ipa_proof.r) {
        transcript.commit_point(l)?; // L[i]
        transcript.commit_point(r)?; // R[i]

        let c = transcript.get_challenge();
        challenges.push(c);
    }

    Ok(challenges)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializableIpaProof {
    pub l: Vec<(String, String)>, // affine form
    pub r: Vec<(String, String)>, // affine form
    pub a: String,
}
