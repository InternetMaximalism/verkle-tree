use franklin_crypto::bellman::pairing::bn256::{Bn256, Fr, G1};
use franklin_crypto::bellman::CurveProjective;
use serde::{Deserialize, Serialize};

use super::rns::BaseRnsParameters;
use super::transcript::Bn256Transcript;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpaProof<G: CurveProjective> {
    pub l: Vec<G::Affine>,
    pub r: Vec<G::Affine>,
    pub a: G::Scalar,
}

pub fn generate_challenges<T: Bn256Transcript>(
    ipa_proof: &IpaProof<G1>,
    rns_params: &BaseRnsParameters<Bn256>,
    transcript: &mut T,
) -> anyhow::Result<Vec<Fr>> {
    let mut challenges: Vec<Fr> = Vec::with_capacity(ipa_proof.l.len());
    for (l, r) in ipa_proof.l.iter().zip(&ipa_proof.r) {
        transcript.commit_point(l, &rns_params)?; // L[i]
        transcript.commit_point(r, &rns_params)?; // R[i]

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
