use franklin_crypto::babyjubjub::edwards::Point;
use franklin_crypto::babyjubjub::fs::Fs;
use franklin_crypto::babyjubjub::{JubjubEngine, Unknown};
use franklin_crypto::bellman::pairing::bn256::Bn256;

use super::transcript::Bn256Transcript;

#[derive(Clone)]
pub struct IpaProof<E: JubjubEngine> {
    pub l: Vec<Point<E, Unknown>>,
    pub r: Vec<Point<E, Unknown>>,
    pub a: E::Fs,
}

pub fn generate_challenges<T: Bn256Transcript>(
    ipa_proof: &IpaProof<Bn256>,
    transcript: &mut T,
) -> anyhow::Result<Vec<Fs>> {
    let mut challenges: Vec<Fs> = Vec::with_capacity(ipa_proof.l.len());
    for (l, r) in ipa_proof.l.iter().zip(&ipa_proof.r) {
        transcript.commit_point(l)?; // L[i]
        transcript.commit_point(r)?; // R[i]

        let c = transcript.get_challenge();
        challenges.push(c);
    }

    Ok(challenges)
}
