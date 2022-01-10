use ff::PrimeField;

use super::transcript::Transcript;

#[derive(Clone, Debug)]
pub struct IpaProof<F: PrimeField> {
  pub l: Vec<(F, F)>,
  pub r: Vec<(F, F)>,
  pub a: F,
}

pub fn generate_challenges<F: PrimeField, T: Transcript<F>>(
  ipa_proof: &IpaProof<F>,
  transcript: &mut T,
) -> anyhow::Result<Vec<F>> {
  let mut challenges: Vec<F> = Vec::with_capacity(ipa_proof.l.len());
  for (l, r) in ipa_proof.l.iter().zip(&ipa_proof.r) {
    transcript.commit_field_element(&l.0)?; // L[i]_x
    transcript.commit_field_element(&l.1)?; // L[i]_y
    transcript.commit_field_element(&r.0)?; // R[i]_x
    transcript.commit_field_element(&l.1)?; // R[i]_y

    let c = transcript.get_challenge();
    challenges.push(c);
  }

  Ok(challenges)
}
