use franklin_crypto::babyjubjub::{edwards::Point, JubjubEngine, PrimeOrder};
use franklin_crypto::bellman::{Field, PrimeField};

use super::utils::from_bytes_le;

pub const NUM_IPA_ROUNDS: usize = 1; // log_2(common.POLY_DEGREE);
pub const DOMAIN_SIZE: usize = 2; // common.POLY_DEGREE;

#[derive(Clone, Debug)]
pub struct PrecomputedWeights<E: JubjubEngine> {
  // This stores A'(x_i) and 1/A'(x_i)
  pub barycentric_weights: Vec<E::Fr>,
  // This stores 1/k and -1/k for k \in [0, 255]
  pub inverted_domain: Vec<E::Fr>,
}

// Computes the coefficients `barycentric_coeffs` for a point `z` such that
// when we have a polynomial `p` in lagrange basis, the inner product of `p` and `barycentric_coeffs`
// is equal to p(z)
// Note that `z` should not be in the domain
// This can also be seen as the lagrange coefficients L_i(point)
pub fn compute_barycentric_coefficients<E: JubjubEngine>(
  precomputed_weights: &PrecomputedWeights<E>,
  point: &E::Fr,
) -> anyhow::Result<Vec<E::Fr>> {
  // Compute A(x_i) * point - x_i
  let mut lagrange_evals: Vec<E::Fr> = Vec::with_capacity(DOMAIN_SIZE);
  for i in 0..DOMAIN_SIZE {
    let weight = precomputed_weights.barycentric_weights[i];
    let wrapped_i = from_bytes_le(&i.to_le_bytes()).unwrap();
    let mut eval = point.clone();
    eval.sub_assign(&wrapped_i);
    eval.mul_assign(&weight);
    lagrange_evals.push(eval);
  }

  let mut total_prod = E::Fr::one();
  for i in 0..DOMAIN_SIZE {
    let i_fr: E::Fr = from_bytes_le(&i.to_le_bytes())?;
    let mut tmp = point.clone();
    tmp.sub_assign(&i_fr);
    total_prod.mul_assign(&tmp);
  }

  let mut minus_one = E::Fs::one();
  minus_one.negate();

  for i in 0..DOMAIN_SIZE {
    // TODO: there was no batch inversion API.
    // TODO: once we fully switch over to bandersnatch
    // TODO: we can switch to batch invert API

    lagrange_evals[i] = lagrange_evals[i].pow(minus_one.into_repr());
    lagrange_evals[i].mul_assign(&total_prod);
  }

  Ok(lagrange_evals)
}

#[derive(Clone)]
pub struct IpaConfig<E: JubjubEngine> {
  pub srs: Vec<Point<E, PrimeOrder>>,
  pub q: Point<E, PrimeOrder>,
  pub precomputed_weights: PrecomputedWeights<E>,
  pub num_ipa_rounds: usize,
}
