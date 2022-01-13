use franklin_crypto::babyjubjub::{edwards::Point, JubjubEngine, Unknown};
use franklin_crypto::bellman::{Field, PrimeField};

use super::utils::{commit, from_bytes_le};

pub const NUM_IPA_ROUNDS: usize = 1; // log_2(common.POLY_DEGREE);
pub const DOMAIN_SIZE: usize = 2; // common.POLY_DEGREE;

#[derive(Clone, Debug)]
pub struct PrecomputedWeights<E: JubjubEngine> {
  // This stores A'(x_i) and 1/A'(x_i)
  pub barycentric_weights: Vec<E::Fr>,
  // This stores 1/k and -1/k for k \in [0, 255]
  pub inverted_domain: Vec<E::Fr>,
}

impl<E: JubjubEngine> PrecomputedWeights<E> {
  // Computes the coefficients `barycentric_coeffs` for a point `z` such that
  // when we have a polynomial `p` in lagrange basis, the inner product of `p` and `barycentric_coeffs`
  // is equal to p(z)
  // Note that `z` should not be in the domain
  // This can also be seen as the lagrange coefficients L_i(point)
  pub fn compute_barycentric_coefficients(&self, point: &E::Fr) -> anyhow::Result<Vec<E::Fr>> {
    // Compute A(x_i) * point - x_i
    let mut lagrange_evals: Vec<E::Fr> = Vec::with_capacity(DOMAIN_SIZE);
    for i in 0..DOMAIN_SIZE {
      let weight = self.barycentric_weights[i];
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
      lagrange_evals[i] = lagrange_evals[i].pow(minus_one.into_repr());
      lagrange_evals[i].mul_assign(&total_prod);
    }

    Ok(lagrange_evals)
  }

  pub fn get_inverted_element(&self, element: usize, is_neg: bool) -> E::Fr {
    assert!(element != 0, "cannot compute the inverse of zero");
    let mut index = element - 1;

    if is_neg {
      let midpoint = self.inverted_domain.len() / 2;
      index += midpoint;
    }

    return self.inverted_domain[index];
  }

  pub fn get_ratio_of_weights(&self, numerator: usize, denominator: usize) -> E::Fr {
    let a = self.barycentric_weights[numerator];
    let midpoint = self.barycentric_weights.len() / 2;
    let b = self.barycentric_weights[denominator + midpoint];

    let mut result = a;
    result.mul_assign(&b);
    result
  }

  pub fn divide_on_domain(&self, index: usize, f: &[E::Fr]) -> Vec<E::Fr> {
    let mut quotient = vec![E::Fr::zero(); DOMAIN_SIZE];

    let y = f[index];

    for i in 0..DOMAIN_SIZE {
      if i != index {
        // den = i - index
        let (abs_den, is_neg) = sub_abs(i, index);

        let den_inv = self.get_inverted_element(abs_den, is_neg);

        // compute q_i
        quotient[i] = f[i];
        quotient[i].sub_assign(&y);
        quotient[i].mul_assign(&den_inv);

        let weight_ratio = self.get_ratio_of_weights(index, i);
        let mut tmp = weight_ratio.clone();
        tmp.mul_assign(&quotient[i]);
        quotient[index].sub_assign(&tmp);
      }
    }

    quotient
  }
}

// Return (|a - b|, a < b).
fn sub_abs<N: std::ops::Sub<Output = N> + std::cmp::PartialOrd>(a: N, b: N) -> (N, bool) {
  if a < b {
    (b - a, true)
  } else {
    (a - b, false)
  }
}

#[derive(Clone)]
pub struct IpaConfig<E: JubjubEngine> {
  pub srs: Vec<Point<E, Unknown>>,
  pub q: Point<E, Unknown>,
  pub precomputed_weights: PrecomputedWeights<E>,
  pub num_ipa_rounds: usize,
}

impl<E: JubjubEngine> IpaConfig<E> {
  pub fn commit(
    &self,
    polynomial: &[E::Fr],
    jubjub_params: &E::Params,
  ) -> anyhow::Result<Point<E, Unknown>> {
    commit(&self.srs, polynomial, jubjub_params)
  }
}
