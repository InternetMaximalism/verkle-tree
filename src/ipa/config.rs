use franklin_crypto::babyjubjub::{edwards::Point, JubjubEngine, Unknown};
use franklin_crypto::babyjubjub::{FixedGenerators, JubjubParams};
use franklin_crypto::bellman::{Field, PrimeField};

use super::utils::{commit, generate_random_points, log2_ceil, read_point_le};

pub const NUM_IPA_ROUNDS: usize = 8; // log_2(common.POLY_DEGREE);
pub const DOMAIN_SIZE: usize = 256; // common.POLY_DEGREE;

// computes A'(x_j) where x_j must be an element in the domain
// This is computed as the product of x_j - x_i where x_i is an element in the domain
// and x_i is not equal to x_j
pub fn compute_barycentric_weight_for_element<F: PrimeField>(element: usize) -> F {
    assert!(
        element < DOMAIN_SIZE,
        "the domain is [0, {}], {} is not in the domain",
        DOMAIN_SIZE - 1,
        element
    );

    let domain_element_fr = read_point_le::<F>(&element.to_le_bytes()).unwrap();

    let mut total = F::one();

    for i in 0..DOMAIN_SIZE {
        if i == element {
            continue;
        }

        let i_fr = read_point_le::<F>(&i.to_le_bytes()).unwrap();

        let mut tmp = domain_element_fr;
        tmp.sub_assign(&i_fr);
        total.mul_assign(&tmp);
    }

    total
}

#[derive(Clone, Debug)]
pub struct PrecomputedWeights<E: JubjubEngine> {
    // This stores A'(x_i) and 1/A'(x_i)
    pub barycentric_weights: Vec<E::Fs>,
    // This stores 1/k and -1/k for k \in [0, 255]
    pub inverted_domain: Vec<E::Fs>,
}

impl<E: JubjubEngine> Default for PrecomputedWeights<E> {
    fn default() -> Self {
        // Imagine we have two arrays of the same length and we concatenate them together
        // This is how we will store the A'(x_i) and 1/A'(x_i)
        // This midpoint variable is used to compute the offset that we need
        // to place 1/A'(x_i)
        let midpoint = DOMAIN_SIZE;

        // Note there are DOMAIN_SIZE number of weights, but we are also storing their inverses
        // so we need double the amount of space
        let mut barycentric_weights = vec![E::Fs::zero(); midpoint * 2];
        for i in 0..midpoint {
            let weight: E::Fs = compute_barycentric_weight_for_element(i);
            let inv_weight = weight.inverse().unwrap();

            barycentric_weights[i] = weight;
            barycentric_weights[i + midpoint] = inv_weight;
        }

        // Computing 1/k and -1/k for k \in [0, 255]
        // Note that since we cannot do 1/0, we have one less element
        let midpoint = DOMAIN_SIZE - 1;
        let mut inverted_domain = vec![E::Fs::zero(); midpoint * 2];
        for i in 1..DOMAIN_SIZE {
            let k = read_point_le::<E::Fs>(&i.to_le_bytes()).unwrap();
            let k = k.inverse().unwrap();

            let mut negative_k = E::Fs::zero();
            negative_k.sub_assign(&k);

            inverted_domain[i - 1] = k;
            inverted_domain[(i - 1) + midpoint] = negative_k;
        }

        Self {
            barycentric_weights,
            inverted_domain,
        }
    }
}

impl<E: JubjubEngine> PrecomputedWeights<E> {
    pub fn new() -> Self {
        Self::default()
    }

    // Computes the coefficients `barycentric_coeffs` for a point `z` such that
    // when we have a polynomial `p` in lagrange basis, the inner product of `p` and `barycentric_coeffs`
    // is equal to p(z)
    // Note that `z` should not be in the domain
    // This can also be seen as the lagrange coefficients L_i(point)
    pub fn compute_barycentric_coefficients(&self, point: &E::Fs) -> anyhow::Result<Vec<E::Fs>> {
        // Compute A(x_i) * point - x_i
        let mut lagrange_evals: Vec<E::Fs> = Vec::with_capacity(DOMAIN_SIZE);
        let mut total_prod = E::Fs::one();
        for i in 0..DOMAIN_SIZE {
            let weight = self.barycentric_weights[i];
            let mut tmp: E::Fs = read_point_le(&i.to_le_bytes())?;
            tmp.sub_assign(point);
            tmp.negate();
            total_prod.mul_assign(&tmp); // total_prod *= (point - i)

            tmp.mul_assign(&weight);
            lagrange_evals.push(tmp); // lagrange_evals[i] = (point - i) * weight
        }

        // TODO: Calculate the inverses of all elements together.
        let mut lagrange_evals = {
            let mut tmp = vec![];
            for eval in lagrange_evals {
                let inverse_of_eval = eval.inverse().ok_or(anyhow::anyhow!(
                    "cannot find inverse of `lagrange_evals[i]`"
                ))?; // lagrange_evals[i] = 1 / ((point - i) * weight)
                tmp.push(inverse_of_eval);
            }

            tmp
        };

        for lagrange_evals_i in lagrange_evals.iter_mut() {
            lagrange_evals_i.mul_assign(&total_prod); // lagrange_evals[i] = total_prod / ((point - i) * weight)
        }

        Ok(lagrange_evals)
    }

    pub fn get_inverted_element(&self, element: usize, is_neg: bool) -> E::Fs {
        assert!(element != 0, "cannot compute the inverse of zero");
        let mut index = element - 1;

        if is_neg {
            let midpoint = self.inverted_domain.len() / 2;
            index += midpoint;
        }

        self.inverted_domain[index]
    }

    pub fn get_ratio_of_weights(&self, numerator: usize, denominator: usize) -> E::Fs {
        let a = self.barycentric_weights[numerator];
        let midpoint = self.barycentric_weights.len() / 2;
        let b = self.barycentric_weights[denominator + midpoint];

        let mut result = a;
        result.mul_assign(&b);
        result
    }

    // Computes f(x) - f(x_i) / x - x_i where x_i is an element in the domain.
    pub fn divide_on_domain(&self, index: usize, f: &[E::Fs]) -> Vec<E::Fs> {
        let mut quotient = vec![E::Fs::zero(); DOMAIN_SIZE];

        let y = f[index];

        for i in 0..DOMAIN_SIZE {
            if i != index {
                // den = i - index
                let (abs_den, is_neg) = sub_abs(i, index); // den = i - index

                let den_inv = self.get_inverted_element(abs_den, is_neg);

                // compute q_i
                quotient[i] = f[i];
                quotient[i].sub_assign(&y);
                quotient[i].mul_assign(&den_inv); // quotient[i] = (f[i] - f[index]) / (i - index)

                let weight_ratio = self.get_ratio_of_weights(index, i);
                let mut tmp = weight_ratio;
                tmp.mul_assign(&quotient[i]); // tmp = weight_ratio * quotient[i]
                quotient[index].sub_assign(&tmp); // quotient[index] -= tmp
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
    pub fn new(jubjub_params: &E::Params) -> Self {
        let start = std::time::Instant::now();
        let srs = generate_random_points(DOMAIN_SIZE, jubjub_params).unwrap();
        println!("{:?}", srs[0].into_xy());
        println!("{:?}", srs[1].into_xy());
        println!("srs: {} s", start.elapsed().as_micros() as f64 / 1000000.0);
        let q = Point::<E, Unknown>::from(
            jubjub_params
                .generator(FixedGenerators::ProofGenerationKey)
                .clone(),
        );
        let precomputed_weights = PrecomputedWeights::new();
        let num_ipa_rounds = log2_ceil(DOMAIN_SIZE);

        Self {
            srs,
            q,
            precomputed_weights,
            num_ipa_rounds,
        }
    }

    pub fn commit(
        &self,
        polynomial: &[E::Fs],
        jubjub_params: &E::Params,
    ) -> anyhow::Result<Point<E, Unknown>> {
        commit(&self.srs, polynomial, jubjub_params)
    }
}
