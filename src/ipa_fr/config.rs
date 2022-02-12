use franklin_crypto::bellman::{CurveAffine, CurveProjective, Field, PrimeField};

use super::utils::{commit, generate_random_points, log2_ceil, read_field_element_le};

// pub const NUM_IPA_ROUNDS: usize = 1; // log_2(common.POLY_DEGREE);
// pub const DOMAIN_SIZE: usize = 2; // common.POLY_DEGREE;

// computes A'(x_j) where x_j must be an element in the domain
// This is computed as the product of x_j - x_i where x_i is an element in the domain
// and x_i is not equal to x_j
pub fn compute_barycentric_weight_for_element<F: PrimeField>(
    element: usize,
    domain_size: usize,
) -> F {
    assert!(
        element < domain_size,
        "the domain is [0, {}], {} is not in the domain",
        domain_size - 1,
        element
    );

    let domain_element_fr = read_field_element_le::<F>(&element.to_le_bytes()).unwrap();

    let mut total = F::one();

    for i in 0..domain_size {
        if i == element {
            continue;
        }

        let i_fr = read_field_element_le::<F>(&i.to_le_bytes()).unwrap();

        let mut tmp = domain_element_fr;
        tmp.sub_assign(&i_fr);
        total.mul_assign(&tmp);
    }

    total
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrecomputedWeights<F: PrimeField> {
    // This stores A'(x_i) and 1/A'(x_i)
    pub barycentric_weights: Vec<F>,
    // This stores 1/k and -1/k for k \in [0, 255]
    pub inverted_domain: Vec<F>,
    pub num_ipa_rounds: u32,
}

impl<F: PrimeField> PrecomputedWeights<F> {
    fn new(domain_size: usize) -> Self {
        // Imagine we have two arrays of the same length and we concatenate them together
        // This is how we will store the A'(x_i) and 1/A'(x_i)
        // This midpoint variable is used to compute the offset that we need
        // to place 1/A'(x_i)
        let midpoint = domain_size;

        // Note there are DOMAIN_SIZE number of weights, but we are also storing their inverses
        // so we need double the amount of space
        let mut barycentric_weights = vec![<F as Field>::zero(); midpoint * 2];
        for i in 0..midpoint {
            let weight: F = compute_barycentric_weight_for_element(i, domain_size);
            let inv_weight = weight.inverse().unwrap();

            barycentric_weights[i] = weight;
            barycentric_weights[i + midpoint] = inv_weight;
        }

        // Computing 1/k and -1/k for k \in [0, 255]
        // Note that since we cannot do 1/0, we have one less element
        let midpoint = domain_size - 1;
        let mut inverted_domain = vec![<F as Field>::zero(); midpoint * 2];
        for i in 1..domain_size {
            let k = read_field_element_le::<F>(&i.to_le_bytes()).unwrap();
            let k = k.inverse().unwrap();

            let mut negative_k = <F as Field>::zero();
            negative_k.sub_assign(&k);

            inverted_domain[i - 1] = k;
            inverted_domain[(i - 1) + midpoint] = negative_k;
        }

        let num_ipa_rounds = log2_ceil(domain_size);

        Self {
            barycentric_weights,
            inverted_domain,
            num_ipa_rounds,
        }
    }

    // Computes the coefficients `barycentric_coeffs` for a point `z` such that
    // when we have a polynomial `p` in lagrange basis, the inner product of `p` and `barycentric_coeffs`
    // is equal to p(z)
    // Note that `z` should not be in the domain
    // This can also be seen as the lagrange coefficients L_i(point)
    pub fn compute_barycentric_coefficients(&self, point: &F) -> anyhow::Result<Vec<F>> {
        let domain_size = 2usize.pow(self.num_ipa_rounds);

        // Compute A(x_i) * point - x_i
        let mut lagrange_evals: Vec<F> = Vec::with_capacity(domain_size);
        let mut total_prod = F::one();
        for i in 0..domain_size {
            let weight = self.barycentric_weights[i];
            let mut tmp = read_field_element_le::<F>(&i.to_le_bytes())?;
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

        for eval in lagrange_evals.iter_mut() {
            eval.mul_assign(&total_prod); // lagrange_evals[i] = total_prod / ((point - i) * weight)
        }

        Ok(lagrange_evals)
    }

    pub fn get_inverted_element(&self, element: usize, is_neg: bool) -> F {
        assert!(element != 0, "cannot compute the inverse of zero");
        let mut index = element - 1;

        if is_neg {
            let midpoint = self.inverted_domain.len() / 2;
            index += midpoint;
        }

        self.inverted_domain[index]
    }

    pub fn get_ratio_of_weights(&self, numerator: usize, denominator: usize) -> F {
        let a = self.barycentric_weights[numerator];
        let midpoint = self.barycentric_weights.len() / 2;
        let b = self.barycentric_weights[denominator + midpoint];

        let mut result = a;
        result.mul_assign(&b);
        result
    }

    // Computes f(x) - f(x_i) / x - x_i where x_i is an element in the domain.
    pub fn divide_on_domain(&self, index: usize, f: &[F]) -> Vec<F> {
        let domain_size = 2usize.pow(self.num_ipa_rounds);

        let mut quotient = vec![<F as Field>::zero(); domain_size];

        let y = f[index];

        for i in 0..domain_size {
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpaConfig<G: CurveProjective> {
    pub srs: Vec<G::Affine>,
    pub q: G::Affine,
    pub precomputed_weights: PrecomputedWeights<G::Scalar>,
}

impl<G: CurveProjective> IpaConfig<G>
where
    <G::Affine as CurveAffine>::Base: PrimeField,
{
    pub fn new(domain_size: usize) -> Self {
        let start = std::time::Instant::now();
        let srs = generate_random_points::<G>(domain_size).unwrap();
        println!("srs: {} s", start.elapsed().as_micros() as f64 / 1000000.0);
        let q = <G::Affine as CurveAffine>::one();
        let precomputed_weights = PrecomputedWeights::new(domain_size);

        Self {
            srs,
            q,
            precomputed_weights,
        }
    }
}

pub trait Committer<GA: CurveAffine> {
    type Err: Send + Sync + 'static;

    fn commit(&self, polynomial: &[GA::Scalar]) -> Result<GA, Self::Err>;
}

impl<G: CurveProjective> Committer<G::Affine> for IpaConfig<G> {
    type Err = anyhow::Error;

    fn commit(
        &self,
        polynomial: &[<G::Affine as CurveAffine>::Scalar],
    ) -> anyhow::Result<G::Affine> {
        let result = commit::<G>(
            &self
                .srs
                .iter()
                .map(|x| x.into_projective())
                .collect::<Vec<_>>(),
            polynomial,
        )?
        .into_affine();

        Ok(result)
    }
}
