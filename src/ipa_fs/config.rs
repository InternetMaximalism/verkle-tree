use franklin_crypto::babyjubjub::{edwards, JubjubEngine, Unknown};
use franklin_crypto::babyjubjub::{FixedGenerators, JubjubParams};

use crate::ipa_fr::config::PrecomputedWeights;

use super::utils::{commit, generate_random_points};

pub const NUM_IPA_ROUNDS: usize = 8; // log_2(common.POLY_DEGREE);
pub const DOMAIN_SIZE: usize = 256; // common.POLY_DEGREE;

#[derive(Clone)]
pub struct IpaConfig<E: JubjubEngine> {
    pub srs: Vec<edwards::Point<E, Unknown>>,
    pub q: edwards::Point<E, Unknown>,
    pub precomputed_weights: PrecomputedWeights<E::Fs>,
}

impl<E: JubjubEngine> IpaConfig<E> {
    pub fn new(domain_size: usize, jubjub_params: &E::Params) -> Self {
        let start = std::time::Instant::now();
        let srs = generate_random_points(domain_size, jubjub_params).unwrap();
        println!("srs: {} s", start.elapsed().as_micros() as f64 / 1000000.0);
        let q = edwards::Point::<E, Unknown>::from(
            jubjub_params
                .generator(FixedGenerators::ProofGenerationKey)
                .clone(),
        );
        let precomputed_weights = PrecomputedWeights::new(domain_size);

        Self {
            srs,
            q,
            precomputed_weights,
        }
    }

    pub fn get_srs(&self) -> &Vec<edwards::Point<E, Unknown>> {
        &self.srs
    }

    pub fn get_q(&self) -> &edwards::Point<E, Unknown> {
        &self.q
    }

    pub fn get_precomputed_weights(&self) -> &PrecomputedWeights<E::Fs> {
        &self.precomputed_weights
    }
}

pub trait Committer<E: JubjubEngine> {
    type Err: Send + Sync + 'static;

    fn get_domain_size(&self) -> usize;

    fn commit(
        &self,
        polynomial: &[E::Fs],
        jubjub_params: &E::Params,
    ) -> Result<edwards::Point<E, Unknown>, Self::Err>;
}

impl<E: JubjubEngine> Committer<E> for IpaConfig<E> {
    type Err = anyhow::Error;

    fn get_domain_size(&self) -> usize {
        self.precomputed_weights.get_domain_size()
    }

    fn commit(
        &self,
        polynomial: &[E::Fs],
        jubjub_params: &E::Params,
    ) -> anyhow::Result<edwards::Point<E, Unknown>> {
        let basis = &self.srs;
        let result = commit(basis, polynomial, jubjub_params)?;

        Ok(result)
    }
}
