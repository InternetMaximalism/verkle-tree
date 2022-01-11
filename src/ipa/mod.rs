pub mod config;
pub mod proof;
pub mod transcript;
pub mod utils;

use std::io::{Error, ErrorKind};

use franklin_crypto::babyjubjub::edwards::Point;
use franklin_crypto::babyjubjub::{JubjubEngine, Unknown};
use franklin_crypto::bellman::pairing::bn256::{Bn256, Fr};
use franklin_crypto::bellman::{Field, PrimeField};

use crate::ipa::config::{compute_barycentric_coefficients, IpaConfig};
use crate::ipa::proof::generate_challenges;
use crate::ipa::transcript::{Bn256Transcript, PoseidonBn256Transcript};
use crate::ipa::utils::{commit, fold_points, fold_scalars, fr_to_fs};

use self::proof::IpaProof;

pub trait Ipa<E: JubjubEngine> {
  fn check_ipa_proof(
    commitment: Point<E, Unknown>,
    proof: IpaProof<E::Fr>,
    eval_point: E::Fr,
    inner_prod: E::Fr,
    ipa_conf: IpaConfig<E>,
    jubjub_params: &E::Params,
    transcript_params: E::Fr,
  ) -> anyhow::Result<bool>;
}
pub struct Bn256Ipa;

impl Ipa<Bn256> for Bn256Ipa {
  fn check_ipa_proof(
    commitment: Point<Bn256, Unknown>,
    proof: IpaProof<Fr>,
    eval_point: Fr,
    inner_prod: Fr,
    ipa_conf: IpaConfig<Bn256>,
    jubjub_params: &<Bn256 as JubjubEngine>::Params,
    transcript_params: Fr,
  ) -> anyhow::Result<bool> {
    let mut transcript = PoseidonBn256Transcript::new(&transcript_params);
    // transcript.consume("ipa", cs);

    // println!("{:?}", self.proof);
    if proof.l.len() != proof.r.len() {
      return Err(Error::new(ErrorKind::InvalidData, "L and R should be the same size").into());
    }

    if proof.l.len() != ipa_conf.num_ipa_rounds {
      return Err(
        Error::new(
          ErrorKind::InvalidData,
          "The number of points for L or R should be equal to the number of rounds",
        )
        .into(),
      );
    }

    // let bit_limit = None; // Some(256usize);
    let mut b = compute_barycentric_coefficients(&ipa_conf.precomputed_weights, &eval_point)?;

    if b.len() != ipa_conf.srs.len() {
      return Err(
        Error::new(
          ErrorKind::InvalidData,
          "`barycentric_coefficients` had incorrect length",
        )
        .into(),
      );
    }

    let (c_x, c_y) = commitment.into_xy();
    transcript.commit_field_element(&c_x)?;
    transcript.commit_field_element(&c_y)?;
    transcript.commit_field_element(&eval_point)?;
    transcript.commit_field_element(&inner_prod)?;
    // transcript.commit_field_element(&commitment.get_x().get_value().unwrap()); // C_x
    // transcript.commit_field_element(&commitment.get_y().get_value().unwrap()); // C_y
    // transcript.commit_field_element(&eval_point.get_value().unwrap()); // input point
    // transcript.commit_field_element(&inner_prod.get_value().unwrap()); // output point

    let w = transcript.get_challenge();

    let q = ipa_conf.q.clone();
    let qy = ipa_conf.q.clone();
    let q = q.mul(fr_to_fs::<Bn256>(&w)?, &jubjub_params);
    let qy = qy.mul(fr_to_fs::<Bn256>(&inner_prod)?, &jubjub_params);
    let mut commitment = commitment.add(&Point::<Bn256, Unknown>::from(qy.clone()), &jubjub_params);

    let challenges = generate_challenges(&proof.clone(), &mut transcript).unwrap();

    let mut challenges_inv: Vec<Fr> = Vec::with_capacity(challenges.len());

    let mut minus_one = <Bn256 as JubjubEngine>::Fs::one();
    minus_one.negate();

    // Compute expected commitment
    for (i, x) in challenges.iter().enumerate() {
      println!("challenges_inv: {}/{}", i, challenges.len());
      let l = Point::<Bn256, Unknown>::get_for_y(proof.l[i].1, true, &jubjub_params).unwrap();
      let r = Point::<Bn256, Unknown>::get_for_y(proof.r[i].1, true, &jubjub_params).unwrap();

      let x_inv = x.pow(minus_one.into_repr());
      challenges_inv.push(x_inv.clone());

      let one = Fr::one();
      commitment = commit(
        &[commitment, l, r],
        &[one, x.clone(), x_inv],
        &jubjub_params,
      )?;
    }

    println!("challenges_inv: {}/{}", challenges.len(), challenges.len());

    let mut current_basis = ipa_conf.srs;

    println!("reduction starts");
    let start = std::time::Instant::now();

    for (i, x_inv) in challenges_inv.iter().enumerate() {
      println!("x_inv: {}/{}", i, challenges_inv.len());
      assert_eq!(
        current_basis.len() % 2,
        0,
        "cannot split `current_basis` in half"
      );
      let mut g_chunks = current_basis.chunks(current_basis.len() / 2);
      let g_l = g_chunks.next().unwrap().to_vec();
      let g_r = g_chunks.next().unwrap().to_vec();

      let mut b_chunks = b.chunks(b.len() / 2);
      let b_l = b_chunks.next().unwrap().to_vec();
      let b_r = b_chunks.next().unwrap().to_vec();

      b = fold_scalars::<Fr>(&b_l, &b_r, x_inv)?;
      current_basis = fold_points::<Bn256>(&g_l, &g_r, &fr_to_fs::<Bn256>(x_inv)?, &jubjub_params)?;
    }

    println!("x_inv: {}/{}", challenges_inv.len(), challenges_inv.len());

    if b.len() != 1 {
      return Err(
        Error::new(
          ErrorKind::InvalidData,
          "`b` and `current_basis` should be 1",
        )
        .into(),
      );
    }

    println!(
      "reduction ends: {} s",
      start.elapsed().as_millis() as f64 / 1000.0
    );

    println!("verification check starts");
    let start = std::time::Instant::now();

    // Compute `result = G[0] * a + (a * b[0]) * Q`.
    let mut result1 = current_basis[0].clone(); // result1 = G[0]
    let mut part_2a = b[0].clone(); // part_2a = b[0]

    result1 = result1.mul(fr_to_fs::<Bn256>(&proof.a)?, &jubjub_params); // result1 *= proof_a

    part_2a.mul_assign(&proof.a); // part_2a *= proof_a
    let mut result2 = q;
    result2 = result2.mul(fr_to_fs::<Bn256>(&part_2a)?, &jubjub_params); // q *= part_2a

    let result = Point::<Bn256, Unknown>::from(result1.add(&result2, &jubjub_params)); // result = result1 + result2

    // Ensure `commitment` is equal to `result`.
    let is_ok = commitment.eq(&result);

    println!(
      "verification check ends: {} s",
      start.elapsed().as_millis() as f64 / 1000.0
    );

    Ok(is_ok)
  }
}
