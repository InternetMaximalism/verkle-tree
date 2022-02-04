pub mod config;
pub mod proof;
pub mod rns;
pub mod transcript;
pub mod utils;

use franklin_crypto::bellman::pairing::bn256::{Fr, G1};
use franklin_crypto::bellman::{CurveProjective, Field};

use self::config::IpaConfig;
use self::proof::{generate_challenges, IpaProof};
use self::transcript::{Bn256Transcript, PoseidonBn256Transcript};
use self::utils::{commit, fold_points, fold_scalars, inner_prod};

pub trait Ipa<G: CurveProjective, T: Bn256Transcript> {
    fn create_proof(
        commitment: G,
        a: &[<G as CurveProjective>::Scalar],
        eval_point: <G as CurveProjective>::Scalar,
        transcript_params: T::Params,
        ipa_conf: &IpaConfig<G>,
    ) -> anyhow::Result<IpaProof<G>>;

    fn check_proof(
        commitment: G,
        proof: IpaProof<G>,
        eval_point: <G as CurveProjective>::Scalar,
        inner_prod: <G as CurveProjective>::Scalar,
        transcript_params: T::Params,
        ipa_conf: &IpaConfig<G>,
    ) -> anyhow::Result<bool>;
}

pub struct Bn256Ipa;

#[cfg(test)]
mod tests {
    use franklin_crypto::bellman::pairing::bn256::{Fr, G1};

    use super::config::IpaConfig;
    use super::transcript::{Bn256Transcript, PoseidonBn256Transcript};
    use super::utils::{inner_prod, read_point_le, test_poly};
    use super::{Bn256Ipa, Ipa};

    #[test]
    fn test_ipa_proof_create_verify() -> Result<(), Box<dyn std::error::Error>> {
        let point: Fr = read_point_le(&123456789u64.to_le_bytes()).unwrap();
        let ipa_conf = &IpaConfig::<G1>::new();

        // Prover view
        let poly = test_poly::<Fr>(&[12, 97, 37, 0, 1, 208, 132, 3]);
        let prover_commitment = ipa_conf.commit(&poly).unwrap();

        let prover_transcript = PoseidonBn256Transcript::with_bytes(b"ipa");

        let proof = Bn256Ipa::create_proof(
            prover_commitment.clone(),
            &poly,
            point,
            prover_transcript.into_params(),
            ipa_conf,
        )?;

        let lagrange_coeffs = ipa_conf
            .precomputed_weights
            .compute_barycentric_coefficients(&point)?;
        let inner_product = inner_prod(&poly, &lagrange_coeffs)?;

        // test_serialize_deserialize_proof(proof);

        // Verifier view
        let verifier_commitment = prover_commitment.clone(); // In reality, the verifier will rebuild this themselves
        let verifier_transcript = PoseidonBn256Transcript::with_bytes(b"ipa");

        let success = Bn256Ipa::check_proof(
            verifier_commitment,
            proof,
            point,
            inner_product,
            verifier_transcript.into_params(),
            ipa_conf,
        )
        .unwrap();
        assert!(success, "inner product proof failed");

        Ok(())
    }
}

impl Ipa<G1, PoseidonBn256Transcript> for Bn256Ipa {
    fn create_proof(
        commitment: G1,
        a: &[Fr],
        eval_point: Fr,
        transcript_params: Fr,
        ipa_conf: &IpaConfig<G1>,
    ) -> anyhow::Result<IpaProof<G1>> {
        let mut transcript = PoseidonBn256Transcript::new(&transcript_params);
        let mut current_basis = ipa_conf.srs.clone();
        // let _commitment = commit(&current_basis.clone(), a, jubjub_params)?;
        // assert!(commitment.eq(&_commitment));

        let mut a = a.to_vec();
        let start = std::time::Instant::now();
        let mut b = ipa_conf
            .precomputed_weights
            .compute_barycentric_coefficients(&eval_point)?;
        println!(
            "compute barycentric coefficients of eval_point: {} s",
            start.elapsed().as_micros() as f64 / 1000000.0
        );
        if b.len() != ipa_conf.srs.len() {
            anyhow::bail!("`barycentric_coefficients` had incorrect length");
        }

        let ip = inner_prod(&a, &b)?;

        let start = std::time::Instant::now();
        transcript.commit_point(&commitment)?; // C
        transcript.commit_field_element(&eval_point)?; // input point
        transcript.commit_field_element(&ip)?; // output point
        let w = transcript.get_challenge(); // w
        println!(
            "update transcript: {} s",
            start.elapsed().as_micros() as f64 / 1000000.0
        );

        let q = ipa_conf.q.clone();
        let mut qw = q.clone();
        qw.mul_assign(w.clone());

        let num_rounds = ipa_conf.num_ipa_rounds;

        let mut ls = Vec::with_capacity(num_rounds);
        let mut rs = Vec::with_capacity(num_rounds);

        for _ in 0..num_rounds {
            let lap_start = std::time::Instant::now();

            let a_lr = a.chunks(a.len() / 2).collect::<Vec<_>>();
            let a_l = a_lr[0];
            let a_r = a_lr[1];
            let b_lr = b.chunks(b.len() / 2).collect::<Vec<_>>();
            let b_l = b_lr[0];
            let b_r = b_lr[1];
            let g_lr = current_basis
                .chunks(current_basis.len() / 2)
                .collect::<Vec<_>>();
            let g_l = g_lr[0];
            let g_r = g_lr[1];

            let z_l = inner_prod(&a_r, &b_l)?;
            let z_r = inner_prod(&a_l, &b_r)?;

            let start = std::time::Instant::now();
            let c_l_1 = commit(g_l, a_r)?;
            let c_l = commit(&[c_l_1, qw.clone()], &[Fr::one(), z_l])?;

            let c_r_1 = commit(g_r, a_l)?;
            let c_r = commit(&[c_r_1, qw.clone()], &[Fr::one(), z_r])?;
            println!(
                "commit: {} s",
                start.elapsed().as_micros() as f64 / 1000000.0
            );

            ls.push(c_l);
            rs.push(c_r);

            let start = std::time::Instant::now();
            transcript.commit_point(&c_l)?; // L
            transcript.commit_point(&c_r)?; // R
            println!(
                "update transcript: {} s",
                start.elapsed().as_micros() as f64 / 1000000.0
            );

            let x = transcript.get_challenge(); // x

            let x_inv = x
                .inverse()
                .ok_or(anyhow::anyhow!("cannot find inverse of `x`"))?;

            a = fold_scalars(&a_l, &a_r, &x)?;
            b = fold_scalars(&b_l, &b_r, &x_inv)?;
            current_basis = fold_points(&g_l, &g_r, x_inv.clone())?;

            println!(
                "lap: {} s",
                lap_start.elapsed().as_micros() as f64 / 1000000.0
            );
        }

        if a.len() != 1 {
            anyhow::bail!("`a`, `b` and `current_basis` should be 1 at the end of the reduction");
        }

        Ok(IpaProof {
            l: ls,
            r: rs,
            a: a[0],
        })
    }

    fn check_proof(
        commitment: G1,
        proof: IpaProof<G1>,
        eval_point: Fr,
        ip: Fr, // inner_prod
        transcript_params: Fr,
        ipa_conf: &IpaConfig<G1>,
    ) -> anyhow::Result<bool> {
        let mut transcript = PoseidonBn256Transcript::new(&transcript_params);

        // println!("{:?}", proof);
        if proof.l.len() != proof.r.len() {
            anyhow::bail!("L and R should be the same size");
        }

        if proof.l.len() != ipa_conf.num_ipa_rounds {
            anyhow::bail!(
                "The number of points for L or R should be equal to the number of rounds"
            );
        }

        // let bit_limit = None; // Some(256usize);
        let mut b = ipa_conf
            .precomputed_weights
            .compute_barycentric_coefficients(&eval_point)?;

        if b.len() != ipa_conf.srs.len() {
            anyhow::bail!("`barycentric_coefficients` had incorrect length");
        }

        transcript.commit_point(&commitment)?; // C
        transcript.commit_field_element(&eval_point)?; // input point
        transcript.commit_field_element(&ip)?; // output point

        let w = transcript.get_challenge();

        let q = ipa_conf.q.clone();
        let mut qw = q.clone();
        qw.mul_assign(w.clone());
        let mut qy = qw.clone();
        qy.mul_assign(ip.clone());
        let mut result_c = commitment.clone();
        result_c.add_assign(&qy);

        let challenges = generate_challenges(&proof.clone(), &mut transcript).unwrap();

        let mut challenges_inv: Vec<Fr> = Vec::with_capacity(challenges.len());

        // Compute expected commitment
        for (i, x) in challenges.iter().enumerate() {
            // println!("challenges_inv: {}/{}", i, challenges.len());
            let l = proof.l[i];
            let r = proof.r[i];

            let x_inv = x
                .inverse()
                .ok_or(anyhow::anyhow!("cannot find inverse of `x`"))?;
            challenges_inv.push(x_inv.clone());

            let one = Fr::one();
            result_c = commit(&[result_c, l, r], &[one, x.clone(), x_inv])?;
        }

        // println!("challenges_inv: {}/{}", challenges.len(), challenges.len());

        let mut current_basis = ipa_conf.srs.clone();

        println!("reduction starts");
        let start = std::time::Instant::now();

        for (_i, x_inv) in challenges_inv.iter().enumerate() {
            // println!("x_inv: {}/{}", _i, challenges_inv.len());
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

            b = fold_scalars(&b_l, &b_r, &x_inv.clone())?;
            current_basis = fold_points(&g_l, &g_r, x_inv.clone())?;
        }

        // println!("x_inv: {}/{}", challenges_inv.len(), challenges_inv.len());

        if b.len() != 1 {
            anyhow::bail!("`b` and `current_basis` should be 1 at the end of the reduction");
        }

        println!(
            "reduction ends: {} s",
            start.elapsed().as_micros() as f64 / 1000000.0
        );

        println!("verification check starts");
        let start = std::time::Instant::now();

        // Compute `result = a[0] * G[0] + (a[0] * b[0] * w) * Q`.
        let mut result1 = current_basis[0].clone();
        result1.mul_assign(proof.a.clone()); // result1 = a[0] * G[0]
        let mut part_2a = b[0].clone(); // part_2a = b[0]
        part_2a.mul_assign(&proof.a); // part_2a = a[0] * b[0]
        let mut result2 = qw.clone();
        result2.mul_assign(part_2a); // result2 = a[0] * b[0] * w * Q
        let mut result = result1.clone();
        result.add_assign(&result2); // result = result1 + result2

        // Ensure `commitment` is equal to `result`.
        let is_ok = result_c.eq(&result);

        println!(
            "verification check ends: {} s",
            start.elapsed().as_micros() as f64 / 1000000.0
        );

        Ok(is_ok)
    }
}
