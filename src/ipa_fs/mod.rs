pub mod config;
pub mod proof;
pub mod transcript;
pub mod utils;

use franklin_crypto::babyjubjub::edwards::Point;
use franklin_crypto::babyjubjub::fs::Fs;
use franklin_crypto::babyjubjub::{JubjubEngine, Unknown};
use franklin_crypto::bellman::pairing::bn256::{Bn256, Fr};
use franklin_crypto::bellman::Field;

use crate::ipa_fr::utils::log2_ceil;
use crate::ipa_fs::config::Committer;

use self::config::IpaConfig;
use self::proof::{generate_challenges, IpaProof};
use self::transcript::{Bn256Transcript, PoseidonBn256Transcript};
use self::utils::{commit, fold_points, fold_scalars, inner_prod};

#[cfg(test)]
mod tests {
    use franklin_crypto::babyjubjub::fs::Fs;
    use franklin_crypto::babyjubjub::JubjubBn256;
    use franklin_crypto::bellman::pairing::bn256::Bn256;

    use crate::ipa_fr::utils::test_poly;

    use super::config::{Committer, IpaConfig};
    use super::proof::IpaProof;
    use super::transcript::{Bn256Transcript, PoseidonBn256Transcript};
    use super::utils::{inner_prod, read_field_element_le};

    #[test]
    fn test_ipa_fs_proof_create_verify() -> Result<(), Box<dyn std::error::Error>> {
        let domain_size = 256;
        let point: Fs = read_field_element_le(&123456789u64.to_le_bytes()).unwrap();
        let jubjub_params = &JubjubBn256::new();
        let ipa_conf = &IpaConfig::<Bn256>::new(domain_size, jubjub_params);

        // Prover view
        let poly = test_poly::<Fs>(&[12, 97, 37, 0, 1, 208, 132, 3], domain_size);
        let prover_commitment = ipa_conf.commit(&poly, jubjub_params).unwrap();

        let prover_transcript = PoseidonBn256Transcript::with_bytes(b"ipa");

        let (proof, inner_product) = IpaProof::create(
            prover_commitment.clone(),
            &poly,
            point,
            prover_transcript.into_params(),
            ipa_conf,
            jubjub_params,
        )?;

        // test_serialize_deserialize_proof(proof);

        // Verifier view
        let verifier_commitment = prover_commitment; // In reality, the verifier will rebuild this themselves
        let verifier_transcript = PoseidonBn256Transcript::with_bytes(b"ipa");

        let success = proof
            .check(
                verifier_commitment,
                point,
                inner_product,
                verifier_transcript.into_params(),
                ipa_conf,
                jubjub_params,
            )
            .unwrap();
        assert!(success, "inner product proof failed");

        Ok(())
    }
}

impl IpaProof<Bn256> {
    pub fn create(
        commitment: Point<Bn256, Unknown>,
        lagrange_poly: &[Fs],
        eval_point: Fs,
        transcript_params: Fr,
        ipa_conf: &IpaConfig<Bn256>,
        jubjub_params: &<Bn256 as JubjubEngine>::Params,
    ) -> anyhow::Result<(Self, <Bn256 as JubjubEngine>::Fs)> {
        dbg!(transcript_params);

        let mut transcript = PoseidonBn256Transcript::new(&transcript_params);
        let mut current_basis = ipa_conf.srs.clone();
        // let _commitment = commit(&current_basis.clone(), lagrange_poly, jubjub_params)?;
        // assert!(commitment.eq(&_commitment));

        let mut lagrange_poly = lagrange_poly.to_vec();
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

        let ip = inner_prod(&lagrange_poly, &b)?;

        let start = std::time::Instant::now();
        transcript.commit_point(&commitment)?; // C
        transcript.commit_field_element(&eval_point)?; // input point
        transcript.commit_field_element(&ip)?; // output point
        let w = transcript.get_challenge(); // w
        dbg!(w);

        println!(
            "update transcript: {} s",
            start.elapsed().as_micros() as f64 / 1000000.0
        );

        let q = ipa_conf.q.clone();
        let qw = q.mul(w, jubjub_params);

        let num_ipa_rounds = log2_ceil(ipa_conf.get_domain_size()) as usize;

        let mut ls = Vec::with_capacity(num_ipa_rounds);
        let mut rs = Vec::with_capacity(num_ipa_rounds);

        for _ in 0..num_ipa_rounds {
            let lap_start = std::time::Instant::now();

            let a_lr = lagrange_poly
                .chunks(lagrange_poly.len() / 2)
                .collect::<Vec<_>>();
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

            let z_l = inner_prod(a_r, b_l)?;
            let z_r = inner_prod(a_l, b_r)?;

            let start = std::time::Instant::now();
            let c_l_1 = commit(g_l, a_r, jubjub_params)?;
            let c_l = commit(&[c_l_1, qw.clone()], &[Fs::one(), z_l], jubjub_params)?;

            let c_r_1 = commit(g_r, a_l, jubjub_params)?;
            let c_r = commit(&[c_r_1, qw.clone()], &[Fs::one(), z_r], jubjub_params)?;
            println!(
                "commit: {} s",
                start.elapsed().as_micros() as f64 / 1000000.0
            );

            ls.push(c_l.clone());
            rs.push(c_r.clone());

            let start = std::time::Instant::now();
            transcript.commit_point(&c_l)?; // L
            transcript.commit_point(&c_r)?; // R
            println!(
                "update transcript: {} s",
                start.elapsed().as_micros() as f64 / 1000000.0
            );

            let x = transcript.get_challenge(); // x
            dbg!(x);

            let x_inv = x
                .inverse()
                .ok_or(anyhow::anyhow!("cannot find inverse of `x`"))?;

            lagrange_poly = fold_scalars(a_l, a_r, &x)?;
            b = fold_scalars(b_l, b_r, &x_inv)?;
            current_basis = fold_points(g_l, g_r, &x_inv, jubjub_params)?;

            println!(
                "lap: {} s",
                lap_start.elapsed().as_micros() as f64 / 1000000.0
            );
        }

        if lagrange_poly.len() != 1 {
            anyhow::bail!(
                "`lagrange_poly`, `b` and `current_basis` should be 1 at the end of the reduction"
            );
        }

        let ipa_proof = IpaProof {
            l: ls,
            r: rs,
            a: lagrange_poly[0],
        };

        Ok((ipa_proof, ip))
    }

    pub fn check(
        &self,
        commitment: Point<Bn256, Unknown>,
        eval_point: Fs,
        ip: Fs, // inner_prod
        transcript_params: Fr,
        ipa_conf: &IpaConfig<Bn256>,
        jubjub_params: &<Bn256 as JubjubEngine>::Params,
    ) -> anyhow::Result<bool> {
        let proof = self;
        let mut transcript = PoseidonBn256Transcript::new(&transcript_params);

        // println!("{:?}", proof);
        if proof.l.len() != proof.r.len() {
            anyhow::bail!("L and R should be the same size");
        }

        let num_ipa_rounds = log2_ceil(ipa_conf.get_domain_size()) as usize;
        if proof.l.len() != num_ipa_rounds {
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
        let qw = q.mul(w, jubjub_params);
        let qy = qw.mul(ip, jubjub_params);
        let mut result_c = commitment.add(&qy, jubjub_params);

        let challenges = generate_challenges(&proof, &mut transcript).unwrap();

        let mut challenges_inv: Vec<Fs> = Vec::with_capacity(challenges.len());

        // Compute expected commitment
        for (i, x) in challenges.iter().enumerate() {
            // println!("challenges_inv: {}/{}", i, challenges.len());
            let l = proof.l[i].clone();
            let r = proof.r[i].clone();

            let x_inv = x
                .inverse()
                .ok_or(anyhow::anyhow!("cannot find inverse of `x`"))?;
            challenges_inv.push(x_inv);

            let one = Fs::one();
            result_c = commit(&[result_c, l, r], &[one, *x, x_inv], jubjub_params)?;
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

            b = fold_scalars::<Fs>(&b_l, &b_r, &x_inv.clone())?;
            current_basis = fold_points(&g_l, &g_r, &x_inv.clone(), jubjub_params)?;
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
        let result1 = current_basis[0].mul(proof.a, jubjub_params); // result1 = a[0] * G[0]
        let mut part_2a = b[0]; // part_2a = b[0]
        part_2a.mul_assign(&proof.a); // part_2a = a[0] * b[0]
        let result2 = qw.mul(part_2a, jubjub_params); // result2 = a[0] * b[0] * w * Q
        let result = result1.add(&result2, jubjub_params); // result = result1 + result2

        // Ensure `commitment` is equal to `result`.
        let is_ok = result_c.eq(&result);

        println!(
            "verification check ends: {} s",
            start.elapsed().as_micros() as f64 / 1000000.0
        );

        Ok(is_ok)
    }
}
