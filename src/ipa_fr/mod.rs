pub mod config;
pub mod proof;
pub mod rns;
pub mod transcript;
pub mod utils;

use franklin_crypto::bellman::pairing::bn256::{Bn256, Fr, G1Affine};
use franklin_crypto::bellman::{CurveAffine, CurveProjective, Field};

use crate::ipa_fr::config::Committer;
use crate::ipa_fr::utils::log2_ceil;

use self::config::IpaConfig;
use self::proof::{generate_challenges, IpaProof};
use self::rns::BaseRnsParameters;
use self::transcript::{Bn256Transcript, PoseidonBn256Transcript};
use self::utils::{commit, fold_points, fold_scalars, inner_prod};

#[cfg(test)]
mod tests {
    use franklin_crypto::bellman::pairing::bn256::{Bn256, Fr, G1Affine};

    use crate::ipa_fr::proof::IpaProof;
    use crate::ipa_fr::rns::BaseRnsParameters;

    use super::config::{Committer, IpaConfig};
    use super::transcript::{Bn256Transcript, PoseidonBn256Transcript};
    use super::utils::{read_field_element_le, test_poly};

    #[test]
    fn test_ipa_fr_proof_create_verify() -> Result<(), Box<dyn std::error::Error>> {
        let point: Fr = read_field_element_le(&123456789u64.to_le_bytes()).unwrap();

        // Prover view

        let poly = vec![12, 97];
        // let poly = vec![12, 97, 37, 0, 1, 208, 132, 3];
        let domain_size = poly.len();
        let ipa_conf = &IpaConfig::<G1Affine>::new(domain_size);
        let rns_params = &BaseRnsParameters::<Bn256>::new_for_field(68, 110, 4);

        let padded_poly = test_poly::<Fr>(&poly, domain_size);
        let prover_commitment = ipa_conf.commit(&padded_poly).unwrap();

        let prover_transcript = PoseidonBn256Transcript::with_bytes(b"ipa");

        let (proof, inner_product) = IpaProof::<G1Affine>::create(
            prover_commitment,
            &padded_poly,
            point,
            prover_transcript.into_params(),
            rns_params,
            ipa_conf,
        )?;

        // Verifier view

        let verifier_commitment = prover_commitment; // In reality, the verifier will rebuild this themselves.
        let verifier_transcript = PoseidonBn256Transcript::with_bytes(b"ipa");

        let success = proof
            .check(
                verifier_commitment,
                point,
                inner_product,
                verifier_transcript.into_params(),
                rns_params,
                ipa_conf,
            )
            .unwrap();
        assert!(success, "inner product proof failed");

        Ok(())
    }
}

/// Create a proof which shows `inner_prod = f(eval_point)` and verify it.
/// Here, f(z) is a `G::Scalar`-polynomial of degree at most `domain_size - 1`,
///
/// `lagrange_poly` is a `G::Scalar`-array which satisfies
/// `lagrange_poly[z] = f(z)` for any integer z in [0, `domain_size`).
///
/// `commitment` must be equal to `ipa_conf.commit(&lagrange_poly)`.
///
/// `eval_point` and `inner_prod` are elements in `G::Scalar`.
///
/// `transcript_params` is a initialization parameter of the transcript `T`.
impl IpaProof<G1Affine> {
    /// Create a proof which shows `inner_prod = f(eval_point)`.
    pub fn create(
        commitment: G1Affine,
        lagrange_poly: &[Fr],
        eval_point: Fr,
        transcript_params: Fr,
        rns_params: &BaseRnsParameters<Bn256>,
        ipa_conf: &IpaConfig<G1Affine>,
    ) -> anyhow::Result<(Self, Fr)> {
        let mut transcript = PoseidonBn256Transcript::new(&transcript_params);
        let mut current_basis = ipa_conf
            .get_srs()
            .iter()
            .map(|x| x.into_projective())
            .collect::<Vec<_>>();
        if cfg!(debug_assertions) {
            assert!(commitment.eq(&ipa_conf.commit(lagrange_poly).unwrap()));
        }

        let mut a = lagrange_poly.to_vec();
        let start = std::time::Instant::now();
        let mut b = ipa_conf
            .get_precomputed_weights()
            .compute_barycentric_coefficients(&eval_point)?;
        println!(
            "compute barycentric coefficients of eval_point: {} s",
            start.elapsed().as_micros() as f64 / 1000000.0
        );
        if b.len() != current_basis.len() {
            anyhow::bail!("`barycentric_coefficients` had incorrect length");
        }

        let ip = inner_prod(&a, &b)?;

        let start = std::time::Instant::now();
        transcript.commit_point(&commitment, rns_params)?; // C
        transcript.commit_field_element(&eval_point)?; // input point
        transcript.commit_field_element(&ip)?; // output point
        let w = transcript.get_challenge(); // w
        println!(
            "update transcript: {} s",
            start.elapsed().as_micros() as f64 / 1000000.0
        );

        let q = ipa_conf.get_q().into_projective();
        let mut qw = q;
        qw.mul_assign(w);

        let domain_size = ipa_conf.get_precomputed_weights().get_domain_size();
        let num_rounds = log2_ceil(domain_size) as usize;

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

            let z_l = inner_prod(a_r, b_l)?;
            let z_r = inner_prod(a_l, b_r)?;

            let start = std::time::Instant::now();
            let c_l_1 = commit(g_l, a_r)?;
            let c_l = commit(&[c_l_1, qw], &[Fr::one(), z_l])?.into_affine();

            let c_r_1 = commit(g_r, a_l)?;
            let c_r = commit(&[c_r_1, qw], &[Fr::one(), z_r])?.into_affine();
            println!(
                "commit: {} s",
                start.elapsed().as_micros() as f64 / 1000000.0
            );

            ls.push(c_l);
            rs.push(c_r);

            let start = std::time::Instant::now();
            transcript.commit_point(&c_l, rns_params)?; // L
            transcript.commit_point(&c_r, rns_params)?; // R
            println!(
                "update transcript: {} s",
                start.elapsed().as_micros() as f64 / 1000000.0
            );

            let x = transcript.get_challenge(); // x

            let x_inv = x
                .inverse()
                .ok_or(anyhow::anyhow!("cannot find inverse of `x`"))?;

            a = fold_scalars(a_l, a_r, &x)?;
            b = fold_scalars(b_l, b_r, &x_inv)?;
            current_basis = fold_points(g_l, g_r, x_inv)?;

            println!(
                "lap: {} s",
                lap_start.elapsed().as_micros() as f64 / 1000000.0
            );
        }

        if a.len() != 1 {
            anyhow::bail!("`a`, `b` and `current_basis` should be 1 at the end of the reduction");
        }

        Ok((
            IpaProof {
                l: ls,
                r: rs,
                a: a[0],
            },
            ip,
        ))
    }

    /// Verify given `proof`.
    pub fn check(
        &self,
        commitment: G1Affine,
        eval_point: Fr,
        ip: Fr, // inner_prod
        transcript_params: Fr,
        rns_params: &BaseRnsParameters<Bn256>,
        ipa_conf: &IpaConfig<G1Affine>,
    ) -> anyhow::Result<bool> {
        let proof = self;
        let mut transcript = PoseidonBn256Transcript::new(&transcript_params);

        // println!("{:?}", proof);
        if proof.l.len() != proof.r.len() {
            anyhow::bail!("L and R should be the same size");
        }

        let domain_size = ipa_conf.get_domain_size();
        let num_rounds = log2_ceil(domain_size) as usize;
        if proof.l.len() != num_rounds {
            anyhow::bail!(
                "The number of points for L or R should be equal to the number of rounds"
            );
        }

        let mut b = ipa_conf
            .get_precomputed_weights()
            .compute_barycentric_coefficients(&eval_point)?;

        if b.len() != ipa_conf.get_srs().len() {
            anyhow::bail!("`barycentric_coefficients` had incorrect length");
        }

        transcript.commit_point(&commitment, rns_params)?; // C
        transcript.commit_field_element(&eval_point)?; // input point
        transcript.commit_field_element(&ip)?; // output point

        let w = transcript.get_challenge();

        let q = ipa_conf.get_q().into_projective();
        let mut qw = q;
        qw.mul_assign(w);
        let mut qy = qw;
        qy.mul_assign(ip);
        let mut result_c = commitment.into_projective();
        result_c.add_assign(&qy);

        let challenges = generate_challenges(proof, rns_params, &mut transcript).unwrap();

        let mut challenges_inv: Vec<Fr> = Vec::with_capacity(challenges.len());

        // Compute expected commitment
        for (i, x) in challenges.iter().enumerate() {
            // println!("challenges_inv: {}/{}", i, challenges.len());
            let l = proof.l[i].into_projective();
            let r = proof.r[i].into_projective();

            let x_inv = x
                .inverse()
                .ok_or(anyhow::anyhow!("cannot find inverse of `x`"))?;
            challenges_inv.push(x_inv);

            let one = Fr::one();
            result_c = commit(&[result_c, l, r], &[one, *x, x_inv])?;
        }

        // println!("challenges_inv: {}/{}", challenges.len(), challenges.len());

        let mut current_basis = ipa_conf
            .get_srs()
            .iter()
            .map(|x| x.into_projective())
            .collect::<Vec<_>>();

        println!("reduction starts");
        let start = std::time::Instant::now();

        for (_i, x_inv) in challenges_inv.iter().enumerate() {
            // println!("x_inv: {}/{}", _i, challenges_inv.len());
            assert_eq!(
                current_basis.len() % 2,
                0,
                "cannot split `current_basis` in half"
            );

            // Split the vector G into 2 parts.
            let mut g_chunks = current_basis.chunks(current_basis.len() / 2);
            let g_l = g_chunks.next().unwrap().to_vec();
            let g_r = g_chunks.next().unwrap().to_vec();

            // Split the vector b into 2 parts.
            let mut b_chunks = b.chunks(b.len() / 2);
            let b_l = b_chunks.next().unwrap().to_vec();
            let b_r = b_chunks.next().unwrap().to_vec();

            b = fold_scalars(&b_l, &b_r, &x_inv.clone())?;
            current_basis = fold_points(&g_l, &g_r, *x_inv)?;
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
        let mut result1 = current_basis[0];
        result1.mul_assign(proof.a); // result1 = a[0] * G[0]
        let mut part_2a = b[0]; // part_2a = b[0]
        part_2a.mul_assign(&proof.a); // part_2a = a[0] * b[0]
        let mut result2 = qw;
        result2.mul_assign(part_2a); // result2 = a[0] * b[0] * w * Q
        let mut result = result1;
        result.add_assign(&result2); // result = result1 + result2

        // Ensure `result_c` is equal to `result`.
        let is_ok = result_c.eq(&result);

        println!(
            "verification check ends: {} s",
            start.elapsed().as_micros() as f64 / 1000000.0
        );

        Ok(is_ok)
    }
}
