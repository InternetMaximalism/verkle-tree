use franklin_crypto::babyjubjub::edwards::Point;
use franklin_crypto::babyjubjub::fs::Fs;
use franklin_crypto::babyjubjub::{JubjubEngine, Unknown};
use franklin_crypto::bellman::pairing::bn256::Bn256;
use franklin_crypto::bellman::Field;

use crate::ipa::config::{IpaConfig, DOMAIN_SIZE};
use crate::ipa::proof::IpaProof;
use crate::ipa::transcript::{Bn256Transcript, PoseidonBn256Transcript};
use crate::ipa::utils::read_point_le;
use crate::ipa::{Bn256Ipa, Ipa};

#[derive(Clone)]
pub struct MultiProof<E: JubjubEngine> {
    ipa: IpaProof<E>,
    d: Point<E, Unknown>,
}

trait BatchProof<E: JubjubEngine, T: Bn256Transcript> {
    fn create_proof(
        commitments: &[Point<Bn256, Unknown>],
        fs: &[Vec<Fs>],
        zs: &[usize],
        transcript_params: T::Params,
        ipa_conf: &IpaConfig<Bn256>,
        jubjub_params: &E::Params,
    ) -> anyhow::Result<MultiProof<E>>;

    fn check_proof(
        proof: MultiProof<E>,
        commitments: &[Point<E, Unknown>],
        ys: &[E::Fs],
        zs: &[usize],
        transcript_params: T::Params,
        ipa_conf: &IpaConfig<E>,
        jubjub_params: &E::Params,
    ) -> anyhow::Result<bool>;
}

pub struct Bn256BatchProof;

#[cfg(test)]
mod tests {
    use franklin_crypto::babyjubjub::fs::Fs;
    use franklin_crypto::babyjubjub::JubjubBn256;
    use franklin_crypto::bellman::pairing::bn256::Bn256;

    use super::{BatchProof, Bn256BatchProof};
    use crate::ipa::transcript::Bn256Transcript;
    use crate::ipa::{config::IpaConfig, transcript::PoseidonBn256Transcript, utils::test_poly};

    #[test]
    fn test_multi_proof_create_verify() -> Result<(), Box<dyn std::error::Error>> {
        // Shared View
        let jubjub_params = &JubjubBn256::new();
        println!("create ipa_conf");
        let ipa_conf = &IpaConfig::<Bn256>::new(jubjub_params);

        // Prover view
        let poly_1 = test_poly::<Fs>(&[12, 97, 37, 0, 1, 208, 132, 3]);
        let prover_transcript = PoseidonBn256Transcript::with_bytes(b"multi_proof");
        let prover_commitment_1 = ipa_conf.commit(&poly_1, jubjub_params)?;

        let commitments = vec![prover_commitment_1];
        let fs = vec![poly_1];
        let index_1 = 36;
        let zs = vec![index_1];
        let mut ys = vec![];
        for i in 0..zs.len() {
            let y_i = fs[i][zs[i]];
            ys.push(y_i);
        }
        let proof = Bn256BatchProof::create_proof(
            &commitments,
            &fs,
            &zs,
            prover_transcript.into_params(),
            ipa_conf,
            jubjub_params,
        )?;

        // test_serialize_deserialize_proof(proof);

        // Verifier view
        let verifier_transcript = PoseidonBn256Transcript::with_bytes(b"multi_proof");
        let success = Bn256BatchProof::check_proof(
            proof,
            &commitments,
            &ys,
            &zs,
            verifier_transcript.into_params(),
            ipa_conf,
            jubjub_params,
        )?;

        assert!(success, "inner product proof failed");

        Ok(())
    }
}

impl BatchProof<Bn256, PoseidonBn256Transcript> for Bn256BatchProof {
    fn create_proof(
        commitments: &[Point<Bn256, Unknown>],
        fs: &[Vec<Fs>],
        zs: &[usize],
        transcript_params: Fs,
        ipa_conf: &IpaConfig<Bn256>,
        jubjub_params: &<Bn256 as JubjubEngine>::Params,
    ) -> anyhow::Result<MultiProof<Bn256>> {
        let mut transcript = PoseidonBn256Transcript::new(&transcript_params);

        // transcript.DomainSep("multiproof");

        if commitments.len() != fs.len() {
            anyhow::anyhow!(
                "number of commitments = {}, while number of functions = {}",
                commitments.len(),
                fs.len()
            );
        }
        if commitments.len() != zs.len() {
            anyhow::anyhow!(
                "number of commitments = {}, while number of points = {}",
                commitments.len(),
                zs.len()
            );
        }

        let num_queries = commitments.len();
        if num_queries == 0 {
            anyhow::anyhow!("cannot create a batch proof with no data");
        }

        for i in 0..num_queries {
            transcript.commit_point(&commitments[i])?; // C

            assert!(zs[i] < DOMAIN_SIZE);
            transcript.commit_bytes(&zs[i].to_le_bytes())?;

            // get the `y` value

            let f_i = fs[i].clone();
            let y_i = f_i[zs[i]];
            transcript.commit_field_element(&y_i)?; // y
        }
        let r = transcript.get_challenge(); // r
                                            // println!("r: {:?}", r);

        // Compute g(X)
        let mut g_x = vec![Fs::zero(); DOMAIN_SIZE];
        let mut powers_of_r = Fs::one(); // powers_of_r = 1
        for i in 0..num_queries {
            let quotient = ipa_conf.precomputed_weights.divide_on_domain(zs[i], &fs[i]); // quotient[j] = (f_i(j) - f_i(zs[i])) / (j - zs[i])

            for j in 0..DOMAIN_SIZE {
                let mut tmp = quotient[j];
                tmp.mul_assign(&powers_of_r);
                g_x[j].add_assign(&tmp); // g_x[j] += r^i * quotient[j]
            }

            powers_of_r.mul_assign(&r);
        }

        let d = ipa_conf.commit(&g_x, jubjub_params)?;

        transcript.commit_point(&d)?; // D

        let t = transcript.get_challenge(); // t
                                            // println!("t: {:?}", t);

        // Compute h(X) = g_1(X)
        let mut h_x = vec![Fs::zero(); DOMAIN_SIZE];
        let mut powers_of_r = Fs::one(); // powers_of_r = 1
        for i in 0..num_queries {
            let z_i = read_point_le::<Fs>(&zs[i].to_le_bytes()).unwrap();
            let mut den = t; // den_inv = t
            den.sub_assign(&z_i); // den_inv = t - z_i
            let den_inv = den
                .inverse()
                .ok_or(anyhow::anyhow!("cannot find inverse of `t - z_i`"))?; // den_inv = 1 / (t - z_i)

            for (k, h_x_k) in h_x.iter_mut().enumerate() {
                let mut tmp = powers_of_r;
                tmp.mul_assign(&fs[i][k]);
                tmp.mul_assign(&den_inv);
                h_x_k.add_assign(&tmp); // h_x[k] += r^i * f[i][k] / (t - z_i)
            }

            powers_of_r.mul_assign(&r); // powers_of_r *= r
        }

        let mut h_minus_g = vec![Fs::zero(); DOMAIN_SIZE];
        for i in 0..DOMAIN_SIZE {
            h_minus_g[i] = h_x[i];
            h_minus_g[i].sub_assign(&g_x[i]);
        }

        let start = std::time::Instant::now();
        let e = ipa_conf.commit(&h_x, jubjub_params)?;
        println!(
            "commit h_x: {} s",
            start.elapsed().as_micros() as f64 / 1000000.0
        );
        transcript.commit_point(&e)?; // E

        let minus_d = d.negate();

        let e_minus_d = e.add(&minus_d, jubjub_params);

        let transcript_params = transcript.get_challenge();

        let ipa_proof = Bn256Ipa::create_proof(
            e_minus_d,
            &h_minus_g,
            t,
            transcript_params,
            ipa_conf,
            jubjub_params,
        )?;

        Ok(MultiProof { ipa: ipa_proof, d })
    }

    fn check_proof(
        proof: MultiProof<Bn256>,
        commitments: &[Point<Bn256, Unknown>],
        ys: &[Fs],
        zs: &[usize],
        transcript_params: Fs,
        ipa_conf: &IpaConfig<Bn256>,
        jubjub_params: &<Bn256 as JubjubEngine>::Params,
    ) -> anyhow::Result<bool> {
        let mut transcript = PoseidonBn256Transcript::new(&transcript_params);

        if commitments.len() != ys.len() {
            anyhow::anyhow!(
                "number of commitments = {}, while number of output points = {}",
                commitments.len(),
                ys.len()
            );
        }
        if commitments.len() != zs.len() {
            anyhow::anyhow!(
                "number of commitments = {}, while number of input points = {}",
                commitments.len(),
                zs.len()
            );
        }

        let num_queries = commitments.len();
        if num_queries == 0 {
            anyhow::anyhow!("cannot create a batch proof with no data");
        }

        println!("update transcript");
        for i in 0..num_queries {
            assert!(zs[i] < DOMAIN_SIZE);
            let start = std::time::Instant::now();
            transcript.commit_point(&commitments[i])?;
            println!(
                "updated transcript {}/{}: {} s",
                3 * i,
                3 * num_queries,
                start.elapsed().as_micros() as f64 / 1000000.0
            );
            let start = std::time::Instant::now();
            transcript.commit_bytes(&zs[i].to_le_bytes())?;
            println!(
                "updated transcript {}/{}: {} s",
                3 * i + 1,
                3 * num_queries,
                start.elapsed().as_micros() as f64 / 1000000.0
            );
            let start = std::time::Instant::now();
            transcript.commit_field_element(&ys[i])?;
            println!(
                "updated transcript {}/{}: {} s",
                3 * i + 2,
                3 * num_queries,
                start.elapsed().as_micros() as f64 / 1000000.0
            );
        }

        let r = transcript.get_challenge();
        // println!("r: {:?}", r);

        transcript.commit_point(&proof.d)?;

        let t = transcript.get_challenge();
        // println!("t: {:?}", t);

        // Compute helper_scalars. This is r^i / t - z_i
        // There are more optimal ways to do this, but
        // this is more readable, so will leave for now
        let mut helper_scalars: Vec<Fs> = Vec::with_capacity(num_queries);
        let mut powers_of_r = Fs::one(); // powers_of_r = 1
        for z_i in zs.iter() {
            // helper_scalars[i] = r^i / (t - z_i)
            let mut t_minus_z_i = t;
            t_minus_z_i.sub_assign(&read_point_le::<Fs>(&z_i.to_le_bytes()).unwrap()); // t - z_i

            let mut helper_scalars_i = t_minus_z_i
                .inverse()
                .ok_or(anyhow::anyhow!("cannot find inverse of `t - z_i`"))?; // 1 / (t - z_i)
            helper_scalars_i.mul_assign(&powers_of_r); // r^i / (t - z_i)
            helper_scalars.push(helper_scalars_i); // helper_scalars[i] = r^i / (t - z_i)

            powers_of_r.mul_assign(&r); // powers_of_r *= r
        }

        // Compute g_2(t) = SUM y_i * (r^i / t - z_i) = SUM y_i * helper_scalars
        let mut g_2_t = Fs::zero();
        for i in 0..num_queries {
            let mut tmp = ys[i];
            tmp.mul_assign(&helper_scalars[i]);
            g_2_t.add_assign(&tmp); // g_2_t += ys[i] * helper_scalars[i]
        }

        // Compute E = \sum_{i = 0}^{num_queries - 1} C_i * (r^i / t - z_i)
        let mut e = Point::zero();
        for (i, c_i) in commitments.iter().enumerate() {
            let tmp = c_i.mul(helper_scalars[i], jubjub_params); // tmp = c_i * helper_scalars_i
            e = e.add(&tmp, jubjub_params); // e += c_i * helper_scalars_i
        }

        transcript.commit_point(&e)?;

        let minus_d = proof.d.negate();
        let e_minus_d = e.add(&minus_d, jubjub_params);

        let transcript_params = transcript.get_challenge();
        Bn256Ipa::check_proof(
            e_minus_d,
            proof.ipa,
            t,
            g_2_t,
            transcript_params,
            ipa_conf,
            jubjub_params,
        )
    }
}
