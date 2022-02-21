use franklin_crypto::bellman::pairing::bn256::{Fr, G1Affine, G1};
use franklin_crypto::bellman::{CurveAffine, CurveProjective, Field};

use crate::ipa_fr::config::{Committer, IpaConfig};
use crate::ipa_fr::proof::IpaProof;
use crate::ipa_fr::transcript::{Bn256Transcript, PoseidonBn256Transcript};
use crate::ipa_fr::utils::read_field_element_le;
use crate::ipa_fr::{Bn256Ipa, Ipa};

#[derive(Clone, Debug)]
pub struct MultiProof<G: CurveProjective> {
    pub ipa: IpaProof<G>,
    pub d: G::Affine,
}

pub trait BatchProof<G: CurveProjective, T: Bn256Transcript> {
    fn create_proof(
        commitments: &[G::Affine],
        fs: &[Vec<G::Scalar>],
        zs: &[usize],
        transcript_params: T::Params,
        ipa_conf: &IpaConfig<G>,
    ) -> anyhow::Result<MultiProof<G>>;

    fn check_proof(
        proof: MultiProof<G>,
        commitments: &[G::Affine],
        ys: &[G::Scalar],
        zs: &[usize],
        transcript_params: T::Params,
        ipa_conf: &IpaConfig<G>,
    ) -> anyhow::Result<bool>;
}

pub struct Bn256BatchProof;

#[cfg(test)]
mod tests {
    use franklin_crypto::bellman::pairing::bn256::{Fr, G1};

    use super::{BatchProof, Bn256BatchProof};
    use crate::ipa_fr::config::Committer;
    use crate::ipa_fr::transcript::Bn256Transcript;
    use crate::ipa_fr::{config::IpaConfig, transcript::PoseidonBn256Transcript, utils::test_poly};

    #[test]
    fn test_multi_proof_create_verify() -> Result<(), Box<dyn std::error::Error>> {
        // Shared View
        println!("create ipa_conf");
        let domain_size = 256;
        let ipa_conf = &IpaConfig::<G1>::new(domain_size);

        // Prover view
        let poly_1 = test_poly::<Fr>(&[12, 97, 37, 0, 1, 208, 132, 3], domain_size);
        let prover_transcript = PoseidonBn256Transcript::with_bytes(b"multi_proof");
        let prover_commitment_1 = ipa_conf.commit(&poly_1)?;

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
        )?;

        assert!(success, "inner product proof failed");

        Ok(())
    }
}

impl BatchProof<G1, PoseidonBn256Transcript> for Bn256BatchProof {
    fn create_proof(
        commitments: &[G1Affine],
        fs: &[Vec<Fr>],
        zs: &[usize],
        transcript_params: Fr,
        ipa_conf: &IpaConfig<G1>,
    ) -> anyhow::Result<MultiProof<G1>> {
        let mut transcript = PoseidonBn256Transcript::new(&transcript_params);

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

        let domain_size = ipa_conf.get_domain_size();
        for i in 0..num_queries {
            transcript.commit_point(&commitments[i])?; // C

            assert!(
                zs[i] < domain_size,
                "{:?} must be less than {:?}.",
                zs[i],
                domain_size
            );
            transcript.commit_bytes(&zs[i].to_le_bytes())?;

            // get the `y` value
            let f_i = fs[i].clone();
            let y_i = f_i[zs[i]];
            transcript.commit_field_element(&y_i)?; // y
        }
        let r = transcript.get_challenge(); // r

        // println!("r: {:?}", r);

        // Compute g(X)
        let mut g_x = vec![Fr::zero(); domain_size];
        let mut powers_of_r = Fr::one(); // powers_of_r = 1
        for i in 0..num_queries {
            let quotient = ipa_conf
                .get_precomputed_weights()
                .divide_on_domain(zs[i], &fs[i]); // quotient[j] = (f_i(j) - f_i(zs[i])) / (j - zs[i])

            for j in 0..domain_size {
                let mut tmp = quotient[j];
                tmp.mul_assign(&powers_of_r);
                g_x[j].add_assign(&tmp); // g_x[j] += r^i * quotient[j]
            }

            powers_of_r.mul_assign(&r);
        }

        let d = ipa_conf.commit(&g_x)?;

        transcript.commit_point(&d)?; // D

        let t = transcript.get_challenge(); // t

        // println!("t: {:?}", t);

        // Compute h(X) = g_1(X)
        let mut h_x = vec![Fr::zero(); domain_size];
        let mut powers_of_r = Fr::one(); // powers_of_r = 1
        for i in 0..num_queries {
            let z_i = read_field_element_le::<Fr>(&zs[i].to_le_bytes()).unwrap();
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

        let mut h_minus_g = vec![Fr::zero(); domain_size];
        for i in 0..domain_size {
            h_minus_g[i] = h_x[i];
            h_minus_g[i].sub_assign(&g_x[i]);
        }

        let start = std::time::Instant::now();
        let e = ipa_conf.commit(&h_x)?;
        println!(
            "commit h_x: {} s",
            start.elapsed().as_micros() as f64 / 1000000.0
        );
        transcript.commit_point(&e)?; // E

        let mut minus_d = G1::zero();
        minus_d.sub_assign(&d.into_projective());

        let mut e_minus_d = e.into_projective();
        e_minus_d.add_assign(&minus_d);

        let transcript_params = transcript.get_challenge();

        let (ipa_proof, _) = Bn256Ipa::create_proof(
            e_minus_d.into_affine(),
            &h_minus_g,
            t,
            transcript_params,
            ipa_conf,
        )?;

        Ok(MultiProof { ipa: ipa_proof, d })
    }

    fn check_proof(
        proof: MultiProof<G1>,
        commitments: &[G1Affine],
        ys: &[Fr],
        zs: &[usize],
        transcript_params: Fr,
        ipa_conf: &IpaConfig<G1>,
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

        let domain_size = ipa_conf.get_domain_size();
        for i in 0..num_queries {
            assert!(zs[i] < domain_size);
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

        let mut helper_scalars: Vec<Fr> = Vec::with_capacity(num_queries);
        let mut powers_of_r = Fr::one(); // powers_of_r = 1
        for z_i in zs.iter() {
            // helper_scalars[i] = r^i / (t - z_i)
            let mut t_minus_z_i = t;
            t_minus_z_i.sub_assign(&read_field_element_le::<Fr>(&z_i.to_le_bytes()).unwrap()); // t - z_i

            let mut helper_scalars_i = t_minus_z_i
                .inverse()
                .ok_or(anyhow::anyhow!("cannot find inverse of `t - z_i`"))?; // 1 / (t - z_i)
            helper_scalars_i.mul_assign(&powers_of_r); // r^i / (t - z_i)
            helper_scalars.push(helper_scalars_i); // helper_scalars[i] = r^i / (t - z_i)

            powers_of_r.mul_assign(&r); // powers_of_r *= r
        }

        // Compute g_2(t) = \sum_{i = 0}^{num_queries - 1} y_i * (r^i / t - z_i).
        let mut g_2_t = Fr::zero();
        for i in 0..num_queries {
            let mut tmp = ys[i];
            tmp.mul_assign(&helper_scalars[i]);
            g_2_t.add_assign(&tmp); // g_2_t += ys[i] * helper_scalars[i]
        }

        // Compute E = \sum_{i = 0}^{num_queries - 1} C_i * (r^i / t - z_i).
        let mut e = G1::zero();
        for (i, c_i) in commitments.iter().enumerate() {
            let tmp = c_i.mul(helper_scalars[i]); // tmp = c_i * helper_scalars_i
            e.add_assign(&tmp); // e += c_i * helper_scalars_i
        }

        transcript.commit_point(&e.into_affine())?;

        let mut e_minus_d = e;
        e_minus_d.sub_assign(&proof.d.into_projective());

        let transcript_params = transcript.get_challenge();
        println!("transcript_params: {:?}", transcript_params);
        Bn256Ipa::check_proof(
            e_minus_d.into_affine(),
            proof.ipa,
            t,
            g_2_t,
            transcript_params,
            ipa_conf,
        )
    }
}
