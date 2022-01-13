use franklin_crypto::babyjubjub::edwards::Point;
use franklin_crypto::babyjubjub::{JubjubEngine, Unknown};
use franklin_crypto::bellman::pairing::bn256::{Bn256, Fr};
use franklin_crypto::bellman::{Field, PrimeField, PrimeFieldRepr};

use crate::ipa::config::{IpaConfig, DOMAIN_SIZE};
use crate::ipa::proof::IpaProof;
use crate::ipa::transcript::{Bn256Transcript, PoseidonBn256Transcript};
use crate::ipa::utils::fr_to_fs;
use crate::ipa::{Bn256Ipa, Ipa};

#[derive(Clone)]
pub struct MultiProof<E: JubjubEngine> {
  ipa: IpaProof<E::Fr>,
  d: Point<E, Unknown>,
}

pub fn read_point_le<F: PrimeField>(reader: &mut std::io::Cursor<Vec<u8>>) -> anyhow::Result<F> {
  let mut raw_value = F::Repr::default();
  raw_value.read_le(reader)?;
  let result = F::from_repr(raw_value)?;

  Ok(result)
}

trait BatchProof<E: JubjubEngine> {
  fn create_proof(
    transcript_params: Fr,
    ipa_conf: IpaConfig<Bn256>,
    commitments: &[Point<Bn256, Unknown>],
    fs: &[Vec<Fr>],
    zs: &[u8],
    jubjub_params: &E::Params,
  ) -> anyhow::Result<MultiProof<E>>;

  fn check_proof(
    transcript_params: E::Fr,
    ipa_conf: IpaConfig<E>,
    proof: MultiProof<E>,
    commitments: Vec<Point<E, Unknown>>,
    ys: Vec<E::Fr>,
    zs: Vec<u8>,
    jubjub_params: &E::Params,
  ) -> anyhow::Result<bool>;
}

pub struct Bn256BatchProof;

impl BatchProof<Bn256> for Bn256BatchProof {
  fn create_proof(
    transcript_params: Fr,
    ipa_conf: IpaConfig<Bn256>,
    commitments: &[Point<Bn256, Unknown>],
    fs: &[Vec<Fr>],
    zs: &[u8],
    jubjub_params: &<Bn256 as JubjubEngine>::Params,
  ) -> anyhow::Result<MultiProof<Bn256>> {
    let mut transcript = PoseidonBn256Transcript::new(&transcript_params);

    // transcript.DomainSep("multiproof");

    if commitments.len() != fs.len() {
      panic!(
        "number of commitments = {}, while number of functions = {}",
        commitments.len(),
        fs.len()
      );
    }
    if commitments.len() != zs.len() {
      panic!(
        "number of commitments = {}, while number of points = {}",
        commitments.len(),
        zs.len()
      );
    }

    let num_queries = commitments.len();
    if num_queries == 0 {
      // TODO: does this need to be a panic? no
      panic!("cannot create a multiproof with 0 queries");
    }

    for i in 0..num_queries {
      transcript.commit_point(&commitments[i])?; // C

      // let mut reader = std::io::Cursor::new(vec![zs[i]]);
      // let z_i = read_point_le::<Fr>(&mut reader).unwrap();
      // transcript.commit_field_element(&z_i); // z
      transcript.commit_bytes(&[zs[i]])?;

      // get the `y` value

      let f_i = fs[i].clone();
      let y = f_i[zs[i] as usize];
      transcript.commit_field_element(&y)?; // y
    }
    let r = transcript.get_challenge(); // r

    // Compute g(X)
    let mut g_x = vec![Fr::zero(); DOMAIN_SIZE];

    let mut powers_of_r = Fr::one(); // powers_of_r = 1
    for i in 0..num_queries {
      let quotient = ipa_conf
        .precomputed_weights
        .divide_on_domain(zs[i] as usize, &fs[i]);

      for j in 0..DOMAIN_SIZE {
        let mut tmp = powers_of_r.clone();
        tmp.mul_assign(&quotient[j]);
        g_x[j].add_assign(&tmp);
      }

      powers_of_r.mul_assign(&r);
    }

    let d = ipa_conf.commit(&g_x, jubjub_params)?;

    transcript.commit_point(&d)?; // D

    let t = transcript.get_challenge(); // t

    // Compute h(X) = g_1(X)
    let mut h_x = vec![Fr::zero(); DOMAIN_SIZE];

    let mut powers_of_r = Fr::one(); // powers_of_r = 1
    for i in 0..num_queries {
      let mut reader = std::io::Cursor::new(vec![zs[i]]);
      let z_i = read_point_le::<Fr>(&mut reader).unwrap();
      let mut den_inv = t.clone();
      den_inv.sub_assign(&z_i);
      den_inv.inverse();

      for k in 0..DOMAIN_SIZE {
        let f_i_k = fs[i][k];

        let mut tmp = powers_of_r.clone();
        tmp.mul_assign(&f_i_k);
        tmp.mul_assign(&den_inv);
        h_x[k].add_assign(&tmp);
      }

      powers_of_r.mul_assign(&r); // powers_of_r *= r
    }

    let mut h_minus_g = vec![Fr::zero(); DOMAIN_SIZE];
    for i in 0..DOMAIN_SIZE {
      h_minus_g[i] = h_x[i].clone();
      h_minus_g[i].sub_assign(&g_x[i]);
    }

    let e = ipa_conf.commit(&h_x, jubjub_params)?;
    transcript.commit_point(&e)?; // E

    let minus_d = d.negate();
    let e_minus_d = e.add(&minus_d, jubjub_params);

    let transcript_params = transcript.get_challenge();
    let ipa_proof = Bn256Ipa::create_proof(transcript_params, ipa_conf, e_minus_d, &h_minus_g, t);

    Ok(MultiProof { ipa: ipa_proof, d })
  }

  fn check_proof(
    transcript_params: Fr,
    ipa_conf: IpaConfig<Bn256>,
    proof: MultiProof<Bn256>,
    commitments: Vec<Point<Bn256, Unknown>>,
    ys: Vec<Fr>,
    zs: Vec<u8>,
    jubjub_params: &<Bn256 as JubjubEngine>::Params,
  ) -> anyhow::Result<bool> {
    let mut transcript = PoseidonBn256Transcript::new(&transcript_params);

    if commitments.len() != ys.len() {
      panic!(
        "number of commitments = {}, while number of output points = {}",
        commitments.len(),
        ys.len()
      );
    }
    if commitments.len() != zs.len() {
      panic!(
        "number of commitments = {}, while number of input points = {}",
        commitments.len(),
        zs.len()
      );
    }

    let num_queries = commitments.len();
    if num_queries == 0 {
      // XXX: does this need to be a panic?
      // XXX: this comment is also in CreateMultiProof
      panic!("cannot create a multiproof with no data");
    }

    for i in 0..num_queries {
      transcript.commit_point(&commitments[i])?;

      // let reader = &mut std::io::Cursor::new(vec![zs[i]]);
      // let z_i = read_point_le::<Fr>(reader).unwrap();
      // transcript.commit_field_element(&z_i)?;
      transcript.commit_bytes(&[zs[i]])?;
      transcript.commit_field_element(&ys[i])?;
    }

    let r: Fr = transcript.get_challenge();

    transcript.commit_point(&proof.d)?;

    let t: Fr = transcript.get_challenge();

    // Compute helper_scalars. This is r^i / t - z_i
    //
    // There are more optimal ways to do this, but
    // this is more readable, so will leave for now
    let mut minus_one = <Bn256 as JubjubEngine>::Fs::one();
    minus_one.negate(); // minus_one = -1
    let mut helper_scalars: Vec<Fr> = Vec::with_capacity(num_queries);
    let mut powers_of_r = Fr::one(); // powers_of_r = 1
    for i in 0..num_queries {
      // helper_scalars[i] = r^i / (t - z_i)
      let mut reader = std::io::Cursor::new(vec![zs[i]]);
      let z_i = read_point_le::<Fr>(&mut reader).unwrap();
      let mut t_minus_z_i = t;
      t_minus_z_i.sub_assign(&z_i); // t - z_i
      let mut helper_scalars_i = t_minus_z_i.pow(minus_one.into_repr()); // 1 / (t - z_i)
      helper_scalars_i.mul_assign(&powers_of_r); // r^i / (t - z_i)
      helper_scalars.push(helper_scalars_i);

      // powers_of_r *= r
      powers_of_r.mul_assign(&r);
    }

    // Compute g_2(t) = SUM y_i * (r^i / t - z_i) = SUM y_i * helper_scalars
    let mut g_2_t = Fr::zero();
    for i in 0..num_queries {
      let mut tmp = ys[i];
      tmp.mul_assign(&helper_scalars[i]);
      g_2_t.add_assign(&tmp);
    }

    // Compute E = \sum_{i = 0}^{num_queries - 1} C_i * (r^i / t - z_i)
    let mut e = Point::zero();
    for (i, c_i) in commitments.iter().enumerate() {
      let tmp = c_i.mul(fr_to_fs::<Bn256>(&helper_scalars[i])?, &jubjub_params); // c_i * helper_scalars_i
      e = e.add(&tmp, &jubjub_params); // e += c_i * helper_scalars_i
    }

    transcript.commit_point(&e)?;

    let minus_d = proof.d.negate();
    let e_minus_d = e.add(&minus_d, &jubjub_params);

    let transcript_params = transcript.get_challenge();
    Bn256Ipa::check_proof(
      e_minus_d,
      proof.ipa,
      t,
      g_2_t,
      ipa_conf,
      jubjub_params,
      transcript_params,
    )
  }
}
