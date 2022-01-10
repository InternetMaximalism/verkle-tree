use franklin_crypto::babyjubjub::edwards::Point;
use franklin_crypto::babyjubjub::{JubjubBn256, JubjubEngine, Unknown};
use franklin_crypto::bellman::plonk::commitments::transcript::{
  Blake2sTranscript, Prng, Transcript,
};
use franklin_crypto::bellman::{CurveAffine, Field, PrimeField, PrimeFieldRepr};

use crate::ipa::{check_ipa_proof, IpaConfig, IpaProof};
// pub fn create_multi_proof(transcript : Transcript, ipaConf : IPAConfig, Cs:  &[PointAffine], fs : &[Vec<F>], zs: &[u8]) -> MultiProof {
// 	transcript.DomainSep("multiproof");

// 	if len(Cs) != len(fs) {
// 		panic(fmt.Sprintf("number of commitments = %d, while number of functions = %d", len(Cs), len(fs)))
// 	}
// 	if len(Cs) != len(zs) {
// 		panic(fmt.Sprintf("number of commitments = %d, while number of points = %d", len(Cs), len(zs)))
// 	}

// 	num_queries := len(Cs)
// 	if num_queries == 0 {
// 		// TODO does this need to be a panic? no
// 		panic("cannot create a multiproof with 0 queries")
// 	}

// 	for i := 0; i < num_queries; i++ {
// 		transcript.AppendPoint(Cs[i], "C")
// 		var z = domainToFr(zs[i])
// 		transcript.AppendScalar(&z, "z")

// 		// get the `y` value

// 		f := fs[i]
// 		y := f[zs[i]]
// 		transcript.AppendScalar(&y, "y")
// 	}
// 	r := transcript.ChallengeScalar("r")
// 	powers_of_r := common.PowersOf(r, num_queries)

// 	// Compute g(X)
// 	g_x := make([]fr.Element, common.POLY_DEGREE)

// 	for i := 0; i < num_queries; i++ {
// 		f := fs[i]
// 		index := zs[i]
// 		r := powers_of_r[i]

// 		quotient := ipaConf.PrecomputedWeights.DivideOnDomain(index, f)

// 		for j := 0; j < common.POLY_DEGREE; j++ {
// 			var tmp fr.Element

// 			tmp.Mul(&r, &quotient[j])
// 			g_x[j].Add(&g_x[j], &tmp)
// 		}
// 	}

// 	D := ipaConf.Commit(g_x)

// 	transcript.AppendPoint(&D, "D")
// 	t := transcript.ChallengeScalar("t")

// 	// Compute h(X) = g_1(X)
// 	h_x := make([]fr.Element, common.POLY_DEGREE)

// 	for i := 0; i < num_queries; i++ {
// 		r := powers_of_r[i]
// 		f := fs[i]

// 		var den_inv fr.Element
// 		var z = domainToFr(zs[i])
// 		den_inv.Sub(&t, &z)
// 		den_inv.Inverse(&den_inv)

// 		for k := 0; k < common.POLY_DEGREE; k++ {
// 			f_k := f[k]

// 			var tmp fr.Element
// 			tmp.Mul(&r, &f_k)
// 			tmp.Mul(&tmp, &den_inv)
// 			h_x[k].Add(&h_x[k], &tmp)
// 		}
// 	}

// 	h_minus_g := make([]fr.Element, common.POLY_DEGREE)
// 	for i := 0; i < common.POLY_DEGREE; i++ {
// 		h_minus_g[i].Sub(&h_x[i], &g_x[i])
// 	}

// 	E := ipaConf.Commit(h_x)
// 	transcript.AppendPoint(&E, "E")

// 	var E_minus_D bandersnatch.PointAffine

// 	E_minus_D.Sub(&E, &D)

// 	ipa_proof := ipa.CreateIPAProof(transcript, ipaConf, E_minus_D, h_minus_g, t)

// 	return &MultiProof{
// 		IPA: ipa_proof,
// 		D:   D,
// 	}
// }

pub fn read_point_le<F: PrimeField>(reader: &mut std::io::Cursor<Vec<u8>>) -> anyhow::Result<F> {
  let mut raw_value = F::Repr::default();
  raw_value.read_le(reader)?;
  let result = F::from_repr(raw_value)?;

  Ok(result)
}

pub fn check_multi_proof<E: JubjubEngine>(
  transcript_params: &E::Fs,
  ipa_conf: IpaConfig<E::Fs>,
  proof: IpaProof<E::Fs>,
  d: &Point<E, Unknown>,
  commitments: Vec<Point<E, Unknown>>,
  ys: Vec<E::Fs>,
  zs: Vec<u8>,
  jubjub_params: &E::Params,
) -> anyhow::Result<bool> {
  let mut transcript = Blake2sTranscript::new(transcript_params);

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
    let (c_x, c_y) = commitments[i].into_xy();
    transcript.commit_field_element(&c_x); // commitments[i]_x
    transcript.commit_field_element(&c_y); // commitments[i]_y
    let reader = &mut std::io::Cursor::new(vec![zs[i]]);
    let z_i = read_point_le::<E::Fs>(reader).unwrap();
    transcript.commit_field_element(&z_i);
    transcript.commit_field_element(&ys[i]);
  }

  let r: E::Fs = transcript.get_challenge();

  let (d_x, d_y) = d.into_xy();
  transcript.commit_field_element(&d_x); // D_x
  transcript.commit_field_element(&d_y); // D_y
  let t: E::Fs = transcript.get_challenge();

  // Compute helper_scalars. This is r^i / t - z_i
  //
  // There are more optimal ways to do this, but
  // this is more readable, so will leave for now
  let mut minus_one = E::Fs::one();
  minus_one.negate(); // minus_one = -1
  let mut helper_scalars: Vec<E::Fs> = Vec::with_capacity(num_queries);
  let mut powers_of_r = E::Fs::one(); // powers_of_r = 1
  for i in 0..num_queries {
    // helper_scalars[i] = r^i / (t - z_i)
    let mut reader = std::io::Cursor::new(vec![zs[i]]);
    let z_i: E::Fs = read_point_le::<E::Fs>(&mut reader).unwrap();
    let t_minus_z_i = t.sub(&z_i)?;
    let inverse_of_t_minus_z_i = t_minus_z_i.pow(&minus_one)?;
    let helper_scalars_i = inverse_of_t_minus_z_i.mul(&powers_of_r)?;
    helper_scalars.push(helper_scalars_i);

    // powers_of_r *= r
    powers_of_r.mul_assign(&r);
  }

  // Compute g_2(t) = SUM y_i * (r^i / t - z_i) = SUM y_i * helper_scalars
  let mut g_2_t = E::Fs::zero();
  for i in 0..num_queries {
    let mut tmp = ys[i];
    tmp.mul_assign(&helper_scalars[i]);
    g_2_t.add_assign(&tmp);
  }

  // Compute E = SUM C_i * (r^i / t - z_i) = SUM C_i * helper_scalars
  let zero = E::Fs::zero();
  let mut e = Point::zero();
  for i in 0..num_queries {
    let mut tmp = commitments[i];
    tmp = tmp.mul(helper_scalars[i], &jubjub_params);
    e = e.add(&tmp, &jubjub_params);
  }

  let (e_x, e_y) = e.into_xy();
  transcript.commit_field_element(&e_x); // E_x
  transcript.commit_field_element(&e_y); // E_y

  let minus_d = d.negate();
  let e_minus_d = e.add(&minus_d, &jubjub_params);

  let ipa_commitment = e_minus_d;
  let transcript_params = transcript.get_challenge();
  check_ipa_proof(
    ipa_commitment,
    proof,
    t,
    g_2_t,
    ipa_conf,
    jubjub_params,
    transcript_params,
  )
}
