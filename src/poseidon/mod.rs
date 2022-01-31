use ff_utils::bn256_fr::Bn256Fr;
use franklin_crypto::babyjubjub::edwards::Point;
use franklin_crypto::bellman::pairing::bn256::{Bn256, Fr};
use franklin_crypto::bellman::{Field, PrimeField};
use neptune::poseidon::PoseidonConstants;
use neptune::Poseidon;

use super::ipa::utils::{read_point_le, write_point_le};

pub trait Bn256Transcript: Sized + Clone {
  type Params;

  fn new(init_state: &Fr) -> Self;
  fn commit_field_element(&mut self, element: &Fr) -> anyhow::Result<()>;
  fn commit_point<Subgroup>(&mut self, point: &Point<Bn256, Subgroup>) -> anyhow::Result<()>;
  fn into_params(self) -> Self::Params;
  fn get_challenge(&self) -> Fr;
}

#[derive(Clone)]
pub struct PoseidonBn256Transcript {
  pub state: Bn256Fr,
}

#[test]
fn test_fr_poseidon_hash1() {
  let constants = PoseidonConstants::new();
  let mut preimage = vec![<Bn256Fr as ff::Field>::zero(); 2];
  let input1 = read_point_le::<Fr>(&[1]).unwrap();
  let input2 = read_point_le::<Fr>(&[2]).unwrap();
  preimage[0] = convert_ff_ce_to_ff(input1).unwrap();
  preimage[1] = convert_ff_ce_to_ff(input2).unwrap();
  let mut h = Poseidon::<Bn256Fr, typenum::U2>::new_with_preimage(&preimage, &constants);
  let output = h.hash();
  println!("output: {:?}", output);
}

#[test]
fn test_fr_poseidon_hash2() {
  let constants = PoseidonConstants::new();
  let mut preimage = vec![<Bn256Fr as ff::Field>::zero(); 2];
  let mut minus_one = Fr::one();
  minus_one.negate();
  let input1 = minus_one.clone();
  let input2 = minus_one.clone();
  preimage[0] = convert_ff_ce_to_ff(input1).unwrap();
  preimage[1] = convert_ff_ce_to_ff(input2).unwrap();
  let mut h = Poseidon::<Bn256Fr, typenum::U2>::new_with_preimage(&preimage, &constants);
  let output = h.hash();
  println!("output: {:?}", output);
}

impl Bn256Transcript for PoseidonBn256Transcript {
  type Params = Fr;

  fn new(init_state: &Self::Params) -> Self {
    // let blake_2s_state = Blake2sTranscript::new();

    Self {
      // blake_2s_state,
      state: convert_ff_ce_to_ff(init_state.clone()).unwrap(),
      // _marker: std::marker::PhantomData,
    }
  }

  fn commit_field_element(&mut self, element: &Fr) -> anyhow::Result<()> {
    let mut preimage = vec![<Bn256Fr as ff::Field>::zero(); 2];
    let constants = PoseidonConstants::new();
    preimage[0] = self.state;
    preimage[1] = convert_ff_ce_to_ff(element.clone()).unwrap();

    let mut h = Poseidon::<Bn256Fr, typenum::U2>::new_with_preimage(&preimage, &constants);
    self.state = h.hash();

    Ok(())
  }

  fn commit_point<Subgroup>(&mut self, point: &Point<Bn256, Subgroup>) -> anyhow::Result<()> {
    let (point_x, point_y) = point.into_xy();
    let mut point_bytes = write_point_le(&point_x);
    let mut point_y_bytes = write_point_le(&point_y);
    point_bytes.append(&mut point_y_bytes);
    self.commit_bytes(&point_bytes)?;

    Ok(())
  }

  fn into_params(self) -> Self::Params {
    convert_ff_to_ff_ce(self.state).unwrap()
  }

  fn get_challenge(&self) -> Fr {
    let challenge = convert_ff_to_ff_ce(self.state.clone()).unwrap();

    challenge
  }
}

impl PoseidonBn256Transcript {
  pub fn with_bytes(bytes: &[u8]) -> Self {
    let chunk_size = (Fr::NUM_BITS / 8) as usize;
    assert!(chunk_size != 0);
    assert!(bytes.len() <= chunk_size);
    let element = read_point_le::<Fr>(&bytes).unwrap();

    Self {
      state: convert_ff_ce_to_ff(element.clone()).unwrap(),
    }
  }

  pub fn commit_bytes(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
    let chunk_size = (Fr::NUM_BITS / 8) as usize;
    assert!(chunk_size != 0);
    for b in bytes.chunks(chunk_size) {
      let element = read_point_le::<Fr>(&b).unwrap();
      self.commit_field_element(&element)?;
    }

    Ok(())
  }
}

// uncheck overflow
pub fn from_bytes_le<F: ff::PrimeField>(bytes: &[u8]) -> anyhow::Result<F> {
  let mut value = F::zero();
  let mut factor = F::one();
  for b in bytes {
    value += factor * F::from(*b as u64);
    factor *= F::from(256u64);
  }

  Ok(value)
}

pub fn to_bytes_le<F: ff::PrimeField>(scalar: &F) -> Vec<u8> {
  scalar.to_repr().as_ref().to_vec()
}

#[test]
fn test_read_write_ff_ce() {
  let bytes = [
    101u8, 121, 238, 208, 145, 118, 73, 126, 4, 129, 129, 133, 67, 167, 1, 64, 164, 189, 107, 239,
    228, 126, 238, 70, 205, 50, 174, 80, 238, 181, 137, 47,
  ];
  let point = from_bytes_le::<Bn256Fr>(&bytes).unwrap();
  assert_eq!(
    format!("{:?}", point),
    "Bn256Fs(0x2f89b5ee50ae32cd46ee7ee4ef6bbda44001a743858181047e497691d0ee7965)"
  );

  let recovered_bytes = to_bytes_le(&point);
  assert_eq!(recovered_bytes, bytes);
}

pub fn convert_ff_to_ff_ce(value: Bn256Fr) -> anyhow::Result<Fr> {
  read_point_le::<Fr>(&to_bytes_le(&value))
}

pub fn convert_ff_ce_to_ff(value: Fr) -> anyhow::Result<Bn256Fr> {
  from_bytes_le(&super::ipa::utils::write_point_le(&value))
}
