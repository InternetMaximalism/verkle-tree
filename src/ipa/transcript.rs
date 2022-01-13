use ff_utils::bn256_fr::Bn256Fr;
use franklin_crypto::babyjubjub::edwards::Point;
use franklin_crypto::bellman::pairing::bn256::{Bn256, Fr};
use franklin_crypto::bellman::PrimeField;
use neptune::poseidon::PoseidonConstants;
use neptune::Poseidon;

use crate::batch_proof::read_point_le;

pub trait Bn256Transcript: Sized + Clone {
  type Params;

  fn new(init_state: &Fr) -> Self;
  fn commit_field_element(&mut self, element: &Fr) -> anyhow::Result<()>;
  fn get_challenge(&mut self) -> Fr;
}

#[derive(Clone)]
pub struct PoseidonBn256Transcript {
  // blake_2s_state: Blake2sTranscript<E::Fr>,
  state: Bn256Fr,
  // _marker: PhantomData<CS>,
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

  fn get_challenge(&mut self) -> Fr {
    let challenge = convert_ff_to_ff_ce(self.state.clone()).unwrap();

    challenge
  }
}

impl PoseidonBn256Transcript {
  pub fn commit_bytes(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
    let chunk_size = (Fr::NUM_BITS / 8) as usize;
    assert!(chunk_size != 0);
    for b in bytes.chunks(chunk_size) {
      let mut reader = std::io::Cursor::new(b.to_vec());
      let element = read_point_le::<Fr>(&mut reader).unwrap();
      self.commit_field_element(&element)?;
    }

    Ok(())
  }

  pub fn commit_point<Subgroup>(&mut self, point: &Point<Bn256, Subgroup>) -> anyhow::Result<()> {
    let (point_x, point_y) = point.into_xy();
    self.commit_field_element(&point_x)?;
    self.commit_field_element(&point_y)?;

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
  let mut result = vec![];
  for (bytes, tmp) in scalar
    .to_repr()
    .as_ref()
    .iter()
    .map(|x| x.to_le_bytes())
    .zip(result.chunks_mut(8))
  {
    for i in 0..bytes.len() {
      tmp[i] = bytes[i];
    }
  }

  result
}

pub fn convert_ff_to_ff_ce(value: Bn256Fr) -> anyhow::Result<Fr> {
  super::utils::from_bytes_le(&to_bytes_le(&value))
}

pub fn convert_ff_ce_to_ff(value: Fr) -> anyhow::Result<Bn256Fr> {
  from_bytes_le(&super::utils::to_bytes_le(&value))
}
