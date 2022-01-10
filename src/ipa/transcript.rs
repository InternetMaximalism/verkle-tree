use ff::PrimeField;
use neptune::poseidon::PoseidonConstants;
use neptune::Poseidon;

pub trait Transcript<F: PrimeField>: Sized + Clone {
  fn new(init_state: &F) -> Self;
  fn commit_field_element(&mut self, element: &F) -> anyhow::Result<()>;
  fn get_challenge(&mut self) -> F;
}

#[derive(Clone)]
pub struct PoseidonTranscript<F>
where
  F: PrimeField,
{
  // blake_2s_state: Blake2sTranscript<E::Fr>,
  state: F,
  // _marker: PhantomData<CS>,
}

impl<F: PrimeField> Transcript<F> for PoseidonTranscript<F> {
  fn new(init_state: &F) -> Self {
    // let blake_2s_state = Blake2sTranscript::new();

    Self {
      // blake_2s_state,
      state: init_state.clone(),
      // _marker: std::marker::PhantomData,
    }
  }

  fn commit_field_element(&mut self, element: &F) -> anyhow::Result<()> {
    let mut preimage = vec![F::zero(); 2];
    let constants = PoseidonConstants::new();
    preimage[0] = self.state;
    preimage[1] = element.clone();

    let mut h = Poseidon::<F, typenum::U2>::new_with_preimage(&preimage, &constants);
    self.state = h.hash();

    Ok(())
  }

  fn get_challenge(&mut self) -> F {
    let challenge = self.state.clone();

    challenge
  }
}
