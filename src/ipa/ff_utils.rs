// uncheck overflow
pub fn from_bytes_le<F: ff::PrimeField>(bytes: &[u8]) -> anyhow::Result<F> {
  let value = F::zero();
  let factor = F::one();
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
