use std::io::{Error, ErrorKind};

// use ff_utils::{Bn256Fr, FromBytes, ToBytes};
use franklin_crypto::babyjubjub::edwards::Point;
use franklin_crypto::babyjubjub::{FixedGenerators, JubjubEngine, JubjubParams, Unknown};
use franklin_crypto::bellman::{PrimeField, PrimeFieldRepr};

pub fn from_bytes_le<F: PrimeField>(bytes: &[u8]) -> anyhow::Result<F> {
  let mut repr = F::Repr::default();
  repr.read_le(bytes)?;
  let value = F::from_repr(repr)?;

  Ok(value)
}

pub fn to_bytes_le<F: PrimeField>(scalar: &F) -> Vec<u8> {
  let mut result = vec![];
  for (bytes, tmp) in scalar
    .into_repr()
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

pub fn fr_to_fs<E: JubjubEngine>(value: &E::Fr) -> anyhow::Result<E::Fs> {
  from_bytes_le(&to_bytes_le(value))
}

// Computes c[i] = a[i] + b[i] * x
// returns c
// panics if len(a) != len(b)
pub fn fold_scalars<F: PrimeField>(a: &[F], b: &[F], x: &F) -> anyhow::Result<Vec<F>> {
  if a.len() != b.len() {
    return Err(Error::new(ErrorKind::InvalidData, "slices not equal length").into());
  }

  let mut result = b.to_vec();
  for i in 0..result.len() {
    result[i].mul_assign(x);
    result[i].add_assign(&a[i]);
  }

  Ok(result)
}

// Computes c[i] = a[i] + b[i] * x
// returns c
// panics if len(a) != len(b)
pub fn fold_points<E: JubjubEngine, Subgroup>(
  a: &[Point<E, Subgroup>],
  b: &[Point<E, Subgroup>],
  x: &E::Fs,
  jubjub_params: &E::Params,
) -> anyhow::Result<Vec<Point<E, Subgroup>>> {
  if a.len() != b.len() {
    return Err(Error::new(ErrorKind::InvalidData, "slices not equal length").into());
  }

  let mut result = b.to_vec();
  for i in 0..b.len() {
    result[i] = result[i].mul(x.clone(), jubjub_params);
    result[i] = result[i].add(&a[i], jubjub_params);
  }

  Ok(result)
}

pub fn multi_scalar<E: JubjubEngine>(
  points: &[Point<E, Unknown>],
  scalars: &[E::Fs],
  jubjub_params: &E::Params,
) -> anyhow::Result<Point<E, Unknown>> {
  let mut result = Point::<E, Unknown>::from(
    jubjub_params
      .generator(FixedGenerators::ProofGenerationKey)
      .clone(),
  ); // E::G1Affine::one()
  for i in 0..points.len() {
    let mut tmp = points[i].clone();
    tmp = tmp.mul(scalars[i], jubjub_params); // tmp = points[i] * scalars[i]
    result = result.add(&tmp, jubjub_params);
    // result += tmp
  }

  Ok(result)
}

// Commits to a polynomial using the input group elements
// panics if the number of group elements does not equal the number of polynomial coefficients
pub fn commit<E: JubjubEngine>(
  group_elements: &[Point<E, Unknown>],
  polynomial: &[E::Fr],
  jubjub_params: &E::Params,
) -> anyhow::Result<Point<E, Unknown>> {
  if group_elements.len() != polynomial.len() {
    let error = format!(
      "diff sizes, {} != {}",
      group_elements.len(),
      polynomial.len()
    );
    return Err(Error::new(ErrorKind::InvalidData, error).into());
  }

  let scalars = polynomial
    .iter()
    .map(|v| fr_to_fs::<E>(v).unwrap())
    .collect::<Vec<E::Fs>>();
  let result = multi_scalar::<E>(group_elements, &scalars, jubjub_params)?;

  Ok(result)
}
