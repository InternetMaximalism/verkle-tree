// use ff_utils::{Bn256Fr, FromBytes, ToBytes};
use franklin_crypto::babyjubjub::edwards::Point;
use franklin_crypto::babyjubjub::{JubjubEngine, Unknown};
use franklin_crypto::bellman::{Field, PrimeField, PrimeFieldRepr};
use sha2::{Digest, Sha256};

pub fn log2_ceil(value: usize) -> usize {
    assert!(value != 0, "The first argument must be a positive number.");

    if value == 1 {
        return 0;
    }

    let mut log_value = 1;
    let mut tmp_value = value - 1;
    while tmp_value > 1 {
        tmp_value /= 2;
        log_value += 1;
    }

    log_value
}

#[test]
#[should_panic]
pub fn test_error_log2_ceil() {
    log2_ceil(0);
}

#[test]
pub fn test_log2_ceil() {
    let res0 = log2_ceil(1);
    assert_eq!(res0, 0);

    let res1 = log2_ceil(2);
    assert_eq!(res1, 1);

    let res2 = log2_ceil(3);
    assert_eq!(res2, 2);

    let res3 = log2_ceil(4);
    assert_eq!(res3, 2);

    let res4 = log2_ceil(5);
    assert_eq!(res4, 3);

    let res5 = log2_ceil(127);
    assert_eq!(res5, 7);
}

pub fn read_field_element_le<F: PrimeField>(bytes: &[u8]) -> anyhow::Result<F> {
    let mut repr = F::Repr::default();
    let mut padded_bytes = bytes.to_vec();
    let num_bits = F::NUM_BITS as usize;
    // assert!(bytes.len() <= (num_bits + 7) / 8);
    // for _ in bytes.len()..num_bits {
    //     padded_bytes.push(0);
    // }
    padded_bytes.resize((num_bits + 7) / 8, 0);
    repr.read_le::<&[u8]>(padded_bytes.as_ref())?;
    let value = F::from_repr(repr)?;

    Ok(value)
}

pub fn read_field_element_be<F: PrimeField>(bytes: &[u8]) -> anyhow::Result<F> {
    let mut padded_bytes = bytes.to_vec();
    padded_bytes.reverse();
    read_field_element_le(&padded_bytes)
}

pub fn write_field_element_le<F: PrimeField>(scalar: &F) -> Vec<u8> {
    let scalar_u64_vec = scalar.into_repr().as_ref().to_vec();
    let mut result = vec![0; scalar_u64_vec.len() * 8];
    for (bytes, tmp) in scalar_u64_vec
        .iter()
        .map(|x| x.to_le_bytes())
        .zip(result.chunks_mut(8))
    {
        // for i in 0..bytes.len() {
        //     tmp[i] = bytes[i];
        // }
        tmp[..bytes.len()].clone_from_slice(&bytes[..]);
    }

    result
}

pub fn write_field_element_be<F: PrimeField>(scalar: &F) -> Vec<u8> {
    let mut result = write_field_element_le(scalar);
    result.reverse();

    result
}

const FS_REPR_3_MASK: u64 = 0x03FFFFFFFFFFFFFF; // (250 - 192) bits

pub fn convert_fr_to_fs<E: JubjubEngine>(value: &E::Fr) -> anyhow::Result<E::Fs> {
    let raw_value = value.into_repr();
    let mut raw_result = <E::Fs as PrimeField>::Repr::default();
    raw_result.as_mut()[0] = raw_value.as_ref()[0];
    raw_result.as_mut()[1] = raw_value.as_ref()[1];
    raw_result.as_mut()[2] = raw_value.as_ref()[2];
    raw_result.as_mut()[3] = raw_value.as_ref()[3] & FS_REPR_3_MASK;
    let result = E::Fs::from_repr(raw_result)?;

    Ok(result)
}

pub fn convert_fs_to_fr<E: JubjubEngine>(value: &E::Fs) -> anyhow::Result<E::Fr> {
    let raw_value = value.into_repr();
    let raw_result = convert_fs_repr_to_fr_repr::<E>(&raw_value)?;
    let result = E::Fr::from_repr(raw_result)?;

    Ok(result)
}

pub fn convert_fs_repr_to_fr_repr<E: JubjubEngine>(
    raw_value: &<E::Fs as PrimeField>::Repr,
) -> anyhow::Result<<E::Fr as PrimeField>::Repr> {
    let mut raw_result = <E::Fr as PrimeField>::Repr::default();
    for (r, &v) in raw_result.as_mut().iter_mut().zip(raw_value.as_ref()) {
        let _ = std::mem::replace(r, v);
    }

    Ok(raw_result)
}

#[test]
fn test_read_write_ff() {
    use franklin_crypto::bellman::pairing::bn256::Fr;

    let bytes = [
        101u8, 121, 238, 208, 145, 118, 73, 126, 4, 129, 129, 133, 67, 167, 1, 64, 164, 189, 107,
        239, 228, 126, 238, 70, 205, 50, 174, 80, 238, 181, 137, 47,
    ];
    let point = read_field_element_le::<Fr>(&bytes).unwrap();
    assert_eq!(
        format!("{:?}", point),
        "Fr(0x2f89b5ee50ae32cd46ee7ee4ef6bbda44001a743858181047e497691d0ee7965)"
    );

    let recovered_bytes = write_field_element_le(&point);
    assert_eq!(recovered_bytes, bytes);
}

// pub fn fr_to_fs_repr<E: JubjubEngine>(
//   value: &E::Fr,
// ) -> anyhow::Result<<E::Fs as PrimeField>::Repr> {
//   let bytes = write_field_element_le(value);
//   let mut fs_repr = <E::Fs as PrimeField>::Repr::default();
//   fs_repr.read_le::<&[u8]>(bytes.as_ref())?;

//   Ok(fs_repr)
// }

// pub fn fr_to_fs<E: JubjubEngine>(value: &E::Fr) -> anyhow::Result<E::Fs> {
//   read_field_element_le(&write_field_element_le(value))
// }

pub fn generate_random_points<E: JubjubEngine>(
    num_points: usize,
    jubjub_params: &E::Params,
) -> anyhow::Result<Vec<Point<E, Unknown>>> {
    let mut hasher = Sha256::new();
    hasher.update(b"eth_verkle_oct_2021"); // In case it changes or needs updating, we can use eth_verkle_month_year.
    let digest = hasher.finalize();
    let u = read_field_element_le::<E::Fr>(digest.as_ref())?;

    // flag to indicate whether we choose the lexicographically larger
    // element of `x` out of it and it's negative (?)
    let choose_largest = false;

    let mut points = vec![];

    let mut increment = 0usize;

    // TODO: It takes too long to find some random points with the specific order.
    while points.len() != num_points {
        let mut y = u;
        y.add_assign(&read_field_element_le(&increment.to_le_bytes()).unwrap()); // y = u + increment
        increment += 1;

        let point_found = Point::<E, Unknown>::get_for_y(y, choose_largest, jubjub_params);
        if point_found.is_none() {
            continue;
        }

        let point_found = point_found.unwrap();
        let result = point_found.as_prime_order(jubjub_params);
        if let Some(_p) = result {
            points.push(point_found);
        }
    }

    Ok(points)
}

// pub fn is_in_prime_subgroup<E: JubjubEngine>(
//   p: &Point<E, Unknown>,
//   jubjub_params: &E::Params,
// ) -> bool {
//   let order = jubjub_params.order();

//   let mut res_proj = Point::<E, Unknown>::zero(); // identity

//   let bit_len = order.bit_len();

//   for i in 0..(bit_len + 1) {
//     res_proj = res_proj.double(jubjub_params);
//     if order.bit(bit_len - i) == 1 {
//       res_proj = res_proj.add(p, jubjub_params);
//     }
//   }

//   let identity = Point::<E, Unknown>::zero(); // identity

//   identity.eq(&res_proj)
// }

// Computes vector c satisfying c[i] = a[i] + b[i] * x.
// Error if vectors a, b have different lengths.
pub fn fold_scalars<F: PrimeField>(a: &[F], b: &[F], x: &F) -> anyhow::Result<Vec<F>> {
    if a.len() != b.len() {
        anyhow::bail!(
            "two vectors must have the same lengths, {} != {}",
            a.len(),
            b.len()
        );
    }

    let mut result = b.to_vec();
    for (result_i, a_i) in result.iter_mut().zip(a) {
        result_i.mul_assign(x);
        result_i.add_assign(a_i);
    }

    Ok(result)
}

// Computes vector c satisfying c[i] = a[i] + b[i] * x.
// Error if vectors a, b have different lengths.
pub fn fold_points<E: JubjubEngine, Subgroup>(
    a: &[Point<E, Subgroup>],
    b: &[Point<E, Subgroup>],
    x: &E::Fs,
    jubjub_params: &E::Params,
) -> anyhow::Result<Vec<Point<E, Subgroup>>> {
    if a.len() != b.len() {
        anyhow::bail!(
            "two vectors must have the same lengths, {} != {}",
            a.len(),
            b.len()
        );
    }

    let mut result = b.to_vec();
    for i in 0..b.len() {
        result[i] = result[i].mul(*x, jubjub_params);
        result[i] = result[i].add(&a[i], jubjub_params);
    }

    Ok(result)
}

// Computes the inner product of vectors a and b.
// Error if the two vectors have different lengths.
pub fn inner_prod<F: PrimeField>(a: &[F], b: &[F]) -> anyhow::Result<F> {
    if a.len() != b.len() {
        anyhow::bail!(
            "two vectors must have the same lengths, {} != {}",
            a.len(),
            b.len()
        );
    }

    let mut result = F::zero();
    for i in 0..a.len() {
        let mut tmp = a[i];
        tmp.mul_assign(&b[i]);
        result.add_assign(&tmp);
    }

    Ok(result)
}

// Computes the inner product of vectors a and b.
// Error if the two vectors have different lengths.
pub fn multi_scalar<E: JubjubEngine>(
    points: &[Point<E, Unknown>],
    scalars: &[E::Fs],
    jubjub_params: &E::Params,
) -> anyhow::Result<Point<E, Unknown>> {
    if points.len() != scalars.len() {
        anyhow::bail!(
            "the number of points does not equal the number of scalars, {} != {}",
            points.len(),
            scalars.len()
        );
    }

    let mut result = Point::<E, Unknown>::zero();
    for i in 0..points.len() {
        let mut tmp = points[i].clone();
        tmp = tmp.mul(scalars[i], jubjub_params); // tmp = points[i] * scalars[i]
        result = result.add(&tmp, jubjub_params); // result += tmp
    }

    Ok(result)
}

// Commits to a polynomial using the input group elements.
// Error if the number of group elements does not equal the number of polynomial coefficients.
pub fn commit<E: JubjubEngine>(
    group_elements: &[Point<E, Unknown>],
    polynomial: &[E::Fs],
    jubjub_params: &E::Params,
) -> anyhow::Result<Point<E, Unknown>> {
    // let scalars = polynomial
    //   .iter()
    //   .map(fr_to_fs::<E>)
    //   .collect::<anyhow::Result<Vec<_>>>()?;
    let result = multi_scalar::<E>(group_elements, polynomial, jubjub_params)?;

    Ok(result)
}
