use franklin_crypto::bellman::pairing::CurveAffine;
use franklin_crypto::bellman::{CurveProjective, Field, PrimeField, PrimeFieldRepr, SqrtField};
use sha2::{Digest, Sha256};

use super::config::DOMAIN_SIZE;

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

pub fn read_point_le<F: PrimeField>(bytes: &[u8]) -> anyhow::Result<F> {
    let mut repr = F::Repr::default();
    let mut padded_bytes = bytes.to_vec();
    let num_bits = F::NUM_BITS as usize;
    assert!(bytes.len() <= num_bits);
    // for _ in bytes.len()..num_bits {
    //     padded_bytes.push(0);
    // }
    padded_bytes.resize(num_bits, 0);
    repr.read_le::<&[u8]>(padded_bytes.as_ref())?;
    let value = F::from_repr(repr)?;

    Ok(value)
}

pub fn read_point_be<F: PrimeField>(bytes: &[u8]) -> anyhow::Result<F> {
    let mut padded_bytes = bytes.to_vec();
    padded_bytes.reverse();
    read_point_le(&padded_bytes)
}

pub fn write_point_le<F: PrimeField>(scalar: &F) -> Vec<u8> {
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

pub fn write_point_be<F: PrimeField>(scalar: &F) -> Vec<u8> {
    let mut result = write_point_le(scalar);
    result.reverse();

    result
}

#[test]
fn test_read_write_ff() {
    use franklin_crypto::bellman::pairing::bn256::Fr;

    let bytes = [
        101u8, 121, 238, 208, 145, 118, 73, 126, 4, 129, 129, 133, 67, 167, 1, 64, 164, 189, 107,
        239, 228, 126, 238, 70, 205, 50, 174, 80, 238, 181, 137, 47,
    ];
    let point = read_point_le::<Fr>(&bytes).unwrap();
    assert_eq!(
        format!("{:?}", point),
        "Fr(0x2f89b5ee50ae32cd46ee7ee4ef6bbda44001a743858181047e497691d0ee7965)"
    );

    let recovered_bytes = write_point_le(&point);
    assert_eq!(recovered_bytes, bytes);
}

// pub fn fr_to_fs_repr<E: JubjubEngine>(
//   value: &E::Fr,
// ) -> anyhow::Result<<E::Fs as PrimeField>::Repr> {
//   let bytes = write_point_le(value);
//   let mut fs_repr = <E::Fs as PrimeField>::Repr::default();
//   fs_repr.read_le::<&[u8]>(bytes.as_ref())?;

//   Ok(fs_repr)
// }

// pub fn fr_to_fs<E: JubjubEngine>(value: &E::Fr) -> anyhow::Result<E::Fs> {
//   read_point_le(&write_point_le(value))
// }

pub fn generate_random_points<G: CurveProjective>(num_points: usize) -> anyhow::Result<Vec<G>>
where
    <G::Affine as CurveAffine>::Base: PrimeField,
{
    let mut hasher = Sha256::new();
    hasher.update(b"eth_verkle_oct_2021"); // In case it changes or needs updating, we can use eth_verkle_month_year.
    let digest = hasher.finalize();
    let u = read_point_le::<<G::Affine as CurveAffine>::Base>(digest.as_ref())?;

    // flag to indicate whether we choose the lexicographically larger
    // element of `x` out of it and it's negative (?)
    let is_largest = false;

    let mut points = vec![];

    let mut increment = 0usize;

    // TODO: It takes too long to find some random points with the specific order.
    while points.len() != num_points {
        let mut x = u;
        x.add_assign(&read_point_le(&increment.to_le_bytes()).unwrap()); // y = u + increment
        increment += 1;

        let mut rhs = x;
        rhs.square();
        rhs.mul_assign(&x);
        rhs.add_assign(&G::Affine::b_coeff());

        if let Some(y) = rhs.sqrt() {
            let y_repr = y.into_repr();
            let mut neg_y = y;
            neg_y.negate();
            let neg_y_repr = neg_y.into_repr();
            let is_positive = is_largest ^ (neg_y_repr < y_repr); // XOR
            let selected_y = if is_positive { y } else { neg_y };

            let point_found = G::Affine::from_xy_checked(x, selected_y)
                .unwrap()
                .into_projective();
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
    for i in 0..result.len() {
        result[i].mul_assign(x);
        result[i].add_assign(&a[i]);
    }

    Ok(result)
}

// Computes vector c satisfying c[i] = a[i] + b[i] * x.
// Error if vectors a, b have different lengths.
pub fn fold_points<G>(a: &[G], b: &[G], x: G::Scalar) -> anyhow::Result<Vec<G>>
where
    G: CurveProjective,
{
    if a.len() != b.len() {
        anyhow::bail!(
            "two vectors must have the same lengths, {} != {}",
            a.len(),
            b.len()
        );
    }

    let mut result = b.to_vec();
    for i in 0..b.len() {
        result[i].mul_assign(x);
        result[i].add_assign(&a[i]);
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
pub fn multi_scalar<G>(points: &[G], scalars: &[G::Scalar]) -> anyhow::Result<G>
where
    G: CurveProjective,
{
    if points.len() != scalars.len() {
        anyhow::bail!(
            "the number of points does not equal the number of scalars, {} != {}",
            points.len(),
            scalars.len()
        );
    }

    let mut result = G::zero();
    for i in 0..points.len() {
        let mut tmp = points[i];
        tmp.mul_assign(scalars[i]); // tmp = points[i] * scalars[i]
        result.add_assign(&tmp); // result += tmp
    }

    Ok(result)
}

// Commits to a polynomial using the input group elements.
// Error if the number of group elements does not equal the number of polynomial coefficients.
pub fn commit<G>(group_elements: &[G], polynomial: &[G::Scalar]) -> anyhow::Result<G>
where
    G: CurveProjective,
{
    let result = multi_scalar(group_elements, polynomial)?;

    Ok(result)
}

pub fn test_poly<F: PrimeField>(polynomial: &[u64]) -> Vec<F> {
    let n = polynomial.len();
    assert!(
        n <= DOMAIN_SIZE,
        "polynomial cannot exceed {} coefficients",
        DOMAIN_SIZE
    );

    let mut polynomial_fr = Vec::with_capacity(DOMAIN_SIZE);
    for polynomial_i in polynomial {
        polynomial_fr.push(read_point_le(&polynomial_i.to_le_bytes()).unwrap());
    }

    // for _ in n..DOMAIN_SIZE {
    //     polynomial_fr.push(F::zero());
    // }
    polynomial_fr.resize(DOMAIN_SIZE, F::zero());

    polynomial_fr
}
