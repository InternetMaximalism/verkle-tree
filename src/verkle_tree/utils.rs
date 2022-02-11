use franklin_crypto::bellman::{CurveAffine, PrimeField};

use crate::ipa_fr::utils::{read_field_element_le, write_field_element_le};

// //following https://tools.ietf.org/html/rfc8032#section-3.1,
// // an fr element x is negative if its binary encoding is
// // lexicographically larger than -x.
// const M_COMPRESSED_NEGATIVE: u8 = 0x80;
// const M_COMPRESSED_POSITIVE: u8 = 0x00;
// const M_UNMASK: u8 = 0x7f;

// // size in byte of a compressed point (point.Y --> fp.Element)
// const SIZE_POINT_COMPRESSED: usize = 32;

// // `sub64` returns the difference of x, y and borrow: diff = x - y - borrow.
// // The borrow input must be 0 or 1; otherwise the behavior is undefined.
// // The `borrow_out` output is guaranteed to be 0 or 1.
// //
// // This function's execution time does not depend on the inputs.
// pub fn sub64(x: u64, y: u64, borrow: u64) -> (u64, u64) {
//     let diff = x - y - borrow;
//     // See Sub32 for the bit logic.
//     let borrow_out = ((!x & y) | (!(x ^ y) & diff)) >> 63;
//     (diff, borrow_out)
// }

// // `lexicographically_largest` returns true if this element is strictly lexicographically
// // larger than its negation, false otherwise
// pub fn lexicographically_largest(z: franklin_crypto::bellman::bls12_381::Fr) -> bool {
//     // adapted from github.com/zkcrypto/bls12_381
//     // we check if the element is larger than (q - 1) / 2
//     // if z - (((q - 1) / 2) + 1) have no underflow, then z > (q - 1) / 2

//     let mut _z = z.clone();
//     _z.from_mont();

//     let (_, b) = sub64(_z[0], 9223372034707292161, 0);
//     let (_, b) = sub64(_z[1], 12240451741123816959, b);
//     let (_, b) = sub64(_z[2], 1845609449319885826, b);
//     let (_, b) = sub64(_z[3], 4176758429732224676, b);

//     b == 0
// }

// // Bytes returns the compressed point as a byte array
// // Follows https://tools.ietf.org/html/rfc8032#section-3.1,
// // as the twisted Edwards implementation is primarily used
// // for eddsa.
// pub fn point_to_bytes<GA: CurveAffine>(point: &GA) -> Vec<u8>
// where
//     GA::Base: PrimeField,
// {
//     let (x, y) = point.into_xy_unchecked();
//     let mut result = write_field_element_le(&x);

//     let mask = if lexicographically_largest(y) {
//         M_COMPRESSED_NEGATIVE
//     } else {
//         M_COMPRESSED_POSITIVE
//     };
//     // p.Y must be in little endian
//     result[result.len() - 1] |= mask; // msb of y

//     result
// }

pub fn point_to_field_element<GA: CurveAffine>(point: &GA) -> anyhow::Result<GA::Scalar>
where
    GA::Base: PrimeField,
{
    let (point_x, point_y) = point.into_xy_unchecked();
    let mut point_bytes = write_field_element_le(&point_x);
    let mut point_bytes_y = write_field_element_le(&point_y);
    point_bytes.append(&mut point_bytes_y);
    println!("point_bytes: {:?}", point_bytes);
    let result = read_field_element_le(&point_bytes)?;

    Ok(result)
}

pub fn fill_suffix_tree_poly<F: PrimeField>(
    dest: &mut [F],
    src: &[Option<[u8; 32]>],
) -> anyhow::Result<usize> {
    let mut count = 0;
    for (idx, val) in src.iter().enumerate() {
        if let Some(v) = val {
            count += 1;
            leaf_to_commitments(&mut dest[((idx << 1) & 0xFF)..], *v)?;
        }
    }

    Ok(count)
}

pub fn leaf_to_commitments<F: PrimeField>(poly: &mut [F], val: [u8; 32]) -> anyhow::Result<()> {
    if val.len() > 32 {
        panic!("invalid leaf length {}, {:?}", val.len(), val);
    }

    let mut val_lo_with_marker = val.to_vec();
    val_lo_with_marker.resize(16, 0u8);
    val_lo_with_marker.push(1); // 2 ** 128

    poly[0] = read_field_element_le(&val_lo_with_marker)?;
    if val.len() >= 16 {
        poly[1] = read_field_element_le(&val[16..])?;
    }

    Ok(())
}

pub fn equal_paths(key1: &[u8], key2: &[u8]) -> bool {
    key1[..31] == key2[..31]
}

// offset2key extracts the n bits of a key that correspond to the
// index of a child node.
pub fn offset2key(key: &[u8], offset: usize) -> u8 {
    key[offset]
}
