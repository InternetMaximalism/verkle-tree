use franklin_crypto::bellman::{CurveAffine, PrimeField};

use crate::ipa_fr::utils::{read_field_element_le, write_field_element_le};

pub fn point_to_field_element<GA: CurveAffine>(point: &GA) -> anyhow::Result<GA::Scalar>
where
    GA::Base: PrimeField,
{
    let (point_x, point_y) = point.into_xy_unchecked();
    let mut point_bytes = write_field_element_le(&point_x);
    let mut point_bytes_y = write_field_element_le(&point_y);
    point_bytes.append(&mut point_bytes_y);
    let result = read_field_element_le(&point_bytes)?;

    Ok(result)
}

pub fn fill_leaf_tree_poly<F: PrimeField>(
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

pub fn equal_stems(key1: &[u8], key2: &[u8]) -> bool {
    key1[..31] == key2[..31]
}
