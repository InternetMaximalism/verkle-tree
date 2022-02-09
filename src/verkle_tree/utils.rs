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

    let mut val_lo_with_marker = vec![0u8; 17];
    let mut lo_end = 16usize;
    if val.len() < lo_end {
        lo_end = val.len();
    }

    let _ = std::mem::replace(
        &mut val_lo_with_marker[..lo_end].to_vec(),
        val[..lo_end].to_vec(),
    );

    val_lo_with_marker[16] = 1; // 2 ** 128
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
