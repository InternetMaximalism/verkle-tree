use franklin_crypto::{
    babyjubjub::{edwards, JubjubEngine, Unknown},
    bellman::PrimeField,
};

use crate::ipa_fs::utils::{read_field_element_le, write_field_element_le};

pub fn point_to_field_element<E: JubjubEngine>(
    point: &edwards::Point<E, Unknown>,
) -> anyhow::Result<E::Fs> {
    let (_point_x, point_y) = point.into_xy();
    let mut point_bytes = write_field_element_le(&point_y);
    // let mut point_bytes_x = write_field_element_le(&_point_x);
    // point_bytes.append(&mut point_bytes_x);

    // let num_bits_rest = E::Fs::NUM_BITS - 248;
    // let mask = (1 << (num_bits_rest - 1)) - 1;
    let mask = 0b00000011;
    point_bytes[31] &= mask;
    let result = read_field_element_le(&point_bytes)?;

    Ok(result)
}

// This function returns the number of non-empty leaves.
pub fn fill_leaf_tree_poly<F: PrimeField>(
    dest: &mut [F],
    src: &[Option<[u8; 32]>],
    num_limbs: usize,
) -> anyhow::Result<usize> {
    let domain_size = dest.len();
    assert_eq!(domain_size % num_limbs, 0);
    let mut count = 0;
    for (idx, val) in src.iter().enumerate() {
        if let Some(v) = val {
            count += 1;
            let start_index = (num_limbs * idx) % domain_size;
            leaf_to_commitments(
                &mut dest[start_index..(start_index + num_limbs)],
                *v,
                num_limbs,
            )?;
        }
    }

    Ok(count)
}

pub fn leaf_to_commitments<F: PrimeField>(
    poly: &mut [F],
    val: [u8; 32],
    num_limbs: usize,
) -> anyhow::Result<()> {
    assert_eq!(num_limbs, 2); // TODO: `num_limbs` takes any positive number.
    let bits_of_value = 256;
    let limb_size = bits_of_value / num_limbs;
    let limb_size_bytes = limb_size / 8; // 16
    debug_assert!(poly.len() >= num_limbs);
    debug_assert!(limb_size + 1 < F::NUM_BITS as usize);

    let mut val_lo_with_marker = val.to_vec();
    val_lo_with_marker.resize(limb_size_bytes, 0u8);
    val_lo_with_marker.push(1); // 2 ** limb_size

    poly[0] = read_field_element_le(&val_lo_with_marker)?;
    if val.len() >= limb_size_bytes {
        poly[1] = read_field_element_le(&val[limb_size_bytes..])?;
    }

    Ok(())
}

pub fn equal_stems(key1: &[u8], key2: &[u8]) -> bool {
    key1[..31] == key2[..31]
}
