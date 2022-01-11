use crate::utils::{FromBytes, ToBytes};
use core::iter::FromIterator;
use ff::PrimeField;
use hex::{FromHexError, ToHex};
use num::bigint::BigUint;

// #[PrimeFieldModulus = "115792089237316195423570985008687907853269984665640564039457584006405596119041"]
#[derive(PrimeField)]
#[PrimeFieldModulus = "21888242871839275222246405745257275088548364400416034343698204186575808495617"]
#[PrimeFieldGenerator = "7"]
#[PrimeFieldReprEndianness = "little"]
pub struct Bn256Fr([u64; 4]);

impl ToHex for Bn256Fr {
    // Parse a Bn256Fr value to a hex string with 0x-prefix.
    fn encode_hex<T: FromIterator<char>>(&self) -> T {
        let repr = format!("{:?}", self.to_repr());
        T::from_iter(repr[2..].chars())
    }

    fn encode_hex_upper<T: FromIterator<char>>(&self) -> T {
        let repr = format!("{:?}", self.to_repr());
        T::from_iter(repr.to_uppercase()[2..].chars())
    }
}

#[test]
fn test_fp_to_hex() {
    let input = 31;
    let x = Bn256Fr::from(input);
    assert_eq!(x.encode_hex::<String>(), format!("{:064x}", input));
    assert_eq!(x.encode_hex_upper::<String>(), format!("{:064X}", input));
}

impl ToBytes for Bn256Fr {
    fn to_bytes_be(&self) -> Result<Vec<u8>, FromHexError> {
        hex::decode(&self.encode_hex::<String>())
    }
    fn to_bytes_le(&self) -> Result<Vec<u8>, FromHexError> {
        let mut res = self.to_bytes_be()?;
        res.reverse();
        Ok(res)
    }
}

#[test]
fn test_fp_to_bytes() {
    let input = 31;
    let x = Bn256Fr::from(input);
    let x_bytes_be = x.to_bytes_be().unwrap();
    let x_bytes_le = x.to_bytes_le().unwrap();
    assert_eq!(
        x_bytes_be,
        vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 31
        ]
    );
    assert_eq!(x_bytes_be.len(), 32);
    assert_eq!(
        x_bytes_le,
        vec![
            31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0
        ]
    );
    assert_eq!(x_bytes_le.len(), 32);
}

impl FromBytes for Bn256Fr {
    fn from_bytes_be(value: &[u8]) -> Option<Self> {
        Self::from_str_vartime(&BigUint::from_bytes_be(value.as_ref()).to_str_radix(10))
    }
    fn from_bytes_le(value: &[u8]) -> Option<Self> {
        Self::from_str_vartime(&BigUint::from_bytes_le(value.as_ref()).to_str_radix(10))
    }
}
