use crate::utils::{FromBytes, ToBytes};
use core::iter::FromIterator;
use ff::PrimeField;
use hex::{FromHexError, ToHex};
use num::bigint::BigUint;

#[derive(PrimeField)]
#[PrimeFieldModulus = "2736030358979909402780800718157159386076813972158567259200215660948447373041"]
#[PrimeFieldGenerator = "679638403160184741879882486296176694152956900548039552939252414651485059416"] // 6
#[PrimeFieldReprEndianness = "little"]
pub struct Bn256Fs([u64; 4]);

impl ToHex for Bn256Fs {
    // Parse a Bn256Fs value to a hex string with 0x-prefix.
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
    let x = Bn256Fs::from(input);
    assert_eq!(x.encode_hex::<String>(), format!("{:064x}", input));
    assert_eq!(x.encode_hex_upper::<String>(), format!("{:064X}", input));
}

impl ToBytes for Bn256Fs {
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
    let x = Bn256Fs::from(input);
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

impl FromBytes for Bn256Fs {
    fn from_bytes_be(value: &[u8]) -> Option<Self> {
        Self::from_str_vartime(&BigUint::from_bytes_be(value.as_ref()).to_str_radix(10))
    }
    fn from_bytes_le(value: &[u8]) -> Option<Self> {
        Self::from_str_vartime(&BigUint::from_bytes_le(value.as_ref()).to_str_radix(10))
    }
}
