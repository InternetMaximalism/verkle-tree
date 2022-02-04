use hex::FromHexError;

pub trait ToBytes {
    fn to_bytes_be(&self) -> Result<Vec<u8>, FromHexError>;
    fn to_bytes_le(&self) -> Result<Vec<u8>, FromHexError>;
}

pub trait FromBytes
where
    Self: Sized,
{
    fn from_bytes_be(value: &[u8]) -> Option<Self>;
    fn from_bytes_le(value: &[u8]) -> Option<Self>;
}
