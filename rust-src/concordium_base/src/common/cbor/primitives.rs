use crate::common::cbor::{
    CborDecoder, CborDeserialize, CborEncoder, CborSerializationError, CborSerializationResult,
    CborSerialize, DataItemType,
};
use anyhow::{anyhow, Context};
use ciborium_ll::simple;
use concordium_contracts_common::hashes::Hash;

impl<const N: usize> CborSerialize for [u8; N] {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> CborSerializationResult<()> {
        encoder.encode_bytes(self)
    }
}

impl<const N: usize> CborDeserialize for [u8; N] {
    fn deserialize<C: CborDecoder>(decoder: C) -> CborSerializationResult<Self>
    where
        Self: Sized, {
        let mut dest = [0; N];
        decoder.decode_bytes_exact(&mut dest)?;
        Ok(dest)
    }
}

impl CborSerialize for [u8] {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> CborSerializationResult<()> {
        encoder.encode_bytes(self)
    }
}

/// CBOR bytes data item.
///
/// Notice that this serializes different from a plain `Vec<u8>` which
/// serializes to an array data item.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Bytes(pub Vec<u8>);

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

impl CborSerialize for Bytes {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> CborSerializationResult<()> {
        encoder.encode_bytes(&self.0)
    }
}

impl CborDeserialize for Bytes {
    fn deserialize<C: CborDecoder>(decoder: C) -> CborSerializationResult<Self>
    where
        Self: Sized, {
        Ok(Bytes(decoder.decode_bytes()?))
    }
}

impl CborSerialize for Hash {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> CborSerializationResult<()> {
        encoder.encode_bytes(self.as_ref())
    }
}

impl CborDeserialize for Hash {
    fn deserialize<C: CborDecoder>(decoder: C) -> CborSerializationResult<Self>
    where
        Self: Sized, {
        let bytes = decoder.decode_bytes()?;
        let hash = Hash::try_from(bytes.as_slice()).context("CBOR data item not a valid hash")?;
        Ok(hash)
    }
}

impl CborSerialize for bool {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> CborSerializationResult<()> {
        encoder.encode_simple(if *self { simple::TRUE } else { simple::FALSE })
    }
}

impl CborDeserialize for bool {
    fn deserialize<C: CborDecoder>(decoder: C) -> CborSerializationResult<Self>
    where
        Self: Sized, {
        let value = decoder.decode_simple()?;
        match value {
            simple::TRUE => Ok(true),
            simple::FALSE => Ok(false),
            value => Err(CborSerializationError::invalid_data(format!(
                "simple value not a valid bool: {}",
                value
            ))),
        }
    }
}

macro_rules! serialize_deserialize_unsigned_integer {
    ($t:ty) => {
        impl CborSerialize for $t {
            fn serialize<C: CborEncoder>(&self, encoder: C) -> CborSerializationResult<()> {
                encoder.encode_positive(
                    (*self)
                        .try_into()
                        .context(concat!("convert from usize to ", stringify!($t)))?,
                )
            }
        }

        impl CborDeserialize for $t {
            fn deserialize<C: CborDecoder>(decoder: C) -> CborSerializationResult<Self>
            where
                Self: Sized, {
                Ok(decoder.decode_positive()?.try_into().context(concat!(
                    "convert ",
                    stringify!($t),
                    " to usize"
                ))?)
            }
        }
    };
}

serialize_deserialize_unsigned_integer!(u8);
serialize_deserialize_unsigned_integer!(u16);
serialize_deserialize_unsigned_integer!(u32);
serialize_deserialize_unsigned_integer!(u64);
serialize_deserialize_unsigned_integer!(usize);

macro_rules! serialize_deserialize_signed_integer {
    ($t:ty) => {
        impl CborSerialize for $t {
            fn serialize<C: CborEncoder>(&self, encoder: C) -> CborSerializationResult<()> {
                if *self >= 0 {
                    encoder.encode_positive(u64::try_from(*self).context(concat!(
                        "convert ",
                        stringify!($t),
                        " to positive"
                    ))?)
                } else {
                    encoder.encode_negative(
                        self.checked_add(1)
                            .and_then(|val| val.checked_neg())
                            .and_then(|val| u64::try_from(val).ok())
                            .context(concat!("convert ", stringify!($t), " to negative"))?,
                    )
                }
            }
        }

        impl CborDeserialize for $t {
            fn deserialize<C: CborDecoder>(mut decoder: C) -> CborSerializationResult<Self>
            where
                Self: Sized, {
                match decoder.peek_data_item_header()?.to_type() {
                    DataItemType::Positive => Ok(<$t>::try_from(decoder.decode_positive()?)
                        .context(concat!("convert positive to ", stringify!($t)))?),
                    DataItemType::Negative => Ok(<$t>::try_from(decoder.decode_negative()?)
                        .ok()
                        .and_then(|val| val.checked_add(1))
                        .and_then(|val| val.checked_neg())
                        .context(concat!("convert negative to ", stringify!($t)))?),
                    data_item_type => Err(anyhow!(
                        "expected data item {:?} or {:?} as for {}, was {:?}",
                        DataItemType::Positive,
                        DataItemType::Negative,
                        stringify!($t),
                        data_item_type
                    )
                    .into()),
                }
            }
        }
    };
}

serialize_deserialize_signed_integer!(i8);
serialize_deserialize_signed_integer!(i16);
serialize_deserialize_signed_integer!(i32);
serialize_deserialize_signed_integer!(i64);
serialize_deserialize_signed_integer!(isize);

impl CborSerialize for f64 {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> CborSerializationResult<()> {
        encoder.encode_float(*self)
    }
}

impl CborDeserialize for f64 {
    fn deserialize<C: CborDecoder>(decoder: C) -> CborSerializationResult<Self>
    where
        Self: Sized, {
        decoder.decode_float()
    }
}

impl CborSerialize for str {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> CborSerializationResult<()> {
        encoder.encode_text(self)
    }
}

impl CborSerialize for &str {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> CborSerializationResult<()> {
        encoder.encode_text(self)
    }
}

impl CborSerialize for String {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> CborSerializationResult<()> {
        encoder.encode_text(self)
    }
}

impl CborDeserialize for String {
    fn deserialize<C: CborDecoder>(decoder: C) -> CborSerializationResult<Self>
    where
        Self: Sized, {
        Ok(String::from_utf8(decoder.decode_text()?)
            .context("text data item not valid UTF8 encoding")?)
    }
}

/// Key in a CBOR map
#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub enum MapKey {
    Positive(u64),
    Text(String),
}

impl From<String> for MapKey {
    fn from(value: String) -> Self { Self::Text(value) }
}

impl From<u64> for MapKey {
    fn from(value: u64) -> Self { Self::Positive(value) }
}

impl TryFrom<MapKey> for String {
    type Error = CborSerializationError;

    fn try_from(value: MapKey) -> Result<Self, Self::Error> {
        match value {
            MapKey::Positive(_) => Err(anyhow!("MapKey not a of type Text").into()),
            MapKey::Text(value) => Ok(value),
        }
    }
}

impl TryFrom<MapKey> for u64 {
    type Error = CborSerializationError;

    fn try_from(value: MapKey) -> Result<Self, Self::Error> {
        match value {
            MapKey::Positive(value) => Ok(value),
            MapKey::Text(_) => Err(anyhow!("MapKey not a of type Positive").into()),
        }
    }
}

impl MapKey {
    pub fn as_ref(&self) -> MapKeyRef {
        match self {
            MapKey::Positive(positive) => MapKeyRef::Positive(*positive),
            MapKey::Text(text) => MapKeyRef::Text(text),
        }
    }
}

/// Key in a CBOR map
#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub enum MapKeyRef<'a> {
    Positive(u64),
    Text(&'a str),
}

impl CborSerialize for MapKeyRef<'_> {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> CborSerializationResult<()> {
        match self {
            Self::Positive(positive) => encoder.encode_positive(*positive),
            Self::Text(text) => encoder.encode_text(text),
        }
    }
}

impl CborDeserialize for MapKey {
    fn deserialize<C: CborDecoder>(mut decoder: C) -> CborSerializationResult<Self>
    where
        Self: Sized, {
        match decoder.peek_data_item_header()?.to_type() {
            DataItemType::Positive => Ok(Self::Positive(u64::deserialize(decoder)?)),
            DataItemType::Text => Ok(Self::Text(String::deserialize(decoder)?)),
            data_item_type => Err(anyhow!(
                "expected data item {:?} or {:?} as map key, was {:?}",
                DataItemType::Positive,
                DataItemType::Text,
                data_item_type
            )
            .into()),
        }
    }
}

impl CborSerialize for MapKey {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> CborSerializationResult<()> {
        match self {
            Self::Positive(positive) => encoder.encode_positive(*positive),
            Self::Text(text) => encoder.encode_text(text),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::common::cbor::{cbor_decode, cbor_encode};

    #[test]
    fn test_u64() {
        let value = 0u64;
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "00");
        let value_decoded: u64 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);

        let value = 1u64;
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "01");
        let value_decoded: u64 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);

        let value = 1230u64;
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "1904ce");
        let value_decoded: u64 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
    }

    #[test]
    fn test_i64() {
        let value = 0i64;
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "00");
        let value_decoded: i64 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);

        let value = 1i64;
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "01");
        let value_decoded: i64 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);

        let value = 2i64;
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "02");
        let value_decoded: i64 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);

        let value = -1i64;
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "20");
        let value_decoded: i64 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);

        let value = -2i64;
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "21");
        let value_decoded: i64 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);

        let value = 1230i64;
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "1904ce");
        let value_decoded: i64 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);

        let value = -1230i64;
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "3904cd");
        let value_decoded: i64 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
    }

    #[test]
    fn test_bool() {
        let value = false;
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "f4");
        let value_decoded: bool = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);

        let value = true;
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "f5");
        let value_decoded: bool = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
    }

    #[test]
    fn test_f64() {
        let value = 1.123f64;
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "fb3ff1f7ced916872b");
        let value_decoded: f64 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
    }

    #[test]
    fn test_bytes() {
        let bytes = Bytes(vec![1, 2, 3, 4, 5]);

        let cbor = cbor_encode(&bytes).unwrap();
        assert_eq!(hex::encode(&cbor), "450102030405");
        let bytes_decoded: Bytes = cbor_decode(&cbor).unwrap();
        assert_eq!(bytes_decoded, bytes);
    }

    #[test]
    fn test_bytes_exact_length() {
        let bytes: [u8; 5] = [1, 2, 3, 4, 5];

        let cbor = cbor_encode(&bytes).unwrap();
        assert_eq!(hex::encode(&cbor), "450102030405");
        let bytes_decoded: [u8; 5] = cbor_decode(&cbor).unwrap();
        assert_eq!(bytes_decoded, bytes);

        let err = cbor_decode::<[u8; 4]>(&cbor).unwrap_err().to_string();
        assert!(err.contains("expected 4 bytes"), "err: {}", err);
    }

    /// Test where CBOR is not well-formed: Bytes length in header does not
    /// match actual data. Test that we get an error and don't panic
    #[test]
    fn test_bytes_length_invalid() {
        let cbor = hex::decode("58ff0102030405").unwrap();
        cbor_decode::<[u8; 0xff]>(&cbor).expect_err("should give error");

        let cbor = hex::decode("410102030405").unwrap();
        cbor_decode::<[u8; 0x01]>(&cbor).expect_err("should give error");
    }

    #[test]
    fn test_text() {
        let text = "abcd";

        let cbor = cbor_encode(&text).unwrap();
        assert_eq!(hex::encode(&cbor), "6461626364");
        let text_decoded: String = cbor_decode(&cbor).unwrap();
        assert_eq!(text_decoded, text);
    }

    /// Test where CBOR is not well-formed: Text length in header does not match
    /// actual data. Test that we get an error and don't panic
    #[test]
    fn test_text_length_invalid() {
        let cbor = hex::decode("78ff61626364").unwrap();
        cbor_decode::<String>(&cbor).expect_err("should give error");

        let cbor = hex::decode("6161626364").unwrap();
        cbor_decode::<String>(&cbor).expect_err("should give error");
    }
}
