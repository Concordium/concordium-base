use crate::common::cbor::{
    CborDecoder, CborDeserialize, CborEncoder, CborSerializationError, CborSerializationResult,
    CborSerialize, DataItemHeader, DataItemType,
};
use anyhow::{anyhow, Context};
use ciborium_ll::simple;

/// Unsigned bignum, see <https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml>
const UNSIGNED_BIGNUM_TAG: u64 = 2;
/// Negative bignum, see <https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml>
const NEGATIVE_BIGNUM_TAG: u64 = 3;

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
                encoder.encode_positive((*self).try_into().context(concat!(
                    "convert from ",
                    stringify!($t),
                    " to u64"
                ))?)
            }
        }

        impl CborDeserialize for $t {
            fn deserialize<C: CborDecoder>(mut decoder: C) -> CborSerializationResult<Self>
            where
                Self: Sized, {
                let value = match decoder.peek_data_item_header()? {
                    // support the non-preferred bignum encoding as long as we are within range
                    DataItemHeader::Tag(UNSIGNED_BIGNUM_TAG) => {
                        decode_unsigned_bignum_to_u64(decoder)?
                    }
                    DataItemHeader::Positive(_) => decoder.decode_positive()?,
                    header => {
                        return Err(anyhow!(
                            "data item {:?} cannot be decoded to positive integer",
                            header.to_type()
                        )
                        .into())
                    }
                };
                Ok(value
                    .try_into()
                    .context(concat!("convert from u64 to ", stringify!($t)))?)
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
                fn convert_positive(value: u64) -> anyhow::Result<$t> {
                    <$t>::try_from(value).context(concat!("convert positive to ", stringify!($t)))
                }

                fn convert_negative(value: u64) -> anyhow::Result<$t> {
                    <$t>::try_from(value)
                        .ok()
                        .and_then(|val| val.checked_neg())
                        .and_then(|val| val.checked_sub(1))
                        .context(concat!("convert negative to ", stringify!($t)))
                }

                match decoder.peek_data_item_header()? {
                    DataItemHeader::Positive(_) => {
                        Ok(convert_positive(decoder.decode_positive()?)?)
                    }
                    // support the non-preferred bignum encoding as long as we are within range
                    DataItemHeader::Tag(UNSIGNED_BIGNUM_TAG) => {
                        Ok(convert_positive(decode_unsigned_bignum_to_u64(decoder)?)?)
                    }
                    DataItemHeader::Negative(_) => {
                        Ok(convert_negative(decoder.decode_negative()?)?)
                    }
                    // support the non-preferred bignum encoding as long as we are within range
                    DataItemHeader::Tag(NEGATIVE_BIGNUM_TAG) => {
                        Ok(convert_negative(decode_negative_bignum_to_u64(decoder)?)?)
                    }
                    header => {
                        return Err(anyhow!(
                            "data item {:?} cannot be decoded to positive or negative integer",
                            header.to_type()
                        )
                        .into())
                    }
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

fn decode_unsigned_bignum_to_u64<C: CborDecoder>(mut decoder: C) -> CborSerializationResult<u64> {
    decoder.decode_tag_expect(UNSIGNED_BIGNUM_TAG)?;
    decode_ne_bytes_to_u64(&decoder.decode_bytes()?)
}

fn decode_negative_bignum_to_u64<C: CborDecoder>(mut decoder: C) -> CborSerializationResult<u64> {
    decoder.decode_tag_expect(NEGATIVE_BIGNUM_TAG)?;
    decode_ne_bytes_to_u64(&decoder.decode_bytes()?)
}

/// Decode the given bytes as a bignum represented in network byte order
/// (<https://www.rfc-editor.org/rfc/rfc8949.html#name-bignums>).
/// The output value is restricted to `u64`; decoding will fail if the value
/// is outside the range of `u64`.
fn decode_ne_bytes_to_u64(bytes: &[u8]) -> CborSerializationResult<u64> {
    // The bytes that are outside the range of the 8 bytes covered by u64 must
    // all be 0.
    let bytes_outside_range = &bytes[..bytes.len() - bytes.len().min(8)];
    if bytes_outside_range.iter().copied().any(|byte| byte != 0) {
        return Err(anyhow!("bignum out of u64 range").into());
    }

    // The bytes that are inside the range of the 8 bytes covered by u64 are
    // then interpreted as an u64.
    let bytes_in_range = &bytes[bytes.len() - bytes.len().min(8)..];
    let mut u64bytes = [0u8; 8];
    u64bytes[8 - bytes_in_range.len()..].copy_from_slice(bytes_in_range);

    Ok(u64::from_be_bytes(u64bytes))
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

        let value = u64::MAX;
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "1bffffffffffffffff");
        let value_decoded: u64 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
    }

    #[test]
    fn test_u8() {
        let value = 0u8;
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "00");
        let value_decoded: u8 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);

        let value = 1u8;
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "01");
        let value_decoded: u8 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);

        let value = 255u8;
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "18ff");
        let value_decoded: u8 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
    }

    /// Tests decoding tag 2 bignums into u64
    #[test]
    fn test_u64_bignum() {
        let cbor = hex::decode("C240").unwrap();
        let value_decoded: u64 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, 0x00);

        let cbor = hex::decode("C24100").unwrap();
        let value_decoded: u64 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, 0x00);

        let cbor = hex::decode("C24101").unwrap();
        let value_decoded: u64 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, 0x01);

        let cbor = hex::decode("C2420101").unwrap();
        let value_decoded: u64 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, 0x0101);

        // bignum in non-preferred serialization (leading zeros)
        let cbor = hex::decode("C243000001").unwrap();
        let value_decoded: u64 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, 0x01);

        // if we are within range, it is ok that the bignum is more than 8 bytes
        let cbor = hex::decode("C24A00000000000000000001").unwrap();
        let value_decoded: u64 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, 0x01);

        // if we are within range, it is ok that the bignum is more than 8 bytes
        let cbor = hex::decode("C24A00001000000000000001").unwrap();
        let value_decoded: u64 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, 0x01000000000000001);

        // test max value
        let cbor = hex::decode("C248FFFFFFFFFFFFFFFF").unwrap();
        let value_decoded: u64 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, 0xFFFFFFFFFFFFFFFF);

        // value outside range
        let cbor = hex::decode("C249FF0000000000000000").unwrap();
        let error = cbor_decode::<u64>(&cbor).unwrap_err();
        assert!(
            error.to_string().contains("bignum out of u64 range"),
            "message: {}",
            error
        );

        // value outside range
        let cbor = hex::decode("C24AFF000000000000000000").unwrap();
        let error = cbor_decode::<u64>(&cbor).unwrap_err();
        assert!(
            error.to_string().contains("bignum out of u64 range"),
            "message: {}",
            error
        );
    }

    /// Tests decoding tag 2 bignums into u8
    #[test]
    fn test_u8_bignum() {
        let cbor = hex::decode("C24100").unwrap();
        let value_decoded: u8 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, 0x00);

        let cbor = hex::decode("C24101").unwrap();
        let value_decoded: u8 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, 0x01);

        // test max value
        let cbor = hex::decode("C241FF").unwrap();
        let value_decoded: u8 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, 0xFF);

        // value outside range
        let cbor = hex::decode("C2420100").unwrap();
        let error = cbor_decode::<u8>(&cbor).unwrap_err();
        assert!(
            error.to_string().contains("convert from u64 to u8"),
            "message: {}",
            error
        );
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

        let value = i64::MAX;
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "1b7fffffffffffffff");
        let value_decoded: i64 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);

        let value = i64::MIN;
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "3b7fffffffffffffff");
        let value_decoded: i64 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
    }

    #[test]
    fn test_i8() {
        let value = 0i8;
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "00");
        let value_decoded: i8 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);

        let value = 1i8;
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "01");
        let value_decoded: i8 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);

        let value = 2i8;
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "02");
        let value_decoded: i8 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);

        let value = -1i8;
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "20");
        let value_decoded: i8 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);

        let value = -2i8;
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "21");
        let value_decoded: i8 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);

        let value = 127i8;
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "187f");
        let value_decoded: i8 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);

        let value = -128i8;
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "387f");
        let value_decoded: i8 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
    }

    /// Tests decoding tag 2 and 3 bignums into i64
    #[test]
    fn test_i64_bignum() {
        let cbor = hex::decode("C240").unwrap();
        let value_decoded: i64 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, 0x00);

        let cbor = hex::decode("C24101").unwrap();
        let value_decoded: i64 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, 0x01);

        let cbor = hex::decode("C34100").unwrap();
        let value_decoded: i64 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, -0x01);

        let cbor = hex::decode("C3420100").unwrap();
        let value_decoded: i64 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, -0x0101);

        let cbor = hex::decode("C34101").unwrap();
        let value_decoded: i64 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, -0x02);

        // max value
        let cbor = hex::decode("C2487FFFFFFFFFFFFFFF").unwrap();
        let value_decoded: i64 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, 0x7FFFFFFFFFFFFFFF);

        // min value
        let cbor = hex::decode("C3487FFFFFFFFFFFFFFF").unwrap();
        let value_decoded: i64 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, -0x8000000000000000);

        // value outside range
        let cbor = hex::decode("C2488000000000000000").unwrap();
        let error = cbor_decode::<i64>(&cbor).unwrap_err();
        assert!(
            error.to_string().contains("convert positive to i64"),
            "message: {}",
            error
        );

        // value outside range
        let cbor = hex::decode("C3488000000000000000").unwrap();
        let error = cbor_decode::<i64>(&cbor).unwrap_err();
        assert!(
            error.to_string().contains("convert negative to i64"),
            "message: {}",
            error
        );
    }

    /// Tests decoding tag 2 and 3 bignums into i8
    #[test]
    fn test_i8_bignum() {
        let cbor = hex::decode("C24100").unwrap();
        let value_decoded: i8 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, 0x00);

        let cbor = hex::decode("C24101").unwrap();
        let value_decoded: i8 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, 0x01);

        let cbor = hex::decode("C34100").unwrap();
        let value_decoded: i8 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, -0x01);

        // max value
        let cbor = hex::decode("C2417F").unwrap();
        let value_decoded: i8 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, 0x7F);

        // min value
        let cbor = hex::decode("C3417F").unwrap();
        let value_decoded: i8 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, -0x80);

        // value outside range
        let cbor = hex::decode("C2420100").unwrap();
        let error = cbor_decode::<i8>(&cbor).unwrap_err();
        assert!(
            error.to_string().contains("convert positive to i8"),
            "message: {}",
            error
        );

        // value outside range
        let cbor = hex::decode("C3420100").unwrap();
        let error = cbor_decode::<i8>(&cbor).unwrap_err();
        assert!(
            error.to_string().contains("convert negative to i8"),
            "message: {}",
            error
        );
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
    fn test_bytes_empty() {
        let bytes = Bytes(vec![]);

        let cbor = cbor_encode(&bytes).unwrap();
        assert_eq!(hex::encode(&cbor), "40");
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

    #[test]
    fn test_text_empty() {
        let text = "";

        let cbor = cbor_encode(&text).unwrap();
        assert_eq!(hex::encode(&cbor), "60");
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
