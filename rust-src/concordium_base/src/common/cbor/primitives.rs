use crate::common::cbor::{
    CborDecoder, CborDeserialize, CborEncoder, CborSerializationError, CborSerializationResult,
    CborSerialize, DataItemType,
};
use anyhow::{anyhow, Context};
use ciborium_ll::simple;

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
            MapKeyRef::Positive(positive) => encoder.encode_positive(*positive),
            MapKeyRef::Text(text) => encoder.encode_text(text),
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
