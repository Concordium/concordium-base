use crate::common::cbor::{
    Bytes, CborDecoder, CborDeserialize, CborEncoder, CborSerializationResult, CborSerialize,
    DataItemHeader,
};
use anyhow::Context;
use ciborium_ll::simple;

/// Generic CBOR data item that can represent
/// any data item type.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Positive(u64),
    Negative(u64),
    Bytes(Bytes),
    Float(f64),
    Text(String),
    Bool(bool),
    Null,
    Tag(u64, Box<Value>),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
}

impl CborSerialize for Value {
    fn serialize<C: CborEncoder>(&self, mut encoder: C) -> CborSerializationResult<()> {
        match self {
            Value::Positive(value) => encoder.encode_positive(*value),
            Value::Negative(value) => encoder.encode_negative(*value),
            Value::Bytes(value) => encoder.encode_bytes(&value.0),
            Value::Float(_) => {
                todo!()
            }
            Value::Text(value) => encoder.encode_text(value),
            Value::Bool(value) => {
                if *value {
                    encoder.encode_simple(simple::TRUE)
                } else {
                    encoder.encode_simple(simple::FALSE)
                }
            }
            Value::Null => {
                todo!()
            }
            Value::Tag(tag, value) => {
                encoder.encode_tag(*tag)?;
                value.serialize(encoder)
            }
            Value::Array(_) => {
                todo!()
            }
            Value::Map(_) => {
                todo!()
            }
        }
    }

    fn is_null(&self) -> bool {
        false // todo ar
    }
}

impl CborDeserialize for Value {
    fn deserialize<C: CborDecoder>(mut decoder: C) -> CborSerializationResult<Self>
    where
        Self: Sized, {
        Ok(match decoder.peek_data_item_header()? {
            DataItemHeader::Positive(_) => Value::Positive(decoder.decode_positive()?),
            DataItemHeader::Negative(_) => Value::Negative(decoder.decode_negative()?),
            DataItemHeader::Bytes(_) => Value::Bytes(Bytes(decoder.decode_bytes()?)),
            DataItemHeader::Text(_) => Value::Text(
                String::from_utf8(decoder.decode_text()?)
                    .context("text data item not valid UTF8 encoding")?,
            ),
            DataItemHeader::Array(_) => {
                todo!()
            }
            DataItemHeader::Map(_) => {
                todo!()
            }
            DataItemHeader::Tag(_) => {
                let tag = decoder.decode_tag()?;
                let value = Value::deserialize(decoder)?;
                Value::Tag(tag, Box::new(value))
            }
            DataItemHeader::Simple(_) => match decoder.decode_simple()? {
                simple::TRUE => Value::Bool(true),
                simple::FALSE => Value::Bool(false),
                _ => {
                    todo!()
                }
            },
            DataItemHeader::Float(_) => {
                todo!()
            }
            DataItemHeader::Break => {
                todo!()
            }
        })
    }

    fn null() -> Option<Self>
    where
        Self: Sized, {
        None // todo ar
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::common::cbor::{cbor_decode, cbor_encode};

    #[test]
    fn test_positive() {
        let value = Value::Positive(3);

        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "03");
        let value_decoded: Value = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
    }

    #[test]
    fn test_negative() {
        let value = Value::Negative(3);

        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "23");
        let value_decoded: Value = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
    }

    #[test]
    fn test_bool() {
        let value = Value::Bool(false);

        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "f4");
        let value_decoded: Value = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);

        let value = Value::Bool(true);

        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "f5");
        let value_decoded: Value = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
    }

    #[test]
    fn test_text() {
        let value = Value::Text("abcd".to_string());

        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "6461626364");
        let value_decoded: Value = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
    }

    #[test]
    fn test_bytes() {
        let bytes = Value::Bytes(Bytes(vec![1, 2, 3, 4, 5]));

        let cbor = cbor_encode(&bytes).unwrap();
        assert_eq!(hex::encode(&cbor), "450102030405");
        let bytes_decoded: Value = cbor_decode(&cbor).unwrap();
        assert_eq!(bytes_decoded, bytes);
    }

    #[test]
    fn test_tag() {
        let value = Value::Tag(123, Box::new(Value::Positive(3)));

        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "d87b03");
        let value_decoded: Value = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
    }
}
