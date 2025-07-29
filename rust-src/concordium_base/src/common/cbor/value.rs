use crate::common::cbor::{
    Bytes, CborArrayDecoder, CborArrayEncoder, CborDecoder, CborDeserialize, CborEncoder,
    CborMapDecoder, CborMapEncoder, CborSerializationResult, CborSerialize, DataItemHeader,
};
use anyhow::Context;
use ciborium_ll::simple;

/// Generic CBOR data item that can represent
/// any data item type.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Positive integer (major type 0)
    Positive(u64),
    /// Negative integer (major type 1)
    Negative(u64),
    /// Bytes (major type 2)
    Bytes(Bytes),
    /// Text (major type 3)
    Text(String),
    /// Array (major type 4)
    Array(Vec<Value>),
    /// Map (major type 5)
    Map(Vec<(Value, Value)>),
    /// Tagged data item (major type 6)
    Tag(u64, Box<Value>),
    /// Simple value FALSE and TRUE (major type 7)
    Bool(bool),
    /// Simple value NULL (major type 7)
    Null,
    /// Other simple values (major type 7)
    Simple(u8),
    /// Float (major type 7)
    Float(f64),
}

impl CborSerialize for Value {
    fn serialize<C: CborEncoder>(&self, mut encoder: C) -> CborSerializationResult<()> {
        match self {
            Value::Positive(value) => encoder.encode_positive(*value),
            Value::Negative(value) => encoder.encode_negative(*value),
            Value::Bytes(value) => encoder.encode_bytes(&value.0),
            Value::Text(value) => encoder.encode_text(value),
            Value::Array(value) => {
                let mut array_encoder = encoder.encode_array(value.len())?;
                for element in value {
                    array_encoder.serialize_element(element)?;
                }
                array_encoder.end()
            }
            Value::Map(value) => {
                let mut map_encoder = encoder.encode_map(value.len())?;
                for entry in value {
                    map_encoder.serialize_entry(&entry.0, &entry.1)?;
                }
                map_encoder.end()
            }
            Value::Tag(tag, value) => {
                encoder.encode_tag(*tag)?;
                value.serialize(encoder)
            }
            Value::Bool(value) => {
                if *value {
                    encoder.encode_simple(simple::TRUE)
                } else {
                    encoder.encode_simple(simple::FALSE)
                }
            }
            Value::Null => encoder.encode_simple(simple::NULL),
            Value::Simple(value) => encoder.encode_simple(*value),
            Value::Float(value) => encoder.encode_float(*value),
        }
    }

    fn is_null(&self) -> bool { matches!(self, Value::Null) }
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
                let mut array_decoder = decoder.decode_array()?;
                let mut vec = Vec::with_capacity(array_decoder.size().unwrap_or_default());
                while let Some(element) = array_decoder.deserialize_element()? {
                    vec.push(element);
                }
                Value::Array(vec)
            }
            DataItemHeader::Map(_) => {
                let mut map_decoder = decoder.decode_map()?;
                let mut vec = Vec::with_capacity(map_decoder.size().unwrap_or_default());
                while let Some(entry) = map_decoder.deserialize_entry()? {
                    vec.push(entry);
                }
                Value::Map(vec)
            }
            DataItemHeader::Tag(_) => {
                let tag = decoder.decode_tag()?;
                let value = Value::deserialize(decoder)?;
                Value::Tag(tag, Box::new(value))
            }
            DataItemHeader::Simple(_) => match decoder.decode_simple()? {
                simple::TRUE => Value::Bool(true),
                simple::FALSE => Value::Bool(false),
                simple::NULL => Value::Null,
                value => Value::Simple(value),
            },
            DataItemHeader::Float(_) => Value::Float(decoder.decode_float()?),
        })
    }

    fn null() -> Option<Self>
    where
        Self: Sized, {
        Some(Value::Null)
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

    #[test]
    fn test_null() {
        let value = Value::Null;

        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "f6");
        let value_decoded: Value = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
    }

    #[test]
    fn test_simple() {
        let value = Value::Simple(15);

        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "ef");
        let value_decoded: Value = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);

        let value = Value::Simple(65);

        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "f841");
        let value_decoded: Value = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
    }

    #[test]
    fn test_float() {
        let value = Value::Float(1.123);

        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "fb3ff1f7ced916872b");
        let value_decoded: Value = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
    }

    #[test]
    fn test_array() {
        let value = Value::Array(vec![Value::Positive(1), Value::Positive(3)]);

        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "820103");
        let value_decoded: Value = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
    }

    #[test]
    fn test_map() {
        let value = Value::Map(vec![
            (Value::Positive(1), Value::Positive(3)),
            (Value::Positive(2), Value::Positive(4)),
        ]);

        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "a201030204");
        let value_decoded: Value = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
    }
}
