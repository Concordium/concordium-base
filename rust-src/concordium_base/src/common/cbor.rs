//! # CBOR serialization
//! This module implementations generic CBOR serialization based on data models
//! defined via Rust types. Types should implement [`CborSerialize`] and
//! [`CborDeserialize`] to define the serialization structure. The interface to
//! implement the serialization goes through [`CborEncoder`] and [`CborDecoder`]
//! that implements the CBOR encoding format. The module implements
//! serialization of primitive Rust types like integers, strings and byte
//! arrays.
//!
//! ## Deriving `CborSerialize` and `CborDeserialize`
//!
//! ### Structs
//!
//! [`CborSerialize`] and [`CborDeserialize`] can be derived on structs with
//! named fields and struct tuples:
//! ```ignore
//! #[derive(CborSerialize, CborDeserialize)]
//! struct TestStruct {
//!     field1: u64,
//!     field2: String,
//! }
//!
//! #[derive(Debug, Eq, PartialEq, CborSerialize, CborDeserialize)]
//! struct TestTuple(u64, String);
//! ```
//! Structs with named fields are serialized as CBOR maps using camel cased
//! field names as keys (of data item type text) and tuples are serialized as
//! CBOR arrays.
//!
//! ### Enums
//!
//! [`CborSerialize`] and [`CborDeserialize`] can be derived on enums using
//! `map` representation:
//! ```ignore
//! # use concordium_base_derive::{CborDeserialize, CborSerialize};
//! #
//! #[derive(CborSerialize, CborDeserialize)]
//! #[cbor(map)]
//! enum TestEnum {
//!     Var1(u64),
//!     Var2(String),
//! }
//! ```
//! All enum variants must be single element tuples.
//!
//! Using `#[cbor(map)]` represents the enum as a map with a single key
//! that is the variant name camel cased (the key is a text data item).
//!
//! ### Supported attributes
//!
//! #### `cbor(key)`
//! For CBOR maps, set map key explicit to positive (integer) data item:
//! ```ignore
//! #[derive(CborSerialize, CborDeserialize)]
//! struct TestStruct {
//!     #[cbor(key = 1)]
//!     field1: u64,
//! }
//! ```
//! In this example, the field is encoded with a key that is the positive
//! (integer) data item `1`.
//!
//! #### `cbor(tag)`
//! Adds tag <https://www.rfc-editor.org/rfc/rfc8949.html#name-tagging-of-items> to encoded
//! data item:
//! ```ignore
//! #[derive(CborSerialize, CborDeserialize)]
//! #[cbor(tag = 39999)]
//! struct TestStruct {
//!     field1: u64,
//! }
//! ```
//! In this example the tag 39999 is prefixed the encoding of `TestStruct` in
//! the CBOR.
//!
//! #### `cbor(transparent)`
//! Serializes the type as the (single) field in the struct.
//! ```ignore
//! #[derive(CborSerialize, CborDeserialize)]
//! struct TestStruct {
//!     field1: u64,
//! }
//!
//! #[derive(CborSerialize, CborDeserialize)]
//! #[cbor(transparent)]
//! struct TestStructWrapper(TestStruct);
//! ```
//! In this example `TestStructWrapper` is serialized as `TestStruct`.
//!
//! #### `cbor(other)`
//! Deserializes "unknown" content to this enum variant.
//! ```ignore
//! # use concordium_base_derive::{CborDeserialize, CborSerialize};
//! #
//! #[derive(CborSerialize, CborDeserialize)]
//! #[cbor(map)]
//! enum TestEnum {
//!     Var1(u64),
//!     Var2(String),
//!     #[cbor(other)]
//!     Unknown,
//! }
//! ```
//! In this example variants in the CBOR that is not represented in the enum are
//! deserialized as `Unknown`. Serializing `Unknown` will always fail.

mod primitives;
mod decoder;
mod encoder;

pub use primitives::*;
pub use decoder::*;
pub use encoder::*;

use anyhow::{anyhow, };

use ciborium_ll::{simple, Header};
use concordium_base_derive::{CborDeserialize, CborSerialize};
use std::fmt::{Debug, Display};

/// Reexports for derive macros
#[doc(hidden)]
pub mod __private {
    pub use anyhow;
}


/// How to handle unknown keys in decoded CBOR maps.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Default)]
pub enum UnknownMapKeys {
    /// Ignore unknown keys and their value
    #[default]
    Ignore,
    /// Fail if unknown keys are encountered
    Fail,
}

/// Options applied when serializing and deserializing
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Default)]
pub struct SerializationOptions {
    pub unknown_map_keys: UnknownMapKeys,
}

impl SerializationOptions {
    pub fn unknown_map_keys(self, unknown_map_keys: UnknownMapKeys) -> Self {
        Self { unknown_map_keys }
    }
}

/// Error for serializing or deserializing CBOR
#[derive(thiserror::Error, Debug)]
#[error(transparent)]
pub struct CborSerializationError(#[from] anyhow::Error);

impl CborSerializationError {
    pub fn expected_tag(expected: u64, actual: u64) -> Self {
        anyhow!("expected tag {}, was {}", expected, actual).into()
    }

    pub fn expected_data_item(expected: DataItemType, actual: DataItemType) -> Self {
        anyhow!("expected data item {:?}, was {:?}", expected, actual).into()
    }

    pub fn remaining_data(offset: usize) -> Self {
        anyhow!("data remaining after parse at offset {}", offset).into()
    }

    pub fn expected_map_key(expected: u64, actual: u64) -> Self {
        anyhow!("expected map key {}, was {}", expected, actual).into()
    }

    pub fn unknown_map_key(key: MapKeyRef) -> Self { anyhow!("unknown map key {:?}", key).into() }

    pub fn invalid_data(message: impl Display) -> Self {
        anyhow!("invalid data: {}", message).into()
    }

    pub fn map_value_missing(key: MapKeyRef) -> Self {
        anyhow!("map value for key {:?} not present and cannot be null", key).into()
    }

    pub fn array_size(expected: usize, actual: usize) -> Self {
        anyhow!("expected array length {}, was {}", expected, actual).into()
    }

    pub fn map_size(expected: usize, actual: usize) -> Self {
        anyhow!("expected map size {}, was {}", expected, actual).into()
    }
}

/// Result of serialization or deserialization
pub type CborSerializationResult<T> = Result<T, CborSerializationError>;

impl<T> From<ciborium_ll::Error<T>> for CborSerializationError
where
    T: Display,
{
    fn from(err: ciborium_ll::Error<T>) -> Self {
        match err {
            ciborium_ll::Error::Io(err) => anyhow!("IO error: {}", err).into(),
            ciborium_ll::Error::Syntax(offset) => anyhow!("CBOR syntax error at {}", offset).into(),
        }
    }
}

impl From<std::io::Error> for CborSerializationError {
    fn from(err: std::io::Error) -> Self { anyhow!("IO error: {}", err).into() }
}

/// Encodes the given value as CBOR
pub fn cbor_encode<T: CborSerialize + ?Sized>(value: &T) -> CborSerializationResult<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut encoder = Encoder::new(&mut bytes);
    value.serialize(&mut encoder)?;
    Ok(bytes)
}

/// Decodes value from the given CBOR. If all input is not parsed,
/// an error is returned.
pub fn cbor_decode<T: CborDeserialize>(cbor: &[u8]) -> CborSerializationResult<T> {
    cbor_decode_with_options(cbor, SerializationOptions::default())
}

/// Decodes value from the given CBOR. If all input is not parsed,
/// an error is returned.
pub fn cbor_decode_with_options<T: CborDeserialize>(
    cbor: &[u8],
    options: SerializationOptions,
) -> CborSerializationResult<T> {
    let mut decoder = Decoder::new(cbor, options);
    let value = T::deserialize(&mut decoder)?;
    if decoder.offset() != cbor.len() {
        return Err(CborSerializationError::remaining_data(
            decoder.offset(),
        ));
    }
    Ok(value)
}



/// Type that can be CBOR serialized
pub trait CborSerialize {
    /// Serialize value to CBOR
    fn serialize<C: CborEncoder>(&self, encoder: &mut C) -> CborSerializationResult<()>;

    /// Whether the value corresponds to `null`
    fn is_null(&self) -> bool { false }
}

impl<T: CborSerialize> CborSerialize for Option<T> {
    fn serialize<C: CborEncoder>(&self, encoder: &mut C) -> CborSerializationResult<()> {
        match self {
            None => encoder.encode_simple(simple::NULL),
            Some(value) => value.serialize(encoder),
        }
    }

    fn is_null(&self) -> bool { self.is_none() }
}

/// Type that can be deserialized from CBOR
pub trait CborDeserialize {
    /// Deserialize value from the given decoder
    fn deserialize<C: CborDecoder>(decoder: &mut C) -> CborSerializationResult<Self>
    where
        Self: Sized;

    /// Produce value corresponding to `null` if possible for this type
    fn null() -> Option<Self>
    where
        Self: Sized, {
        None
    }
}

impl<T: CborDeserialize> CborDeserialize for Option<T> {
    fn deserialize<C: CborDecoder>(decoder: &mut C) -> CborSerializationResult<Self>
    where
        Self: Sized, {
        Ok(match decoder.peek_data_item_header()? {
            DataItemHeader::Simple(simple::NULL) => {
                let value = decoder.decode_simple()?;
                debug_assert_eq!(value, simple::NULL);
                None
            }
            _ => Some(T::deserialize(decoder)?),
        })
    }

    fn null() -> Option<Self>
    where
        Self: Sized, {
        Some(None)
    }
}

/// Encoder of CBOR. See <https://www.rfc-editor.org/rfc/rfc8949.html#section-3>
pub trait CborEncoder {
    /// Encodes tag data item with given value
    fn encode_tag(&mut self, tag: u64) -> CborSerializationResult<()>;

    /// Encodes positive integer data item with given value
    fn encode_positive(&mut self, positive: u64) -> CborSerializationResult<()>;

    /// Encodes negative integer data item with given value. Notice that the
    /// value of the data item is -(`negative` + 1)
    fn encode_negative(&mut self, negative: u64) -> CborSerializationResult<()>;

    /// Encodes start of map with given size
    fn encode_map_header(&mut self, size: usize) -> CborSerializationResult<()>;

    /// Encodes start of array with given size
    fn encode_array_header(&mut self, size: usize) -> CborSerializationResult<()>;

    /// Encodes bytes data item
    fn encode_bytes(&mut self, bytes: &[u8]) -> CborSerializationResult<()>;

    /// Encodes text data item
    fn encode_text(&mut self, text: &str) -> CborSerializationResult<()>;

    /// Encodes simple value, see <https://www.rfc-editor.org/rfc/rfc8949.html#name-floating-point-numbers-and->
    fn encode_simple(&mut self, simple: u8) -> CborSerializationResult<()>;
}


/// Decoder of CBOR. See <https://www.rfc-editor.org/rfc/rfc8949.html#section-3>
pub trait CborDecoder {
    /// Decode tag data item
    fn decode_tag(&mut self) -> CborSerializationResult<u64>;

    /// Decode that and check it equals the given `expected_tag`
    fn decode_tag_expect(&mut self, expected_tag: u64) -> CborSerializationResult<()> {
        let tag = self.decode_tag()?;
        if tag != expected_tag {
            return Err(CborSerializationError::expected_tag(expected_tag, tag));
        }
        Ok(())
    }

    /// Decode positive integer data item
    fn decode_positive(&mut self) -> CborSerializationResult<u64>;

    /// Decode negative integer data item. Notice that the
    /// value of the data item is -(`negative` + 1) where
    /// `negative` is the returned value.
    fn decode_negative(&mut self) -> CborSerializationResult<u64>;

    /// Decode map start. Returns the map size
    fn decode_map_header(&mut self) -> CborSerializationResult<usize>;

    /// Decode map start and check size equals `expected_length`
    fn decode_map_header_expect_size(
        &mut self,
        expected_size: usize,
    ) -> CborSerializationResult<()> {
        let size = self.decode_map_header()?;
        if size != expected_size {
            return Err(CborSerializationError::map_size(expected_size, size));
        }
        Ok(())
    }

    /// Decode array start. Returns the array size
    fn decode_array_header(&mut self) -> CborSerializationResult<usize>;

    /// Decode array start and check size equals `expected_length`
    fn decode_array_header_expect_size(
        &mut self,
        expected_size: usize,
    ) -> CborSerializationResult<()> {
        let size = self.decode_array_header()?;
        if size != expected_size {
            return Err(CborSerializationError::array_size(expected_size, size));
        }
        Ok(())
    }

    /// Decode bytes.
    ///
    /// Works only for definite length bytes.
    fn decode_bytes(&mut self) -> CborSerializationResult<Vec<u8>>;

    /// Decode bytes into given `destination`. The length of the bytes data item
    /// must match the `destination` length, else an error is returned.
    ///
    /// Works only for definite length bytes.
    fn decode_bytes_exact(&mut self, destination: &mut [u8]) -> CborSerializationResult<()>;

    /// Decode text and return UTF8 encoding.
    ///
    /// Works only for definite length text.
    fn decode_text(&mut self) -> CborSerializationResult<Vec<u8>>;

    /// Decode simple value, see <https://www.rfc-editor.org/rfc/rfc8949.html#name-floating-point-numbers-and->
    fn decode_simple(&mut self) -> CborSerializationResult<u8>;

    /// Peeks header of next data item to be decoded.
    fn peek_data_item_header(&mut self) -> CborSerializationResult<DataItemHeader>;

    /// Skips next header and potential content for the data item
    fn skip_data_item(&mut self) -> CborSerializationResult<()>;

    /// Serialization options in current context
    fn options(&self) -> SerializationOptions;
}


impl<T: CborSerialize> CborSerialize for &T {
    fn serialize<C: CborEncoder>(&self, encoder: &mut C) -> CborSerializationResult<()> {
        CborSerialize::serialize(*self, encoder)
    }
}

impl<T: CborSerialize> CborSerialize for &mut T {
    fn serialize<C: CborEncoder>(&self, encoder: &mut C) -> CborSerializationResult<()> {
        CborSerialize::serialize(*self, encoder)
    }
}


/// CBOR data item type. Corresponds roughly to CBOR major types.
#[derive(Eq, PartialEq, Copy, Clone, Hash, Debug)]
pub enum DataItemType {
    Positive,
    Negative,
    Bytes,
    Text,
    Array,
    Map,
    Tag,
    Simple,
    Float,
    Break,
}

impl DataItemType {
    pub fn from_header(header: Header) -> Self {
        use DataItemType::*;

        match header {
            Header::Positive(_) => Positive,
            Header::Negative(_) => Negative,
            Header::Float(_) => Float,
            Header::Simple(_) => Simple,
            Header::Tag(_) => Tag,
            Header::Break => Break,
            Header::Bytes(_) => Bytes,
            Header::Text(_) => Text,
            Header::Array(_) => Array,
            Header::Map(_) => Map,
        }
    }
}

/// CBOR data item header.
#[derive(PartialEq, Copy, Clone, Debug)]
pub enum DataItemHeader {
    Positive(u64),
    Negative(u64),
    Bytes(Option<usize>),
    Text(Option<usize>),
    Array(Option<usize>),
    Map(Option<usize>),
    Tag(u64),
    Simple(u8),
    Float(f64),
    Break,
}

impl DataItemHeader {
    pub fn to_type(self) -> DataItemType {
        use DataItemType::*;

        match self {
            DataItemHeader::Positive(_) => Positive,
            DataItemHeader::Negative(_) => Negative,
            DataItemHeader::Bytes(_) => Bytes,
            DataItemHeader::Text(_) => Text,
            DataItemHeader::Array(_) => Array,
            DataItemHeader::Map(_) => Map,
            DataItemHeader::Tag(_) => Tag,
            DataItemHeader::Simple(_) => Simple,
            DataItemHeader::Float(_) => Float,
            DataItemHeader::Break => Break,
        }
    }

    pub fn from_header(header: Header) -> Self {
        use DataItemHeader::*;

        match header {
            Header::Positive(value) => Positive(value),
            Header::Negative(value) => Negative(value),
            Header::Float(value) => Float(value),
            Header::Simple(value) => Simple(value),
            Header::Tag(tag) => Tag(tag),
            Header::Break => Break,
            Header::Bytes(length) => Bytes(length),
            Header::Text(length) => Text(length),
            Header::Array(length) => Array(length),
            Header::Map(length) => Map(length),
        }
    }
}


impl<T: CborSerialize> CborSerialize for Vec<T> {
    fn serialize<C: CborEncoder>(&self, encoder: &mut C) -> CborSerializationResult<()> {
        encoder.encode_array_header(self.len())?;
        for item in self {
            item.serialize(encoder)?
        }
        Ok(())
    }
}

impl<T: CborSerialize> CborSerialize for &[T] {
    fn serialize<C: CborEncoder>(&self, encoder: &mut C) -> CborSerializationResult<()> {
        encoder.encode_array_header(self.len())?;
        for item in self.iter() {
            item.serialize(encoder)?
        }
        Ok(())
    }
}

impl<T: CborDeserialize> CborDeserialize for Vec<T> {
    fn deserialize<C: CborDecoder>(decoder: &mut C) -> CborSerializationResult<Self>
    where
        Self: Sized, {
        let size = decoder.decode_array_header()?;
        let mut vec = Vec::with_capacity(size);
        for _ in 0..size {
            vec.push(T::deserialize(decoder)?);
        }

        Ok(vec)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use concordium_base_derive::{CborDeserialize, CborSerialize};

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

    /// Struct with named fields encoded as map. Uses field name string literals
    /// as keys.
    #[test]
    fn test_struct_as_map_derived() {
        #[derive(Debug, Eq, PartialEq, CborSerialize, CborDeserialize)]
        struct TestStruct {
            field1: u64,
            field2: String,
        }

        let value = TestStruct {
            field1: 3,
            field2: "abcd".to_string(),
        };

        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(
            hex::encode(&cbor),
            "a2666669656c643103666669656c64326461626364"
        );
        let value_decoded: TestStruct = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
    }

    #[test]
    fn test_struct_as_map_derived_camel_case() {
        #[derive(Debug, Eq, PartialEq, CborSerialize, CborDeserialize)]
        struct TestStruct {
            field_name: u64,
        }

        let value = TestStruct { field_name: 3 };

        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "a1696669656c644e616d6503");
        let value_decoded: TestStruct = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
    }

    #[test]
    fn test_struct_as_map_derived_explicit_keys() {
        const KEY: u64 = 2;

        #[derive(Debug, Eq, PartialEq, CborSerialize, CborDeserialize)]
        struct TestStruct {
            #[cbor(key = 1)]
            field1: u64,
            #[cbor(key = KEY)]
            field2: String,
        }

        let value = TestStruct {
            field1: 3,
            field2: "abcd".to_string(),
        };

        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "a20103026461626364");
        let value_decoded: TestStruct = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
    }

    #[test]
    fn test_struct_as_map_derived_optional_field() {
        #[derive(Debug, Eq, PartialEq, CborSerialize, CborDeserialize)]
        struct TestStruct {
            field1: Option<u64>,
            field2: String,
        }

        let value = TestStruct {
            field1: Some(3),
            field2: "abcd".to_string(),
        };

        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(
            hex::encode(&cbor),
            "a2666669656c643103666669656c64326461626364"
        );
        let value_decoded: TestStruct = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);

        let value = TestStruct {
            field1: None,
            field2: "abcd".to_string(),
        };

        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "a1666669656c64326461626364");
        let value_decoded: TestStruct = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
    }

    #[test]
    fn test_struct_as_map_derived_unknown_field() {
        #[derive(Debug, Eq, PartialEq, CborSerialize, CborDeserialize)]
        struct TestStruct {
            field1: u64,
            field2: String,
        }

        #[derive(Debug, Eq, PartialEq, CborSerialize, CborDeserialize)]
        struct TestStruct2 {
            field1: u64,
        }

        let value = TestStruct {
            field1: 3,
            field2: "abcd".to_string(),
        };

        let cbor = cbor_encode(&value).unwrap();

        let value_decoded: TestStruct2 = cbor_decode_with_options(
            &cbor,
            SerializationOptions::default().unknown_map_keys(UnknownMapKeys::Ignore),
        )
        .unwrap();
        assert_eq!(value_decoded.field1, value.field1);

        let err = cbor_decode_with_options::<TestStruct2>(
            &cbor,
            SerializationOptions::default().unknown_map_keys(UnknownMapKeys::Fail),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("unknown map key"), "err: {}", err);
    }

    #[test]
    fn test_struct_as_array_derived() {
        #[derive(Debug, Eq, PartialEq, CborSerialize, CborDeserialize)]
        struct TestStruct(u64, String);

        let value = TestStruct(3, "abcd".to_string());

        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "82036461626364");
        let value_decoded: TestStruct = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
    }

    #[test]
    fn test_struct_as_array_derived_wrong_length() {
        #[derive(Debug, Eq, PartialEq, CborSerialize, CborDeserialize)]
        struct TestStruct(u64, String);

        #[derive(Debug, Eq, PartialEq, CborSerialize, CborDeserialize)]
        struct TestStruct2(u64);

        let value = TestStruct(3, "abcd".to_string());

        let cbor = cbor_encode(&value).unwrap();
        let err = cbor_decode::<TestStruct2>(&cbor).unwrap_err().to_string();
        assert!(err.contains("expected array length 1"), "err: {}", err);
    }

    #[test]
    fn test_struct_derived_transparent_tuple() {
        #[derive(Debug, Eq, PartialEq, CborSerialize, CborDeserialize)]
        #[cbor(transparent)]
        struct TestStructWrapper(TestStruct);

        #[derive(Debug, Eq, PartialEq, CborSerialize, CborDeserialize)]
        struct TestStruct {
            field1: u64,
        }

        let value = TestStructWrapper(TestStruct { field1: 3 });

        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "a1666669656c643103");
        let value_decoded: TestStructWrapper = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
    }

    #[test]
    fn test_struct_derived_transparent_named() {
        #[derive(Debug, Eq, PartialEq, CborSerialize, CborDeserialize)]
        #[cbor(transparent)]
        struct TestStructWrapper {
            field1: TestStruct,
        }

        #[derive(Debug, Eq, PartialEq, CborSerialize, CborDeserialize)]
        struct TestStruct {
            field1: u64,
        }

        let value = TestStructWrapper {
            field1: TestStruct { field1: 3 },
        };

        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "a1666669656c643103");
        let value_decoded: TestStructWrapper = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
    }

    #[test]
    fn test_struct_tag_derived_map() {
        const TAG: u64 = 39999;

        #[derive(Debug, Eq, PartialEq, CborSerialize, CborDeserialize)]
        #[cbor(tag = TAG)]
        struct TestStruct {
            field1: u64,
        }

        #[derive(Debug, Eq, PartialEq, CborSerialize, CborDeserialize)]
        #[cbor(tag = 39998)]
        struct TestStruct2 {
            field1: u64,
        }

        let value = TestStruct { field1: 3 };

        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "d99c3fa1666669656c643103");
        let value_decoded: TestStruct = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);

        let err = cbor_decode::<TestStruct2>(&cbor).unwrap_err().to_string();
        assert!(err.contains("expected tag 39998"), "err: {}", err);
    }

    #[test]
    fn test_struct_tag_derived_transparent() {
        #[derive(Debug, Eq, PartialEq, CborSerialize, CborDeserialize)]
        #[cbor(transparent, tag = 39999)]
        struct TestStructWrapper(TestStruct);

        #[derive(Debug, Eq, PartialEq, CborSerialize, CborDeserialize)]
        #[cbor(transparent, tag = 39998)]
        struct TestStructWrapper2(TestStruct);

        #[derive(Debug, Eq, PartialEq, CborSerialize, CborDeserialize)]
        struct TestStruct {
            field1: u64,
        }

        let value = TestStructWrapper(TestStruct { field1: 3 });

        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "d99c3fa1666669656c643103");
        let value_decoded: TestStructWrapper = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);

        let err = cbor_decode::<TestStructWrapper2>(&cbor)
            .unwrap_err()
            .to_string();
        assert!(err.contains("expected tag 39998"), "err: {}", err);
    }

    #[test]
    fn test_enum_as_map_derived() {
        #[derive(Debug, Eq, PartialEq, CborSerialize, CborDeserialize)]
        #[cbor(map)]
        enum TestEnum {
            Var1(u64),
            Var2(String),
        }

        let value = TestEnum::Var1(3);
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "a1647661723103");
        let value_decoded: TestEnum = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);

        let value = TestEnum::Var2("abcd".to_string());
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "a164766172326461626364");
        let value_decoded: TestEnum = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
    }

    #[test]
    fn test_enum_as_map_derived_unknown_key() {
        #[derive(Debug, Eq, PartialEq, CborSerialize, CborDeserialize)]
        #[cbor(map)]
        enum TestEnum {
            Var1(u64),
            Var2(String),
        }

        #[derive(Debug, Eq, PartialEq, CborSerialize, CborDeserialize)]
        #[cbor(map)]
        enum TestEnum2 {
            Var1(u64),
        }

        let value = TestEnum::Var2("abcd".to_string());
        let cbor = cbor_encode(&value).unwrap();
        let err = cbor_decode::<TestEnum2>(&cbor).unwrap_err().to_string();
        assert!(err.contains("unknown map key"), "err: {}", err);
    }

    #[test]
    fn test_enum_as_map_derived_other_variant() {
        #[derive(Debug, Eq, PartialEq, CborSerialize, CborDeserialize)]
        #[cbor(map)]
        enum TestEnum {
            Var1(u64),
            Var2(String),
        }

        #[derive(Debug, Eq, PartialEq, CborSerialize, CborDeserialize)]
        #[cbor(map)]
        enum TestEnum2 {
            Var1(u64),
            #[cbor(other)]
            Unknown,
        }

        let value = TestEnum::Var2("abcd".to_string());
        let cbor = cbor_encode(&value).unwrap();
        let value_decoded: TestEnum2 = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, TestEnum2::Unknown);

        let err = cbor_encode(&TestEnum2::Unknown).unwrap_err().to_string();
        assert!(
            err.contains("cannot serialize variant marked with #[cbor(other)]"),
            "err: {}",
            err
        );
    }

    #[test]
    fn test_vec() {
        let vec = vec![1, 2, 3, 4, 5];

        let cbor = cbor_encode(&vec).unwrap();
        assert_eq!(hex::encode(&cbor), "850102030405");
        let bytes_decoded: Vec<u64> = cbor_decode(&cbor).unwrap();
        assert_eq!(bytes_decoded, vec);
    }

    #[test]
    fn test_option() {
        let value = Some(3u64);
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "03");
        let value_decoded: Option<u64> = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);

        let value = None;
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "f6");
        let value_decoded: Option<u64> = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
    }

    #[test]
    fn test_decimal_fraction() {
        let value = DecimalFraction::new(-3, 12345);
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "c48222193039");
        let value_decoded: DecimalFraction = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
    }

    #[test]
    fn test_skip_data_item() {
        test_skip_data_item_impl(|encoder| encoder.encode_simple(simple::TRUE).unwrap());
        test_skip_data_item_impl(|encoder| encoder.encode_positive(2).unwrap());
        test_skip_data_item_impl(|encoder| encoder.encode_negative(2).unwrap());
        test_skip_data_item_impl(|encoder| {
            encoder.encode_tag(2).unwrap();
            encoder.encode_positive(2).unwrap();
        });
        test_skip_data_item_impl(|encoder| encoder.encode_bytes(&[0x01; 30]).unwrap());
        test_skip_data_item_impl(|encoder| encoder.encode_text(&"a".repeat(30)).unwrap());
        test_skip_data_item_impl(|encoder| {
            encoder.encode_array_header(2).unwrap();
            encoder.encode_positive(2).unwrap();
            encoder.encode_positive(2).unwrap();
        });
        test_skip_data_item_impl(|encoder| {
            encoder.encode_map_header(2).unwrap();
            encoder.encode_positive(2).unwrap();
            encoder.encode_positive(2).unwrap();
            encoder.encode_positive(2).unwrap();
            encoder.encode_positive(2).unwrap();
        });
    }

    fn test_skip_data_item_impl(encode_data_item: impl FnOnce(&mut Encoder<&mut Vec<u8>>)) {
        let mut bytes = Vec::new();
        let mut encoder = Encoder::new(&mut bytes);
        encode_data_item(&mut encoder);
        encoder.encode_positive(1).unwrap();
        let mut decoder = Decoder::new(bytes.as_slice(), SerializationOptions::default());
        decoder.skip_data_item().unwrap();
        assert_eq!(1, decoder.decode_positive().unwrap());
    }
}
