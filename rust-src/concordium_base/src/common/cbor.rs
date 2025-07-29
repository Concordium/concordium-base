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
//!
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
//!
//! Structs with named fields are serialized as CBOR maps using camel cased
//! field names as keys (of data item type text) and tuples are serialized as
//! CBOR arrays.
//!
//! ### Enums
//!
//! [`CborSerialize`] and [`CborDeserialize`] can be derived on enums using
//! `map` or `tagged` representation.
//!
//! Using `#[cbor(map)]` represents the enum as a map with a single key
//! that is the variant name camel cased (the key is a text data item).
//!
//! ```ignore
//! #[derive(CborSerialize, CborDeserialize)]
//! #[cbor(map)]
//! enum TestEnum {
//!     Var1(u64),
//!     Var2(String),
//! }
//! ```
//!
//! Using `#[cbor(tagged)]` represents the enum as a tagged data item.
//! At most one of the variants can be untagged:
//!
//! ```ignore
//! #[derive(CborSerialize, CborDeserialize)]
//! #[cbor(tagged)]
//! enum TestEnum {
//!     #[cbor(tag = 39991)]
//!     Var1(u64),
//!     #[cbor(tag = 39992)]
//!     Var2(bool),
//!     Var3(String),
//! }
//! ```
//!
//! Each varaint is serialized prefixed with the declared tag (except for the
//! untagged variant).
//!
//! All enum variants must be single element tuples.
//!
//! ### Supported attributes
//!
//! #### `cbor(key)`
//! For structs with named fields, set map key explicit to positive (integer)
//! data item:
//!
//! ```ignore
//! #[derive(CborSerialize, CborDeserialize)]
//! struct TestStruct {
//!     #[cbor(key = 1)]
//!     field1: u64,
//! }
//! ```
//!
//! In this example, the field is encoded with a key that is the positive
//! (integer) data item `1`, instead of using the field name.
//!
//! #### `cbor(tag)`
//! Adds tag <https://www.rfc-editor.org/rfc/rfc8949.html#name-tagging-of-items> to encoded
//! data item:
//!
//! ```ignore
//! #[derive(CborSerialize, CborDeserialize)]
//! #[cbor(tag = 39999)]
//! struct TestStruct {
//!     field1: u64,
//! }
//! ```
//!
//! In this example the tag 39999 is prefixed the encoding of `TestStruct` in
//! the CBOR.
//!
//! The attribute is also needed on enum variants when using `tagged`
//! representations, see example above.
//!
//! #### `cbor(peek_tag)`
//! For enums using `tagged` representation, marks the enum variant
//! as being prefixed with this tag, without serializing/deserializing the tag:
//!
//! ```ignore
//! #[derive(CborSerialize, CborDeserialize)]
//! enum TestEnum {
//!     #[cbor(tag = 39991)]
//!     Var1(u64),
//!     #[cbor(peek_tag = 39992)]
//!     Var2(TaggedStruct),
//! }
//!
//! #[derive(CborSerialize, CborDeserialize)]
//! #[cbor(tag = 39992)]
//! struct TaggedStruct(String);
//! ```
//!
//! In this example, the tag `39992` is serialized as part of `TaggedStruct`,
//! not as part of serializing the enum `TestEnum`.
//!
//! #### `cbor(transparent)`
//! Serializes the type as the (single) field in the struct.
//!
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
//!
//! In this example `TestStructWrapper` is serialized as `TestStruct`.
//!
//! #### `cbor(other)`
//! This attribute can be applied to a variant in an enum for a field in a
//! struct. When applied to a variant in an enum represented as a CBOR map,
//! "unknown" map entries are deserialized to this variant.
//!
//! ```ignore
//! #[derive(CborSerialize, CborDeserialize)]
//! #[cbor(map)]
//! enum TestEnum {
//!     Var1(u64),
//!     Var2(String),
//!     #[cbor(other)]
//!     Unknown(String, value::Value),
//! }
//! ```
//!
//! In this example, entries in the CBOR map that is not present in the enum are
//! deserialized as `Unknown`. The `#[cbor(other)]` variant is a tuple of
//! the map key and the map value.
//!
//! When applied to a variant in an enum represented with tags,
//! tags not declared in the enum are deserialized to this variant.
//!
//! ```ignore
//! #[derive(CborSerialize, CborDeserialize)]
//! #[cbor(tagged)]
//! enum TestEnum {
//!     #[cbor(tag = 39991)]
//!     Var1(u64),
//!     #[cbor(tag = 39991)]
//!     Var2(String),
//!     #[cbor(other)]
//!     Unknown(u64, value::Value),
//! }
//! ```
//!
//! In this example, entries in the CBOR map that is not present in the enum are
//! deserialized as `Unknown`. The `#[cbor(other)]` variant is a tuple of
//! the tag and tagged data item.
//!
//! When applied to a field in a struct with named fields, "unknown" map entries
//! are deserialized into this field.
//!
//! ```ignore
//! #[derive(CborSerialize, CborDeserialize)]
//! struct TestStruct {
//!     field1:  u64,
//!     #[cbor(other)]
//!     unknown: HashMap<MapKey, value::Value>,
//! }
//! ```
//!
//! In this example, entries in the CBOR map that are not present in the struct
//! are each deserialized into an entry in the map in the field `unknown`.

mod composites;
/// CBOR serialization of types from `concordium-contracts-common`
mod contracts_common_types;
mod decoder;
mod encoder;
mod primitives;
/// Serde serialization of the types in `cbor` module
pub(crate) mod serde;
/// Dynamic data model for generic CBOR
pub mod value;

pub use composites::*;
pub use decoder::*;
pub use encoder::*;
pub use primitives::*;
use std::collections::HashMap;

use anyhow::anyhow;

use ciborium_ll::{simple, Header};
use concordium_base_derive::{CborDeserialize, CborSerialize};
use std::{
    fmt::{Debug, Display},
    hash::Hash,
};

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

    pub fn array_size(expected: usize, actual: Option<usize>) -> Self {
        if let Some(actual) = actual {
            anyhow!("expected array length {}, was {}", expected, actual).into()
        } else {
            anyhow!("expected array length {}, was indefinite", expected).into()
        }
    }

    pub fn map_size(expected: usize, actual: Option<usize>) -> Self {
        if let Some(actual) = actual {
            anyhow!("expected map size {}, was {}", expected, actual).into()
        } else {
            anyhow!("expected map size {}, was indefinite", expected).into()
        }
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
pub fn cbor_decode<T: CborDeserialize>(cbor: impl AsRef<[u8]>) -> CborSerializationResult<T> {
    cbor_decode_with_options(cbor, SerializationOptions::default())
}

/// Decodes value from the given CBOR. If all input is not parsed,
/// an error is returned.
pub fn cbor_decode_with_options<T: CborDeserialize>(
    cbor: impl AsRef<[u8]>,
    options: SerializationOptions,
) -> CborSerializationResult<T> {
    let cbor = cbor.as_ref();
    let mut decoder = Decoder::new(cbor, options);
    let value = T::deserialize(&mut decoder)?;
    if decoder.offset() != cbor.len() {
        return Err(CborSerializationError::remaining_data(decoder.offset()));
    }
    Ok(value)
}

/// Type that can be CBOR serialized
pub trait CborSerialize {
    /// Serialize value to CBOR
    fn serialize<C: CborEncoder>(&self, encoder: C) -> CborSerializationResult<()>;

    /// Whether the value corresponds to `null`
    fn is_null(&self) -> bool { false }
}

impl<T: CborSerialize> CborSerialize for Option<T> {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> CborSerializationResult<()> {
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
    fn deserialize<C: CborDecoder>(decoder: C) -> CborSerializationResult<Self>
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
    fn deserialize<C: CborDecoder>(mut decoder: C) -> CborSerializationResult<Self>
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
    /// Associated map encoder
    type MapEncoder: CborMapEncoder;
    /// Associated array encoder
    type ArrayEncoder: CborArrayEncoder;

    /// Encodes tag data item with given value
    fn encode_tag(&mut self, tag: u64) -> CborSerializationResult<()>;

    /// Encodes positive integer data item with given value
    fn encode_positive(self, positive: u64) -> CborSerializationResult<()>;

    /// Encodes negative integer data item with given value. Notice that the
    /// value of the data item is -(`negative` + 1)
    fn encode_negative(self, negative: u64) -> CborSerializationResult<()>;

    /// Encodes map with given number of entries (key-value pairs). Returns a
    /// map encoder that must be used to encode the map.
    fn encode_map(self, size: usize) -> CborSerializationResult<Self::MapEncoder>;

    /// Encodes array with given number of elements. Returns an array encoder
    /// that must be used to encode the array.
    fn encode_array(self, size: usize) -> CborSerializationResult<Self::ArrayEncoder>;

    /// Encodes bytes data item
    fn encode_bytes(self, bytes: &[u8]) -> CborSerializationResult<()>;

    /// Encodes text data item
    fn encode_text(self, text: &str) -> CborSerializationResult<()>;

    /// Encodes simple value, see <https://www.rfc-editor.org/rfc/rfc8949.html#name-floating-point-numbers-and->
    fn encode_simple(self, simple: u8) -> CborSerializationResult<()>;

    /// Encodes float value, see <https://www.rfc-editor.org/rfc/rfc8949.html#name-floating-point-numbers-and->
    fn encode_float(self, float: f64) -> CborSerializationResult<()>;
}

/// Encoder of CBOR map
pub trait CborMapEncoder {
    /// Serialize an entry consisting of a `key` and `value` and add it to the
    /// map (appended to current list of entries). The number of entries
    /// added to the map must equal the size given to
    /// [`CborEncoder::encode_map`] When all entries have been serialized,
    /// [`Self::end`] must be called.
    fn serialize_entry<K: CborSerialize + ?Sized, V: CborSerialize + ?Sized>(
        &mut self,
        key: &K,
        value: &V,
    ) -> CborSerializationResult<()>;

    /// End map serialization.
    fn end(self) -> CborSerializationResult<()>;
}

/// Encoder of CBOR array
pub trait CborArrayEncoder {
    /// Serialize an `element` and add it to the array (appended to the current
    /// elements in the array). The number of elements added to the array
    /// must equal the size given to [`CborEncoder::encode_array`]
    /// When all elements have been serialized, [`Self::end`] must be called.
    fn serialize_element<T: CborSerialize + ?Sized>(
        &mut self,
        element: &T,
    ) -> CborSerializationResult<()>;

    /// End array serialization.
    fn end(self) -> CborSerializationResult<()>;
}

/// Decoder of CBOR. See <https://www.rfc-editor.org/rfc/rfc8949.html#section-3>
pub trait CborDecoder {
    /// Associated map decoder
    type MapDecoder: CborMapDecoder;
    /// Associated array decoder
    type ArrayDecoder: CborArrayDecoder;

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
    fn decode_positive(self) -> CborSerializationResult<u64>;

    /// Decode negative integer data item. Notice that the
    /// value of the data item is -(`negative` + 1) where
    /// `negative` is the returned value.
    fn decode_negative(self) -> CborSerializationResult<u64>;

    /// Decode map. Returns a map decoder that must be used to decode the map.
    fn decode_map(self) -> CborSerializationResult<Self::MapDecoder>;

    /// Decode map and check number of entries equals `expected_size`
    fn decode_map_expect_size(
        self,
        expected_size: usize,
    ) -> CborSerializationResult<Self::MapDecoder>
    where
        Self: Sized, {
        let map_decoder = self.decode_map()?;
        if map_decoder.size() != Some(expected_size) {
            return Err(CborSerializationError::map_size(
                expected_size,
                map_decoder.size(),
            ));
        }
        Ok(map_decoder)
    }

    /// Decode array. Returns an array decoder that must be used to decode the
    /// array.
    fn decode_array(self) -> CborSerializationResult<Self::ArrayDecoder>;

    /// Decode array and check number of elements equals `expected_size`
    fn decode_array_expect_size(
        self,
        expected_size: usize,
    ) -> CborSerializationResult<Self::ArrayDecoder>
    where
        Self: Sized, {
        let array_decoder = self.decode_array()?;
        if array_decoder.size() != Some(expected_size) {
            return Err(CborSerializationError::array_size(
                expected_size,
                array_decoder.size(),
            ));
        }
        Ok(array_decoder)
    }

    /// Decode bytes.
    ///
    /// Works only for definite length bytes.
    fn decode_bytes(self) -> CborSerializationResult<Vec<u8>>;

    /// Decode bytes into given `destination`. The length of the bytes data item
    /// must match the `destination` length, else an error is returned.
    ///
    /// Works only for definite length bytes.
    fn decode_bytes_exact(self, destination: &mut [u8]) -> CborSerializationResult<()>;

    /// Decode text and return UTF8 encoding.
    ///
    /// Works only for definite length text.
    fn decode_text(self) -> CborSerializationResult<Vec<u8>>;

    /// Decode simple value, see <https://www.rfc-editor.org/rfc/rfc8949.html#name-floating-point-numbers-and->
    fn decode_simple(self) -> CborSerializationResult<u8>;

    /// Decode float, see <https://www.rfc-editor.org/rfc/rfc8949.html#name-floating-point-numbers-and->
    fn decode_float(self) -> CborSerializationResult<f64>;

    /// Peeks header of next data item to be decoded.
    fn peek_data_item_header(&mut self) -> CborSerializationResult<DataItemHeader>;

    /// Skips next header and potential content for the data item
    fn skip_data_item(self) -> CborSerializationResult<()>;

    /// Serialization options in current context
    fn options(&self) -> SerializationOptions;
}

/// Decoder of CBOR map
pub trait CborMapDecoder {
    /// Number of entries of the map being decoded (total number of entries, not
    /// remaining). Returns `None` if the map has indefinite size.
    fn size(&self) -> Option<usize>;

    /// Deserialize an entry consisting of a key and value. Returns `None` if
    /// all entries in the map has been deserialized.
    /// The total number of entries that can be deserialized is equal
    /// to [`Self::size`].
    fn deserialize_entry<K: CborDeserialize, V: CborDeserialize>(
        &mut self,
    ) -> CborSerializationResult<Option<(K, V)>> {
        let Some(key) = self.deserialize_key()? else {
            return Ok(None);
        };
        Ok(Some((key, self.deserialize_value()?)))
    }

    /// Deserialize an entry key. Returns `None` if
    /// all entries in the map has been deserialized.
    fn deserialize_key<K: CborDeserialize>(&mut self) -> CborSerializationResult<Option<K>>;

    /// Deserialize an entry value.
    fn deserialize_value<V: CborDeserialize>(&mut self) -> CborSerializationResult<V>;

    /// Skips entry value
    fn skip_value(&mut self) -> CborSerializationResult<()>;
}

/// Decoder of CBOR array
pub trait CborArrayDecoder {
    /// Number of elements in the array being decoded (total number of elements,
    /// not remaining). Returns `None` if the array has indefinite length.
    fn size(&self) -> Option<usize>;

    /// Deserialize an array element. Returns `None` if all
    /// elements in the array has been deserialized.
    /// The total number of elements that can be deserialized is equal
    /// to [`Self::size`].
    fn deserialize_element<T: CborDeserialize>(&mut self) -> CborSerializationResult<Option<T>>;
}

impl<T: CborSerialize> CborSerialize for &T {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> CborSerializationResult<()> {
        CborSerialize::serialize(*self, encoder)
    }
}

impl<T: CborSerialize> CborSerialize for &mut T {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> CborSerializationResult<()> {
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
        }
    }

    pub fn try_from_header(header: Header) -> CborSerializationResult<Self> {
        use DataItemHeader::*;

        Ok(match header {
            Header::Positive(value) => Positive(value),
            Header::Negative(value) => Negative(value),
            Header::Float(value) => Float(value),
            Header::Simple(value) => Simple(value),
            Header::Tag(tag) => Tag(tag),
            Header::Bytes(length) => Bytes(length),
            Header::Text(length) => Text(length),
            Header::Array(length) => Array(length),
            Header::Map(length) => Map(length),
            Header::Break => {
                return Err(anyhow!("Break is not a valid data item header").into());
            }
        })
    }
}

impl<T: CborSerialize> CborSerialize for Vec<T> {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> CborSerializationResult<()> {
        let mut array_encoder = encoder.encode_array(self.len())?;
        for item in self {
            array_encoder.serialize_element(item)?
        }
        array_encoder.end()?;
        Ok(())
    }
}

impl<T: CborSerialize> CborSerialize for &[T] {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> CborSerializationResult<()> {
        let mut array_encoder = encoder.encode_array(self.len())?;
        for item in self.iter() {
            array_encoder.serialize_element(item)?
        }
        array_encoder.end()?;
        Ok(())
    }
}

impl<T: CborDeserialize> CborDeserialize for Vec<T> {
    fn deserialize<C: CborDecoder>(decoder: C) -> CborSerializationResult<Self>
    where
        Self: Sized, {
        let mut array_decoder = decoder.decode_array()?;
        let mut vec = Vec::with_capacity(array_decoder.size().unwrap_or_default());
        while let Some(element) = array_decoder.deserialize_element()? {
            vec.push(element);
        }

        Ok(vec)
    }
}

impl<K: CborSerialize, V: CborSerialize> CborSerialize for HashMap<K, V> {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> CborSerializationResult<()> {
        let mut map_encoder = encoder.encode_map(self.len())?;
        for (key, value) in self.iter() {
            map_encoder.serialize_entry(key, value)?
        }
        map_encoder.end()?;
        Ok(())
    }
}

impl<K: CborDeserialize + Eq + Hash, V: CborDeserialize> CborDeserialize for HashMap<K, V> {
    fn deserialize<C: CborDecoder>(decoder: C) -> CborSerializationResult<Self>
    where
        Self: Sized, {
        let mut map_decoder = decoder.decode_map()?;
        let mut map = HashMap::with_capacity(map_decoder.size().unwrap_or_default());
        while let Some((key, value)) = map_decoder.deserialize_entry()? {
            map.insert(key, value);
        }

        Ok(map)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use concordium_base_derive::{CborDeserialize, CborSerialize};

    use std::collections::HashMap;

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
    fn test_struct_as_map_derived_other_field() {
        #[derive(Debug, Eq, PartialEq, CborSerialize, CborDeserialize)]
        struct TestStruct {
            field1: u64,
            field2: String,
            #[cbor(key = 3)]
            field3: u64,
        }

        #[derive(Debug, PartialEq, CborSerialize, CborDeserialize)]
        struct TestStruct2 {
            field1:  u64,
            #[cbor(other)]
            unknown: HashMap<MapKey, value::Value>,
        }

        let value = TestStruct {
            field1: 3,
            field2: "abcd".to_string(),
            field3: 5,
        };
        let cbor = cbor_encode(&value).unwrap();
        let value_decoded: TestStruct2 = cbor_decode(&cbor).unwrap();
        let value_unknown = TestStruct2 {
            field1:  3,
            unknown: [
                (
                    MapKey::Text("field2".to_string()),
                    value::Value::Text("abcd".to_string()),
                ),
                (MapKey::Positive(3), value::Value::Positive(5)),
            ]
            .into_iter()
            .collect(),
        };
        assert_eq!(value_decoded, value_unknown);

        let cbor = cbor_encode(&value_unknown).unwrap();
        let value_decoded: TestStruct = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
    }

    #[test]
    fn test_struct_as_map_derived_empty() {
        #[derive(Debug, Eq, PartialEq, CborSerialize, CborDeserialize)]
        struct TestStruct {}

        let value = TestStruct {};

        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "a0");
        let value_decoded: TestStruct = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
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
    fn test_struct_as_array_derived_empty() {
        #[derive(Debug, Eq, PartialEq, CborSerialize, CborDeserialize)]
        struct TestStruct();

        let value = TestStruct();

        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "80");
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

        #[derive(Debug, PartialEq, CborSerialize, CborDeserialize)]
        #[cbor(map)]
        enum TestEnum2 {
            Var1(u64),
            #[cbor(other)]
            Unknown(MapKey, value::Value),
        }

        let value = TestEnum::Var2("abcd".to_string());
        let cbor = cbor_encode(&value).unwrap();
        let value_decoded: TestEnum2 = cbor_decode(&cbor).unwrap();
        let value_unknown = TestEnum2::Unknown(
            MapKey::Text("var2".to_string()),
            value::Value::Text("abcd".to_string()),
        );
        assert_eq!(value_decoded, value_unknown);

        let cbor = cbor_encode(&value_unknown).unwrap();
        let value_decoded: TestEnum = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
    }

    #[test]
    fn test_enum_as_tagged_derived() {
        #[derive(Debug, Eq, PartialEq, CborSerialize, CborDeserialize)]
        #[cbor(tagged)]
        enum TestEnum {
            #[cbor(tag = 39991)]
            Var1(u64),
            #[cbor(tag = 39992)]
            Var2(String),
        }

        let value = TestEnum::Var1(3);
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "d99c3703");
        let value_decoded: TestEnum = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);

        let value = TestEnum::Var2("abcd".to_string());
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "d99c386461626364");
        let value_decoded: TestEnum = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
    }

    #[test]
    fn test_enum_as_tagged_derived_untagged_variant() {
        #[derive(Debug, Eq, PartialEq, CborSerialize, CborDeserialize)]
        #[cbor(tagged)]
        enum TestEnum {
            #[cbor(tag = 39991)]
            Var1(u64),
            Var2(String),
        }

        let value = TestEnum::Var1(3);
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "d99c3703");
        let value_decoded: TestEnum = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);

        let value = TestEnum::Var2("abcd".to_string());
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "6461626364");
        let value_decoded: TestEnum = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
    }

    #[test]
    fn test_enum_as_tagged_derived_other_variant() {
        #[derive(Debug, Eq, PartialEq, CborSerialize, CborDeserialize)]
        #[cbor(tagged)]
        enum TestEnum {
            #[cbor(tag = 39991)]
            Var1(u64),
            #[cbor(tag = 39992)]
            Var2(String),
            Var3(String),
        }

        #[derive(Debug, PartialEq, CborSerialize, CborDeserialize)]
        #[cbor(tagged)]
        enum TestEnum2 {
            #[cbor(tag = 39991)]
            Var1(u64),
            #[cbor(other)]
            Unknown(u64, value::Value),
            Var3(String),
        }

        let value = TestEnum::Var2("abcd".to_string());
        let cbor = cbor_encode(&value).unwrap();
        let value_decoded: TestEnum2 = cbor_decode(&cbor).unwrap();
        let value_unknown = TestEnum2::Unknown(39992, value::Value::Text("abcd".to_string()));
        assert_eq!(value_decoded, value_unknown);

        let cbor = cbor_encode(&value_unknown).unwrap();
        let value_decoded: TestEnum = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
    }

    #[test]
    fn test_enum_as_tagged_derived_peek_tag() {
        #[derive(Debug, Eq, PartialEq, CborSerialize, CborDeserialize)]
        #[cbor(tagged)]
        enum TestEnum {
            #[cbor(tag = 39991)]
            Var1(u64),
            #[cbor(peek_tag = 39992)]
            Var2(TaggedStruct),
            Var3(String),
        }

        #[derive(Debug, Eq, PartialEq, CborSerialize, CborDeserialize)]
        #[cbor(transparent, tag = 39992)]
        struct TaggedStruct(String);

        let value = TestEnum::Var1(3);
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "d99c3703");
        let value_decoded: TestEnum = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);

        let value = TestEnum::Var2(TaggedStruct("abcd".to_string()));
        let cbor = cbor_encode(&value).unwrap();
        assert_eq!(hex::encode(&cbor), "d99c386461626364");
        let value_decoded: TestEnum = cbor_decode(&cbor).unwrap();
        assert_eq!(value_decoded, value);
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
    fn test_vec_empty() {
        let vec: Vec<u64> = vec![];

        let cbor = cbor_encode(&vec).unwrap();
        assert_eq!(hex::encode(&cbor), "80");
        let bytes_decoded: Vec<u64> = cbor_decode(&cbor).unwrap();
        assert_eq!(bytes_decoded, vec);
    }

    #[test]
    fn test_vec_indefinite_length() {
        let vec = vec![1, 2];

        let cbor = hex::decode("9f0102ff").unwrap();
        let bytes_decoded: Vec<u64> = cbor_decode(&cbor).unwrap();
        assert_eq!(bytes_decoded, vec);
    }

    #[test]
    fn test_map() {
        let map: HashMap<u64, u64> = [(1, 2), (3, 4)].into_iter().collect();

        let cbor = cbor_encode(&map).unwrap();
        assert_eq!(hex::encode(&cbor), "a201020304");
        let bytes_decoded: HashMap<u64, u64> = cbor_decode(&cbor).unwrap();
        assert_eq!(bytes_decoded, map);
    }

    #[test]
    fn test_map_empty() {
        let map: HashMap<u64, u64> = [].into_iter().collect();

        let cbor = cbor_encode(&map).unwrap();
        assert_eq!(hex::encode(&cbor), "a0");
        let bytes_decoded: HashMap<u64, u64> = cbor_decode(&cbor).unwrap();
        assert_eq!(bytes_decoded, map);
    }

    #[test]
    fn test_map_indefinite_length() {
        let map: HashMap<u64, u64> = [(1, 2), (3, 4)].into_iter().collect();

        let cbor = hex::decode("bf01020304ff").unwrap();
        let bytes_decoded: HashMap<u64, u64> = cbor_decode(&cbor).unwrap();
        assert_eq!(bytes_decoded, map);
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
}
