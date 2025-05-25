use anyhow::{anyhow, Context};
use ciborium_io::{Read, Write};
use ciborium_ll::{simple, Decoder, Encoder, Header};
use std::fmt::{Debug, Display};

#[derive(thiserror::Error, Debug)]
#[error(transparent)]
pub struct CborError(#[from] anyhow::Error);

impl CborError {
    pub fn expected_tag(expected: u64, actual: u64) -> Self {
        anyhow!("expected tag {}, was {}", expected, actual).into()
    }

    pub fn expected_data_item(expected: DataItemType, actual: DataItemType) -> Self {
        anyhow!("expected data item {:?}, was {:?}", expected, actual).into()
    }

    pub fn remaining_data() -> Self {
        anyhow!("data remaining after parse").into()
    }

    pub fn expected_map_key(expected: u64, actual: u64) -> Self {
        anyhow!("expected map key {}, was {}", expected, actual).into()
    }

    pub fn unknown_map_key(key: MapKeyRef) -> Self {
        anyhow!("unknown map key {:?}", key).into()
    }

    pub fn invalid_data(message: impl Display) -> Self {
        anyhow!("invalid data: {}", message).into()
    }

    pub fn map_value_missing(key: MapKeyRef) -> Self {
        anyhow!("map value for key {:?} not present and cannot be null", key).into()
    }
}

pub type CborResult<T> = Result<T, CborError>;

impl<T> From<ciborium_ll::Error<T>> for CborError
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

impl From<std::io::Error> for CborError {
    fn from(err: std::io::Error) -> Self {
        anyhow!("IO error: {}", err).into()
    }
}

/// Encodes the given value as CBOR
pub fn cbor_encode<T: CborSerialize>(value: &T) -> CborResult<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut encoder = Encoder::from(&mut bytes);
    value.serialize(&mut encoder)?;
    Ok(bytes)
}

/// Decodes value from the given CBOR. If all input is not parsed,
/// an error is returned.
pub fn cbor_decode<T: CborDeserialize>(cbor: &[u8]) -> CborResult<T> {
    let mut decoder = Decoder::from(cbor);
    let value = T::deserialize(&mut decoder)?;
    if decoder.offset() != cbor.len() {
        return Err(CborError::remaining_data());
    }
    Ok(value)
}

/// Type that can be CBOR serialized
pub trait CborSerialize {
    /// Serialize value to CBOR
    fn serialize<C: CborEncoder>(&self, encoder: &mut C) -> CborResult<()>;

    /// Whether the value corresponds to `null`
    fn is_null(&self) -> bool {
        false
    }
}

impl<T: CborSerialize> CborSerialize for Option<T> {
    fn serialize<C: CborEncoder>(&self, encoder: &mut C) -> CborResult<()> {
        match self {
            None => encoder.encode_null(),
            Some(value) => value.serialize(encoder),
        }
    }

    fn is_null(&self) -> bool {
        match self {
            None => true,
            Some(_) => false,
        }
    }
}

/// Type that can be deserialized from CBOR
pub trait CborDeserialize {
    /// Deserialize value from the given decoder
    fn deserialize<C: CborDecoder>(decoder: &mut C) -> CborResult<Self>
    where
        Self: Sized;

    /// Produce value corresponding to `null` if possible for this type
    fn null() -> Option<Self>
    where
        Self: Sized,
    {
        None
    }
}

impl<T: CborDeserialize> CborDeserialize for Option<T> {
    fn deserialize<C: CborDecoder>(decoder: &mut C) -> CborResult<Self>
    where
        Self: Sized,
    {
        Ok(Some(T::deserialize(decoder)?))
    }

    fn null() -> Option<Self>
    where
        Self: Sized,
    {
        Some(None)
    }
}

/// Encoder of CBOR. See <https://www.rfc-editor.org/rfc/rfc8949.html#section-3>
pub trait CborEncoder {
    /// Encodes tag data item with given value
    fn encode_tag(&mut self, tag: u64) -> CborResult<()>;

    /// Encodes positive integer data item with given value
    fn encode_positive(&mut self, positive: u64) -> CborResult<()>;

    /// Encodes start of map with given size
    fn encode_map(&mut self, size: usize) -> CborResult<()>;

    /// Encodes start of array with given size
    fn encode_array(&mut self, size: usize) -> CborResult<()>;

    /// Encodes bytes data item
    fn encode_bytes(&mut self, bytes: &[u8]) -> CborResult<()>;

    /// Encodes text data item
    fn encode_text(&mut self, text: &str) -> CborResult<()>;

    /// Encodes simple value null, see <https://www.rfc-editor.org/rfc/rfc8949.html#name-floating-point-numbers-and->
    fn encode_null(&mut self) -> CborResult<()>;
}

impl<W: Write> CborEncoder for Encoder<W>
where
    CborError: From<W::Error>,
{
    fn encode_tag(&mut self, tag: u64) -> CborResult<()> {
        Ok(self.push(Header::Tag(tag))?)
    }

    fn encode_positive(&mut self, positive: u64) -> CborResult<()> {
        Ok(self.push(Header::Positive(positive))?)
    }

    fn encode_map(&mut self, size: usize) -> CborResult<()> {
        Ok(self.push(Header::Map(Some(size)))?)
    }

    fn encode_array(&mut self, size: usize) -> CborResult<()> {
        Ok(self.push(Header::Array(Some(size)))?)
    }

    fn encode_bytes(&mut self, bytes: &[u8]) -> CborResult<()> {
        Ok(self.bytes(bytes, None)?)
    }

    fn encode_text(&mut self, text: &str) -> CborResult<()> {
        Ok(self.text(text, None)?)
    }

    fn encode_null(&mut self) -> CborResult<()> {
        Ok(self.push(Header::Simple(simple::NULL))?)
    }
}

/// Decoder of CBOR. See <https://www.rfc-editor.org/rfc/rfc8949.html#section-3>
pub trait CborDecoder {
    /// Decode tag data item
    fn decode_tag(&mut self) -> CborResult<u64>;

    /// Decode that and check it equals the given `expected_tag`
    fn decode_tag_expect(&mut self, expected_tag: u64) -> CborResult<()> {
        let tag = self.decode_tag()?;
        if tag != expected_tag {
            return Err(CborError::expected_tag(expected_tag, tag));
        }
        Ok(())
    }

    /// Decode positive integer data item
    fn decode_positive(&mut self) -> CborResult<u64>;

    /// Decode positive integer data item and check that it equals
    /// the given map key
    // todo ar remove
    fn decode_positive_expect_key(&mut self, expected_key: u64) -> CborResult<()> {
        let positive = self.decode_positive()?;
        if positive != expected_key {
            return Err(CborError::expected_map_key(expected_key, positive));
        }
        Ok(())
    }

    /// Decode map start. Returns the map size
    fn decode_map(&mut self) -> CborResult<usize>;

    /// Decode array start. Returns the array size
    fn decode_array(&mut self) -> CborResult<usize>;

    /// Decode bytes into given `destination`. The length of the bytes data item
    /// must match the `destination` length, else an error is returned.
    ///
    /// Works only for definite length bytes.
    fn decode_bytes_exact(&mut self, destination: &mut [u8]) -> CborResult<()>;

    /// Decode text and return UTF8 encoding.
    ///
    /// Works only for definite length text.
    fn decode_str(&mut self) -> CborResult<Vec<u8>>;

    fn peek_data_item_type(&mut self) -> CborResult<DataItemType>;
}

impl<R: Read> CborDecoder for Decoder<R>
where
    R::Error: Display,
{
    fn decode_tag(&mut self) -> CborResult<u64> {
        match self.pull()? {
            Header::Tag(tag) => Ok(tag),
            header => Err(CborError::expected_data_item(
                DataItemType::Tag,
                DataItemType::from_header(&header),
            )),
        }
    }

    fn decode_positive(&mut self) -> CborResult<u64> {
        match self.pull()? {
            Header::Positive(positive) => Ok(positive),
            header => Err(CborError::expected_data_item(
                DataItemType::Positive,
                DataItemType::from_header(&header),
            )),
        }
    }

    fn decode_map(&mut self) -> CborResult<usize> {
        match self.pull()? {
            Header::Map(Some(size)) => Ok(size),
            header => Err(CborError::expected_data_item(
                DataItemType::Map,
                DataItemType::from_header(&header),
            )),
        }
    }

    fn decode_array(&mut self) -> CborResult<usize> {
        match self.pull()? {
            Header::Array(Some(size)) => Ok(size),
            header => Err(CborError::expected_data_item(
                DataItemType::Array,
                DataItemType::from_header(&header),
            )),
        }
    }

    fn decode_bytes_exact(&mut self, dest: &mut [u8]) -> CborResult<()> {
        match self.pull()? {
            Header::Bytes(Some(size)) => {
                if size != dest.len() {
                    return Err(anyhow!("expected {} bytes, was {}", dest.len(), size).into());
                }
            }
            header => {
                return Err(CborError::expected_data_item(
                    DataItemType::Bytes,
                    DataItemType::from_header(&header),
                ))
            }
        };

        decode_definite_length_bytes(self, dest)?;
        Ok(())
    }

    fn decode_str(&mut self) -> CborResult<Vec<u8>> {
        let size = match self.pull()? {
            Header::Text(Some(size)) => size,
            header => {
                return Err(CborError::expected_data_item(
                    DataItemType::Text,
                    DataItemType::from_header(&header),
                ))
            }
        };

        let mut bytes = vec![0; size];
        decode_definite_length_text(self, &mut bytes)?;
        Ok(bytes)
    }

    fn peek_data_item_type(&mut self) -> CborResult<DataItemType> {
        let header = self.pull()?;
        let data_item_type = DataItemType::from_header(&header);
        self.push(header);
        Ok(data_item_type)
    }
}

/// Decodes bytes data item into given destination. Length of bytes data item
/// must match the destination length.
///
/// This function works only for bytes data items of definite length (which means there
/// is a single segment)
fn decode_definite_length_bytes<R: Read>(
    decoder: &mut Decoder<R>,
    dest: &mut [u8],
) -> CborResult<()>
where
    R::Error: Display,
{
    let mut segments = decoder.bytes(Some(dest.len()));
    let Some(mut segment) = segments.pull()? else {
        return Err(anyhow!("must have at least one segment").into());
    };

    segment.pull(dest)?;
    if segment.left() != 0 {
        return Err(anyhow!("remaining data in segment").into());
    }
    if segments.pull()?.is_some() {
        return Err(anyhow!("expected to only one segment").into());
    }
    Ok(())
}

/// Decodes text data item into given destination. Length of text data item
/// must match the destination length.
///
/// This function works only for text data items of definite length (which means there
/// is a single segment)
fn decode_definite_length_text<'a, R: Read>(
    decoder: &mut Decoder<R>,
    dest: &'a mut [u8],
) -> CborResult<&'a str>
where
    R::Error: Display,
{
    let mut segments = decoder.text(Some(dest.len()));
    let Some(mut segment) = segments.pull()? else {
        return Err(anyhow!("must have at least one segment").into());
    };

    let str = segment.pull(dest)?.context("no data in segment")?;
    if segment.left() != 0 {
        return Err(anyhow!("remaining data in segment").into());
    }
    if segments.pull()?.is_some() {
        return Err(anyhow!("expected to only one segment").into());
    }
    Ok(str)
}

impl<const N: usize> CborSerialize for [u8; N] {
    fn serialize<C: CborEncoder>(&self, encoder: &mut C) -> CborResult<()> {
        encoder.encode_bytes(self)
    }
}

impl<const N: usize> CborDeserialize for [u8; N] {
    fn deserialize<C: CborDecoder>(decoder: &mut C) -> CborResult<Self>
    where
        Self: Sized,
    {
        let mut dest = [0; N];
        decoder.decode_bytes_exact(&mut dest)?;
        Ok(dest)
    }
}

impl CborSerialize for u64 {
    fn serialize<C: CborEncoder>(&self, encoder: &mut C) -> CborResult<()> {
        encoder.encode_positive(*self)
    }
}

impl CborDeserialize for u64 {
    fn deserialize<C: CborDecoder>(decoder: &mut C) -> CborResult<Self>
    where
        Self: Sized,
    {
        decoder.decode_positive()
    }
}

impl CborSerialize for usize {
    fn serialize<C: CborEncoder>(&self, encoder: &mut C) -> CborResult<()> {
        encoder.encode_positive((*self).try_into().context("convert from usize to u64")?)
    }
}

impl CborDeserialize for usize {
    fn deserialize<C: CborDecoder>(decoder: &mut C) -> CborResult<Self>
    where
        Self: Sized,
    {
        Ok(decoder.decode_positive()?.try_into().context("convert u64 to usize")?)
    }
}

impl CborSerialize for &str {
    fn serialize<C: CborEncoder>(&self, encoder: &mut C) -> CborResult<()> {
        encoder.encode_text(self)
    }
}

impl CborDeserialize for String {
    fn deserialize<C: CborDecoder>(decoder: &mut C) -> CborResult<Self>
    where
        Self: Sized,
    {
        Ok(String::from_utf8(decoder.decode_str()?)
            .context("text data item not valid UTF8 encoding")?)
    }
}

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
    pub fn from_header(header: &Header) -> Self {
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

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub enum MapKeyRef<'a> {
    Positive(u64),
    Text(&'a str),
}

impl CborSerialize for MapKeyRef<'_> {
    fn serialize<C: CborEncoder>(&self, encoder: &mut C) -> CborResult<()> {
        match self {
            MapKeyRef::Positive(positive) => encoder.encode_positive(*positive),
            MapKeyRef::Text(text) => encoder.encode_text(text),
        }
    }
}

impl CborDeserialize for MapKey {
    fn deserialize<C: CborDecoder>(decoder: &mut C) -> CborResult<Self>
    where
        Self: Sized,
    {
        match decoder.peek_data_item_type()? {
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

// todo ar proc macro: map + transparent + tag

#[cfg(test)]
mod test {
    use super::*;

    // todo ar test not well formed bytes and text (different length than specified)

    #[test]
    fn test_bytes_exact() {
        let bytes: [u8; 5] = [1, 2, 3, 4, 5];

        let cbor = cbor_encode(&bytes).unwrap();
        let bytes_decoded: [u8; 5] = cbor_decode(&cbor).unwrap();
        assert_eq!(bytes_decoded, bytes);
    }

    #[test]
    fn test_text() {
        let text = "abcd";

        let cbor = cbor_encode(&text).unwrap();
        let text_decoded: String = cbor_decode(&cbor).unwrap();
        assert_eq!(text_decoded, text);
    }
}
