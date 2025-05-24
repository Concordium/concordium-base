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

    // todo ar use enum for DataItemType
    pub fn expected_data_item(expected: &str, actual: &Header) -> Self {
        anyhow!(
            "expected data item {}, was {}",
            expected,
            header_display(actual)
        )
        .into()
    }

    pub fn remaining_data() -> Self {
        anyhow!("data remaining after parse").into()
    }

    pub fn expected_map_key(expected: u64, actual: u64) -> Self {
        anyhow!("expected map key {}, was {}", expected, actual).into()
    }

    pub fn unknown_map_key(key: u64) -> Self {
        anyhow!("unknown map key {}", key).into()
    }

    pub fn invalid_data(message: impl Display) -> Self {
        anyhow!("invalid data: {}", message).into()
    }

    pub fn map_value_missing(key: u64) -> Self {
        anyhow!("map value for key {} not present and cannot be null", key).into()
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
pub fn cbor_encode<T: CborEncode>(value: &T) -> CborResult<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut encoder = Encoder::from(&mut bytes);
    value.encode(&mut encoder)?;
    Ok(bytes)
}

/// Decodes value from the given CBOR. If all input is not parsed,
/// an error is returned.
pub fn cbor_decode<T: CborDecode>(cbor: &[u8]) -> CborResult<T> {
    let mut decoder = Decoder::from(cbor);
    let value = T::decode(&mut decoder)?;
    if decoder.offset() != cbor.len() {
        return Err(CborError::remaining_data());
    }
    Ok(value)
}

/// Type that can be CBOR encoded
pub trait CborEncode {
    /// Encode value to CBOR
    fn encode<C: CborEncoder>(&self, encoder: &mut C) -> CborResult<()>;

    /// Whether the value corresponds to `null`
    fn is_null(&self) -> bool {
        false
    }
}

impl<T: CborEncode> CborEncode for Option<T> {
    fn encode<C: CborEncoder>(&self, encoder: &mut C) -> CborResult<()> {
        match self {
            None => encoder.encode_null(),
            Some(value) => value.encode(encoder),
        }
    }

    fn is_null(&self) -> bool {
        match self {
            None => true,
            Some(_) => false,
        }
    }
}

/// Type that can be decoded from CBOR
pub trait CborDecode {
    /// Decode value from the given decoder
    fn decode<C: CborDecoder>(decoder: &mut C) -> CborResult<Self>
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

impl<T: CborDecode> CborDecode for Option<T> {
    fn decode<C: CborDecoder>(decoder: &mut C) -> CborResult<Self>
    where
        Self: Sized,
    {
        Ok(Some(T::decode(decoder)?))
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
    fn decode_str(&mut self) -> CborResult<Vec<u8>> ;
}

impl<R: Read> CborDecoder for Decoder<R>
where
    R::Error: Display,
{
    fn decode_tag(&mut self) -> CborResult<u64> {
        match self.pull()? {
            Header::Tag(tag) => Ok(tag),
            header => Err(CborError::expected_data_item("tag", &header)),
        }
    }

    fn decode_positive(&mut self) -> CborResult<u64> {
        match self.pull()? {
            Header::Positive(positive) => Ok(positive),
            header => Err(CborError::expected_data_item("positive", &header)),
        }
    }

    fn decode_map(&mut self) -> CborResult<usize> {
        match self.pull()? {
            Header::Map(Some(size)) => Ok(size),
            header => Err(CborError::expected_data_item("map", &header)),
        }
    }

    fn decode_array(&mut self) -> CborResult<usize> {
        match self.pull()? {
            Header::Array(Some(size)) => Ok(size),
            header => Err(CborError::expected_data_item("array", &header)),
        }
    }

    fn decode_bytes_exact(&mut self, dest: &mut [u8]) -> CborResult<()> {
        match self.pull()? {
            Header::Bytes(Some(size)) => {
                if size != dest.len() {
                    return Err(anyhow!("expected {} bytes, was {}", dest.len(), size).into());
                }
            }
            header => return Err(CborError::expected_data_item("bytes", &header)),
        };

        decode_definite_length_bytes(self, dest)?;
        Ok(())
    }

    fn decode_str(&mut self) -> CborResult<Vec<u8>> {
        let size = match self.pull()? {
            Header::Text(Some(size)) => {
                size
            }
            header => return Err(CborError::expected_data_item("text", &header)),
        };
        
        // todo ar non-allocating branch version

        let mut bytes = vec![0;size];
        decode_definite_length_text(self, &mut bytes)?;
        Ok(bytes)
    }

}

/// Decodes bytes data item into given destination. Length of bytes data item
/// must match the destination length. 
/// 
/// This function works only for bytes data items of definite length (which means there
/// is a single segment)
fn decode_definite_length_bytes<R: Read>(decoder: &mut Decoder<R>, dest: &mut [u8]) -> CborResult<()>
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
fn decode_definite_length_text<'a, R: Read>(decoder: &mut Decoder<R>, dest: &'a mut [u8]) -> CborResult<&'a str>
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

fn header_display(header: &Header) -> &'static str {
    match header {
        Header::Positive(_) => "positive",
        Header::Negative(_) => "negative",
        Header::Float(_) => "float",
        Header::Simple(_) => "simple",
        Header::Tag(_) => "tag",
        Header::Break => "break",
        Header::Bytes(_) => "bytes",
        Header::Text(_) => "text",
        Header::Array(_) => "array",
        Header::Map(_) => "map",
    }
}

impl<const N: usize> CborEncode for [u8; N] {
    fn encode<C: CborEncoder>(&self, encoder: &mut C) -> CborResult<()> {
        encoder.encode_bytes(self)
    }
}

impl<const N: usize> CborDecode for [u8; N] {
    fn decode<C: CborDecoder>(decoder: &mut C) -> CborResult<Self>
    where
        Self: Sized,
    {
        let mut dest = [0; N];
        decoder.decode_bytes_exact(&mut dest)?;
        Ok(dest)
    }
}

impl CborEncode for &str {
    fn encode<C: CborEncoder>(&self, encoder: &mut C) -> CborResult<()> {
        encoder.encode_text(self)
    }
}

impl CborDecode for String {
    fn decode<C: CborDecoder>(decoder: &mut C) -> CborResult<Self>
    where
        Self: Sized
    {
        Ok(String::from_utf8(decoder.decode_str()?).context("text data item not valid UTF8 encoding")?)
    }
}

// todo ar map key encode/decode and match

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
