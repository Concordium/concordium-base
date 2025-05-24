use anyhow::anyhow;
use ciborium_io::{Read, Write};
use ciborium_ll::{Decoder, Encoder, Header};
use std::fmt::{Debug, Display};

#[derive(thiserror::Error, Debug)]
#[error(transparent)]
pub struct CborError(#[from] anyhow::Error);

impl CborError {
    pub fn unexpected_tag(expected: u64, actual: u64) -> Self {
        anyhow!("expected tag {}, was {}", expected, actual).into()
    }

    pub fn unexpected_data_item(expected: &str, actual: &Header) -> Self {
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

    pub fn unexpected_map_key(expected: u64, actual: u64) -> Self {
        anyhow!("expected map key {}, was {}", expected, actual).into()
    }

    pub fn invalid_data(message: impl Display) -> Self {
        anyhow!("invalid data: {}", message).into()
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
    fn encode<C: CborEncoder>(&self, encoder: &mut C) -> CborResult<()>;
}

/// Type that can be decoded from CBOR
pub trait CborDecode {
    fn decode<C: CborDecoder>(decoder: &mut C) -> CborResult<Self>
    where
        Self: Sized;
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
}

/// Decoder of CBOR. See <https://www.rfc-editor.org/rfc/rfc8949.html#section-3>
pub trait CborDecoder {
    /// Decode tag data item
    fn decode_tag(&mut self) -> CborResult<u64>;
    
    /// Decode that and check it equals the given `expected_tag` 
    fn decode_tag_expect(&mut self, expected_tag: u64) -> CborResult<()> {
        let tag = self.decode_tag()?;
        if tag != expected_tag {
            return Err(CborError::unexpected_tag(expected_tag, tag));
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
            return Err(CborError::unexpected_map_key(expected_key, positive));
        }
        Ok(())
    }

    /// Decode map start. Returns the map size
    fn decode_map(&mut self) -> CborResult<usize>;

    /// Decode array start. Returns the array size
    fn decode_array(&mut self) -> CborResult<usize>;
    
    /// Decode bytes into given `destination`. The length of the bytes data item
    /// must match the `destination` length, else an error is returned.
    fn decode_bytes_exact(&mut self, destination: &mut [u8]) -> CborResult<()>;
}

impl<R: Read> CborDecoder for Decoder<R>
where
    R::Error: Display,
{
    fn decode_tag(&mut self) -> CborResult<u64> {
        match self.pull()? {
            Header::Tag(tag) => Ok(tag),
            header => Err(CborError::unexpected_data_item("tag", &header)),
        }
    }

    fn decode_positive(&mut self) -> CborResult<u64> {
        match self.pull()? {
            Header::Positive(positive) => Ok(positive),
            header => Err(CborError::unexpected_data_item("positive", &header)),
        }
    }

    fn decode_map(&mut self) -> CborResult<usize> {
        match self.pull()? {
            Header::Map(Some(size)) => Ok(size),
            header => Err(CborError::unexpected_data_item("map", &header)),
        }
    }

    fn decode_array(&mut self) -> CborResult<usize> {
        match self.pull()? {
            Header::Array(Some(size)) => Ok(size),
            header => Err(CborError::unexpected_data_item("array", &header)),
        }
    }

    fn decode_bytes_exact(&mut self, dest: &mut [u8]) -> CborResult<()> {
        let size = match self.pull()? {
            Header::Bytes(Some(size)) => {
                if size != dest.len() {
                    return Err(anyhow!("expected {} bytes, was {}", dest.len(), size).into());
                }
                size
            }
            header => return Err(CborError::unexpected_data_item("bytes", &header)),
        };
        
        let mut segments = self.bytes(Some(size));
        let Some(mut segment) = segments.pull()? else {
            return Err(anyhow!("bytes must have at least one segment").into());
        };

        segment.pull(dest)?;
        if segment.left() != 0 {
            return Err(anyhow!("bytes left in segment").into());
        }
        if segments.pull()?.is_some() {
            return Err(anyhow!("bytes expected to have only one segment").into());
        }
        Ok(())
    }
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
