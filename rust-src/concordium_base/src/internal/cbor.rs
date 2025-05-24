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

impl From<std::io::Error> for CborError
{
    fn from(err: std::io::Error) -> Self {
        anyhow!("IO error: {}", err).into()
    }
}

pub fn cbor_encode<T: CborEncode>(value: &T) -> CborResult<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut encoder = Encoder::from(&mut bytes);
    value.encode(&mut encoder)?;
    Ok(bytes)
}

pub fn cbor_decode<T: CborDecode>(cbor: &[u8]) -> CborResult<T> {
    let mut decoder = Decoder::from(cbor);
    let value = T::decode(&mut decoder)?;
    if decoder.offset() != cbor.len() {
        return Err(CborError::remaining_data());
    }
    Ok(value)
}

pub trait CborEncode {
    fn encode<C: CborEncoder>(&self, encoder: &mut C) -> CborResult<()>;
}

pub trait CborDecode {
    fn decode<C: CborDecoder>(decoder: &mut C) -> CborResult<Self>
    where
        Self: Sized;
}

pub trait CborEncoder {
    fn push_tag(&mut self, tag: u64) -> CborResult<()>;
    fn push_positive(&mut self, positive: u64) -> CborResult<()>;
    fn push_map(&mut self, size: usize) -> CborResult<()>;
    fn push_array(&mut self, size: usize) -> CborResult<()>;
    fn push_bytes(&mut self, bytes: &[u8]) -> CborResult<()>;
}

impl<W: Write> CborEncoder for Encoder<W>
where
    CborError: From<W::Error>,
{
    fn push_tag(&mut self, tag: u64) -> CborResult<()> {
        Ok(self.push(Header::Tag(tag))?)
    }

    fn push_positive(&mut self, positive: u64) -> CborResult<()> {
        Ok(self.push(Header::Positive(positive))?)
    }

    fn push_map(&mut self, size: usize) -> CborResult<()> {
        Ok(self.push(Header::Map(Some(size)))?)
    }

    fn push_array(&mut self, size: usize) -> CborResult<()> {
        Ok(self.push(Header::Array(Some(size)))?)
    }

    fn push_bytes(&mut self, bytes: &[u8]) -> CborResult<()> {
        Ok(self.bytes(bytes, None)?)
    }
}

pub trait CborDecoder {
    fn pull_tag(&mut self) -> CborResult<u64>;
    fn pull_tag_expect(&mut self, expected_tag: u64) -> CborResult<u64>;
    fn pull_positive(&mut self) -> CborResult<u64>;
    fn pull_map(&mut self) -> CborResult<usize>;
    fn pull_array(&mut self) -> CborResult<usize>;
    fn pull_bytes_exact(&mut self, dest: &mut [u8]) -> CborResult<()>;
}

impl<R: Read> CborDecoder for Decoder<R>
where
    R::Error: Display,
{
    fn pull_tag(&mut self) -> CborResult<u64> {
        match self.pull()? {
            Header::Tag(tag) => Ok(tag),
            header => Err(CborError::unexpected_data_item("tag", &header)),
        }
    }

    fn pull_tag_expect(&mut self, expected_tag: u64) -> CborResult<u64> {
        let tag = self.pull_tag()?;
        if tag != expected_tag {
            return Err(CborError::unexpected_tag(expected_tag, tag));
        }
        Ok(tag)
    }

    fn pull_positive(&mut self) -> CborResult<u64> {
        match self.pull()? {
            Header::Positive(positive) => Ok(positive),
            header => Err(CborError::unexpected_data_item("positive", &header)),
        }
    }

    fn pull_map(&mut self) -> CborResult<usize> {
        match self.pull()? {
            Header::Map(Some(size)) => Ok(size),
            header => Err(CborError::unexpected_data_item("map", &header)),
        }
    }

    fn pull_array(&mut self) -> CborResult<usize> {
        match self.pull()? {
            Header::Array(Some(size)) => Ok(size),
            header => Err(CborError::unexpected_data_item("array", &header)),
        }
    }

    fn pull_bytes_exact(&mut self, dest: &mut [u8]) -> CborResult<()> {
        match self.pull()? {
            Header::Bytes(Some(size)) => {
                if size != dest.len() {
                    todo!()
                }
            }
            _ => todo!(),
        };
        let mut segments = self.bytes(Some(dest.len()));
        let Some(mut segment) = segments.pull()? else {
            todo!()
        };

        segment.pull(dest)?;
        if segment.left() != 0 {
            todo!()
        }
        if segments.pull()?.is_some() {
            todo!()
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
