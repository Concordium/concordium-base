use crate::common::cbor::{CborEncoder, CborSerializationError, CborSerializationResult};
use ciborium_io::Write;
use ciborium_ll::Header;

/// CBOR encoder implementation
pub struct Encoder<W: Write> {
    inner: ciborium_ll::Encoder<W>,
}

impl<W: Write> Encoder<W> {
    pub fn new(write: W) -> Self {
        let inner = ciborium_ll::Encoder::from(write);

        Self { inner }
    }
}

impl<W: Write> CborEncoder for Encoder<W>
where
    CborSerializationError: From<W::Error>,
{
    fn encode_tag(&mut self, tag: u64) -> CborSerializationResult<()> {
        Ok(self.inner.push(Header::Tag(tag))?)
    }

    fn encode_positive(&mut self, positive: u64) -> CborSerializationResult<()> {
        Ok(self.inner.push(Header::Positive(positive))?)
    }

    fn encode_negative(&mut self, negative: u64) -> CborSerializationResult<()> {
        Ok(self.inner.push(Header::Negative(negative))?)
    }

    fn encode_map_header(&mut self, size: usize) -> CborSerializationResult<()> {
        Ok(self.inner.push(Header::Map(Some(size)))?)
    }

    fn encode_array_header(&mut self, size: usize) -> CborSerializationResult<()> {
        Ok(self.inner.push(Header::Array(Some(size)))?)
    }

    fn encode_bytes(&mut self, bytes: &[u8]) -> CborSerializationResult<()> {
        Ok(self.inner.bytes(bytes, None)?)
    }

    fn encode_text(&mut self, text: &str) -> CborSerializationResult<()> {
        Ok(self.inner.text(text, None)?)
    }

    fn encode_simple(&mut self, value: u8) -> CborSerializationResult<()> {
        Ok(self.inner.push(Header::Simple(value))?)
    }
}
