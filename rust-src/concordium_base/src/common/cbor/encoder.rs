use crate::common::cbor::{
    CborArrayEncoder, CborEncoder, CborMapEncoder, CborSerializationError, CborSerializationResult,
    CborSerialize,
};
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

impl<'a, W: Write> CborEncoder for &'a mut Encoder<W>
where
    CborSerializationError: From<W::Error>,
{
    type ArrayEncoder = ArrayEncoder<'a, W>;
    type MapEncoder = MapEncoder<'a, W>;

    fn encode_tag(&mut self, tag: u64) -> CborSerializationResult<()> {
        Ok(self.inner.push(Header::Tag(tag))?)
    }

    fn encode_positive(self, positive: u64) -> CborSerializationResult<()> {
        Ok(self.inner.push(Header::Positive(positive))?)
    }

    fn encode_negative(self, negative: u64) -> CborSerializationResult<()> {
        Ok(self.inner.push(Header::Negative(negative))?)
    }

    fn encode_map(self, size: usize) -> CborSerializationResult<Self::MapEncoder> {
        self.inner.push(Header::Map(Some(size)))?;
        Ok(MapEncoder::new(size, self))
    }

    fn encode_array(self, size: usize) -> CborSerializationResult<Self::ArrayEncoder> {
        self.inner.push(Header::Array(Some(size)))?;
        Ok(ArrayEncoder::new(size, self))
    }

    fn encode_bytes(self, bytes: &[u8]) -> CborSerializationResult<()> {
        Ok(self.inner.bytes(bytes, None)?)
    }

    fn encode_text(self, text: &str) -> CborSerializationResult<()> {
        Ok(self.inner.text(text, None)?)
    }

    fn encode_simple(self, value: u8) -> CborSerializationResult<()> {
        Ok(self.inner.push(Header::Simple(value))?)
    }
}

pub struct MapEncoder<'a, W: Write> {
    declared_size: usize,
    current_size:  usize,
    encoder:       &'a mut Encoder<W>,
}

impl<'a, W: Write> MapEncoder<'a, W> {
    fn new(size: usize, encoder: &'a mut Encoder<W>) -> Self {
        Self {
            declared_size: size,
            current_size: 0,
            encoder,
        }
    }
}

impl<W: Write> CborMapEncoder for MapEncoder<'_, W>
where
    CborSerializationError: From<W::Error>,
{
    fn serialize_entry<K: CborSerialize + ?Sized, V: CborSerialize + ?Sized>(
        &mut self,
        key: &K,
        value: &V,
    ) -> CborSerializationResult<()> {
        self.current_size += 1;
        key.serialize(&mut *self.encoder)?;
        value.serialize(&mut *self.encoder)?;
        Ok(())
    }

    fn end(self) -> CborSerializationResult<()> {
        if self.declared_size == self.current_size {
            Ok(())
        } else {
            Err(CborSerializationError::map_size(
                self.declared_size,
                self.current_size,
            ))
        }
    }
}

pub struct ArrayEncoder<'a, W: Write> {
    declared_size: usize,
    current_size:  usize,
    encoder:       &'a mut Encoder<W>,
}

impl<'a, W: Write> ArrayEncoder<'a, W> {
    fn new(size: usize, encoder: &'a mut Encoder<W>) -> Self {
        Self {
            declared_size: size,
            current_size: 0,
            encoder,
        }
    }
}

impl<W: Write> CborArrayEncoder for ArrayEncoder<'_, W>
where
    CborSerializationError: From<W::Error>,
{
    fn serialize_element<T: CborSerialize + ?Sized>(
        &mut self,
        element: &T,
    ) -> CborSerializationResult<()> {
        self.current_size += 1;
        element.serialize(&mut *self.encoder)?;
        Ok(())
    }

    fn end(self) -> CborSerializationResult<()> {
        if self.declared_size == self.current_size {
            Ok(())
        } else {
            Err(CborSerializationError::array_size(
                self.declared_size,
                self.current_size,
            ))
        }
    }
}
