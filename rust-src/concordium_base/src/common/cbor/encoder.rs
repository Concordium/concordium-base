use crate::common::cbor;
use crate::common::cbor::{CborArrayEncoder, CborEncoder, CborMapEncoder, CborSerialize};
use ciborium_io::Write;
use ciborium_ll::Header;
use std::ops::{Index, Range};

#[derive(Debug)]
pub struct VecWrite<'a>(pub &'a mut Vec<u8>);

impl Write for VecWrite<'_> {
    type Error = core::convert::Infallible;

    fn write_all(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        self.0.extend_from_slice(data);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

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

impl<W: Write> Encoder<W> {
    fn encode_raw(&mut self, bytes: &[u8]) -> Result<(), <W as Write>::Error> {
        self.inner.write_all(bytes)
    }
}

impl<'a, W: Write> CborEncoder for &'a mut Encoder<W> {
    type ArrayEncoder = ArrayEncoder<'a, W>;
    type MapEncoder = MapEncoder<'a, W>;
    type WriteError = <W as Write>::Error;

    fn encode_tag(&mut self, tag: u64) -> Result<(), Self::WriteError> {
        self.inner.push(Header::Tag(tag))
    }

    fn encode_positive(self, positive: u64) -> Result<(), Self::WriteError> {
        self.inner.push(Header::Positive(positive))
    }

    fn encode_negative(self, negative: u64) -> Result<(), Self::WriteError> {
        self.inner.push(Header::Negative(negative))
    }

    fn encode_map(self) -> Result<Self::MapEncoder, Self::WriteError> {
        Ok(MapEncoder::new(self))
    }

    fn encode_array(self) -> Result<Self::ArrayEncoder, Self::WriteError> {
        Ok(ArrayEncoder::new(self))
    }

    fn encode_bytes(self, bytes: &[u8]) -> Result<(), Self::WriteError> {
        self.inner.bytes(bytes, None)
    }

    fn encode_text(self, text: &str) -> Result<(), Self::WriteError> {
        self.inner.text(text, None)
    }

    fn encode_simple(self, value: u8) -> Result<(), Self::WriteError> {
        self.inner.push(Header::Simple(value))
    }

    fn encode_float(self, float: f64) -> Result<(), Self::WriteError> {
        self.inner.push(Header::Float(float))
    }
}

/// CBOR map encoder
#[must_use]
pub struct MapEncoder<'a, W: Write> {
    encoder: &'a mut Encoder<W>,
    /// Temporary buffer for unordered map entries
    buffer: Vec<u8>,
    /// Indexes for each entry in the buffer
    entries_indexes: Vec<Range<usize>>,
}

impl<'a, W: Write> MapEncoder<'a, W> {
    fn new(encoder: &'a mut Encoder<W>) -> Self {
        Self {
            encoder,
            buffer: Vec::new(),
            entries_indexes: Vec::new(),
        }
    }
}

impl<W: Write> CborMapEncoder for MapEncoder<'_, W> {
    type WriteError = <W as Write>::Error;

    fn serialize_entry<K: CborSerialize + ?Sized, V: CborSerialize + ?Sized>(
        &mut self,
        key: &K,
        value: &V,
    ) -> Result<(), Self::WriteError> {
        let index_start = self.buffer.len();
        let mut tmp_encoder = Encoder::new(VecWrite(&mut self.buffer));
        cbor::into_ok(key.serialize(&mut tmp_encoder));
        cbor::into_ok(value.serialize(&mut tmp_encoder));
        self.entries_indexes.push(index_start..self.buffer.len());
        Ok(())
    }

    fn end(mut self) -> Result<(), Self::WriteError> {
        self.encoder
            .inner
            .push(Header::Map(Some(self.entries_indexes.len())))?;
        // Sort according to lexicographic byte order: https://www.rfc-editor.org/rfc/rfc8949.html#name-core-deterministic-encoding
        self.entries_indexes
            .sort_by_key(|index| self.buffer.index(index.clone()));
        for index in &self.entries_indexes {
            self.encoder.encode_raw(self.buffer.index(index.clone()))?;
        }
        Ok(())
    }
}

/// CBOR array encoder
#[must_use]
pub struct ArrayEncoder<'a, W: Write> {
    encoder: &'a mut Encoder<W>,
    /// Temporary buffer for elements
    buffer: Vec<u8>,
    /// Number of elements in buffer
    element_count: usize,
}

impl<'a, W: Write> ArrayEncoder<'a, W> {
    fn new(encoder: &'a mut Encoder<W>) -> Self {
        Self {
            encoder,
            buffer: Vec::new(),
            element_count: 0,
        }
    }
}

impl<W: Write> CborArrayEncoder for ArrayEncoder<'_, W> {
    type WriteError = <W as Write>::Error;

    fn serialize_element<T: CborSerialize + ?Sized>(
        &mut self,
        element: &T,
    ) -> Result<(), Self::WriteError> {
        let mut tmp_encoder = Encoder::new(VecWrite(&mut self.buffer));
        cbor::into_ok(element.serialize(&mut tmp_encoder));
        self.element_count += 1;
        Ok(())
    }

    fn end(self) -> Result<(), Self::WriteError> {
        self.encoder
            .inner
            .push(Header::Array(Some(self.element_count)))?;
        self.encoder.encode_raw(&self.buffer)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// Test that map entries are ordered according to the rules
    /// in <https://www.rfc-editor.org/rfc/rfc8949.html#name-core-deterministic-encoding>
    #[test]
    fn test_map_entry_order() {
        let mut bytes = Vec::new();
        let mut encoder = Encoder::new(&mut bytes);
        let mut map_encoder = encoder.encode_map().unwrap();
        map_encoder.serialize_entry(&"key2", &0).unwrap();
        map_encoder.serialize_entry(&256, &0).unwrap();
        map_encoder.serialize_entry(&"key1", &0).unwrap();
        map_encoder.serialize_entry(&65536, &0).unwrap();
        map_encoder.serialize_entry(&1, &0).unwrap();
        map_encoder.end().unwrap();

        assert_eq!(
            hex::encode(&bytes),
            "a50100190100001a0001000000646b65793100646b65793200"
        );
    }
}
