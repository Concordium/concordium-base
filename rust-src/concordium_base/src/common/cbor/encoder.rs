use crate::common::cbor::{
    CborArrayEncoder, CborEncoder, CborMapEncoder, CborSerializationError, CborSerializationResult,
    CborSerialize,
};
use ciborium_ll::Header;
use std::{
    io::Write,
    ops::{Index, Range},
};

/// CBOR encoder implementation
pub struct Encoder<W: Write> {
    write: W,
}

impl<W: Write> Encoder<W> {
    pub fn new(write: W) -> Self { Self { write } }

    fn encode_raw(&mut self, bytes: &[u8]) -> CborSerializationResult<()> {
        Ok(self.write.write_all(bytes)?)
    }

    fn encoder(&mut self) -> ciborium_ll::Encoder<&mut W> {
        ciborium_ll::Encoder::from(&mut self.write)
    }
}

impl<'a, W: Write> CborEncoder for &'a mut Encoder<W>
where
    CborSerializationError: From<<W as ciborium_io::Write>::Error>,
{
    type ArrayEncoder = ArrayEncoder<'a, W>;
    type MapEncoder = MapEncoder<'a, W>;

    fn encode_tag(&mut self, tag: u64) -> CborSerializationResult<()> {
        Ok(self.encoder().push(Header::Tag(tag))?)
    }

    fn encode_positive(self, positive: u64) -> CborSerializationResult<()> {
        Ok(self.encoder().push(Header::Positive(positive))?)
    }

    fn encode_negative(self, negative: u64) -> CborSerializationResult<()> {
        Ok(self.encoder().push(Header::Negative(negative))?)
    }

    fn encode_map(self, size: usize) -> CborSerializationResult<Self::MapEncoder> {
        self.encoder().push(Header::Map(Some(size)))?;
        Ok(MapEncoder::new(size, self))
    }

    fn encode_array(self, size: usize) -> CborSerializationResult<Self::ArrayEncoder> {
        self.encoder().push(Header::Array(Some(size)))?;
        Ok(ArrayEncoder::new(size, self))
    }

    fn encode_bytes(self, bytes: &[u8]) -> CborSerializationResult<()> {
        Ok(self.encoder().bytes(bytes, None)?)
    }

    fn encode_text(self, text: &str) -> CborSerializationResult<()> {
        Ok(self.encoder().text(text, None)?)
    }

    fn encode_simple(self, value: u8) -> CborSerializationResult<()> {
        Ok(self.encoder().push(Header::Simple(value))?)
    }

    fn encode_float(self, float: f64) -> CborSerializationResult<()> {
        Ok(self.encoder().push(Header::Float(float))?)
    }
}

/// CBOR map encoder
#[must_use]
pub struct MapEncoder<'a, W: Write> {
    declared_size:   usize,
    current_size:    usize,
    encoder:         &'a mut Encoder<W>,
    /// Temporary buffer for unordered map entries
    buffer:          Vec<u8>,
    /// Indexes for each entry in the buffer
    entries_indexes: Vec<Range<usize>>,
}

impl<'a, W: Write> MapEncoder<'a, W> {
    fn new(size: usize, encoder: &'a mut Encoder<W>) -> Self {
        Self {
            declared_size: size,
            current_size: 0,
            encoder,
            buffer: Vec::new(),
            entries_indexes: Vec::with_capacity(size),
        }
    }
}

impl<W: Write> CborMapEncoder for MapEncoder<'_, W>
where
    CborSerializationError: From<<W as ciborium_io::Write>::Error>,
{
    fn serialize_entry<K: CborSerialize + ?Sized, V: CborSerialize + ?Sized>(
        &mut self,
        key: &K,
        value: &V,
    ) -> CborSerializationResult<()> {
        self.current_size += 1;
        let index_start = self.buffer.len();
        let mut tmp_encoder = Encoder::new(&mut self.buffer);
        key.serialize(&mut tmp_encoder)?;
        value.serialize(&mut tmp_encoder)?;
        self.entries_indexes.push(index_start..self.buffer.len());
        Ok(())
    }

    fn end(mut self) -> CborSerializationResult<()> {
        if self.declared_size == self.current_size {
            // Sort according to lexicographic byte order: https://www.rfc-editor.org/rfc/rfc8949.html#name-core-deterministic-encoding
            self.entries_indexes
                .sort_by_key(|index| self.buffer.index(index.clone()));
            for index in &self.entries_indexes {
                self.encoder.encode_raw(self.buffer.index(index.clone()))?;
            }
            Ok(())
        } else {
            Err(CborSerializationError::map_size(
                self.declared_size,
                Some(self.current_size),
            ))
        }
    }
}

/// CBOR array encoder
#[must_use]
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
    CborSerializationError: From<<W as ciborium_io::Write>::Error>,
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
                Some(self.current_size),
            ))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_map_wrong_size() {
        let mut bytes = Vec::new();
        let mut encoder = Encoder::new(&mut bytes);
        let map_encoder = encoder.encode_map(1).unwrap();
        let err = map_encoder.end().unwrap_err().to_string();
        assert!(err.contains("expected map size 1"), "err: {}", err);
    }

    #[test]
    fn test_array_wrong_size() {
        let mut bytes = Vec::new();
        let mut encoder = Encoder::new(&mut bytes);
        let array_encoder = encoder.encode_array(1).unwrap();
        let err = array_encoder.end().unwrap_err().to_string();
        assert!(err.contains("expected array length 1"), "err: {}", err);
    }

    /// Test that map entries are ordered according to the rules
    /// in <https://www.rfc-editor.org/rfc/rfc8949.html#name-core-deterministic-encoding>
    #[test]
    fn test_map_entry_order() {
        let mut bytes = Vec::new();
        let mut encoder = Encoder::new(&mut bytes);
        let mut map_encoder = encoder.encode_map(5).unwrap();
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
