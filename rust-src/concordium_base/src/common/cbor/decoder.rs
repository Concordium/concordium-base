use crate::common::cbor::{
    CborArrayDecoder, CborDecoder, CborDeserialize, CborMapDecoder, CborSerializationError,
    CborSerializationResult, DataItemHeader, DataItemType, SerializationOptions,
};
use anyhow::anyhow;
use ciborium_ll::Header;
use std::{fmt::Display, io::Read};

/// CBOR decoder implementation
pub struct Decoder<R: Read> {
    inner:   ciborium_ll::Decoder<R>,
    options: SerializationOptions,
}

impl<R: Read> Decoder<R> {
    pub fn new(read: R, options: SerializationOptions) -> Self {
        let inner = ciborium_ll::Decoder::from(read);

        Self { inner, options }
    }
}

impl<'a, R: Read> CborDecoder for &'a mut Decoder<R>
where
    <R as ciborium_io::Read>::Error: Display,
{
    type ArrayDecoder = ArrayDecoder<'a, R>;
    type MapDecoder = MapDecoder<'a, R>;

    fn decode_tag(&mut self) -> CborSerializationResult<u64> {
        match self.inner.pull()? {
            Header::Tag(tag) => Ok(tag),
            header => Err(CborSerializationError::expected_data_item(
                DataItemType::Tag,
                DataItemType::from_header(header),
            )),
        }
    }

    fn decode_positive(self) -> CborSerializationResult<u64> {
        match self.inner.pull()? {
            Header::Positive(positive) => Ok(positive),
            header => Err(CborSerializationError::expected_data_item(
                DataItemType::Positive,
                DataItemType::from_header(header),
            )),
        }
    }

    fn decode_negative(self) -> CborSerializationResult<u64> {
        match self.inner.pull()? {
            Header::Negative(negative) => Ok(negative),
            header => Err(CborSerializationError::expected_data_item(
                DataItemType::Negative,
                DataItemType::from_header(header),
            )),
        }
    }

    fn decode_map(self) -> CborSerializationResult<Self::MapDecoder> {
        match self.inner.pull()? {
            Header::Map(size) => Ok(MapDecoder::new(size, self)),
            header => Err(CborSerializationError::expected_data_item(
                DataItemType::Map,
                DataItemType::from_header(header),
            )),
        }
    }

    fn decode_array(self) -> CborSerializationResult<Self::ArrayDecoder> {
        match self.inner.pull()? {
            Header::Array(size) => Ok(ArrayDecoder::new(size, self)),
            header => Err(CborSerializationError::expected_data_item(
                DataItemType::Array,
                DataItemType::from_header(header),
            )),
        }
    }

    fn decode_bytes_exact(self, dest: &mut [u8]) -> CborSerializationResult<()> {
        match self.inner.pull()? {
            Header::Bytes(Some(size)) => {
                if size != dest.len() {
                    return Err(anyhow!("expected {} bytes, was {}", dest.len(), size).into());
                }
            }
            header => {
                return Err(CborSerializationError::expected_data_item(
                    DataItemType::Bytes,
                    DataItemType::from_header(header),
                ))
            }
        };

        self.decode_definite_length_bytes(dest)?;
        Ok(())
    }

    fn decode_bytes(self) -> CborSerializationResult<Vec<u8>> {
        let size = match self.inner.pull()? {
            Header::Bytes(Some(size)) => size,
            header => {
                return Err(CborSerializationError::expected_data_item(
                    DataItemType::Bytes,
                    DataItemType::from_header(header),
                ))
            }
        };

        let mut bytes = vec![0; size];
        self.decode_definite_length_bytes(&mut bytes)?;
        Ok(bytes)
    }

    fn decode_text(self) -> CborSerializationResult<Vec<u8>> {
        let size = match self.inner.pull()? {
            Header::Text(Some(size)) => size,
            header => {
                return Err(CborSerializationError::expected_data_item(
                    DataItemType::Text,
                    DataItemType::from_header(header),
                ))
            }
        };

        let mut bytes = vec![0; size];
        self.decode_definite_length_text(&mut bytes)?;
        Ok(bytes)
    }

    fn decode_simple(self) -> CborSerializationResult<u8> {
        match self.inner.pull()? {
            Header::Simple(value) => Ok(value),
            header => Err(CborSerializationError::expected_data_item(
                DataItemType::Simple,
                DataItemType::from_header(header),
            )),
        }
    }

    fn decode_float(self) -> CborSerializationResult<f64> {
        match self.inner.pull()? {
            Header::Float(value) => Ok(value),
            header => Err(CborSerializationError::expected_data_item(
                DataItemType::Float,
                DataItemType::from_header(header),
            )),
        }
    }

    fn peek_data_item_header(&mut self) -> CborSerializationResult<DataItemHeader> {
        DataItemHeader::try_from_header(self.peek_header()?)
    }

    fn skip_data_item(mut self) -> CborSerializationResult<()> {
        match self.peek_data_item_header()?.to_type() {
            DataItemType::Positive
            | DataItemType::Negative
            | DataItemType::Simple
            | DataItemType::Float => {
                self.inner.pull()?;
            }
            DataItemType::Tag => {
                self.inner.pull()?;
                self.skip_data_item()?;
            }
            DataItemType::Bytes => {
                self.decode_bytes()?;
            }
            DataItemType::Text => {
                self.decode_text()?;
            }
            DataItemType::Array => {
                let array_decoder = self.decode_array()?;
                // Arrays of definite length encodes "size" number of data item elements,
                // arrays of indefinite length encodes data item elements until a break is
                // encountered.
                if let Some(size) = array_decoder.size() {
                    for _ in 0..size {
                        array_decoder.decoder.skip_data_item()?;
                    }
                } else {
                    while !array_decoder.decoder.pull_break()? {
                        array_decoder.decoder.skip_data_item()?;
                    }
                }
            }
            DataItemType::Map => {
                let map_decoder = self.decode_map()?;
                // Maps of definite length encodes "size" number of data item pairs,
                // maps of indefinite length encodes data item pairs until a break is
                // encountered.
                if let Some(size) = map_decoder.size() {
                    for _ in 0..size {
                        map_decoder.decoder.skip_data_item()?;
                        map_decoder.decoder.skip_data_item()?;
                    }
                } else {
                    while !map_decoder.decoder.pull_break()? {
                        map_decoder.decoder.skip_data_item()?;
                        map_decoder.decoder.skip_data_item()?;
                    }
                }
            }
            DataItemType::Break => {
                return Err(anyhow!("break is not a valid data item").into());
            }
        }

        Ok(())
    }

    fn options(&self) -> SerializationOptions { self.options }
}

impl<R: Read> Decoder<R> {
    /// Current byte offset for the decoding
    pub fn offset(&mut self) -> usize { self.inner.offset() }

    /// Decodes bytes data item into given destination. Length of bytes data
    /// item must match the destination length.
    ///
    /// This function works only for bytes data items of definite length (which
    /// means there is a single segment)
    fn decode_definite_length_bytes(&mut self, dest: &mut [u8]) -> CborSerializationResult<()>
    where
        <R as ciborium_io::Read>::Error: Display, {
        let mut segments = self.inner.bytes(Some(dest.len()));
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
    /// This function works only for text data items of definite length (which
    /// means there is a single segment)
    fn decode_definite_length_text(&mut self, dest: &mut [u8]) -> CborSerializationResult<()>
    where
        <R as ciborium_io::Read>::Error: Display, {
        let mut segments = self.inner.text(Some(dest.len()));
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

    fn peek_header(&mut self) -> CborSerializationResult<Header> {
        let header = self.inner.pull()?;
        self.inner.push(header);
        Ok(header)
    }

    fn pull_break(&mut self) -> CborSerializationResult<bool> {
        let header = self.peek_header()?;
        let is_break = header == Header::Break;
        if is_break {
            self.inner.pull()?;
        }
        Ok(is_break)
    }
}

#[derive(Debug)]
enum MapDecoderStateEnum {
    ExpectKey,
    ExpectValue,
}

/// Decoder of CBOR map
#[must_use]
pub struct MapDecoder<'a, R: Read> {
    declared_size:   Option<usize>,
    decoded_entries: usize,
    decoder:         &'a mut Decoder<R>,
    state:           MapDecoderStateEnum,
}

impl<'a, R: Read> MapDecoder<'a, R> {
    fn new(size: Option<usize>, decoder: &'a mut Decoder<R>) -> Self {
        Self {
            declared_size: size,
            decoded_entries: 0,
            decoder,
            state: MapDecoderStateEnum::ExpectKey,
        }
    }
}

impl<R: Read> CborMapDecoder for MapDecoder<'_, R>
where
    <R as ciborium_io::Read>::Error: Display,
{
    fn size(&self) -> Option<usize> { self.declared_size }

    fn deserialize_key<K: CborDeserialize>(&mut self) -> CborSerializationResult<Option<K>> {
        self.state = match self.state {
            MapDecoderStateEnum::ExpectKey => MapDecoderStateEnum::ExpectValue,
            MapDecoderStateEnum::ExpectValue => {
                return Err(anyhow!(
                    "map decoder expected to decode entry value since entry key was decoded last"
                )
                .into());
            }
        };

        // Maps of definite length encodes "size" number of data item pairs.
        // Maps of indefinite length encodes data item pairs until a break is
        // encountered. See https://www.rfc-editor.org/rfc/rfc8949.html#name-indefinite-lengths-for-some
        if let Some(declared_size) = self.declared_size {
            if self.decoded_entries == declared_size {
                return Ok(None);
            }
        } else if self.decoder.pull_break()? {
            return Ok(None);
        }

        self.decoded_entries += 1;

        Ok(Some(K::deserialize(&mut *self.decoder)?))
    }

    fn deserialize_value<V: CborDeserialize>(&mut self) -> CborSerializationResult<V> {
        self.state = match self.state {
            MapDecoderStateEnum::ExpectKey => {
                return Err(anyhow!(
                    "map decoder expected to decode entry key since entry value was decoded last"
                )
                .into());
            }
            MapDecoderStateEnum::ExpectValue => MapDecoderStateEnum::ExpectKey,
        };

        V::deserialize(&mut *self.decoder)
    }

    fn skip_value(&mut self) -> CborSerializationResult<()> {
        self.state = match self.state {
            MapDecoderStateEnum::ExpectKey => {
                return Err(anyhow!(
                    "map decoder expected to decode entry key since entry value was decoded last"
                )
                .into());
            }
            MapDecoderStateEnum::ExpectValue => MapDecoderStateEnum::ExpectKey,
        };

        self.decoder.skip_data_item()
    }
}

/// Decoder of CBOR array
#[must_use]
pub struct ArrayDecoder<'a, R: Read> {
    declared_size:    Option<usize>,
    decoded_elements: usize,
    decoder:          &'a mut Decoder<R>,
}

impl<'a, R: Read> ArrayDecoder<'a, R> {
    fn new(size: Option<usize>, decoder: &'a mut Decoder<R>) -> Self {
        Self {
            declared_size: size,
            decoded_elements: 0,
            decoder,
        }
    }
}

impl<R: Read> CborArrayDecoder for ArrayDecoder<'_, R>
where
    <R as ciborium_io::Read>::Error: Display,
{
    fn size(&self) -> Option<usize> { self.declared_size }

    fn deserialize_element<T: CborDeserialize>(&mut self) -> CborSerializationResult<Option<T>> {
        // Arrays of definite length encodes "size" number of data item elements.
        // Arrays of indefinite length encodes data item elements until a break is
        // encountered. See https://www.rfc-editor.org/rfc/rfc8949.html#name-indefinite-lengths-for-some
        if let Some(declared_size) = self.declared_size {
            if self.decoded_elements == declared_size {
                return Ok(None);
            }
        } else if self.decoder.pull_break()? {
            return Ok(None);
        }

        self.decoded_elements += 1;

        Ok(Some(T::deserialize(&mut *self.decoder)?))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::common::cbor::{
        CborArrayEncoder, CborDecoder, CborEncoder, CborMapEncoder, Encoder,
    };
    use ciborium_ll::simple;

    #[test]
    fn test_array_definite_length() {
        let bytes = hex::decode("820102").unwrap();
        let mut decoder = Decoder::new(bytes.as_slice(), SerializationOptions::default());
        let mut array_decoder = decoder.decode_array().unwrap();
        assert_eq!(array_decoder.size(), Some(2));
        let elm1: u32 = array_decoder.deserialize_element().unwrap().unwrap();
        assert_eq!(elm1, 1);
        let elm2: u32 = array_decoder.deserialize_element().unwrap().unwrap();
        assert_eq!(elm2, 2);
        let elm3: Option<u32> = array_decoder.deserialize_element().unwrap();
        assert_eq!(elm3, None);
        assert_eq!(array_decoder.size(), Some(2));
        assert_eq!(decoder.inner.offset(), bytes.len());
    }

    #[test]
    fn test_array_indefinite_length() {
        let bytes = hex::decode("9f0102ff").unwrap();
        let mut decoder = Decoder::new(bytes.as_slice(), SerializationOptions::default());
        let mut array_decoder = decoder.decode_array().unwrap();
        assert_eq!(array_decoder.size(), None);
        let elm1: u32 = array_decoder.deserialize_element().unwrap().unwrap();
        assert_eq!(elm1, 1);
        let elm2: u32 = array_decoder.deserialize_element().unwrap().unwrap();
        assert_eq!(elm2, 2);
        let elm3: Option<u32> = array_decoder.deserialize_element().unwrap();
        assert_eq!(elm3, None);
        assert_eq!(decoder.inner.offset(), bytes.len());
    }

    #[test]
    fn test_map_definite_length() {
        let bytes = hex::decode("a201020304").unwrap();
        let mut decoder = Decoder::new(bytes.as_slice(), SerializationOptions::default());
        let mut map_decoder = decoder.decode_map().unwrap();
        assert_eq!(map_decoder.size(), Some(2));
        let entry1: (u32, u32) = map_decoder.deserialize_entry().unwrap().unwrap();
        assert_eq!(entry1, (1, 2));
        let entry2: (u32, u32) = map_decoder.deserialize_entry().unwrap().unwrap();
        assert_eq!(entry2, (3, 4));
        let entry3: Option<(u32, u32)> = map_decoder.deserialize_entry().unwrap();
        assert_eq!(entry3, None);
        assert_eq!(map_decoder.size(), Some(2));
        assert_eq!(decoder.inner.offset(), bytes.len());
    }

    #[test]
    fn test_map_indefinite_length() {
        let bytes = hex::decode("bf01020304ff").unwrap();
        let mut decoder = Decoder::new(bytes.as_slice(), SerializationOptions::default());
        let mut map_decoder = decoder.decode_map().unwrap();
        assert_eq!(map_decoder.size(), None);
        let entry1: (u32, u32) = map_decoder.deserialize_entry().unwrap().unwrap();
        assert_eq!(entry1, (1, 2));
        let entry2: (u32, u32) = map_decoder.deserialize_entry().unwrap().unwrap();
        assert_eq!(entry2, (3, 4));
        let entry3: Option<(u32, u32)> = map_decoder.deserialize_entry().unwrap();
        assert_eq!(entry3, None);
        assert_eq!(map_decoder.size(), None);
        assert_eq!(decoder.inner.offset(), bytes.len());
    }

    /// Test skipping data items during decode
    #[test]
    fn test_skip_data_item() {
        // simple
        test_skip_data_item_impl(|encoder| encoder.encode_simple(simple::TRUE).unwrap());
        // positive int
        test_skip_data_item_impl(|encoder| encoder.encode_positive(2).unwrap());
        // negative int
        test_skip_data_item_impl(|encoder| encoder.encode_negative(2).unwrap());
        // tagged data item
        test_skip_data_item_impl(|mut encoder| {
            encoder.encode_tag(2).unwrap();
            encoder.encode_positive(2).unwrap();
        });
        // bytes
        test_skip_data_item_impl(|encoder| encoder.encode_bytes(&[0x01; 30]).unwrap());
        // text
        test_skip_data_item_impl(|encoder| encoder.encode_text(&"a".repeat(30)).unwrap());
        // definite length array
        test_skip_data_item_impl(|encoder| {
            let mut array_encoder = encoder.encode_array(2).unwrap();
            array_encoder.serialize_element(&2).unwrap();
            array_encoder.serialize_element(&2).unwrap();
            array_encoder.end().unwrap();
        });
        // indefinite length array
        test_skip_data_item_impl_ciborium_encoder(|encoder| {
            encoder.push(Header::Array(None)).unwrap();
            encoder.push(Header::Positive(2)).unwrap();
            encoder.push(Header::Positive(2)).unwrap();
            encoder.push(Header::Break).unwrap();
        });
        // definite length map
        test_skip_data_item_impl(|encoder| {
            let mut map_encoder = encoder.encode_map(2).unwrap();
            map_encoder.serialize_entry(&2, &2).unwrap();
            map_encoder.serialize_entry(&2, &2).unwrap();
            map_encoder.end().unwrap();
        });
        // indefinite length map
        test_skip_data_item_impl_ciborium_encoder(|encoder| {
            encoder.push(Header::Map(None)).unwrap();
            encoder.push(Header::Positive(2)).unwrap();
            encoder.push(Header::Positive(2)).unwrap();
            encoder.push(Header::Positive(2)).unwrap();
            encoder.push(Header::Positive(2)).unwrap();
            encoder.push(Header::Break).unwrap();
        });
    }

    fn test_skip_data_item_impl(encode_data_item: impl FnOnce(&mut Encoder<&mut Vec<u8>>)) {
        let mut bytes = Vec::new();
        let mut encoder = Encoder::new(&mut bytes);
        encode_data_item(&mut encoder);
        encoder.encode_positive(12345).unwrap();
        let mut decoder = Decoder::new(bytes.as_slice(), SerializationOptions::default());
        decoder.skip_data_item().unwrap();
        assert_eq!(12345, decoder.decode_positive().unwrap());
        assert_eq!(decoder.inner.offset(), bytes.len());
    }

    fn test_skip_data_item_impl_ciborium_encoder(
        encode_data_item: impl FnOnce(&mut ciborium_ll::Encoder<&mut Vec<u8>>),
    ) {
        let mut bytes = Vec::new();
        let mut encoder = ciborium_ll::Encoder::from(&mut bytes);
        encode_data_item(&mut encoder);
        encoder.push(Header::Positive(12345)).unwrap();
        let mut decoder = Decoder::new(bytes.as_slice(), SerializationOptions::default());
        decoder.skip_data_item().unwrap();
        assert_eq!(12345, decoder.decode_positive().unwrap());
        assert_eq!(decoder.offset(), bytes.len());
    }
}
