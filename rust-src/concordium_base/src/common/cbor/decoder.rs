use crate::common::cbor::{
    CborArrayDecoder, CborDecoder, CborDeserialize, CborMapDecoder, CborSerializationError,
    CborSerializationResult, DataItemHeader, DataItemType, SerializationOptions,
};
use anyhow::{anyhow, Context};
use ciborium_io::Read;
use ciborium_ll::Header;
use std::fmt::Display;

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
    R::Error: Display,
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
            Header::Map(Some(size)) => Ok(MapDecoder::new(size, self)),
            header => Err(CborSerializationError::expected_data_item(
                DataItemType::Map,
                DataItemType::from_header(header),
            )),
        }
    }

    fn decode_array(self) -> CborSerializationResult<Self::ArrayDecoder> {
        match self.inner.pull()? {
            Header::Array(Some(size)) => Ok(ArrayDecoder::new(size, self)),
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
        let header = self.inner.pull()?;
        let data_item_header = DataItemHeader::try_from_header(header)?;
        self.inner.push(header);
        Ok(data_item_header)
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
                for _ in 0..array_decoder.declared_size {
                    array_decoder.decoder.skip_data_item()?;
                }
            }
            DataItemType::Map => {
                let map_decocer = self.decode_map()?;
                for _ in 0..map_decocer.declared_size {
                    map_decocer.decoder.skip_data_item()?;
                    map_decocer.decoder.skip_data_item()?;
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
    pub fn offset(&mut self) -> usize { self.inner.offset() }

    /// Decodes bytes data item into given destination. Length of bytes data
    /// item must match the destination length.
    ///
    /// This function works only for bytes data items of definite length (which
    /// means there is a single segment)
    fn decode_definite_length_bytes(&mut self, dest: &mut [u8]) -> CborSerializationResult<()>
    where
        R::Error: Display, {
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
        R::Error: Display, {
        let mut segments = self.inner.text(Some(dest.len()));
        let Some(mut segment) = segments.pull()? else {
            return Err(anyhow!("must have at least one segment").into());
        };

        segment.pull(dest)?.context("no data in segment")?;
        if segment.left() != 0 {
            return Err(anyhow!("remaining data in segment").into());
        }
        if segments.pull()?.is_some() {
            return Err(anyhow!("expected to only one segment").into());
        }
        Ok(())
    }
}

#[derive(Debug)]
enum MapDecoderStateEnum {
    ExpectKey,
    ExpectValue,
}

#[must_use]
pub struct MapDecoder<'a, R: Read> {
    declared_size:     usize,
    remaining_entries: usize,
    decoder:           &'a mut Decoder<R>,
    state:             MapDecoderStateEnum,
}

impl<'a, R: Read> MapDecoder<'a, R> {
    fn new(size: usize, decoder: &'a mut Decoder<R>) -> Self {
        Self {
            declared_size: size,
            remaining_entries: size,
            decoder,
            state: MapDecoderStateEnum::ExpectKey,
        }
    }
}

impl<R: Read> CborMapDecoder for MapDecoder<'_, R>
where
    R::Error: Display,
{
    fn size(&self) -> usize { self.declared_size }

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

        if self.remaining_entries == 0 {
            return Ok(None);
        }

        self.remaining_entries -= 1;

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

#[must_use]
pub struct ArrayDecoder<'a, R: Read> {
    declared_size:      usize,
    remaining_elements: usize,
    decoder:            &'a mut Decoder<R>,
}

impl<'a, R: Read> ArrayDecoder<'a, R> {
    fn new(size: usize, decoder: &'a mut Decoder<R>) -> Self {
        Self {
            declared_size: size,
            remaining_elements: size,
            decoder,
        }
    }
}

impl<R: Read> CborArrayDecoder for ArrayDecoder<'_, R>
where
    R::Error: Display,
{
    fn size(&self) -> usize { self.declared_size }

    fn deserialize_element<T: CborDeserialize>(&mut self) -> CborSerializationResult<Option<T>> {
        if self.remaining_elements == 0 {
            return Ok(None);
        }

        self.remaining_elements -= 1;

        Ok(Some(T::deserialize(&mut *self.decoder)?))
    }
}
