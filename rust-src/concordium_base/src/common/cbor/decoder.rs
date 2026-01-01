use crate::common::cbor::{
    CborArrayDecoder, CborDecoder, CborDeserialize, CborMapDecoder, CborSerializationError,
    CborSerializationResult, DataItemHeader, DataItemType, SerializationOptions,
};
use anyhow::anyhow;
use ciborium_io::Read;
use ciborium_ll::Header;
use std::{io::Cursor, iter};

/// CBOR decoder implementation
pub struct Decoder<R: Read> {
    inner: ciborium_ll::Decoder<R>,
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
    <R as Read>::Error: std::error::Error,
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
        let size = match self.inner.pull()? {
            Header::Bytes(size) => size,
            header => {
                return Err(CborSerializationError::expected_data_item(
                    DataItemType::Bytes,
                    DataItemType::from_header(header),
                ))
            }
        };

        let mut cursor = Cursor::new(dest);
        self.decode_bytes_impl(&mut cursor, size)?;
        if (cursor.position() as usize) < cursor.get_ref().len() {
            return Err(anyhow!("fixed length byte string destination too long").into());
        }
        Ok(())
    }

    fn decode_bytes(self) -> CborSerializationResult<Vec<u8>> {
        let size = match self.inner.pull()? {
            Header::Bytes(size) => size,
            header => {
                return Err(CborSerializationError::expected_data_item(
                    DataItemType::Bytes,
                    DataItemType::from_header(header),
                ))
            }
        };

        let bytes = Vec::with_capacity(size.unwrap_or_default());
        let mut cursor = Cursor::new(bytes);
        self.decode_bytes_impl(&mut cursor, size)?;
        Ok(cursor.into_inner())
    }

    fn decode_text(self) -> CborSerializationResult<Vec<u8>> {
        let size = match self.inner.pull()? {
            Header::Text(size) => size,
            header => {
                return Err(CborSerializationError::expected_data_item(
                    DataItemType::Text,
                    DataItemType::from_header(header),
                ))
            }
        };

        let mut bytes = Vec::with_capacity(size.unwrap_or_default());
        self.decode_text_impl(&mut bytes, size)?;
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

    fn options(&self) -> SerializationOptions {
        self.options
    }
}

trait CursorExt {
    /// Advance the position of the cursor by `len`, or as many positions
    /// as possible, and return the slice covering the advanced positions.  
    /// Cursors backed by dynamically sized collections like `Vec`
    /// will append to the collection as needed and will always advance
    /// the requested `len`. Cursors that cannot append will advance as far
    /// as possible only.
    fn advance(&mut self, len: usize) -> &mut [u8];
}

impl CursorExt for Cursor<Vec<u8>> {
    fn advance(&mut self, len: usize) -> &mut [u8] {
        advance_vec(self, len)
    }
}

impl CursorExt for Cursor<&mut Vec<u8>> {
    fn advance(&mut self, len: usize) -> &mut [u8] {
        advance_vec(self, len)
    }
}

fn advance_vec<T: AsRef<Vec<u8>> + AsMut<Vec<u8>>>(
    cursor: &mut Cursor<T>,
    len: usize,
) -> &mut [u8] {
    let old_position = cursor.position() as usize;
    let new_position = old_position + len;
    let old_len = cursor.get_ref().as_ref().len();
    let new_len = old_len.max(new_position);
    cursor
        .get_mut()
        .as_mut()
        .extend(iter::repeat(0u8).take(new_len - old_len));
    cursor.set_position(new_position as u64);
    &mut cursor.get_mut().as_mut()[old_position..new_position]
}

impl CursorExt for Cursor<&mut [u8]> {
    fn advance(&mut self, len: usize) -> &mut [u8] {
        let old_position = self.position() as usize;
        let new_position = self.get_ref().len().min(old_position + len);
        self.set_position(new_position as u64);
        &mut self.get_mut()[old_position..new_position]
    }
}

impl<R: Read> Decoder<R>
where
    <R as Read>::Error: std::error::Error,
{
    /// Current byte offset for the decoding
    pub fn offset(&mut self) -> usize {
        self.inner.offset()
    }

    /// Decodes bytes data item into given destination. Destination will
    /// be extended as needed (or an error returned)
    fn decode_bytes_impl<T>(
        &mut self,
        dest: &mut Cursor<T>,
        size: Option<usize>,
    ) -> CborSerializationResult<()>
    where
        Cursor<T>: CursorExt,
    {
        let mut segments = self.inner.bytes(size);
        while let Some(mut segment) = segments.pull()? {
            let left = segment.left();
            if left == 0 {
                continue;
            }
            let advanced = dest.advance(left);
            if advanced.len() != left {
                return Err(anyhow!("fixed length byte string destination too short").into());
            }
            let read = segment.pull(advanced)?;
            debug_assert_eq!(read.map(|bytes| bytes.len()), Some(left));
        }

        Ok(())
    }

    /// Decodes text data item into given destination.
    fn decode_text_impl(
        &mut self,
        dest: &mut Vec<u8>,
        size: Option<usize>,
    ) -> CborSerializationResult<()> {
        let mut dest = Cursor::new(dest);
        let mut segments = self.inner.text(size);
        while let Some(mut segment) = segments.pull()? {
            let left = segment.left();
            if left == 0 {
                continue;
            }
            let advanced = dest.advance(left);
            debug_assert_eq!(advanced.len(), left);
            segment.pull(advanced)?;
            if segment.left() != 0 {
                return Err(anyhow!("invalid UTF-8 in byte string").into());
            }
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
    declared_size: Option<usize>,
    decoded_entries: usize,
    decoder: &'a mut Decoder<R>,
    state: MapDecoderStateEnum,
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
    <R as Read>::Error: std::error::Error,
{
    fn size(&self) -> Option<usize> {
        self.declared_size
    }

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
    declared_size: Option<usize>,
    decoded_elements: usize,
    decoder: &'a mut Decoder<R>,
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
    <R as Read>::Error: std::error::Error,
{
    fn size(&self) -> Option<usize> {
        self.declared_size
    }

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

    #[test]
    fn test_byte_string_zero_length() {
        let cbor = hex::decode("40").unwrap();
        let mut decoder = Decoder::new(cbor.as_slice(), SerializationOptions::default());
        let bytes_decoded = decoder.decode_bytes().unwrap();
        assert_eq!(bytes_decoded, hex::decode("").unwrap());
    }

    #[test]
    fn test_byte_string_definite_length() {
        let cbor = hex::decode("580401020304").unwrap();
        let mut decoder = Decoder::new(cbor.as_slice(), SerializationOptions::default());
        let bytes_decoded = decoder.decode_bytes().unwrap();
        assert_eq!(bytes_decoded, hex::decode("01020304").unwrap());
    }

    #[test]
    fn test_byte_string_indefinite_length() {
        // byte string with two segments
        let cbor = hex::decode("5F44aabbccdd43eeff99FF").unwrap();
        let mut decoder = Decoder::new(cbor.as_slice(), SerializationOptions::default());
        let bytes_decoded = decoder.decode_bytes().unwrap();
        assert_eq!(bytes_decoded, hex::decode("aabbccddeeff99").unwrap());
    }

    #[test]
    fn test_byte_string_indefinite_length_zero_size_segment() {
        // byte string with an empty segment
        let cbor = hex::decode("5F44aabbccdd4043eeff99FF").unwrap();
        let mut decoder = Decoder::new(cbor.as_slice(), SerializationOptions::default());
        let bytes_decoded = decoder.decode_bytes().unwrap();
        assert_eq!(bytes_decoded, hex::decode("aabbccddeeff99").unwrap());
    }

    #[test]
    fn test_byte_string_indefinite_length_zero_segments() {
        // byte string with zero segments
        let cbor = hex::decode("5FFF").unwrap();
        let mut decoder = Decoder::new(cbor.as_slice(), SerializationOptions::default());
        let bytes_decoded = decoder.decode_bytes().unwrap();
        assert_eq!(bytes_decoded, hex::decode("").unwrap());
    }

    /// Decode using `decode_bytes_exact`
    #[test]
    fn test_byte_string_exact_definite_length() {
        let cbor = hex::decode("580401020304").unwrap();
        let mut decoder = Decoder::new(cbor.as_slice(), SerializationOptions::default());
        let mut bytes = [0u8; 4];
        decoder.decode_bytes_exact(&mut bytes).unwrap();
        assert_eq!(bytes.as_slice(), hex::decode("01020304").unwrap());
    }

    /// Decode using `decode_bytes_exact`
    #[test]
    fn test_byte_string_exact_indefinite_length() {
        // byte string with two segments
        let cbor = hex::decode("5F44aabbccdd43eeff99FF").unwrap();
        let mut decoder = Decoder::new(cbor.as_slice(), SerializationOptions::default());
        let mut bytes = [0u8; 7];
        decoder.decode_bytes_exact(&mut bytes).unwrap();
        assert_eq!(bytes.as_slice(), hex::decode("aabbccddeeff99").unwrap());
    }

    /// Decode to array that is too short for string
    #[test]
    fn test_byte_string_exact_too_short() {
        let cbor = hex::decode("580401020304").unwrap();
        let mut decoder = Decoder::new(cbor.as_slice(), SerializationOptions::default());
        let mut bytes = [0u8; 3];
        let error = decoder.decode_bytes_exact(&mut bytes).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("byte string destination too short"),
            "message: {}",
            error.to_string()
        );
    }

    /// Decode to array that is too long for string
    #[test]
    fn test_byte_string_exact_too_long() {
        let cbor = hex::decode("580401020304").unwrap();
        let mut decoder = Decoder::new(cbor.as_slice(), SerializationOptions::default());
        let mut bytes = [0u8; 5];
        let error = decoder.decode_bytes_exact(&mut bytes).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("byte string destination too long"),
            "message: {}",
            error.to_string()
        );
    }

    #[test]
    fn test_text_string_zero_length() {
        let cbor = hex::decode("60").unwrap();
        let mut decoder = Decoder::new(cbor.as_slice(), SerializationOptions::default());
        let text_decoded = String::from_utf8(decoder.decode_text().unwrap()).unwrap();
        assert_eq!(text_decoded, "");
    }

    #[test]
    fn test_text_string_definite_length() {
        let cbor = hex::decode("780461626364").unwrap();
        let mut decoder = Decoder::new(cbor.as_slice(), SerializationOptions::default());
        let text_decoded = String::from_utf8(decoder.decode_text().unwrap()).unwrap();
        assert_eq!(text_decoded, "abcd");
    }

    #[test]
    fn test_text_string_indefinite_length() {
        // text string with two segments
        let cbor = hex::decode("7F646162636463656667FF").unwrap();
        let mut decoder = Decoder::new(cbor.as_slice(), SerializationOptions::default());
        let text_decoded = String::from_utf8(decoder.decode_text().unwrap()).unwrap();
        assert_eq!(text_decoded, "abcdefg");
    }

    #[test]
    fn test_text_string_indefinite_length_zero_size_segment() {
        // text string with an empty segment
        let cbor = hex::decode("7F64616263646063656667FF").unwrap();
        let mut decoder = Decoder::new(cbor.as_slice(), SerializationOptions::default());
        let text_decoded = String::from_utf8(decoder.decode_text().unwrap()).unwrap();
        assert_eq!(text_decoded, "abcdefg");
    }

    #[test]
    fn test_text_string_indefinite_length_zero_segments() {
        // text string with zero segments
        let cbor = hex::decode("7FFF").unwrap();
        let mut decoder = Decoder::new(cbor.as_slice(), SerializationOptions::default());
        let text_decoded = String::from_utf8(decoder.decode_text().unwrap()).unwrap();
        assert_eq!(text_decoded, "");
    }

    /// Test byte string is longer than CBOR content
    #[test]
    fn test_bytes_length_invalid() {
        let cbor = hex::decode("58ff0102030405").unwrap();
        let mut decoder = Decoder::new(cbor.as_slice(), SerializationOptions::default());
        let error = decoder.decode_bytes().unwrap_err();
        assert!(
            error.to_string().contains("failed to fill whole buffer"),
            "message: {}",
            error.to_string()
        );
    }

    /// Test text string is longer than CBOR content
    #[test]
    fn test_text_length_invalid() {
        let cbor = hex::decode("78ff61626364").unwrap();
        let mut decoder = Decoder::new(cbor.as_slice(), SerializationOptions::default());
        let error = decoder.decode_text().unwrap_err();
        assert!(
            error.to_string().contains("failed to fill whole buffer"),
            "message: {}",
            error.to_string()
        );
    }

    /// Test decode UTF-8 two byte code point c2bd
    #[test]
    fn test_text_two_byte_code_point() {
        let cbor = hex::decode("780461c2bd64").unwrap();
        let mut decoder = Decoder::new(cbor.as_slice(), SerializationOptions::default());
        let text_decoded = String::from_utf8(decoder.decode_text().unwrap()).unwrap();
        assert_eq!(text_decoded, "a\u{bd}d");
    }

    /// Test decode where UTF-8 two byte code point is incomplete
    #[test]
    fn test_text_invalid_code_point() {
        let cbor = hex::decode("780261c2").unwrap();
        let mut decoder = Decoder::new(cbor.as_slice(), SerializationOptions::default());
        let error = decoder.decode_text().unwrap_err();
        assert!(
            error.to_string().contains("invalid UTF-8"),
            "message: {}",
            error.to_string()
        );
    }

    /// Test decode UTF-8 two byte code point c2bd that spans two segments
    #[test]
    fn test_text_string_indefinite_length_two_byte_code_point_slit_across_segments() {
        let cbor = hex::decode("7F6261c262bd67FF").unwrap();
        let mut decoder = Decoder::new(cbor.as_slice(), SerializationOptions::default());
        let error = decoder.decode_text().unwrap_err();
        assert!(
            error.to_string().contains("invalid UTF-8"),
            "message: {}",
            error.to_string()
        );
    }

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
            let mut array_encoder = encoder.encode_array().unwrap();
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
            let mut map_encoder = encoder.encode_map().unwrap();
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

    /// Test `<Cursor<&mut Vec<u8>> as CursorExt>::advance` for empty `Vec`
    #[test]
    fn test_vec_cursor_advance_empty() {
        // Test empty vec
        let mut vec = Vec::new();
        let mut cursor = Cursor::new(&mut vec);

        let slice = cursor.advance(0);
        assert_eq!(slice.len(), 0);
        assert_eq!(cursor.position(), 0);
        assert_eq!(cursor.get_ref().len(), 0);

        let slice = cursor.advance(2);
        assert_eq!(slice.len(), 2);
        slice[0] = 1;
        slice[1] = 2;
        assert_eq!(cursor.position(), 2);
        assert_eq!(cursor.get_ref().len(), 2);

        let slice = cursor.advance(3);
        assert_eq!(slice.len(), 3);
        slice[0] = 3;
        slice[1] = 4;
        assert_eq!(cursor.position(), 5);
        assert_eq!(cursor.get_ref().len(), 5);

        assert_eq!(vec, vec![1, 2, 3, 4, 0]);
    }

    /// Test `<Cursor<&mut Vec<u8>> as CursorExt>::advance` for `Vec` with
    /// existing content
    #[test]
    fn test_vec_cursor_advance_non_empty() {
        // Test empty vec
        let mut vec = vec![11, 12, 13];
        let mut cursor = Cursor::new(&mut vec);

        let slice = cursor.advance(0);
        assert_eq!(slice.len(), 0);
        assert_eq!(cursor.position(), 0);
        assert_eq!(cursor.get_ref().len(), 3);

        let slice = cursor.advance(2);
        assert_eq!(slice.len(), 2);
        slice[0] = 1;
        slice[1] = 2;
        assert_eq!(cursor.position(), 2);
        assert_eq!(cursor.get_ref().len(), 3);

        let slice = cursor.advance(3);
        assert_eq!(slice.len(), 3);
        slice[0] = 3;
        slice[1] = 4;
        assert_eq!(cursor.position(), 5);
        assert_eq!(cursor.get_ref().len(), 5);

        assert_eq!(vec, vec![1, 2, 3, 4, 0]);
    }

    /// Test `<Cursor<&mut [u8]> as CursorExt>::advance`
    #[test]
    fn test_slice_cursor_advance() {
        let mut array = [11, 12, 13, 0];
        let mut cursor = Cursor::new(array.as_mut_slice());

        let slice = cursor.advance(0);
        assert_eq!(slice.len(), 0);
        assert_eq!(cursor.position(), 0);

        let slice = cursor.advance(2);
        assert_eq!(slice.len(), 2);
        slice[0] = 1;
        slice[1] = 2;
        assert_eq!(cursor.position(), 2);

        let slice = cursor.advance(3);
        assert_eq!(slice.len(), 2);
        slice[0] = 3;
        slice[1] = 4;
        assert_eq!(cursor.position(), 4);

        assert_eq!(array, [1, 2, 3, 4]);
    }
}
