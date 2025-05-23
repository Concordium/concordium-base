use ciborium_io::{Read, Write};
use ciborium_ll::{Decoder, Encoder, Header};
use std::fmt::Debug;

pub fn cbor_encode<T: CborEncode>(value: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut encoder = Encoder::from(&mut bytes);
    value.encode(&mut encoder);
    bytes
}

pub fn cbor_decode<T: CborDecode>(cbor: &[u8]) -> Result<T, ciborium_ll::Error<&[u8]>> {
    let mut decoder = Decoder::from(cbor);
    let value = T::decode(&mut decoder)?;
    if decoder.offset() != cbor.len() {
        todo!() // todo ar
    }
    Ok(value)
}

pub trait CborEncode {
    fn encode<W: Write>(&self, encoder: &mut Encoder<W>);
}

pub trait CborDecode {
    fn decode<R: Read + Debug>(decoder: &mut Decoder<R>) -> Result<Self, ciborium_ll::Error<R>>
    where
        R::Error: Debug,
        Self: Sized;
}

pub trait EncoderExt {
    fn push_tag(&mut self, tag: u64);
    fn push_positive(&mut self, positive: u64);
    fn push_map(&mut self, size: usize);
    fn push_array(&mut self, size: usize);
    fn push_bytes(&mut self, bytes: &[u8]);
}

impl<W: Write> EncoderExt for Encoder<W> {
    fn push_tag(&mut self, tag: u64) { self.push(Header::Tag(tag)); }

    fn push_positive(&mut self, positive: u64) { self.push(Header::Positive(positive)); }

    fn push_map(&mut self, size: usize) { self.push(Header::Map(Some(size))); }

    fn push_array(&mut self, size: usize) { self.push(Header::Array(Some(size))); }

    fn push_bytes(&mut self, bytes: &[u8]) { self.bytes(bytes, None); }
}

pub trait DecoderExt {
    fn pull_tag(&mut self) -> u64;
    fn pull_positive(&mut self) -> u64;
    fn pull_map(&mut self) -> usize;
    fn pull_array(&mut self) -> usize;
    fn pull_bytes_exact(&mut self, dest: &mut [u8]);
}

impl<R: Read + Debug> DecoderExt for Decoder<R>
where
    R::Error: Debug,
{
    fn pull_tag(&mut self) -> u64 {
        match self.pull().unwrap() {
            Header::Tag(tag) => tag,
            _ => todo!(),
        }
    }

    fn pull_positive(&mut self) -> u64 {
        match self.pull().unwrap() {
            Header::Positive(positive) => positive,
            _ => todo!(),
        }
    }

    fn pull_map(&mut self) -> usize {
        match self.pull().unwrap() {
            Header::Map(Some(size)) => size,
            _ => todo!(),
        }
    }

    fn pull_array(&mut self) -> usize {
        match self.pull().unwrap() {
            Header::Array(Some(size)) => size,
            _ => todo!(),
        }
    }

    fn pull_bytes_exact(&mut self, dest: &mut [u8]) {
        match self.pull().unwrap() {
            Header::Bytes(Some(size)) => {
                if size != dest.len() {
                    todo!()
                }
            }
            _ => todo!(),
        };
        let mut segments = self.bytes(Some(dest.len()));
        let Some(mut segment) = segments.pull().unwrap() else {
            todo!()
        };

        segment.pull(dest);
        if segment.left() != 0 {
            todo!()
        }
        if segments.pull().unwrap().is_some() {
            todo!()
        }
    }
}
