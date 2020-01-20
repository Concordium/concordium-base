pub use crate::impls::*;

use core::cmp;

use std::{convert::TryFrom, marker::PhantomData};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use failure::Fallible;

static MAX_PREALLOCATED_CAPACITY: usize = 4096;

/// As Vec::with_capacity, but only allocate maximum MAX_PREALLOCATED_CAPACITY
/// elements.
#[inline]
pub fn safe_with_capacity<T>(capacity: usize) -> Vec<T> {
    Vec::with_capacity(cmp::min(capacity, MAX_PREALLOCATED_CAPACITY))
}

pub trait Deserial: Sized {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> Fallible<Self>;
}

impl Deserial for u64 {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> Fallible<u64> {
        Ok(source.read_u64::<BigEndian>()?)
    }
}

impl Deserial for u32 {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> Fallible<u32> {
        Ok(source.read_u32::<BigEndian>()?)
    }
}

impl Deserial for u16 {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> Fallible<u16> {
        Ok(source.read_u16::<BigEndian>()?)
    }
}

impl Deserial for u8 {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> Fallible<u8> { Ok(source.read_u8()?) }
}

impl Deserial for i64 {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> Fallible<i64> {
        Ok(source.read_i64::<BigEndian>()?)
    }
}

impl Deserial for i32 {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> Fallible<i32> {
        Ok(source.read_i32::<BigEndian>()?)
    }
}

impl Deserial for i16 {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> Fallible<i16> {
        Ok(source.read_i16::<BigEndian>()?)
    }
}

impl Deserial for i8 {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> Fallible<i8> { Ok(source.read_i8()?) }
}

/// Read a vector where the first 8 bytes are taken as length in big endian.
impl<T: Deserial> Deserial for Vec<T> {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> Fallible<Self> {
        let len: u64 = u64::deserial(source)?;
        deserial_vector_no_length(source, usize::try_from(len)?)
    }
}

impl<T: Deserial, U: Deserial> Deserial for (T, U) {
    #[inline]
    fn deserial<R: ReadBytesExt>(source: &mut R) -> Fallible<Self> {
        let x = T::deserial(source)?;
        let y = U::deserial(source)?;
        Ok((x, y))
    }
}

pub fn deserial_string<R: ReadBytesExt>(reader: &mut R, l: usize) -> Fallible<String> {
    let mut svec = vec![0; l];
    reader.read_exact(&mut svec)?;
    Ok(String::from_utf8(svec)?)
}

pub fn deserial_vector_no_length<R: ReadBytesExt, T: Deserial>(
    reader: &mut R,
    len: usize,
) -> Fallible<Vec<T>> {
    let mut vec = safe_with_capacity(len);
    for _ in 0..len {
        vec.push(T::deserial(reader)?);
    }
    Ok(vec)
}

pub fn deserial_bytes<R: ReadBytesExt>(reader: &mut R, l: usize) -> Fallible<Vec<u8>> {
    let mut svec = vec![0; l];
    reader.read_exact(&mut svec)?;
    Ok(svec)
}

impl<T> Deserial for PhantomData<T> {
    #[inline]
    fn deserial<R: ReadBytesExt>(_source: &mut R) -> Fallible<Self> { Ok(Default::default()) }
}

/// Trait for writers which will not fail in normal operation with
/// small amounts of data, e.g., Vec<u8>.
/// Moreover having a special trait allows us to implement it for
/// other types, such as the SHA Digest.
pub trait Buffer: Sized + WriteBytesExt {
    type Result;
    fn start() -> Self;
    fn start_hint(_l: usize) -> Self { Self::start() }
    fn result(self) -> Self::Result;
}

impl Buffer for Vec<u8> {
    type Result = Vec<u8>;

    fn start() -> Vec<u8> { Vec::new() }

    fn start_hint(l: usize) -> Vec<u8> { Vec::with_capacity(l) }

    fn result(self) -> Self::Result { self }
}

pub trait Serial {
    fn serial<B: Buffer>(&self, _out: &mut B);
}

impl Serial for u64 {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.write_u64::<BigEndian>(*self)
            .expect("Writing to a buffer should not fail.")
    }
}

impl Serial for u32 {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.write_u32::<BigEndian>(*self)
            .expect("Writing to a buffer should not fail.")
    }
}

impl Serial for u16 {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.write_u16::<BigEndian>(*self)
            .expect("Writing to a buffer should not fail.")
    }
}

impl Serial for u8 {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.write_u8(*self)
            .expect("Writing to a buffer should not fail.")
    }
}

impl Serial for i64 {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.write_i64::<BigEndian>(*self)
            .expect("Writing to a buffer should not fail.")
    }
}

impl Serial for i32 {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.write_i32::<BigEndian>(*self)
            .expect("Writing to a buffer should not fail.")
    }
}

impl Serial for i16 {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.write_i16::<BigEndian>(*self)
            .expect("Writing to a buffer should not fail.")
    }
}

impl Serial for i8 {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.write_i8(*self)
            .expect("Writing to a buffer should not fail.")
    }
}

impl<T: Serial> Serial for Vec<T> {
    fn serial<B: Buffer>(&self, out: &mut B) {
        (self.len() as u64).serial(out);
        serial_vector_no_length(self, out)
    }
}

/// Write an array without including length information.
pub fn serial_vector_no_length<B: Buffer, T: Serial>(xs: &[T], out: &mut B) {
    for x in xs.iter() {
        x.serial(out);
    }
}

impl<T: Serial, S: Serial> Serial for (T, S) {
    #[inline]
    fn serial<B: Buffer>(&self, out: &mut B) {
        self.0.serial(out);
        self.1.serial(out);
    }
}

impl<T> Serial for PhantomData<T> {
    #[inline]
    fn serial<B: Buffer>(&self, _out: &mut B) {}
}

/// Conventient wrappers.
pub trait Get<A> {
    fn get(&mut self) -> Fallible<A>;
}

impl<R: ReadBytesExt, A: Deserial> Get<A> for R {
    #[inline]
    fn get(&mut self) -> Fallible<A> { A::deserial(self) }
}

/// Conventient wrappers.
pub trait Put<A> {
    fn put(&mut self, _v: &A);
}

impl<R: Buffer, A: Serial> Put<A> for R {
    #[inline]
    fn put(&mut self, v: &A) { v.serial(self) }
}

/// A convenient way to refer to both put and get together.
pub trait Serialize: Serial + Deserial {}

/// Generic instance deriving Deserialize for any type that implements
/// both put and get.
impl<A: Deserial + Serial> Serialize for A {}
