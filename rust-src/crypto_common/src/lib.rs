use core::cmp;

use std::convert::TryFrom;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use failure::Fallible;

static MAX_PREALLOCATED_CAPACITY: usize = 4096;

/// As Vec::with_capacity, but only allocate maximum MAX_PREALLOCATED_CAPACITY
/// elements.
#[inline]
pub fn safe_with_capacity<T>(capacity: usize) -> Vec<T> {
    Vec::with_capacity(cmp::min(capacity, MAX_PREALLOCATED_CAPACITY))
}

pub trait Get<Result: Sized> {
    fn get(&mut self) -> Fallible<Result>;
}

impl<R: ReadBytesExt> Get<u64> for R {
    fn get(&mut self) -> Fallible<u64> { Ok(self.read_u64::<BigEndian>()?) }
}

impl<R: ReadBytesExt> Get<u32> for R {
    fn get(&mut self) -> Fallible<u32> { Ok(self.read_u32::<BigEndian>()?) }
}

impl<R: ReadBytesExt> Get<u16> for R {
    fn get(&mut self) -> Fallible<u16> { Ok(self.read_u16::<BigEndian>()?) }
}

impl<R: ReadBytesExt> Get<u8> for R {
    fn get(&mut self) -> Fallible<u8> { Ok(self.read_u8()?) }
}

impl<R: ReadBytesExt> Get<i64> for R {
    fn get(&mut self) -> Fallible<i64> { Ok(self.read_i64::<BigEndian>()?) }
}

impl<R: ReadBytesExt> Get<i32> for R {
    fn get(&mut self) -> Fallible<i32> { Ok(self.read_i32::<BigEndian>()?) }
}

impl<R: ReadBytesExt> Get<i16> for R {
    fn get(&mut self) -> Fallible<i16> { Ok(self.read_i16::<BigEndian>()?) }
}

impl<R: ReadBytesExt> Get<i8> for R {
    fn get(&mut self) -> Fallible<i8> { Ok(self.read_i8()?) }
}

/// Read a vector where the first 8 bytes are taken as length in big endian.
impl<T, S: Get<T> + Get<u64>> Get<Vec<T>> for S {
    fn get(&mut self) -> Fallible<Vec<T>> {
        let len: u64 = self.get()?;
        get_vector_no_length(self, usize::try_from(len)?)
    }
}

pub fn get_string<R: ReadBytesExt>(reader: &mut R, l: usize) -> Fallible<String> {
    let mut svec = vec![0; l];
    reader.read_exact(&mut svec)?;
    Ok(String::from_utf8(svec)?)
}

pub fn get_vector_no_length<T, G: Get<T>>(reader: &mut G, len: usize) -> Fallible<Vec<T>> {
    let mut vec = safe_with_capacity(len);
    for _ in 0..len {
        vec.push(reader.get()?);
    }
    Ok(vec)
}

pub fn get_bytes<R: ReadBytesExt>(reader: &mut R, l: usize) -> Fallible<Vec<u8>> {
    let mut svec = vec![0; l];
    reader.read_exact(&mut svec)?;
    Ok(svec)
}

/// Trait for writers which will not fail in normal operation with
/// small amounts of data, e.g., Vec<u8>.
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

pub trait Put<Arg>: Buffer {
    fn put(&mut self, v: &Arg);
}

impl<B: Buffer> Put<u64> for B {
    fn put(&mut self, v: &u64) {
        self.write_u64::<BigEndian>(*v)
            .expect("Writing to a buffer should not fail.")
    }
}

impl<B: Buffer> Put<u32> for B {
    fn put(&mut self, v: &u32) {
        self.write_u32::<BigEndian>(*v)
            .expect("Writing to a buffer should not fail.")
    }
}

impl<B: Buffer> Put<u16> for B {
    fn put(&mut self, v: &u16) {
        self.write_u16::<BigEndian>(*v)
            .expect("Writing to a buffer should not fail.")
    }
}

impl<B: Buffer> Put<u8> for B {
    fn put(&mut self, v: &u8) {
        self.write_u8(*v)
            .expect("Writing to a buffer should not fail.")
    }
}

impl<B: Buffer> Put<i64> for B {
    fn put(&mut self, v: &i64) {
        self.write_i64::<BigEndian>(*v)
            .expect("Writing to a buffer should not fail.")
    }
}

impl<B: Buffer> Put<i32> for B {
    fn put(&mut self, v: &i32) {
        self.write_i32::<BigEndian>(*v)
            .expect("Writing to a buffer should not fail.")
    }
}

impl<B: Buffer> Put<i16> for B {
    fn put(&mut self, v: &i16) {
        self.write_i16::<BigEndian>(*v)
            .expect("Writing to a buffer should not fail.")
    }
}

impl<B: Buffer> Put<i8> for B {
    fn put(&mut self, v: &i8) {
        self.write_i8(*v)
            .expect("Writing to a buffer should not fail.")
    }
}

impl<T, S: Put<T> + Put<u64>> Put<Vec<T>> for S {
    fn put(&mut self, vec: &Vec<T>) {
        self.put(&(vec.len() as u64));
        put_vector_no_length::<T, S>(self, vec)
    }
}

/// Write an array without including length information.
pub fn put_vector_no_length<T, B: Put<T>>(buf: &mut B, xs: &[T]) {
    for x in xs.iter() {
        buf.put(x);
    }
}
