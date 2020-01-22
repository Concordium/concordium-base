pub use crate::impls::*;

use core::cmp;

use std::{convert::TryFrom, marker::PhantomData};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use failure::Fallible;
use std::collections::btree_map::BTreeMap;

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

impl<T: Deserial, S: Deserial, U: Deserial> Deserial for (T, S, U) {
    #[inline]
    fn deserial<R: ReadBytesExt>(source: &mut R) -> Fallible<Self> {
        let x = T::deserial(source)?;
        let y = S::deserial(source)?;
        let z = U::deserial(source)?;
        Ok((x, y, z))
    }
}

pub fn deserial_string<R: ReadBytesExt>(reader: &mut R, l: usize) -> Fallible<String> {
    let mut svec = vec![0; l];
    reader.read_exact(&mut svec)?;
    Ok(String::from_utf8(svec)?)
}

pub fn serial_string<R: Buffer>(s: &str, out: &mut R) {
    out.write_all(s.as_bytes())
        .expect("Writing to buffer should succeed.")
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

/// Serialize all of the elements in the iterator.
pub fn serial_iter<'a, B: Buffer, T: Serial + 'a, I: Iterator<Item = &'a T>>(xs: I, out: &mut B) {
    for x in xs {
        x.serial(out);
    }
}

/// Write an array without including length information.
pub fn serial_vector_no_length<B: Buffer, T: Serial>(xs: &[T], out: &mut B) {
    serial_iter(xs.iter(), out)
}

// Serialize anything that is an iterator over keypairs, which is in practice a
// map.
pub fn serial_map_no_length<'a, B: Buffer, K: Serial + 'a, V: Serial + 'a>(
    map: &BTreeMap<K, V>,
    out: &mut B,
) {
    for (k, v) in map.iter() {
        // iterator over ordered pairs.
        out.put(k);
        out.put(v);
    }
}

/// NB: This ensures there are no duplicates, hence the specialized type.
/// Moreover this will only succeed if keys are listed in order.
pub fn deserial_map_no_length<R: ReadBytesExt, K: Deserial + Ord + Copy, V: Deserial>(
    source: &mut R,
    len: usize,
) -> Fallible<BTreeMap<K, V>> {
    let mut out = BTreeMap::new();
    let mut x = None;
    for _ in 0..len {
        let k = source.get()?;
        let v = source.get()?;
        match x {
            None => {
                out.insert(k, v);
            }
            Some(kk) => {
                if k > kk {
                    out.insert(k, v);
                } else {
                    bail!("Keys not in order.")
                }
            }
        }
        x = Some(k);
    }
    Ok(out)
}

impl<T: Serial, S: Serial> Serial for (T, S) {
    #[inline]
    fn serial<B: Buffer>(&self, out: &mut B) {
        self.0.serial(out);
        self.1.serial(out);
    }
}

impl<T: Serial, S: Serial, U: Serial> Serial for (T, S, U) {
    #[inline]
    fn serial<B: Buffer>(&self, out: &mut B) {
        self.0.serial(out);
        self.1.serial(out);
        self.2.serial(out);
    }
}

impl<T> Serial for PhantomData<T> {
    #[inline]
    fn serial<B: Buffer>(&self, _out: &mut B) {}
}

impl Serial for [u8] {
    #[inline]
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.write_all(&self).expect("Writing to buffer is safe.");
    }
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

/// Directly serialize to a vector of bytes.
#[inline]
pub fn to_bytes<A: Serial>(x: &A) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.put(x);
    buf
}

#[inline]
pub fn from_bytes<A: Deserial, R: ReadBytesExt>(source: &mut R) -> Fallible<A> {
    A::deserial(source)
}

// Some more generic implementations
impl<T: Serial> Serial for [T; 3] {
    fn serial<B: Buffer>(&self, out: &mut B) {
        for x in self.iter() {
            x.serial(out);
        }
    }
}

// Some more generic implementations
impl<T: Deserial> Deserial for [T; 3] {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> Fallible<Self> {
        // This is a bit stupid, but I can't figure out how to avoid a
        // Default constraint otherwise (if I allow it, we can preallocate
        // with let mut out: [T; 3] = Default::default();
        // and then iterate over it
        let x_1 = T::deserial(source)?;
        let x_2 = T::deserial(source)?;
        let x_3 = T::deserial(source)?;
        Ok([x_1, x_2, x_3])
    }
}
