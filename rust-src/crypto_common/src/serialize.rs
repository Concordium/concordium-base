pub use crate::impls::*;
use anyhow::{bail, Context};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use concordium_contracts_common::ExchangeRate;
use core::cmp;
use sha2::Digest;
use std::{
    collections::btree_map::BTreeMap,
    convert::{TryFrom, TryInto},
    marker::PhantomData,
};

static MAX_PREALLOCATED_CAPACITY: usize = 4096;

/// Result when deserializing a value. This is a simple wrapper around `Result`
/// that fixes the error type to be [anyhow::Error].
pub type ParseResult<T> = anyhow::Result<T>;

/// As Vec::with_capacity, but only allocate maximum MAX_PREALLOCATED_CAPACITY
/// elements.
#[inline]
pub fn safe_with_capacity<T>(capacity: usize) -> Vec<T> {
    // TODO: This should probably use the size of the type T as well.
    // As long as sizeof(T) is not excessive it does not matter very much, but it
    // would be cleaner.
    Vec::with_capacity(cmp::min(capacity, MAX_PREALLOCATED_CAPACITY))
}

/// Trait for types which can be recovered from byte sources.
pub trait Deserial: Sized {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self>;
}

impl Deserial for u128 {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<u128> {
        Ok(source.read_u128::<BigEndian>()?)
    }
}

impl Deserial for u64 {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<u64> {
        Ok(source.read_u64::<BigEndian>()?)
    }
}

impl Deserial for u32 {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<u32> {
        Ok(source.read_u32::<BigEndian>()?)
    }
}

impl Deserial for u16 {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<u16> {
        Ok(source.read_u16::<BigEndian>()?)
    }
}

impl Deserial for bool {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let x: u8 = source.read_u8()?;
        match x {
            0 => Ok(false),
            1 => Ok(true),
            _ => anyhow::bail!("Unrecognized boolean value {}", x),
        }
    }
}

impl Deserial for u8 {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<u8> { Ok(source.read_u8()?) }
}

impl Deserial for i128 {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<i128> {
        Ok(source.read_i128::<BigEndian>()?)
    }
}

impl Deserial for i64 {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<i64> {
        Ok(source.read_i64::<BigEndian>()?)
    }
}

impl Deserial for i32 {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<i32> {
        Ok(source.read_i32::<BigEndian>()?)
    }
}

impl Deserial for i16 {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<i16> {
        Ok(source.read_i16::<BigEndian>()?)
    }
}

impl Deserial for i8 {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<i8> { Ok(source.read_i8()?) }
}

impl Deserial for std::num::NonZeroU8 {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let value = source.get()?;
        Self::new(value).context("Zero is not valid.")
    }
}

impl Deserial for std::num::NonZeroU16 {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let value = source.get()?;
        Self::new(value).context("Zero is not valid.")
    }
}
impl Deserial for std::num::NonZeroU32 {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let value = source.get()?;
        Self::new(value).context("Zero is not valid.")
    }
}

impl Deserial for std::num::NonZeroU64 {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let value = source.get()?;
        Self::new(value).context("Zero is not valid.")
    }
}

impl Deserial for std::num::NonZeroU128 {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let value = source.get()?;
        Self::new(value).context("Zero is not valid.")
    }
}

impl Deserial for std::num::NonZeroI8 {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let value = source.get()?;
        Self::new(value).context("Zero is not valid.")
    }
}

impl Deserial for std::num::NonZeroI16 {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let value = source.get()?;
        Self::new(value).context("Zero is not valid.")
    }
}
impl Deserial for std::num::NonZeroI32 {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let value = source.get()?;
        Self::new(value).context("Zero is not valid.")
    }
}

impl Deserial for std::num::NonZeroI64 {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let value = source.get()?;
        Self::new(value).context("Zero is not valid.")
    }
}

impl Deserial for std::num::NonZeroI128 {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let value = source.get()?;
        Self::new(value).context("Zero is not valid.")
    }
}

/// Read a vector where the first 8 bytes are taken as length in big endian.
impl<T: Deserial> Deserial for Vec<T> {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let len: u64 = u64::deserial(source)?;
        deserial_vector_no_length(source, usize::try_from(len)?)
    }
}

impl<T: Deserial, U: Deserial> Deserial for (T, U) {
    #[inline]
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let x = T::deserial(source)?;
        let y = U::deserial(source)?;
        Ok((x, y))
    }
}

impl<T: Deserial, S: Deserial, U: Deserial> Deserial for (T, S, U) {
    #[inline]
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let x = T::deserial(source)?;
        let y = S::deserial(source)?;
        let z = U::deserial(source)?;
        Ok((x, y, z))
    }
}

/// Read a string of given size.
/// NB: Be aware that this allocates a buffer of the given length, and so this
/// must only be used when the size is bounded, otherwise it will lead to a
/// memory allocation failure, and panic.
pub fn deserial_string<R: ReadBytesExt>(reader: &mut R, l: usize) -> ParseResult<String> {
    let mut svec = vec![0; l];
    reader.read_exact(&mut svec)?;
    Ok(String::from_utf8(svec)?)
}

/// Write a string directly to the provided sink (without encoding its length).
/// The string is utf8 encoded.
pub fn serial_string<R: Buffer>(s: &str, out: &mut R) {
    out.write_all(s.as_bytes())
        .expect("Writing to buffer should succeed.")
}

/// Read a vector of a given size. This protects against excessive memory
/// allocation by only pre-allocating a maximum safe size.
pub fn deserial_vector_no_length<R: ReadBytesExt, T: Deserial>(
    reader: &mut R,
    len: usize,
) -> ParseResult<Vec<T>> {
    let mut vec = safe_with_capacity(len);
    for _ in 0..len {
        vec.push(T::deserial(reader)?);
    }
    Ok(vec)
}

/// Read a vector of the given size.
/// NB: Be aware that this allocates a buffer of the given length, and so this
/// must only be used when the size is bounded, otherwise it will lead to a
/// memory allocation failure, and panic.
pub fn deserial_bytes<R: ReadBytesExt>(reader: &mut R, l: usize) -> ParseResult<Vec<u8>> {
    let mut svec = vec![0; l];
    reader.read_exact(&mut svec)?;
    Ok(svec)
}

impl<T> Deserial for PhantomData<T> {
    #[inline]
    fn deserial<R: ReadBytesExt>(_source: &mut R) -> ParseResult<Self> { Ok(Default::default()) }
}

impl<T: Deserial> Deserial for Box<T> {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let x = T::deserial(source)?;
        Ok(Box::new(x))
    }
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

impl Buffer for sha2::Sha256 {
    type Result = [u8; 32];

    fn start() -> Self { sha2::Sha256::new() }

    fn result(self) -> Self::Result { self.finalize().into() }
}

/// Trait implemented by types which can be encoded into byte arrays.
/// The intention is that the encoding is binary and not human readable.
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

impl Serial for bool {
    fn serial<B: Buffer>(&self, out: &mut B) {
        (if *self {
            out.write_u8(1)
        } else {
            out.write_u8(0)
        })
        .expect("Writing to a buffer should not fail.");
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

impl Serial for std::num::NonZeroU8 {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.write_u8(self.get())
            .expect("Writing to a buffer should not fail.")
    }
}

impl Serial for std::num::NonZeroU16 {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.write_u16::<BigEndian>(self.get())
            .expect("Writing to a buffer should not fail.")
    }
}

impl Serial for std::num::NonZeroU32 {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.write_u32::<BigEndian>(self.get())
            .expect("Writing to a buffer should not fail.")
    }
}

impl Serial for std::num::NonZeroU64 {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.write_u64::<BigEndian>(self.get())
            .expect("Writing to a buffer should not fail.")
    }
}

impl Serial for std::num::NonZeroU128 {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.write_u128::<BigEndian>(self.get())
            .expect("Writing to a buffer should not fail.")
    }
}

impl Serial for std::num::NonZeroI8 {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.write_i8(self.get())
            .expect("Writing to a buffer should not fail.")
    }
}

impl Serial for std::num::NonZeroI16 {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.write_i16::<BigEndian>(self.get())
            .expect("Writing to a buffer should not fail.")
    }
}

impl Serial for std::num::NonZeroI32 {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.write_i32::<BigEndian>(self.get())
            .expect("Writing to a buffer should not fail.")
    }
}

impl Serial for std::num::NonZeroI64 {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.write_i64::<BigEndian>(self.get())
            .expect("Writing to a buffer should not fail.")
    }
}

impl Serial for std::num::NonZeroI128 {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.write_i128::<BigEndian>(self.get())
            .expect("Writing to a buffer should not fail.")
    }
}

/// Serialize a vector by encoding its length as a u64 in big endian and then
/// the list of elements in sequence.
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

/// Serialize an ordered map. Serialization is by increasing order of keys.
pub fn serial_map_no_length<B: Buffer, K: Serial, V: Serial>(map: &BTreeMap<K, V>, out: &mut B) {
    for (k, v) in map.iter() {
        // iterator over ordered pairs.
        out.put(k);
        out.put(v);
    }
}

/// Deserialize a map from a byte source. This ensures there are no duplicates,
/// as well as that all keys are in strictly increasing order.
pub fn deserial_map_no_length<R: ReadBytesExt, K: Deserial + Ord + Copy, V: Deserial>(
    source: &mut R,
    len: usize,
) -> ParseResult<BTreeMap<K, V>> {
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

/// Analogous to [serial_map_no_length], but for sets.
pub fn serial_set_no_length<B: Buffer, K: Serial>(map: &BTreeSet<K>, out: &mut B) {
    for k in map.iter() {
        out.put(k);
    }
}

/// Analogous to [deserial_map_no_length], but for sets.
/// NB: This ensures there are no duplicates, and that all the keys are in
/// strictly increasing order.
pub fn deserial_set_no_length<R: ReadBytesExt, K: Deserial + Ord + Copy>(
    source: &mut R,
    len: usize,
) -> ParseResult<BTreeSet<K>> {
    let mut out = BTreeSet::new();
    let mut x = None;
    for _ in 0..len {
        let k = source.get()?;
        match x {
            None => {
                out.insert(k);
            }
            Some(kk) => {
                if k > kk {
                    out.insert(k);
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

impl<T: Serial> Serial for Box<T> {
    #[inline]
    fn serial<B: Buffer>(&self, out: &mut B) { self.as_ref().serial(out) }
}

impl Serial for [u8] {
    #[inline]
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.write_all(self).expect("Writing to buffer is safe.");
    }
}

/// Analogue of [Deserial], but instead this has the type to serialize as a type
/// parameter, and is implemented once for a source. The reason for this trait
/// is that it is often more convenient to use since we can rely on the
/// typechecker to fill in more details. Contrast `A::deserial(source)` to
/// `source.get()`. In the latter case the return type is usually clear from
/// context.
pub trait Get<A> {
    fn get(&mut self) -> ParseResult<A>;
}

impl<R: ReadBytesExt, A: Deserial> Get<A> for R {
    #[inline]
    fn get(&mut self) -> ParseResult<A> { A::deserial(self) }
}

/// Dual to `Get`, and the analogue of `Serial`. It allows writing
/// `sink.put(value)` in contrast to `value.serial(sink)`. It is less important
/// than `Get`.
pub trait Put<A> {
    fn put(&mut self, _v: &A);
}

impl<R: Buffer, A: Serial> Put<A> for R {
    #[inline]
    fn put(&mut self, v: &A) { v.serial(self) }
}

/// A convenient way to refer to both [Serial] and [Deserial] together.
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
/// A small wrapper that is sometimes more convenient than `A::deserial`.
/// It is here mostly for historical reasons, for backwards compatibility.
pub fn from_bytes<A: Deserial, R: ReadBytesExt>(source: &mut R) -> ParseResult<A> {
    A::deserial(source)
}

// Some more generic implementations

impl<T: Serial, const N: usize> Serial for [T; N] {
    fn serial<B: Buffer>(&self, out: &mut B) {
        for x in self.iter() {
            x.serial(out);
        }
    }
}

impl<T: Deserial, const N: usize> Deserial for [T; N] {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let mut out_vec = Vec::with_capacity(N);
        for _ in 0..N {
            out_vec.push(T::deserial(source)?);
        }
        let out_array: [T; N] = out_vec.try_into().map_err(|_| ()).unwrap();
        Ok(out_array)
    }
}

// Some more std implementations
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

impl Serial for Ipv4Addr {
    fn serial<W: WriteBytesExt>(&self, target: &mut W) {
        target.write_u8(4).expect("Writing to buffer is safe.");
        target
            .write_all(&self.octets())
            .expect("Writing to buffer is safe.");
    }
}

impl Deserial for Ipv4Addr {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let mut octects = [0u8; 4];
        source.read_exact(&mut octects)?;
        Ok(Ipv4Addr::from(octects))
    }
}

impl Serial for Ipv6Addr {
    fn serial<W: WriteBytesExt>(&self, target: &mut W) {
        target.write_u8(6).expect("Writing to buffer is safe.");
        target
            .write_all(&self.octets())
            .expect("Writing to buffer is safe.");
    }
}

impl Deserial for Ipv6Addr {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let mut octets = [0u8; 16];
        source.read_exact(&mut octets)?;
        Ok(Ipv6Addr::from(octets))
    }
}

impl Serial for IpAddr {
    fn serial<W: Buffer + WriteBytesExt>(&self, target: &mut W) {
        match self {
            IpAddr::V4(ip4) => ip4.serial(target),
            IpAddr::V6(ip6) => ip6.serial(target),
        }
    }
}

impl Deserial for IpAddr {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        match source.read_u8()? {
            4 => Ok(IpAddr::V4(Ipv4Addr::deserial(source)?)),
            6 => Ok(IpAddr::V6(Ipv6Addr::deserial(source)?)),
            x => bail!("Can't deserialize an IpAddr (unknown type: {})", x),
        }
    }
}

impl Serial for SocketAddr {
    fn serial<W: Buffer + WriteBytesExt>(&self, target: &mut W) {
        self.ip().serial(target);
        self.port().serial(target);
    }
}

impl Deserial for SocketAddr {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        Ok(SocketAddr::new(
            IpAddr::deserial(source)?,
            u16::deserial(source)?,
        ))
    }
}

impl Serial for ExchangeRate {
    fn serial<W: Buffer + WriteBytesExt>(&self, target: &mut W) {
        self.numerator().serial(target);
        self.denominator().serial(target);
    }
}

impl Deserial for ExchangeRate {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let numerator = source.get()?;
        let denominator = source.get()?;
        Self::new(numerator, denominator).ok_or_else(|| anyhow::anyhow!("Invalid exchange rate."))
    }
}

use std::{
    collections::{BTreeSet, HashSet},
    hash::{BuildHasher, Hash},
};

impl<T: Serial + Eq + Hash, S: BuildHasher + Default> Serial for HashSet<T, S> {
    fn serial<W: Buffer + WriteBytesExt>(&self, target: &mut W) {
        (self.len() as u32).serial(target);
        self.iter().for_each(|ref item| item.serial(target));
    }
}

impl<T: Deserial + Eq + Hash, S: BuildHasher + Default> Deserial for HashSet<T, S> {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let len = u32::deserial(source)?;
        let mut out = HashSet::with_capacity_and_hasher(
            std::cmp::min(len as usize, MAX_PREALLOCATED_CAPACITY),
            Default::default(),
        );

        for _i in 0..len {
            out.insert(T::deserial(source)?);
        }
        Ok(out)
    }
}

impl<T: Serial> Serial for &T {
    fn serial<W: Buffer + WriteBytesExt>(&self, target: &mut W) { (*self).serial(target) }
}

// Helpers for json serialization

use hex::{decode, encode};
use serde::{de, de::Visitor, Deserializer, Serializer};
use std::{fmt, io::Cursor};

/// Encode the given value into a byte array using its [Serial] instance, and
/// then encode that byte array as a hex string into the provided serde
/// Serializer.
pub fn base16_encode<S: Serializer, T: Serial>(v: &T, ser: S) -> Result<S::Ok, S::Error> {
    let b16_str = encode(&to_bytes(v));
    ser.serialize_str(&b16_str)
}

/// Dual to [base16_encode].
pub fn base16_decode<'de, D: Deserializer<'de>, T: Deserial>(des: D) -> Result<T, D::Error> {
    struct Base16Visitor<D>(std::marker::PhantomData<D>);

    impl<'de, D: Deserial> Visitor<'de> for Base16Visitor<D> {
        type Value = D;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "A base 16 string.")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            let bytes = decode(v).map_err(de::Error::custom)?;
            D::deserial(&mut Cursor::new(&bytes)).map_err(de::Error::custom)
        }
    }

    des.deserialize_str(Base16Visitor(Default::default()))
}

/// Analogous to [base16_encode], but encodes into a string rather than a serde
/// Serializer.
pub fn base16_encode_string<S: Serial>(x: &S) -> String { encode(&to_bytes(x)) }

/// Dual to [base16_encode_string].
pub fn base16_decode_string<S: Deserial>(x: &str) -> ParseResult<S> {
    let d = decode(x)?;
    from_bytes(&mut Cursor::new(&d))
}

/// Analogous to [base16_encode] but after serializing to a byte array it only
/// encodes the `&[4..]` into the serde Serializer. This is intended to use in
/// cases where we are encoding a collection such as a vector into JSON. Since
/// JSON is self-describing we do not need to explicitly record the length,
/// which we do in binary.
pub fn base16_ignore_length_encode<S: Serializer, T: Serial>(
    v: &T,
    ser: S,
) -> Result<S::Ok, S::Error> {
    let b16_str = encode(&to_bytes(v)[4..]);
    ser.serialize_str(&b16_str)
}

/// Dual to [base16_ignore_length_encode]
pub fn base16_ignore_length_decode<'de, D: Deserializer<'de>, T: Deserial>(
    des: D,
) -> Result<T, D::Error> {
    // Deserialization in base 16 for values which explicitly record the length.
    // In JSON serialization this explicit length is not needed because JSON is
    // self-describing and we always know the length of input.
    struct Base16IgnoreLengthVisitor<D>(std::marker::PhantomData<D>);

    impl<'de, D: Deserial> Visitor<'de> for Base16IgnoreLengthVisitor<D> {
        type Value = D;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "A base 16 string.")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            let bytes = decode(v).map_err(de::Error::custom)?;
            let mut all_bytes = Vec::with_capacity(bytes.len() + 4);
            all_bytes.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            all_bytes.extend_from_slice(&bytes);
            D::deserial(&mut Cursor::new(&all_bytes)).map_err(de::Error::custom)
        }
    }
    des.deserialize_str(Base16IgnoreLengthVisitor(Default::default()))
}
