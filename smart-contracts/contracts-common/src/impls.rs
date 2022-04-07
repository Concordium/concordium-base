use crate::{constants::*, traits::*, types::*};

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, collections, string::String, vec::Vec};
use collections::{BTreeMap, BTreeSet};
#[cfg(not(feature = "std"))]
use core::{hash, marker, mem::MaybeUninit, slice};
use hash::Hash;
#[cfg(feature = "std")]
use std::{collections, hash, marker, mem::MaybeUninit, slice};

// Implementations of Serialize

impl<X: Serial, Y: Serial> Serial for (X, Y) {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.0.serial(out)?;
        self.1.serial(out)
    }
}

impl<X: Deserial, Y: Deserial> Deserial for (X, Y) {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let x = X::deserial(source)?;
        let y = Y::deserial(source)?;
        Ok((x, y))
    }
}

impl Serial for () {
    #[inline(always)]
    fn serial<W: Write>(&self, _out: &mut W) -> Result<(), W::Err> { Ok(()) }
}

impl Deserial for () {
    #[inline(always)]
    fn deserial<R: Read>(_source: &mut R) -> ParseResult<Self> { Ok(()) }
}

impl Serial for u8 {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> { out.write_u8(*self) }
}

impl Deserial for u8 {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> { source.read_u8() }
}

impl Serial for u16 {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> { out.write_u16(*self) }
}

impl Deserial for u16 {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> { source.read_u16() }
}

impl Serial for u32 {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> { out.write_u32(*self) }
}

impl Deserial for u32 {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> { source.read_u32() }
}

impl Serial for u64 {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> { out.write_u64(*self) }
}

impl Serial for u128 {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        out.write_all(&self.to_le_bytes())
    }
}

impl Deserial for u64 {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> { source.read_u64() }
}

impl Deserial for u128 {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let bytes = read_n_bytes!(16, source);
        Ok(u128::from_le_bytes(bytes))
    }
}

impl Serial for i8 {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> { out.write_i8(*self) }
}

impl Deserial for i8 {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> { source.read_i8() }
}

impl Serial for i16 {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> { out.write_i16(*self) }
}

impl Deserial for i16 {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> { source.read_i16() }
}

impl Serial for i32 {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> { out.write_i32(*self) }
}

impl Deserial for i32 {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> { source.read_i32() }
}

impl Serial for i64 {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> { out.write_i64(*self) }
}

impl Deserial for i64 {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> { source.read_i64() }
}

impl Serial for i128 {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        out.write_all(&self.to_le_bytes())
    }
}

impl Deserial for i128 {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let bytes = read_n_bytes!(16, source);
        Ok(i128::from_le_bytes(bytes))
    }
}

/// Serialization of `bool` encodes it as a single byte, `false` is represented
/// by `0u8` and `true` is _only_ represented by `1u8`.
impl Serial for bool {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        if *self {
            out.write_u8(1)?;
        } else {
            out.write_u8(0)?;
        }
        Ok(())
    }
}

/// Deserializing a `bool` reads one byte, and returns the value `false` if the
/// byte is `0u8` and `true` if the byte is `1u8`, every other value results in
/// an error.
impl Deserial for bool {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let b = source.read_u8()?;
        match b {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ParseError::default()),
        }
    }
}

impl Serial for Amount {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> { out.write_u64(self.micro_ccd) }
}

impl Deserial for Amount {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        source.read_u64().map(Amount::from_micro_ccd)
    }
}

impl Serial for Timestamp {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.timestamp_millis().serial(out)
    }
}

impl Deserial for Timestamp {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        u64::deserial(source).map(Timestamp::from_timestamp_millis)
    }
}

impl Serial for Duration {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> { self.millis().serial(out) }
}

impl Deserial for Duration {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        u64::deserial(source).map(Duration::from_millis)
    }
}

/// Serialized by writing an `u32` representing the number of bytes for a
/// utf8-encoding of the string, then writing the bytes. Similar to `Vec<_>`.
impl Serial for &str {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        let bytes = self.as_bytes();
        let len = bytes.len() as u32;
        len.serial(out)?;
        out.write_all(bytes)
    }
}

/// Serialized by writing an `u32` representing the number of bytes for a
/// utf8-encoding of the string, then writing the bytes. Similar to `&str`.
impl Serial for String {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> { self.as_str().serial(out) }
}

/// Deserial by reading an `u32` representing the number of bytes, then takes
/// that number of bytes and tries to decode using utf8.
impl Deserial for String {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let bytes = Vec::deserial(source)?;
        let res = String::from_utf8(bytes).map_err(|_| ParseError::default())?;
        Ok(res)
    }
}

impl<T: Serial> Serial for Box<T> {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> { self.as_ref().serial(out) }
}

impl<T: Deserial> Deserial for Box<T> {
    #[inline]
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let t = T::deserial(source)?;
        Ok(Box::new(t))
    }
}

impl<C: ?Sized> Serial for marker::PhantomData<C> {
    #[inline(always)]
    fn serial<W: Write>(&self, _out: &mut W) -> Result<(), W::Err> { Ok(()) }
}

impl<C: ?Sized> Deserial for marker::PhantomData<C> {
    #[inline(always)]
    fn deserial<R: Read>(_source: &mut R) -> ParseResult<Self> {
        Ok(marker::PhantomData::default())
    }
}

/// Serialized if the `Option` is a `None` we write `0u8`. If `Some`, we write
/// `1u8` followed by the serialization of the contained `T`.
impl<T: Serial> Serial for Option<T> {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        match self {
            None => out.write_u8(0),
            Some(t) => {
                out.write_u8(1)?;
                t.serial(out)
            }
        }
    }
}

/// Deserial by reading one byte, where `0u8` represents `None` and `1u8`
/// represents `Some`, every other value results in an error.
/// In the case of `Some` we deserialize using the contained `T`.
impl<T: Deserial> Deserial for Option<T> {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let idx: u8 = source.get()?;
        match idx {
            0 => Ok(None),
            1 => {
                let t = T::deserial(source)?;
                Ok(Some(t))
            }
            _ => Err(ParseError::default()),
        }
    }
}

impl Serial for AccountAddress {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> { out.write_all(&self.0) }
}

impl Deserial for AccountAddress {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let bytes = {
            // This deliberately does not initialize the array up-front.
            // Initialization is not needed, and costs quite a bit of code space in the Wasm
            // generated code. Since account addresses
            let mut bytes: MaybeUninit<[u8; 32]> = MaybeUninit::uninit();
            let write_bytes =
                unsafe { slice::from_raw_parts_mut(bytes.as_mut_ptr() as *mut u8, 32) };
            source.read_exact(write_bytes)?;
            unsafe { bytes.assume_init() }
        };
        Ok(AccountAddress(bytes))
    }
}

impl Serial for ContractAddress {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        out.write_u64(self.index)?;
        out.write_u64(self.subindex)
    }
}

impl Deserial for ContractAddress {
    #[inline]
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let index = source.get()?;
        let subindex = source.get()?;
        Ok(ContractAddress {
            index,
            subindex,
        })
    }
}

impl Serial for Address {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        match self {
            Address::Account(ref acc) => {
                out.write_u8(0)?;
                acc.serial(out)
            }
            Address::Contract(ref cnt) => {
                out.write_u8(1)?;
                cnt.serial(out)
            }
        }
    }
}

impl Deserial for Address {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let tag = u8::deserial(source)?;
        match tag {
            0 => Ok(Address::Account(source.get()?)),
            1 => Ok(Address::Contract(source.get()?)),
            _ => Err(ParseError::default()),
        }
    }
}

impl<'a> Serial for ContractName<'a> {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        let name = self.get_chain_name();
        let len = name.len() as u16;
        len.serial(out)?;
        serial_vector_no_length(name.as_bytes(), out)
    }
}

impl Serial for OwnedContractName {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.as_contract_name().serial(out)
    }
}

impl Deserial for OwnedContractName {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let len: u16 = source.get()?;
        let bytes = deserial_vector_no_length(source, len as usize)?;
        let name = String::from_utf8(bytes).map_err(|_| ParseError::default())?;
        let owned_contract_name =
            OwnedContractName::new(name).map_err(|_| ParseError::default())?;
        Ok(owned_contract_name)
    }
}

impl<'a> Serial for ReceiveName<'a> {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        let name = self.get_chain_name();
        let len = name.len() as u16;
        len.serial(out)?;
        serial_vector_no_length(name.as_bytes(), out)
    }
}

impl Serial for OwnedReceiveName {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.as_receive_name().serial(out)
    }
}

impl Deserial for OwnedReceiveName {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let len: u16 = source.get()?;
        let bytes = deserial_vector_no_length(source, len as usize)?;
        let name = String::from_utf8(bytes).map_err(|_| ParseError::default())?;
        let owned_receive_name = OwnedReceiveName::new(name).map_err(|_| ParseError::default())?;
        Ok(owned_receive_name)
    }
}

impl<'a> Serial for EntrypointName<'a> {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        let len = self.0.len() as u16;
        len.serial(out)?;
        serial_vector_no_length(self.0.as_bytes(), out)
    }
}

impl Serial for OwnedEntrypointName {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.as_entrypoint_name().serial(out)
    }
}

impl Deserial for OwnedEntrypointName {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let len: u16 = source.get()?;
        let bytes = deserial_vector_no_length(source, len as usize)?;
        let name = String::from_utf8(bytes).map_err(|_| ParseError::default())?;
        let owned_entrypoint_name = Self::new(name).map_err(|_| ParseError::default())?;
        Ok(owned_entrypoint_name)
    }
}

impl<'a> Serial for Parameter<'a> {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        let len = self.0.len() as u16;
        len.serial(out)?;
        out.write_all(&self.0)
    }
}

impl Serial for OwnedParameter {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.as_parameter().serial(out)
    }
}

impl Deserial for OwnedParameter {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let len: u16 = source.get()?;
        let bytes = deserial_vector_no_length(source, len as usize)?;
        Ok(Self(bytes))
    }
}

impl Serial for ChainMetadata {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> { self.slot_time.serial(out) }
}

impl Deserial for ChainMetadata {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let slot_time = source.get()?;
        Ok(Self {
            slot_time,
        })
    }
}

/// Write a slice of elements, without including length information.
/// This is intended to be used either when the length is statically known,
/// or when the length is serialized independently as part of a bigger
/// structure.
pub fn serial_vector_no_length<W: Write, T: Serial>(xs: &[T], out: &mut W) -> Result<(), W::Err> {
    for x in xs {
        x.serial(out)?;
    }
    Ok(())
}

/// Read a vector given a length.
pub fn deserial_vector_no_length<R: Read, T: Deserial>(
    reader: &mut R,
    len: usize,
) -> ParseResult<Vec<T>> {
    let mut vec = Vec::with_capacity(core::cmp::min(len, MAX_PREALLOCATED_CAPACITY));
    for _ in 0..len {
        vec.push(T::deserial(reader)?);
    }
    Ok(vec)
}

/// Write a Map as a list of key-value pairs ordered by the key, without the
/// length information.
pub fn serial_map_no_length<W: Write, K: Serial, V: Serial>(
    map: &BTreeMap<K, V>,
    out: &mut W,
) -> Result<(), W::Err> {
    for (k, v) in map.iter() {
        k.serial(out)?;
        v.serial(out)?;
    }
    Ok(())
}

/// Read a [BTreeMap](https://doc.rust-lang.org/std/collections/struct.BTreeMap.html) as a list of key-value pairs given some length.
/// NB: This ensures there are no duplicates, hence the specialized type.
/// Moreover this will only succeed if keys are listed in order.
pub fn deserial_map_no_length<R: Read, K: Deserial + Ord + Copy, V: Deserial>(
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
                    return Err(ParseError::default());
                }
            }
        }
        x = Some(k);
    }
    Ok(out)
}

/// Read a [BTreeMap](https://doc.rust-lang.org/std/collections/struct.BTreeMap.html) as a list of key-value pairs given some length.
/// Slightly faster version of `deserial_map_no_length` as it is skipping the
/// order checking
pub fn deserial_map_no_length_no_order_check<R: Read, K: Deserial + Ord, V: Deserial>(
    source: &mut R,
    len: usize,
) -> ParseResult<BTreeMap<K, V>> {
    let mut out = BTreeMap::new();
    for _ in 0..len {
        let k = source.get()?;
        let v = source.get()?;
        if out.insert(k, v).is_some() {
            return Err(ParseError::default());
        }
    }
    Ok(out)
}

/// Write a HashMap as a list of key-value pairs in to particular order, without
/// the length information.
pub fn serial_hashmap_no_length<W: Write, K: Serial, V: Serial>(
    map: &HashMap<K, V>,
    out: &mut W,
) -> Result<(), W::Err> {
    for (k, v) in map.iter() {
        k.serial(out)?;
        v.serial(out)?;
    }
    Ok(())
}

/// Read a [HashMap](https://doc.rust-lang.org/std/collections/struct.HashMap.html) as a list of key-value pairs given some length.
pub fn deserial_hashmap_no_length<R: Read, K: Deserial + Eq + Hash, V: Deserial>(
    source: &mut R,
    len: usize,
) -> ParseResult<HashMap<K, V>> {
    let mut out = HashMap::default();
    for _ in 0..len {
        let k = source.get()?;
        let v = source.get()?;
        if out.insert(k, v).is_some() {
            return Err(ParseError::default());
        }
    }
    Ok(out)
}

/// Write a [BTreeSet](https://doc.rust-lang.org/std/collections/struct.BTreeSet.html) as an ascending list of keys, without the length information.
pub fn serial_set_no_length<W: Write, K: Serial>(
    map: &BTreeSet<K>,
    out: &mut W,
) -> Result<(), W::Err> {
    for k in map.iter() {
        k.serial(out)?;
    }
    Ok(())
}

/// Read a [BTreeSet](https://doc.rust-lang.org/std/collections/struct.BTreeSet.html) as a list of keys, given some length.
/// NB: This ensures there are no duplicates, hence the specialized type.
/// Moreover this will only succeed if keys are listed in order.
pub fn deserial_set_no_length<R: Read, K: Deserial + Ord + Copy>(
    source: &mut R,
    len: usize,
) -> ParseResult<BTreeSet<K>> {
    let mut out = BTreeSet::new();
    let mut prev = None;
    for _ in 0..len {
        let key = source.get()?;
        let next = Some(key);
        if next <= prev {
            return Err(ParseError::default());
        }
        out.insert(key);
        prev = next;
    }
    Ok(out)
}

/// Write a [HashSet](https://doc.rust-lang.org/std/collections/struct.HashSet.html) as a list of keys in no particular order, without the length information.
pub fn serial_hashset_no_length<W: Write, K: Serial>(
    map: &HashSet<K>,
    out: &mut W,
) -> Result<(), W::Err> {
    for k in map.iter() {
        k.serial(out)?;
    }
    Ok(())
}

/// Read a [HashSet](https://doc.rust-lang.org/std/collections/struct.HashSet.html) as a list of keys, given some length.
/// NB: This ensures there are no duplicates.
pub fn deserial_hashset_no_length<R: Read, K: Deserial + Eq + Hash>(
    source: &mut R,
    len: usize,
) -> ParseResult<HashSet<K>> {
    let mut out = HashSet::default();
    for _ in 0..len {
        let key = source.get()?;
        if !out.insert(key) {
            return Err(ParseError::default());
        }
    }
    Ok(out)
}

/// Read a [BTreeSet](https://doc.rust-lang.org/std/collections/struct.BTreeSet.html) as an list of key-value pairs given some length.
/// Slightly faster version of `deserial_set_no_length` as it is skipping the
/// order checking. The only check that is made to the set is that there are no
/// duplicates.
pub fn deserial_set_no_length_no_order_check<R: Read, K: Deserial + Ord>(
    source: &mut R,
    len: usize,
) -> ParseResult<BTreeSet<K>> {
    let mut out = BTreeSet::new();
    for _ in 0..len {
        let key = source.get()?;
        if !out.insert(key) {
            return Err(ParseError::default());
        }
    }
    Ok(out)
}

/// Serialized by writing an `u32` representing the number of elements, followed
/// by the elements serialized according to their type `T`.
impl<T: Serial> Serial for Vec<T> {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        let len = self.len() as u32;
        len.serial(out)?;
        serial_vector_no_length(self, out)
    }
}

/// Deserialized by reading an `u32` representing the number of elements, then
/// deserializing that many elements of type `T`.
impl<T: Deserial> Deserial for Vec<T> {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let len: u32 = source.get()?;
        deserial_vector_no_length(source, len as usize)
    }
}

/// The serialization of maps encodes their size as a u32. This should be
/// sufficient for all realistic use cases in smart contracts.
/// They are serialized in ascending order.
impl<K: Serial + Ord, V: Serial> Serial for BTreeMap<K, V> {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        let len = self.len() as u32;
        len.serial(out)?;
        serial_map_no_length(self, out)
    }
}

/// The deserialization of maps assumes their size is a u32.
///
/// <b style="color: darkred">WARNING</b>: Deserialization **does not** ensure
/// the ordering of the keys, it only ensures that there are no duplicates.
/// Serializing a `BTreeMap` via its `Serial` instance will lay out elements
/// by the increasing order of keys. As a consequence deserializing, and
/// serializing back is in general not the identity. This could have
/// consequences if the data is hashed, or the byte representation
/// is used in some other way directly. In those cases the a canonical
/// order should be ensured to avoid subtle, difficult to diagnose,
/// bugs.
impl<K: Deserial + Ord, V: Deserial> Deserial for BTreeMap<K, V> {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let len: u32 = source.get()?;
        deserial_map_no_length_no_order_check(source, len as usize)
    }
}

/// The serialization of maps encodes their size as a u32. This should be
/// sufficient for all realistic use cases in smart contracts.
/// They are serialized in no particular order.
impl<K: Serial, V: Serial> Serial for HashMap<K, V> {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        let len = self.len() as u32;
        len.serial(out)?;
        serial_hashmap_no_length(self, out)
    }
}

/// The deserialization of maps assumes their size is a u32.
///
/// <b style="color: darkred">WARNING</b>: Deserialization only ensures that
/// there are no duplicates. Serializing a `HashMap` via its `Serial` instance
/// will not lay out elements in a particular order. As a consequence
/// deserializing, and serializing back is in general not the identity. This
/// could have consequences if the data is hashed, or the byte representation
/// is used in some other way directly. In those cases use a `BTreeMap` instead.
impl<K: Deserial + Hash + Eq, V: Deserial> Deserial for HashMap<K, V> {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let len: u32 = source.get()?;
        deserial_hashmap_no_length(source, len as usize)
    }
}

/// The serialization of sets encodes their size as a u32. This should be
/// sufficient for all realistic use cases in smart contracts.
/// They are serialized in canonical order (increasing)
impl<K: Serial + Ord> Serial for BTreeSet<K> {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        let len = self.len() as u32;
        len.serial(out)?;
        serial_set_no_length(self, out)
    }
}

/// The deserialization of sets assumes their size is a u32.
///
/// <b style="color: darkred">WARNING</b>: Deserialization **does not** ensure
/// the ordering of the keys, it only ensures that there are no duplicates.
/// Serializing a `BTreeSet` via its `Serial` instance will lay out elements
/// by the increasing order. As a consequence deserializing, and
/// serializing back is in general not the identity. This could have
/// consequences if the data is hashed, or the byte representation
/// is used in some other way directly. In those cases a canonical
/// order should be ensured to avoid subtle, difficult to diagnose,
/// bugs.
impl<K: Deserial + Ord> Deserial for BTreeSet<K> {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let len: u32 = source.get()?;
        deserial_set_no_length_no_order_check(source, len as usize)
    }
}

// The serialization of sets encodes their size as a u32. This should be
/// sufficient for all realistic use cases in smart contracts.
/// They are serialized in no particular order.
impl<K: Serial> Serial for HashSet<K> {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        let len = self.len() as u32;
        len.serial(out)?;
        serial_hashset_no_length(self, out)
    }
}

/// The deserialization of sets assumes their size is a u32.
///
/// <b style="color: darkred">WARNING</b>: Deserialization only ensures that
/// there are no duplicates. Serializing a `HashSet` via its `Serial` instance
/// will not lay out elements in any particular order. As a consequence
/// deserializing, and serializing back is in general not the identity. This
/// could have consequences if the data is hashed, or the byte representation
/// is used in some other way directly. In those cases use a `BTreeSet` instead.
impl<K: Deserial + Hash + Eq> Deserial for HashSet<K> {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let len: u32 = source.get()?;
        deserial_hashset_no_length(source, len as usize)
    }
}

/// Serialize the array by writing elements consecutively starting at 0.
/// Since the length of the array is known statically it is not written out
/// explicitly. Thus serialization of the array A and the slice &A[..] differ.
impl<T: Serial, const N: usize> Serial for [T; N] {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        for elem in self.iter() {
            elem.serial(out)?;
        }
        Ok(())
    }
}

impl<T: Deserial, const N: usize> Deserial for [T; N] {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let mut data: [MaybeUninit<T>; N] = unsafe { MaybeUninit::uninit().assume_init() };
        for item in data.iter_mut() {
            *item = MaybeUninit::new(T::deserial(source)?);
        }
        Ok(unsafe { data.as_ptr().cast::<[T; N]>().read() })
    }
}

impl Address {
    pub fn matches_account(&self, acc: &AccountAddress) -> bool {
        if let Address::Account(ref my_acc) = self {
            my_acc == acc
        } else {
            false
        }
    }

    pub fn matches_contract(&self, cnt: &ContractAddress) -> bool {
        if let Address::Contract(ref my_cnt) = self {
            my_cnt == cnt
        } else {
            false
        }
    }
}

impl Serial for AttributeTag {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> { self.0.serial(out) }
}

impl Deserial for AttributeTag {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> { Ok(AttributeTag(source.get()?)) }
}

impl Serial for OwnedPolicy {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.identity_provider.serial(out)?;
        self.created_at.serial(out)?;
        self.valid_to.serial(out)?;
        (self.items.len() as u16).serial(out)?;
        for item in self.items.iter() {
            item.0.serial(out)?;
            (item.1.len() as u8).serial(out)?;
            out.write_all(&item.1)?;
        }
        Ok(())
    }
}

impl Deserial for OwnedPolicy {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let identity_provider = source.get()?;
        let created_at = source.get()?;
        let valid_to = source.get()?;
        let len: u16 = source.get()?;
        let mut items = Vec::with_capacity(len as usize);
        let mut buf = [0u8; 31];
        for _ in 0..len {
            let tag = AttributeTag::deserial(source)?;
            let value_len: u8 = source.get()?;
            if value_len > 31 {
                // Should not happen because all attributes fit into 31 bytes.
                return Err(ParseError {});
            }
            let value_len = usize::from(value_len);
            source.read_exact(&mut buf[0..value_len])?;
            items.push((tag, buf[0..value_len].to_vec()))
        }
        Ok(Self {
            identity_provider,
            created_at,
            valid_to,
            items,
        })
    }
}

impl<T> Cursor<T> {
    pub fn new(data: T) -> Self {
        Cursor {
            offset: 0,
            data,
        }
    }
}

impl<T: AsRef<[u8]>> Read for Cursor<T> {
    fn read(&mut self, buf: &mut [u8]) -> ParseResult<usize> {
        let mut len = self.data.as_ref().len() - self.offset;
        if len > buf.len() {
            len = buf.len();
        }
        if len > 0 {
            buf[0..len].copy_from_slice(&self.data.as_ref()[self.offset..self.offset + len]);
            self.offset += len;
            Ok(len)
        } else {
            Ok(0)
        }
    }
}

impl Write for Cursor<&mut Vec<u8>> {
    type Err = ();

    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Err> {
        if buf.is_empty() {
            Ok(0)
        } else {
            // remaining capacity.
            let remaining_len = self.data.len() - self.offset;
            let (to_write, to_extend): (_, &[u8]) = {
                if remaining_len >= buf.len() {
                    (buf, &[])
                } else {
                    (&buf[..remaining_len], &buf[remaining_len..])
                }
            };
            self.data[self.offset..self.offset + to_write.len()].copy_from_slice(to_write);
            self.data.extend_from_slice(to_extend);
            self.offset += buf.len();
            Ok(buf.len())
        }
    }
}

/// Serialize the given value to a freshly allocated vector of bytes using
/// the provided `Serial` instance.
///
/// This should only be used as a helper function at the top-level, and not in
/// implementations of `Serial`.
pub fn to_bytes<S: Serial>(x: &S) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cursor = Cursor::new(&mut out);
    x.serial(&mut cursor).expect("Writing to a vector should succeed.");
    out
}

/// Dual to `to_bytes`.
#[inline]
pub fn from_bytes<S: Deserial>(source: &[u8]) -> ParseResult<S> {
    let mut cursor = Cursor::new(source);
    cursor.get()
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_u64_array_deserial_serial_is_id() {
        let xs: [u64; 1] = [123];
        let bytes = to_bytes(&xs);
        let xs2: ParseResult<[u64; 1]> = from_bytes(&bytes);
        assert_eq!(
            xs,
            xs2.unwrap(),
            "Serializing and then deserializing should return original value."
        );
    }

    #[test]
    fn test_string_array_deserial_serial_is_id() {
        let xs: [String; 1] = ["hello".to_string()];
        let bytes = to_bytes(&xs);
        let xs2: ParseResult<[String; 1]> = from_bytes(&bytes);
        assert_eq!(
            xs,
            xs2.unwrap(),
            "Serializing and then deserializing should return original value."
        );
    }
}
