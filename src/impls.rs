use crate::{traits::*, types::*};

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, collections::*, string::String, vec::Vec};
#[cfg(not(feature = "std"))]
use core::{mem::MaybeUninit, slice};
#[cfg(feature = "std")]
use std::{collections::*, mem::MaybeUninit, slice};

static MAX_PREALLOCATED_CAPACITY: usize = 4096;

/// Apply the given macro to each of the elements in the list
/// For example, `repeat_macro!(println, "foo", "bar")` is equivalent to
/// `println!("foo"); println!("bar").
macro_rules! repeat_macro {
    ($f:ident, $n:expr) => ($f!($n););
    ($f:ident, $n:expr, $($ns:expr),*) => {
        $f!($n);
        repeat_macro!($f, $($ns),*);
    };
}

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

impl Deserial for u64 {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> { source.read_u64() }
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
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        out.write_u64((*self).micro_gtu)
    }
}

impl Deserial for Amount {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        source.read_u64().map(Amount::from_micro_gtu)
    }
}

/// Serialized by writing an `u32` representing the number of bytes for a
/// utf8-encoding of the string, then writing the bytes. Similar to `Vec<_>`.
impl Serial for String {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.bytes().collect::<Vec<_>>().serial(out)
    }
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
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let t = T::deserial(source)?;
        Ok(Box::new(t))
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

impl Serial for InitContext {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.metadata.serial(out)?;
        self.init_origin.serial(out)
    }
}

impl Deserial for InitContext {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let metadata = source.get()?;
        let init_origin = source.get()?;
        Ok(Self {
            metadata,
            init_origin,
        })
    }
}

impl Serial for ReceiveContext {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.metadata.serial(out)?;
        self.invoker.serial(out)?;
        self.self_address.serial(out)?;
        self.self_balance.serial(out)?;
        self.sender.serial(out)?;
        self.owner.serial(out)
    }
}

impl Deserial for ReceiveContext {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let metadata = source.get()?;
        let invoker = source.get()?;
        let self_address = source.get()?;
        let self_balance = source.get()?;
        let sender = source.get()?;
        let owner = source.get()?;
        Ok(ReceiveContext {
            metadata,
            invoker,
            self_address,
            self_balance,
            sender,
            owner,
        })
    }
}

impl Serial for ChainMetadata {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.slot_number.serial(out)?;
        self.block_height.serial(out)?;
        self.finalized_height.serial(out)?;
        self.slot_time.serial(out)
    }
}

impl Deserial for ChainMetadata {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let slot_number = source.get()?;
        let block_height = source.get()?;
        let finalized_height = source.get()?;
        let slot_time = source.get()?;
        Ok(Self {
            slot_number,
            block_height,
            finalized_height,
            slot_time,
        })
    }
}

/// Write a vector without including length information.
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
pub fn serial_map_no_length<'a, W: Write, K: Serial + 'a, V: Serial + 'a>(
    map: &BTreeMap<K, V>,
    out: &mut W,
) -> Result<(), W::Err> {
    for (k, v) in map.iter() {
        k.serial(out)?;
        v.serial(out)?;
    }
    Ok(())
}

/// Read a Map as an list of key-value pairs given some length.
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

/// Read a Map as an list of key-value pairs given some length.
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

/// Write a Set as an list of keys ordered, without the length information.
pub fn serial_set_no_length<'a, W: Write, K: Serial + 'a>(
    map: &BTreeSet<K>,
    out: &mut W,
) -> Result<(), W::Err> {
    for k in map.iter() {
        k.serial(out)?;
    }
    Ok(())
}

/// Read a Set as an list of keys, given some length.
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

/// Read a Set as an list of key-value pairs given some length.
/// Slightly faster version of `deserial_set_no_length` as it is skipping the
/// order checking.
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
/// by the elements serialize according to their type `T`.
impl<T: Serial> Serial for Vec<T> {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        let len = self.len() as u32;
        len.serial(out)?;
        serial_vector_no_length(self, out)
    }
}

/// Deserialized by reading an `u32` representing the number of elements, then
/// deserialising that many elements of type `T`.
impl<T: Deserial> Deserial for Vec<T> {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let len: u32 = source.get()?;
        deserial_vector_no_length(source, len as usize)
    }
}

/// The serialization of maps encodes their size as a u32. This should be
/// sufficient for all realistic use cases in smart contracts.
/// They are serialized in canonical order (increasing).
impl<K: Serial + Ord, V: Serial> Serial for BTreeMap<K, V> {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        let len = self.len() as u32;
        len.serial(out)?;
        serial_map_no_length(self, out)
    }
}

/// The deserialization of maps assumes their size as a u32.
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

/// The deserialization of sets assumes their size as a u32.
///
/// <b style="color: darkred">WARNING</b>: Deserialization **does not** ensure
/// the ordering of the keys, it only ensures that there are no duplicates.
/// Serializing a `BTreeSet` via its `Serial` instance will lay out elements
/// by the increasing order. As a consequence deserializing, and
/// serializing back is in general not the identity. This could have
/// consequences if the data is hashed, or the byte representation
/// is used in some other way directly. In those cases the a canonical
/// order should be ensured to avoid subtle, difficult to diagnose,
/// bugs.
impl<K: Deserial + Ord> Deserial for BTreeSet<K> {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let len: u32 = source.get()?;
        deserial_set_no_length_no_order_check(source, len as usize)
    }
}

macro_rules! serialize_array_x {
    ($x:expr) => {
        /// Serialize the array by writing elements consecutively starting at 0.
        /// Since the length of the array is known statically it is not written out
        /// explicitly. Thus serialization of the array A and the slice &A[..] differ.
        impl<T: Serial> Serial for [T; $x] {
            fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
                for elem in self.iter() {
                    elem.serial(out)?;
                }
                Ok(())
            }
        }

        impl<T: Deserial> Deserial for [T; $x] {
            fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
                let mut data: MaybeUninit<[T; $x]> = MaybeUninit::uninit();
                let ptr = data.as_mut_ptr();
                for i in 0..$x {
                    let item = T::deserial(source)?;
                    unsafe { (*ptr)[i] = item };
                }
                Ok(unsafe { data.assume_init() })
            }
        }
    };
}

repeat_macro!(
    serialize_array_x,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    16,
    17,
    18,
    19,
    20,
    21,
    22,
    23,
    24,
    25,
    26,
    27,
    28,
    29,
    30,
    31,
    32
);

impl InitContext {
    pub fn init_origin(&self) -> &AccountAddress { &self.init_origin }

    /// Get time in milliseconds at the beginning of this block.
    pub fn get_time(&self) -> u64 { self.metadata.slot_time }
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

impl ReceiveContext {
    pub fn sender(&self) -> &Address { &self.sender }

    /// Who invoked this transaction.
    pub fn invoker(&self) -> &AccountAddress { &self.invoker }

    /// Get time in milliseconds at the beginning of this block.
    pub fn get_time(&self) -> u64 { self.metadata.slot_time }

    /// Who is the owner of this contract.
    pub fn owner(&self) -> &AccountAddress { &self.owner }

    /// Balance on the smart contract when it was invoked.
    pub fn self_balance(&self) -> Amount { self.self_balance }

    /// Address of the smart contract.
    pub fn self_address(&self) -> &ContractAddress { &self.self_address }
}

pub struct ReadAttributeIterator<'a, R> {
    pos:    u16,
    len:    u16,
    source: &'a mut R,
}

impl<'a, R: Read + 'a> Policy<ReadAttributeIterator<'a, R>> {
    // /// Get the value of the given attribute, if present.
    // pub fn get_attribute(&self, tag: AttributeTag) -> Option<&AttributeValue> {
    //     match self.items.binary_search_by_key(&tag, |x| x.0) {
    //         Ok(idx) => Some(&self.items[idx].1),
    //         Err(_) => None,
    //     }
    // }

    pub fn deserial(source: &'a mut R) -> ParseResult<Self> {
        let identity_provider = source.get()?;
        let created_at = source.get()?;
        let valid_to = source.get()?;
        let len: u16 = source.get()?;
        let items = ReadAttributeIterator {
            pos: 0,
            len,
            source,
        };
        Ok(Self {
            identity_provider,
            created_at,
            valid_to,
            items,
        })
    }
}

impl Serial for AttributeTag {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> { self.0.serial(out) }
}

impl Deserial for AttributeTag {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> { Ok(AttributeTag(source.get()?)) }
}

impl<'a, R: Read> ReadAttributeIterator<'a, R> {
    /// Get the next attribute, storing it in the provided buffer.
    /// The return value, if Some, is a pair of an attribute tag, and the length
    /// of the attribute value.
    ///
    /// The reason this function is added here, and we don't simply implement
    /// an Iterator for this type is that with the supplied buffer we can
    /// iterate through the elements more efficiently, without any allocations,
    /// the consumer being responsible for allocating the buffer.
    pub fn next(&mut self, buf: &mut [u8; 31]) -> Option<(AttributeTag, u8)> {
        if self.pos == self.len {
            return None;
        }
        let tag = AttributeTag::deserial(self.source).ok()?;
        let value_len: u8 = self.source.get().ok()?;
        if value_len > 31 {
            // Should not happen because all attributes fit into 31 bytes.
            return None;
        }
        self.source.read_exact(&mut buf[0..usize::from(value_len)]).ok()?;
        Some((tag, value_len))
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
pub fn to_bytes<S: Serial>(x: &S) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cursor = Cursor::new(&mut out);
    x.serial(&mut cursor).expect("Writing to a vector should succeed.");
    out
}

/// Dual to `to_bytes`.
pub fn from_bytes<S: Deserial>(source: &[u8]) -> ParseResult<S> {
    let mut cursor = Cursor::new(source);
    cursor.get()
}
