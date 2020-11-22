use crate::{traits::*, types::*};

#[cfg(not(feature = "std"))]
use alloc::collections;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(not(feature = "std"))]
use core::{mem::MaybeUninit, slice};
#[cfg(feature = "derive-serde")]
use std::convert::TryInto;
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
/// Deserialization will only succeed if the key-value pairs are ordered.
impl<K: Deserial + Ord + Copy, V: Deserial> Deserial for BTreeMap<K, V> {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let len: u32 = source.get()?;
        deserial_map_no_length(source, len as usize)
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
/// Deserialization will only succeed if the keys are ordered.
impl<K: Deserial + Ord + Copy> Deserial for BTreeSet<K> {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let len: u32 = source.get()?;
        deserial_set_no_length(source, len as usize)
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

pub fn to_bytes<S: Serial>(x: &S) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cursor = Cursor::new(&mut out);
    x.serial(&mut cursor).expect("Writing to a vector should succeed.");
    out
}

pub fn from_bytes<S: Deserial>(source: &[u8]) -> ParseResult<S> {
    let mut cursor = Cursor::new(source);
    cursor.get()
}

impl SchemaType for () {
    fn get_type() -> schema::Type { schema::Type::Unit }
}
impl SchemaType for bool {
    fn get_type() -> schema::Type { schema::Type::Bool }
}
impl SchemaType for u8 {
    fn get_type() -> schema::Type { schema::Type::U8 }
}
impl SchemaType for u16 {
    fn get_type() -> schema::Type { schema::Type::U16 }
}
impl SchemaType for u32 {
    fn get_type() -> schema::Type { schema::Type::U32 }
}
impl SchemaType for u64 {
    fn get_type() -> schema::Type { schema::Type::U64 }
}
impl SchemaType for i8 {
    fn get_type() -> schema::Type { schema::Type::I8 }
}
impl SchemaType for i16 {
    fn get_type() -> schema::Type { schema::Type::I16 }
}
impl SchemaType for i32 {
    fn get_type() -> schema::Type { schema::Type::I32 }
}
impl SchemaType for i64 {
    fn get_type() -> schema::Type { schema::Type::I64 }
}
impl SchemaType for Amount {
    fn get_type() -> schema::Type { schema::Type::Amount }
}
impl SchemaType for AccountAddress {
    fn get_type() -> schema::Type { schema::Type::AccountAddress }
}
impl SchemaType for ContractAddress {
    fn get_type() -> schema::Type { schema::Type::ContractAddress }
}
impl<T: SchemaType> SchemaType for Option<T> {
    fn get_type() -> schema::Type { schema::Type::Option(Box::new(T::get_type())) }
}
impl<L: SchemaType, R: SchemaType> SchemaType for (L, R) {
    fn get_type() -> schema::Type {
        schema::Type::Pair(Box::new(L::get_type()), Box::new(R::get_type()))
    }
}
impl SchemaType for String {
    fn get_type() -> schema::Type { schema::Type::String(schema::SizeLength::U32) }
}
impl<T: SchemaType> SchemaType for Vec<T> {
    fn get_type() -> schema::Type {
        schema::Type::List(schema::SizeLength::U32, Box::new(T::get_type()))
    }
}
impl<T: SchemaType> SchemaType for BTreeSet<T> {
    fn get_type() -> schema::Type {
        schema::Type::Set(schema::SizeLength::U32, Box::new(T::get_type()))
    }
}
impl<K: SchemaType, V: SchemaType> SchemaType for BTreeMap<K, V> {
    fn get_type() -> schema::Type {
        schema::Type::Map(schema::SizeLength::U32, Box::new(K::get_type()), Box::new(V::get_type()))
    }
}
impl SchemaType for [u8] {
    fn get_type() -> schema::Type {
        schema::Type::List(schema::SizeLength::U32, Box::new(schema::Type::U8))
    }
}

macro_rules! schema_type_array_x {
    ($x:expr) => {
        impl<A: SchemaType> SchemaType for [A; $x] {
            fn get_type() -> schema::Type { schema::Type::Array($x, Box::new(A::get_type())) }
        }
    };
}

repeat_macro!(
    schema_type_array_x,
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

impl Serial for schema::Fields {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        match self {
            schema::Fields::Named(fields) => {
                out.write_u8(0)?;
                fields.serial(out)?;
            }
            schema::Fields::Unnamed(fields) => {
                out.write_u8(1)?;
                fields.serial(out)?;
            }
            schema::Fields::Unit => {
                out.write_u8(2)?;
            }
        }
        Ok(())
    }
}

impl Deserial for schema::Fields {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let idx = source.read_u8()?;
        match idx {
            0 => Ok(schema::Fields::Named(source.get()?)),
            1 => Ok(schema::Fields::Unnamed(source.get()?)),
            2 => Ok(schema::Fields::Unit),
            _ => Err(ParseError::default()),
        }
    }
}

impl Serial for schema::Contract {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.state.serial(out)?;
        self.method_parameter.serial(out)?;
        Ok(())
    }
}

impl Deserial for schema::Contract {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let state = source.get()?;
        let len: u32 = source.get()?;
        let method_parameter = deserial_map_no_length_no_order_check(source, len as usize)?;
        Ok(schema::Contract {
            state,
            method_parameter,
        })
    }
}

impl Serial for schema::SizeLength {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        match self {
            schema::SizeLength::U8 => out.write_u8(0)?,
            schema::SizeLength::U16 => out.write_u8(1)?,
            schema::SizeLength::U32 => out.write_u8(2)?,
            schema::SizeLength::U64 => out.write_u8(3)?,
        }
        Ok(())
    }
}

impl Deserial for schema::SizeLength {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        let idx = source.read_u8()?;
        match idx {
            0 => Ok(schema::SizeLength::U8),
            1 => Ok(schema::SizeLength::U16),
            2 => Ok(schema::SizeLength::U32),
            3 => Ok(schema::SizeLength::U64),
            _ => Err(ParseError::default()),
        }
    }
}

impl Serial for schema::Type {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        use schema::Type;
        match self {
            Type::Unit => {
                out.write_u8(0)?;
            }
            Type::Bool => {
                out.write_u8(1)?;
            }
            Type::U8 => {
                out.write_u8(2)?;
            }
            Type::U16 => {
                out.write_u8(3)?;
            }
            Type::U32 => {
                out.write_u8(4)?;
            }
            Type::U64 => {
                out.write_u8(5)?;
            }
            Type::I8 => {
                out.write_u8(6)?;
            }
            Type::I16 => {
                out.write_u8(7)?;
            }
            Type::I32 => {
                out.write_u8(8)?;
            }
            Type::I64 => {
                out.write_u8(9)?;
            }
            Type::Amount => {
                out.write_u8(10)?;
            }
            Type::AccountAddress => {
                out.write_u8(11)?;
            }
            Type::ContractAddress => {
                out.write_u8(12)?;
            }
            Type::Option(ty) => {
                out.write_u8(13)?;
                ty.serial(out)?;
            }
            Type::Pair(left, right) => {
                out.write_u8(14)?;
                left.serial(out)?;
                right.serial(out)?;
            }
            Type::String(len_size) => {
                out.write_u8(15)?;
                len_size.serial(out)?;
            }
            Type::List(len_size, ty) => {
                out.write_u8(16)?;
                len_size.serial(out)?;
                ty.serial(out)?;
            }
            Type::Set(len_size, ty) => {
                out.write_u8(17)?;
                len_size.serial(out)?;
                ty.serial(out)?;
            }
            Type::Map(len_size, key, value) => {
                out.write_u8(18)?;
                len_size.serial(out)?;
                key.serial(out)?;
                value.serial(out)?;
            }
            Type::Array(len, ty) => {
                out.write_u8(19)?;
                len.serial(out)?;
                ty.serial(out)?;
            }
            Type::Struct(fields) => {
                out.write_u8(20)?;
                fields.serial(out)?;
            }
            Type::Enum(fields) => {
                out.write_u8(21)?;
                fields.serial(out)?;
            }
        }
        Ok(())
    }
}

impl Deserial for schema::Type {
    fn deserial<R: Read>(source: &mut R) -> ParseResult<Self> {
        use schema::*;
        let idx = source.read_u8()?;
        match idx {
            0 => Ok(Type::Unit),
            1 => Ok(Type::Bool),
            2 => Ok(Type::U8),
            3 => Ok(Type::U16),
            4 => Ok(Type::U32),
            5 => Ok(Type::U64),
            6 => Ok(Type::I8),
            7 => Ok(Type::I16),
            8 => Ok(Type::I32),
            9 => Ok(Type::I64),
            10 => Ok(Type::Amount),
            11 => Ok(Type::AccountAddress),
            12 => Ok(Type::ContractAddress),
            13 => {
                let ty = Type::deserial(source)?;
                Ok(Type::Option(Box::new(ty)))
            }
            14 => {
                let left = Type::deserial(source)?;
                let right = Type::deserial(source)?;
                Ok(Type::Pair(Box::new(left), Box::new(right)))
            }
            15 => {
                let len_size = SizeLength::deserial(source)?;
                Ok(Type::String(len_size))
            }
            16 => {
                let len_size = SizeLength::deserial(source)?;
                let ty = Type::deserial(source)?;
                Ok(Type::List(len_size, Box::new(ty)))
            }
            17 => {
                let len_size = SizeLength::deserial(source)?;
                let ty = Type::deserial(source)?;
                Ok(Type::Set(len_size, Box::new(ty)))
            }
            18 => {
                let len_size = SizeLength::deserial(source)?;
                let key = Type::deserial(source)?;
                let value = Type::deserial(source)?;
                Ok(Type::Map(len_size, Box::new(key), Box::new(value)))
            }
            19 => {
                let len = u32::deserial(source)?;
                let ty = Type::deserial(source)?;
                Ok(Type::Array(len, Box::new(ty)))
            }
            20 => {
                let fields = source.get()?;
                Ok(Type::Struct(fields))
            }
            21 => {
                let variants = source.get()?;
                Ok(Type::Enum(variants))
            }
            _ => Err(ParseError::default()),
        }
    }
}

#[cfg(feature = "derive-serde")]
impl schema::Fields {
    pub fn to_json<R: Read>(&self, source: &mut R) -> ParseResult<serde_json::Value> {
        use serde_json::*;

        match self {
            schema::Fields::Named(fields) => {
                let mut values = map::Map::new();
                for (key, ty) in fields.iter() {
                    let value = ty.to_json(source)?;
                    values.insert(key.to_string(), value);
                }
                Ok(Value::Object(values))
            }
            schema::Fields::Unnamed(fields) => {
                let mut values = Vec::new();
                for ty in fields.iter() {
                    values.push(ty.to_json(source)?);
                }
                Ok(Value::Array(values))
            }
            schema::Fields::Unit => Ok(Value::Array(vec![])),
        }
    }
}

#[cfg(feature = "derive-serde")]
impl From<std::num::TryFromIntError> for ParseError {
    fn from(_: std::num::TryFromIntError) -> Self { ParseError::default() }
}

#[cfg(feature = "derive-serde")]
impl From<std::string::FromUtf8Error> for ParseError {
    fn from(_: std::string::FromUtf8Error) -> Self { ParseError::default() }
}

#[cfg(feature = "derive-serde")]
fn deserial_length(source: &mut impl Read, size_len: &schema::SizeLength) -> ParseResult<usize> {
    let len: usize = match size_len {
        schema::SizeLength::U8 => u8::deserial(source)?.into(),
        schema::SizeLength::U16 => u16::deserial(source)?.into(),
        schema::SizeLength::U32 => u32::deserial(source)?.try_into()?,
        schema::SizeLength::U64 => u64::deserial(source)?.try_into()?,
    };
    Ok(len)
}

#[cfg(feature = "derive-serde")]
fn item_list_to_json<R: Read>(
    source: &mut R,
    size_len: &schema::SizeLength,
    item_to_json: impl Fn(&mut R) -> ParseResult<serde_json::Value>,
) -> ParseResult<Vec<serde_json::Value>> {
    let len = deserial_length(source, size_len)?;
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        let value = item_to_json(source)?;
        values.push(value);
    }
    Ok(values)
}

#[cfg(feature = "derive-serde")]
impl schema::Type {
    /// Uses the schema to deserialize bytes into pretty json
    pub fn to_json_string_pretty(&self, bytes: &[u8]) -> ParseResult<String> {
        let source = &mut Cursor::new(bytes);
        let js = self.to_json(source)?;
        serde_json::to_string_pretty(&js).map_err(|_| ParseError::default())
    }

    /// Uses the schema to deserialize bytes into json
    pub fn to_json<R: Read>(&self, source: &mut R) -> ParseResult<serde_json::Value> {
        use schema::Type;
        use serde_json::*;

        match self {
            Type::Unit => Ok(Value::Null),
            Type::Bool => {
                let n = bool::deserial(source)?;
                Ok(Value::Bool(n))
            }
            Type::U8 => {
                let n = u8::deserial(source)?;
                Ok(Value::Number(n.into()))
            }
            Type::U16 => {
                let n = u16::deserial(source)?;
                Ok(Value::Number(n.into()))
            }
            Type::U32 => {
                let n = u32::deserial(source)?;
                Ok(Value::Number(n.into()))
            }
            Type::U64 => {
                let n = u64::deserial(source)?;
                Ok(Value::Number(n.into()))
            }
            Type::I8 => {
                let n = i8::deserial(source)?;
                Ok(Value::Number(n.into()))
            }
            Type::I16 => {
                let n = i16::deserial(source)?;
                Ok(Value::Number(n.into()))
            }
            Type::I32 => {
                let n = i32::deserial(source)?;
                Ok(Value::Number(n.into()))
            }
            Type::I64 => {
                let n = i64::deserial(source)?;
                Ok(Value::Number(n.into()))
            }
            Type::Amount => {
                let n = Amount::deserial(source)?;
                Ok(Value::String(n.to_string()))
            }
            Type::AccountAddress => {
                let address = AccountAddress::deserial(source)?;
                Ok(Value::String(address.to_string()))
            }
            Type::ContractAddress => {
                let address = ContractAddress::deserial(source)?;
                Ok(Value::String(address.to_string()))
            }
            Type::Option(ty) => {
                let idx = u8::deserial(source)?;
                let some = match idx {
                    0 => Ok(false),
                    1 => Ok(true),
                    _ => Err(ParseError::default()),
                }?;
                let value = if some {
                    ty.to_json(source)
                } else {
                    Ok(Value::Null)
                }?;
                Ok(value)
            }
            Type::Pair(left_type, right_type) => {
                let left = left_type.to_json(source)?;
                let right = right_type.to_json(source)?;
                Ok(Value::Array(vec![left, right]))
            }
            Type::String(size_len) => {
                let len = deserial_length(source, size_len)?;
                let mut bytes = Vec::with_capacity(len);
                for _ in 0..len {
                    bytes.push(source.read_u8()?);
                }
                let string = String::from_utf8(bytes)?;
                Ok(Value::String(string))
            }
            Type::List(size_len, ty) => {
                let values = item_list_to_json(source, size_len, |s| ty.to_json(s))?;
                Ok(Value::Array(values))
            }
            Type::Set(size_len, ty) => {
                let values = item_list_to_json(source, size_len, |s| ty.to_json(s))?;
                Ok(Value::Array(values))
            }
            Type::Map(size_len, key_type, value_type) => {
                let values = item_list_to_json(source, size_len, |s| {
                    let key = key_type.to_json(s)?;
                    let value = value_type.to_json(s)?;
                    Ok(Value::Array(vec![key, value]))
                })?;
                Ok(Value::Array(values))
            }
            Type::Array(len, ty) => {
                let len: usize = (*len).try_into()?;
                let mut values = Vec::with_capacity(len);
                for _ in 0..len {
                    let value = ty.to_json(source)?;
                    values.push(value);
                }
                Ok(Value::Array(values))
            }
            Type::Struct(fields_ty) => {
                let fields = fields_ty.to_json(source)?;
                Ok(fields)
            }
            Type::Enum(variants) => {
                let idx = if variants.len() <= 256 {
                    u8::deserial(source)? as usize
                } else {
                    u32::deserial(source)? as usize
                };
                let (name, fields_ty) = variants.get(idx).ok_or_else(ParseError::default)?;
                let fields = fields_ty.to_json(source)?;
                Ok(json!({ name: fields }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arbitrary::*;
    use schema::*;

    #[test]
    fn test_schema_serial_deserial_is_id() {
        use rand::prelude::*;
        use rand_pcg::Pcg64;

        let seed: u64 = random();
        let mut rng = Pcg64::seed_from_u64(seed);
        println!("Seed {}", seed);
        let mut data = [0u8; 100000];
        rng.fill_bytes(&mut data);

        let mut unstructured = Unstructured::new(&data);

        for _ in 0..10000 {
            let schema = Type::arbitrary(&mut unstructured).unwrap();

            let res = from_bytes::<Type>(&to_bytes(&schema)).unwrap();
            assert_eq!(schema, res);
        }
    }
}
