use crate::{traits::*, types::*};

#[cfg(not(feature = "std"))]
use alloc::collections;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(not(feature = "std"))]
use core::{mem::MaybeUninit, slice};
#[cfg(feature = "std")]
use std::{collections::*, mem::MaybeUninit, slice};

static MAX_PREALLOCATED_CAPACITY: usize = 4096;

// Implementations of Serialize

impl<X: Serial, Y: Serial> Serial for (X, Y) {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        self.0.serial(out)?;
        self.1.serial(out)
    }
}

impl<X: Deserial, Y: Deserial> Deserial for (X, Y) {
    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
        let x = X::deserial(source)?;
        let y = Y::deserial(source)?;
        Ok((x, y))
    }
}

impl Serial for u8 {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> { out.write_u8(*self) }
}

impl Deserial for u8 {
    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> { source.read_u8() }
}

impl Serial for u16 {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> { out.write_u16(*self) }
}

impl Deserial for u16 {
    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> { source.read_u16() }
}

impl Serial for u32 {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> { out.write_u32(*self) }
}

impl Deserial for u32 {
    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> { source.read_u32() }
}

impl Serial for u64 {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> { out.write_u64(*self) }
}

impl Deserial for u64 {
    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> { source.read_u64() }
}

impl Serial for [u8; 32] {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> { out.write_all(self) }
}

impl Deserial for [u8; 32] {
    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
        // This deliberately does not initialize the array up-front.
        // Initialization is not needed, and costs quite a bit of code space.
        // FIXME: Put this behind a feature flag to only enable for Wasm.
        // I don't think it has any meaningful effect on normal platforms.
        let mut bytes: MaybeUninit<[u8; 32]> = MaybeUninit::uninit();
        let write_bytes = unsafe { slice::from_raw_parts_mut(bytes.as_mut_ptr() as *mut u8, 32) };
        source.read_exact(write_bytes)?;
        Ok(unsafe { bytes.assume_init() })
    }
}

impl Serial for AccountAddress {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> { out.write_all(&self.0) }
}

impl Deserial for AccountAddress {
    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
        let bytes = source.get()?;
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
    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
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
    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
        let tag = u8::deserial(source)?;
        match tag {
            0 => Ok(Address::Account(source.get()?)),
            1 => Ok(Address::Contract(source.get()?)),
            _ => Err(R::Err::default()),
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
    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
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
    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
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
    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
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
) -> Result<Vec<T>, R::Err> {
    let mut vec = Vec::with_capacity(core::cmp::min(len, MAX_PREALLOCATED_CAPACITY));
    for _ in 0..len {
        vec.push(T::deserial(reader)?);
    }
    Ok(vec)
}

/// Write a Map as an list of key-value pairs ordered by the key, without the
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
) -> Result<BTreeMap<K, V>, R::Err> {
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
                    panic!("Keys not in order.")
                }
            }
        }
        x = Some(k);
    }
    Ok(out)
}

/// Read a Map as an list of key-value pairs given some length.
/// Sligthly faster version of `deserial_map_no_length` as it is skipping the
/// order checking
pub fn deserial_map_no_length_no_order_check<R: Read, K: Deserial + Ord + Copy, V: Deserial>(
    source: &mut R,
    len: usize,
) -> Result<BTreeMap<K, V>, R::Err> {
    let mut out = BTreeMap::new();
    for _ in 0..len {
        let k = source.get()?;
        let v = source.get()?;
        out.insert(k, v);
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
) -> Result<BTreeSet<K>, R::Err> {
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
                    panic!("Keys not in order.")
                }
            }
        }
        x = Some(k);
    }
    Ok(out)
}

/// Read a Set as an list of key-value pairs given some length.
/// Sligthly faster version of `deserial_set_no_length` as it is skipping the
/// order checking.
pub fn deserial_set_no_length_no_order_check<R: Read, K: Deserial + Ord>(
    source: &mut R,
    len: usize,
) -> Result<BTreeSet<K>, R::Err> {
    let mut out = BTreeSet::new();
    for _ in 0..len {
        let k = source.get()?;
        out.insert(k);
    }
    Ok(out)
}

impl<T: Serial> Serial for Vec<T> {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        let len = self.len() as u32;
        len.serial(out)?;
        serial_vector_no_length(self, out)
    }
}

impl<T: Deserial> Deserial for Vec<T> {
    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
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
    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
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
    fn deserial<R: Read>(source: &mut R) -> Result<Self, R::Err> {
        let len: u32 = source.get()?;
        deserial_set_no_length(source, len as usize)
    }
}

impl InitContext {
    pub fn init_origin(&self) -> &AccountAddress { &self.init_origin }

    /// Get time in miliseconds at the beginning of this block.
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

    /// Get time in miliseconds at the beginning of this block.
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
    type Err = ();

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Err> {
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

pub fn from_bytes<S: Deserial>(source: &[u8]) -> Result<S, ()> {
    let mut cursor = Cursor::new(source);
    cursor.get()
}
