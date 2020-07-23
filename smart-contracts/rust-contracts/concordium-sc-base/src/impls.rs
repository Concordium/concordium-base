use crate::{collections, prims::*, traits::*, types::*};

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

// Implementations of Serialize

impl<X: Serialize, Y: Serialize> Serialize for (X, Y) {
    fn serial<W: Write>(&self, out: &mut W) -> Option<()> {
        self.0.serial(out)?;
        self.1.serial(out)
    }

    fn deserial<R: Read>(source: &mut R) -> Option<Self> {
        let x = X::deserial(source)?;
        let y = Y::deserial(source)?;
        Some((x, y))
    }
}

impl Serialize for u8 {
    fn serial<W: Write>(&self, out: &mut W) -> Option<()> { out.write_u8(*self).ok() }

    fn deserial<R: Read>(source: &mut R) -> Option<Self> { source.read_u8().ok() }
}

impl Serialize for u32 {
    fn serial<W: Write>(&self, out: &mut W) -> Option<()> { out.write_u32(*self).ok() }

    fn deserial<R: Read>(source: &mut R) -> Option<Self> { source.read_u32().ok() }
}

impl Serialize for u64 {
    fn serial<W: Write>(&self, out: &mut W) -> Option<()> { out.write_u64(*self).ok() }

    fn deserial<R: Read>(source: &mut R) -> Option<Self> { source.read_u64().ok() }
}

impl Serialize for [u8; 32] {
    fn serial<W: Write>(&self, out: &mut W) -> Option<()> { out.write_all(self).ok() }

    fn deserial<R: Read>(source: &mut R) -> Option<Self> {
        let mut bytes = [0u8; 32];
        source.read_exact(&mut bytes).ok()?;
        Some(bytes)
    }
}

impl Serialize for AccountAddress {
    fn serial<W: Write>(&self, out: &mut W) -> Option<()> { out.write_all(&self.0).ok() }

    fn deserial<R: Read>(source: &mut R) -> Option<Self> {
        let mut bytes = [0u8; 32];
        source.read_exact(&mut bytes).ok()?;
        Some(AccountAddress(bytes))
    }
}

impl Serialize for ContractAddress {
    fn serial<W: Write>(&self, out: &mut W) -> Option<()> {
        out.write_u64(self.index).ok()?;
        out.write_u64(self.subindex).ok()
    }

    fn deserial<R: Read>(source: &mut R) -> Option<Self> {
        let index = source.get()?;
        let subindex = source.get()?;
        Some(ContractAddress {
            index,
            subindex,
        })
    }
}

impl Serialize for Address {
    fn serial<W: Write>(&self, out: &mut W) -> Option<()> {
        match self {
            Address::Account(ref acc) => {
                out.write_u8(0).ok()?;
                acc.serial(out)
            }
            Address::Contract(ref cnt) => {
                out.write_u8(0).ok()?;
                cnt.serial(out)
            }
        }
    }

    fn deserial<R: Read>(source: &mut R) -> Option<Self> {
        let tag = u8::deserial(source)?;
        match tag {
            0 => Some(Address::Account(source.get()?)),
            1 => Some(Address::Contract(source.get()?)),
            _ => None,
        }
    }
}

impl Serialize for InitContext {
    fn serial<W: Write>(&self, out: &mut W) -> Option<()> {
        self.metadata.serial(out)?;
        self.init_origin.serial(out)
    }

    fn deserial<R: Read>(source: &mut R) -> Option<Self> {
        let metadata = source.get()?;
        let init_origin = source.get()?;
        Some(Self {
            metadata,
            init_origin,
        })
    }
}

impl Serialize for ReceiveContext {
    fn serial<W: Write>(&self, out: &mut W) -> Option<()> {
        self.metadata.serial(out)?;
        self.invoker.serial(out)?;
        self.self_address.serial(out)?;
        self.self_balance.serial(out)?;
        self.sender.serial(out)?;
        self.owner.serial(out)
    }

    fn deserial<R: Read>(source: &mut R) -> Option<Self> {
        let metadata = source.get()?;
        let invoker = source.get()?;
        let self_address = source.get()?;
        let self_balance = source.get()?;
        let sender = source.get()?;
        let owner = source.get()?;
        Some(ReceiveContext {
            metadata,
            invoker,
            self_address,
            self_balance,
            sender,
            owner,
        })
    }
}

impl Serialize for ChainMetadata {
    fn serial<W: Write>(&self, out: &mut W) -> Option<()> {
        self.slot_number.serial(out)?;
        self.block_height.serial(out)?;
        self.finalized_height.serial(out)?;
        self.slot_time.serial(out)
    }

    fn deserial<R: Read>(source: &mut R) -> Option<Self> {
        let slot_number = source.get()?;
        let block_height = source.get()?;
        let finalized_height = source.get()?;
        let slot_time = source.get()?;
        Some(Self {
            slot_number,
            block_height,
            finalized_height,
            slot_time,
        })
    }
}

impl<K: Serialize + Ord, V: Serialize> Serialize for collections::BTreeMap<K, V> {
    fn serial<W: Write>(&self, out: &mut W) -> Option<()> {
        let len = self.len() as u32;
        len.serial(out)?;
        for (k, v) in self.iter() {
            k.serial(out)?;
            v.serial(out)?;
        }
        Some(())
    }

    fn deserial<R: Read>(source: &mut R) -> Option<Self> {
        let len: u32 = source.get()?;
        // FIXME: Ensure order.
        let mut map = collections::BTreeMap::<K, V>::new();
        for _ in 0..len {
            let k = source.get()?;
            let v = source.get()?;
            map.insert(k, v)?;
        }
        Some(map)
    }
}

// Implementations of seek/read/write

impl Seek for ContractState {
    type Err = ();

    fn seek(&mut self, pos: SeekFrom) -> Result<u64, Self::Err> {
        use core::convert::TryFrom;
        use SeekFrom::*;
        match pos {
            Start(offset) => match u32::try_from(offset) {
                Ok(offset_u32) => {
                    self.current_position = offset_u32;
                    Ok(offset)
                }
                _ => Err(()),
            },
            End(delta) => {
                let end = self.size();
                if delta >= 0 {
                    match u32::try_from(delta)
                        .ok()
                        .and_then(|x| self.current_position.checked_add(x))
                    {
                        Some(offset_u32) => {
                            self.current_position = offset_u32;
                            Ok(u64::from(offset_u32))
                        }
                        _ => Err(()),
                    }
                } else {
                    match delta.checked_abs().and_then(|x| u32::try_from(x).ok()) {
                        Some(before) if before <= end => {
                            let new_pos = end - before;
                            self.current_position = new_pos;
                            Ok(u64::from(new_pos))
                        }
                        _ => Err(()),
                    }
                }
            }
            Current(delta) => {
                let new_offset = if delta >= 0 {
                    u32::try_from(delta).ok().and_then(|x| self.current_position.checked_add(x))
                } else {
                    delta
                        .checked_abs()
                        .and_then(|x| u32::try_from(x).ok())
                        .and_then(|x| self.current_position.checked_sub(x))
                };
                match new_offset {
                    Some(offset) => {
                        self.current_position = offset;
                        Ok(u64::from(offset))
                    }
                    _ => Err(()),
                }
            }
        }
    }
}

impl Read for ContractState {
    type Err = ();

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Err> {
        use core::convert::TryInto;
        let len: u32 = {
            match buf.len().try_into() {
                Ok(v) => v,
                _ => return Err(()),
            }
        };
        let num_read = unsafe { load_state(buf.as_mut_ptr(), len, self.current_position) };
        self.current_position += num_read;
        Ok(num_read as usize)
    }
}

impl Write for ContractState {
    type Err = ();

    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Err> {
        use core::convert::TryInto;
        let len: u32 = {
            match buf.len().try_into() {
                Ok(v) => v,
                _ => return Err(()),
            }
        };
        if self.current_position.checked_add(len).is_none() {
            return Err(());
        }
        let num_bytes = unsafe { write_state(buf.as_ptr(), len, self.current_position) };
        self.current_position += num_bytes; // safe because of check above that len + pos is small enough
        Ok(num_bytes as usize)
    }
}

// Implementations of non-trait functionality for defined types.

impl ContractState {
    pub fn new() -> Self {
        ContractState {
            current_position: 0,
        }
    }

    /// Make sure that the memory size is at least that many bytes in size.
    /// Returns true iff this was successful.
    pub fn reserve(&self, len: u32) -> bool {
        let cur_size = unsafe { state_size() };
        if cur_size < len {
            let res = unsafe { resize_state(len) };
            res == 1
        } else {
            true
        }
    }

    /// Get the full contract state as a byte array.
    pub fn get_all(&self) -> Vec<u8> {
        let len = unsafe { state_size() };
        let mut out: Vec<u8> = vec![0u8; len as usize];
        let res = unsafe { load_state(out.as_mut_ptr(), len, 0u32) };
        if res != len {
            panic!()
        }
        out
    }

    pub fn size(&self) -> u32 { unsafe { state_size() } }
}

/// Create a new init context by using an external call.
impl Default for InitContext {
    fn default() -> Self { Self::new() }
}

impl InitContext {
    /// Create a new init context by using an external call.
    pub fn new() -> Self {
        let mut bytes = [0u8; 4 * 8 + 32];
        unsafe { get_chain_context(bytes.as_mut_ptr()) }
        unsafe { get_init_ctx(bytes[4 * 8..].as_mut_ptr()) };
        let mut cursor = Cursor::<&[u8]>::new(&bytes);
        cursor.get().expect(
            "Invariant violation, host did not provide valid init context and chain metadata.",
        )
    }

    pub fn sender(&self) -> &AccountAddress { &self.init_origin }

    pub fn parameter_bytes(&self) -> Vec<u8> {
        let len = unsafe { get_parameter_size() };
        let mut bytes = vec![0u8; len as usize];
        unsafe { get_parameter(bytes.as_mut_ptr()) };
        bytes
    }

    pub fn parameter<S: Serialize>(&self) -> Option<S> {
        let params = self.parameter_bytes();
        let mut cursor = Cursor::<&[u8]>::new(&params);
        cursor.get()
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

/// Create a new receive context by using an external call.
impl Default for ReceiveContext {
    fn default() -> Self { Self::new() }
}

impl ReceiveContext {
    /// Create a new receive context by using an external call.
    pub fn new() -> Self {
        let metadata_size = 4 * 8;
        let size = unsafe { get_receive_ctx_size() };
        let mut bytes = vec![0u8; metadata_size + size as usize];
        unsafe { get_chain_context(bytes.as_mut_ptr()) }
        unsafe { get_receive_ctx(bytes[metadata_size..].as_mut_ptr()) };
        let mut cursor = Cursor::<&[u8]>::new(&bytes);
        let ctx = cursor.get();
        ctx.expect("Invariant violation: environment did not provide valid receive context.")
    }

    pub fn sender(&self) -> &Address { &self.sender }

    pub fn parameter_bytes(&self) -> Vec<u8> {
        let len = unsafe { get_parameter_size() };
        let mut bytes = vec![0u8; len as usize];
        unsafe { get_parameter(bytes.as_mut_ptr()) };
        bytes
    }

    pub fn parameter<S: Serialize>(&self) -> Option<S> {
        let params = self.parameter_bytes();
        let mut cursor = Cursor::<&[u8]>::new(&params);
        cursor.get()
    }

    /// Get time in miliseconds at the beginning of this block.
    pub fn get_time(&self) -> u64 { self.metadata.slot_time }

    /// Who is the owner of this contract.
    pub fn owner(&self) -> &AccountAddress { &self.owner }

    /// Balance on the smart contract when it was invoked.
    pub fn self_balance(&self) -> Amount { self.self_balance }

    /// Address of the smart contract.
    pub fn self_address(&self) -> &ContractAddress { &self.self_address }
}

pub struct Cursor<T> {
    pub offset: usize,
    pub data:   T,
}

impl<T> Cursor<T> {
    pub fn new(data: T) -> Self {
        Cursor {
            offset: 0,
            data,
        }
    }
}

impl Read for Cursor<&[u8]> {
    type Err = ();

    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Err> {
        let mut len = self.data.len() - self.offset;
        if len > buf.len() {
            len = buf.len();
        }
        if len > 0 {
            buf[0..len].copy_from_slice(&self.data[self.offset..self.offset + len]);
            self.offset += len;
            Ok(len)
        } else {
            Ok(0)
        }
    }
}
