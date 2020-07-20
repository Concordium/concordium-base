use crate::{prims::*, traits::*, types::*};

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

impl Serialize for AccountAddress {
    fn serial<W: Write>(&self, out: &mut W) -> Option<()> { out.write_all(&self.0).ok() }

    fn deserial<R: Read>(source: &mut R) -> Option<Self> {
        let mut bytes = [0u8; 32];
        source.read_exact(&mut bytes).ok()?;
        Some(AccountAddress(bytes))
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

impl InitContext {
    pub fn sender(&self) -> AccountAddress {
        let mut sender_bytes = [0u8; 32];
        unsafe {
            sender(sender_bytes.as_mut_ptr());
        }
        AccountAddress(sender_bytes)
    }
}

impl ReceiveContext {
    pub fn sender(&self) -> AccountAddress {
        let mut sender_bytes = [0u8; 32];
        unsafe {
            sender(sender_bytes.as_mut_ptr());
        }
        AccountAddress(sender_bytes)
    }
}
