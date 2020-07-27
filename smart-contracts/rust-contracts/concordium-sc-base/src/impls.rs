use crate::{convert, prims::*, types::*};
use contracts_common::*;

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

impl convert::From<()> for Reject {
    #[inline(always)]
    fn from(_: ()) -> Self { Reject {} }
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

impl Create for ContractState {
    fn new() -> Self {
        ContractState {
            current_position: 0,
        }
    }
}

impl ContractState {
    /// Make sure that the memory size is at least that many bytes in size.
    /// Returns true iff this was successful.
    pub fn reserve(&mut self, len: u32) -> bool {
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

    /// Return current size of contract state.
    pub fn size(&self) -> u32 { unsafe { state_size() } }

    /// Truncate the state to the given size. If the given size is more than the
    /// current state size this operation does nothing. The new position is at
    /// most at the end of the stream.
    pub fn truncate(&mut self, new_size: u32) {
        let cur_size = self.size();
        if cur_size > new_size {
            unsafe { resize_state(new_size) };
        }
        if new_size < self.current_position {
            self.current_position = new_size
        }
    }
}

pub trait Create {
    fn new() -> Self;
}

pub trait HasParameter: private::Sealed {
    // TODO: Add functions where a user can supply a buffer
    // for getting the parameters to avoid vector allocations.
    fn parameter_bytes(&self) -> Vec<u8> {
        let len = unsafe { get_parameter_size() };
        let mut bytes = vec![0u8; len as usize];
        unsafe { get_parameter(bytes.as_mut_ptr()) };
        bytes
    }

    fn parameter<S: Serialize>(&self) -> Result<S, ()> {
        let params = self.parameter_bytes();
        let mut cursor = Cursor::<&[u8]>::new(&params);
        cursor.get()
    }
}

impl Create for InitContext {
    /// Create a new init context by using an external call.
    fn new() -> Self {
        let mut bytes = [0u8; 4 * 8 + 32];
        // unsafe { get_chain_context(bytes.as_mut_ptr()) }
        // unsafe { get_init_ctx(bytes[4 * 8..].as_mut_ptr()) };
        unsafe { get_init_ctx(bytes.as_mut_ptr()) };
        let mut cursor = Cursor::<&[u8]>::new(&bytes);
        if let Ok(v) = cursor.get() {
            v
        } else {
            panic!()
            // Host did not provide valid init context and chain metadata.
        }
    }
}

impl Create for ReceiveContext {
    /// Create a new receive context by using an external call.
    fn new() -> Self {
        // let metadata_size = 4 * 8;
        // We reduce this to a purely stack-based allocation
        // by overapproximating the size of the context.
        // unsafe { get_receive_ctx_size() };
        let mut bytes = [0u8; 4 * 8 + 121];
        // unsafe { get_chain_context(bytes.as_mut_ptr()) }
        // unsafe { get_receive_ctx(bytes[metadata_size..].as_mut_ptr()) };
        unsafe { get_receive_ctx(bytes.as_mut_ptr()) };
        let mut cursor = Cursor::<&[u8]>::new(&bytes);
        if let Ok(v) = cursor.get() {
            v
        } else {
            panic!()
            // environment did not provide a valid receive context, this should
            // not happen and cannot be recovered.
        }
    }
}

impl HasParameter for InitContext {}
impl HasParameter for ReceiveContext {}

mod private {
    // A trick to not allow anybody else to implement HasParameter.
    // This module is not exported, hence nobody else can implement the Sealed
    // trait.
    pub trait Sealed {}
    impl Sealed for super::InitContext {}
    impl Sealed for super::ReceiveContext {}
}
