#![no_std]
#![feature(alloc_error_handler)]
extern crate alloc;
extern crate wee_alloc;

pub mod traits;

pub use crate::traits::{Read, Seek, SeekFrom, Write};
use alloc::{alloc::Layout, vec, vec::Vec};
use core::result::*;

// Use `wee_alloc` as the global allocator.
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[alloc_error_handler]
fn on_oom(_layout: Layout) -> ! { panic!() }

#[panic_handler]
fn abort_panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[cfg_attr(target_arch = "wasm32", link(wasm_import_module = "concordium"))]
extern "C" {
    fn fail();
    fn accept();
    fn sender(addr_bytes: *mut u8); // write the sender (32 bytes) to the given location
    pub fn log_event(start: *const u8, length: u32);
    pub fn load_state(start: *mut u8, length: u32, offset: u32) -> u32; // returns how many bytes were read.
    pub fn write_state(start: *const u8, length: u32, offset: u32) -> u32; // returns how many bytes were written
    pub fn resize_state(new_size: u32) -> u32; // returns 0 or 1.
    pub fn state_size() -> u32; // get current state size in bytes.
}

pub mod internal {
    pub fn fail() { unsafe { super::fail() } }

    pub fn accept() { unsafe { super::accept() } }
}

/// A type representing the constract state bytes.
#[derive(Default)]
pub struct ContractState {
    current_position: u32,
}

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

/// The type of amounts on the chain.
pub type Amount = u64;

/// Address of an account, as raw bytes.
#[derive(Eq, PartialEq)]
pub struct AccountAddress([u8; 32]);

impl Serialize for AccountAddress {
    fn serial<W: Write>(&self, out: &mut W) -> Option<()> { out.write_all(&self.0).ok() }

    fn deserial<R: Read>(source: &mut R) -> Option<Self> {
        let mut bytes = [0u8; 32];
        source.read_exact(&mut bytes).ok()?;
        Some(AccountAddress(bytes))
    }
}

/// Chain context accessible to the init methods.
pub struct InitContext {}

impl InitContext {
    pub fn sender(&self) -> AccountAddress {
        let mut sender_bytes = [0u8; 32];
        unsafe {
            sender(sender_bytes.as_mut_ptr());
        }
        AccountAddress(sender_bytes)
    }
}

/// Chain context accessible to the receive methods.
pub struct ReceiveContext {}

impl ReceiveContext {
    pub fn sender(&self) -> AccountAddress {
        let mut sender_bytes = [0u8; 32];
        unsafe {
            sender(sender_bytes.as_mut_ptr());
        }
        AccountAddress(sender_bytes)
    }
}

pub trait Serialize: Sized {
    fn serial<W: Write>(&self, _out: &mut W) -> Option<()>;
    fn deserial<R: Read>(_source: &mut R) -> Option<Self>;
}

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

pub mod events {
    use super::*;
    #[inline(always)]
    pub fn log_bytes(event: &[u8]) {
        unsafe {
            log_event(event.as_ptr(), event.len() as u32);
        }
    }

    #[inline(always)]
    pub fn log<S: Serialize>(event: &S) {
        let mut out = Vec::new();
        event.serial(&mut out);
        log_bytes(&out)
    }

    #[inline(always)]
    pub fn log_str(event: &str) { log_bytes(event.as_bytes()) }
}

pub unsafe trait IntoActions {
    fn into_actions(self);
}

unsafe impl IntoActions for Option<()> {
    fn into_actions(self) {
        match self {
            None => unsafe { fail() },
            Some(_) => unsafe { accept() },
        }
    }
}
