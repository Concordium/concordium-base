#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::traits::Serialize;

#[cfg_attr(target_arch = "wasm32", link(wasm_import_module = "concordium"))]
extern "C" {
    fn fail();
    fn accept();
    pub(crate) fn sender(addr_bytes: *mut u8); // write the sender (32 bytes) to the given location
    pub fn log_event(start: *const u8, length: u32);
    pub fn load_state(start: *mut u8, length: u32, offset: u32) -> u32; // returns how many bytes were read.
    pub fn write_state(start: *const u8, length: u32, offset: u32) -> u32; // returns how many bytes were written
    pub fn resize_state(new_size: u32) -> u32; // returns 0 or 1.
    pub fn state_size() -> u32; // get current state size in bytes.
}

pub mod internal {
    #[inline(always)]
    pub fn fail() { unsafe { super::fail() } }

    #[inline(always)]
    pub fn accept() { unsafe { super::accept() } }
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
