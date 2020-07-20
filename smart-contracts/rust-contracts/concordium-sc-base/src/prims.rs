#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::traits::Serialize;

#[cfg_attr(target_arch = "wasm32", link(wasm_import_module = "concordium"))]
extern "C" {
    fn fail();
    fn accept();
    // write the sender (32 bytes) to the given location
    pub(crate) fn sender(addr_bytes: *mut u8);
    pub fn log_event(start: *const u8, length: u32);
    // returns how many bytes were read.
    pub fn load_state(start: *mut u8, length: u32, offset: u32) -> u32;
    // returns how many bytes were written
    pub fn write_state(start: *const u8, length: u32, offset: u32) -> u32;
    pub fn resize_state(new_size: u32) -> u32; // returns 0 or 1.
    pub fn state_size() -> u32; // get current state size in bytes.
}

pub mod internal {
    //! Internal functions that should not be used in most cases, but could be
    //! necessary in some cases to improve efficiency.
    #[inline(always)]
    /// Signal that the contract wishes to reject the invocation.
    pub fn fail() { unsafe { super::fail() } }

    #[inline(always)]
    /// Signal that the contract accepts the invocation.
    pub fn accept() { unsafe { super::accept() } }
}

pub mod events {
    //! This module provides logging functions that can be used by smart
    //! contracts to record events that might be of interest to external
    //! parties. These events are not used on the chain, and cannot be observed
    //! by other contracts, but they are stored by the node, and can be queried
    //! to provide information to off-chain actors.
    use super::*;
    #[inline(always)]
    /// Log an array of bytes as-is.
    pub fn log_bytes(event: &[u8]) {
        unsafe {
            log_event(event.as_ptr(), event.len() as u32);
        }
    }

    #[inline(always)]
    /// Log a serializable event by serializing it with a supplied serializer.
    pub fn log<S: Serialize>(event: &S) {
        let mut out = Vec::new();
        event.serial(&mut out);
        log_bytes(&out)
    }

    #[inline(always)]
    /// Log the given string, encoded as utf-8.
    pub fn log_str(event: &str) { log_bytes(event.as_bytes()) }
}
