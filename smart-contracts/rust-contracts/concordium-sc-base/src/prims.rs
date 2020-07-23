//! This internal module provides the primitive interface to the chain.
//! Functions here should be wrapped in safer wrappers when used from contracts.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::traits::Serialize;

/// Interface to the chain. These functions are assumed to be instantiated by
/// the scheduler with relevant primitives.
#[cfg_attr(target_arch = "wasm32", link(wasm_import_module = "concordium"))]
extern "C" {
    // Signal failure.
    fn fail();
    fn accept();
    // Basic action to send tokens to an account.
    fn simple_transfer(addr_bytes: *const u8, amount: u64);
    // Send a message to a smart contract.
    fn send(
        addr_index: u64,
        addr_subindex: u64,
        receive_name: *const u8,
        receive_name_len: u32,
        amount: u64,
        parameter: *const u8,
        parameter_len: u32,
    );
    // Combine two actions using normal sequencing. This is using the stack of
    // actions already produced.
    fn combine_and();
    // Combine two actions using or. This is using the stack of actions already
    // produced.
    fn combine_or();
    // Get the size of the parameter to the method (either init or receive).
    pub(crate) fn get_parameter_size() -> u32;
    // Write the parameter to the given location. The location is assumed to contain
    // enough memory to write the parameter into (as returned by the previous
    // method).
    pub(crate) fn get_parameter(param_bytes: *mut u8) -> u32;
    // Add a log item.
    fn log_event(start: *const u8, length: u32);
    // returns how many bytes were read.
    pub(crate) fn load_state(start: *mut u8, length: u32, offset: u32) -> u32;
    // returns how many bytes were written
    pub(crate) fn write_state(start: *const u8, length: u32, offset: u32) -> u32;
    // Resize state to the new value (truncate if new size is smaller). Return 0 if
    // this was unsuccesful (new state too big), or 1 if successful.
    pub(crate) fn resize_state(new_size: u32) -> u32; // returns 0 or 1.
                                                      // get current state size in bytes.
    pub(crate) fn state_size() -> u32;

    // Write the chain context to the given location. Chain context
    // is fixed-length consisting of
    // - slotNumber
    // - blockHeight
    // - finalizedHeight
    // - slotTime (in milliseconds)
    pub(crate) fn get_chain_context(start: *mut u8);
    // Get the init context (without the chain context).
    // This consists of
    // - address of the sender, 32 bytes
    pub(crate) fn get_init_ctx(start: *mut u8);

    pub(crate) fn get_receive_ctx_size() -> u32;
    // Get the receive context (without the chain context).
    // This consists of
    // - invoker of the top-level transaction
    // - address of the contract itself
    // - self-balance of the contract
    // - immediate sender of the message (either contract or account)
    // - owner of the contract.
    pub(crate) fn get_receive_ctx(start: *mut u8);
}

pub mod actions {
    //! The actions that a smart contract can produce as a
    //! result of its execution. These actions form a tree and are executed by
    //! the scheduler in the predefined order.
    use crate::types::{AccountAddress, Action, Amount, ContractAddress};

    impl Action {
        /// Send a given amount to an account.
        #[inline(always)]
        pub fn simple_transfer(acc: &AccountAddress, amount: Amount) -> Self {
            unsafe { super::simple_transfer(acc.0.as_ptr(), amount) };
            Action {
                _private: (),
            }
        }

        /// Send a message to a contract.
        #[inline(always)]
        pub fn send(
            ca: &ContractAddress,
            receive_name: &str,
            amount: Amount,
            parameter: &[u8],
        ) -> Self {
            let receive_bytes = receive_name.as_bytes();
            unsafe {
                super::send(
                    ca.index,
                    ca.subindex,
                    receive_bytes.as_ptr(),
                    receive_bytes.len() as u32,
                    amount,
                    parameter.as_ptr(),
                    parameter.len() as u32,
                )
            };
            Action {
                _private: (),
            }
        }

        /// If the execution of the first action succeeds, run the second action
        /// as well.
        #[inline(always)]
        pub fn and_then(self, _then: Self) -> Self {
            unsafe { super::combine_and() };
            Action {
                _private: (),
            }
        }

        /// If the execution of the first action fails, try the second.
        #[inline(always)]
        pub fn or_else(self, _el: Self) -> Self {
            unsafe { super::combine_or() }
            Action {
                _private: (),
            }
        }
    }
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
