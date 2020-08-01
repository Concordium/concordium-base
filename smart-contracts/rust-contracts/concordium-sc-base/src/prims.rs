//! This internal module provides the primitive interface to the chain.
//! Functions here should be wrapped in safer wrappers when used from contracts.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use contracts_common::*;

/// Interface to the chain. These functions are assumed to be instantiated by
/// the scheduler with relevant primitives.
#[cfg_attr(target_arch = "wasm32", link(wasm_import_module = "concordium"))]
extern "C" {
    fn accept() -> u32;
    // Basic action to send tokens to an account.
    fn simple_transfer(addr_bytes: *const u8, amount: u64) -> u32;
    // Send a message to a smart contract.
    fn send(
        addr_index: u64,
        addr_subindex: u64,
        receive_name: *const u8,
        receive_name_len: u32,
        amount: u64,
        parameter: *const u8,
        parameter_len: u32,
    ) -> u32;
    // Combine two actions using normal sequencing. This is using the stack of
    // actions already produced.
    fn combine_and(l: u32, r: u32) -> u32;
    // Combine two actions using or. This is using the stack of actions already
    // produced.
    fn combine_or(l: u32, r: u32) -> u32;
    // Get the size of the parameter to the method (either init or receive).
    pub(crate) fn get_parameter_size() -> u32;
    // Write a section of the parameter to the given location. Return the number
    // of bytes written. The location is assumed to contain enough memory to
    // write the requested length into.
    pub(crate) fn get_parameter_section(param_bytes: *mut u8, length: u32, offset: u32) -> u32;
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
    // pub(crate) fn get_chain_context(start: *mut u8);
    // Get the init context (without the chain context).
    // This consists of
    // - address of the sender, 32 bytes
    pub(crate) fn get_init_ctx(start: *mut u8);

    // FIXME: Resolve this so the annotation is not needed.
    #[allow(dead_code)]
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
    use crate::types::Action;
    use contracts_common::{AccountAddress, Amount, ContractAddress};

    impl Action {
        /// Default accept action.
        pub fn accept() -> Self {
            Action {
                _private: unsafe { super::accept() },
            }
        }

        /// Send a given amount to an account.
        #[inline(always)]
        pub fn simple_transfer(acc: &AccountAddress, amount: Amount) -> Self {
            let res = unsafe { super::simple_transfer(acc.0.as_ptr(), amount) };
            Action {
                _private: res,
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
            let res = unsafe {
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
                _private: res,
            }
        }

        /// If the execution of the first action succeeds, run the second action
        /// as well.
        #[inline(always)]
        pub fn and_then(self, then: Self) -> Self {
            let res = unsafe { super::combine_and(self._private, then._private) };
            Action {
                _private: res,
            }
        }

        /// If the execution of the first action fails, try the second.
        #[inline(always)]
        pub fn or_else(self, el: Self) -> Self {
            let res = unsafe { super::combine_or(self._private, el._private) };
            Action {
                _private: res,
            }
        }
    }
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
        if event.serial(&mut out).is_err() {
            panic!();
            // should not happen
        }
        log_bytes(&out)
    }
}
