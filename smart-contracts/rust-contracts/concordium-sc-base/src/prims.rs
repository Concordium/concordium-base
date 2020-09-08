//! This internal module provides the primitive interface to the chain.
//! Functions here should be wrapped in safer wrappers when used from contracts.

use contracts_common::*;

/// Interface to the chain. These functions are assumed to be instantiated by
/// the scheduler with relevant primitives.
#[cfg_attr(target_arch = "wasm32", link(wasm_import_module = "concordium"))]
extern "C" {
    pub(crate) fn accept() -> u32;
    // Basic action to send tokens to an account.
    pub(crate) fn simple_transfer(addr_bytes: *const u8, amount: u64) -> u32;
    // Send a message to a smart contract.
    pub(crate) fn send(
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
    pub(crate) fn combine_and(l: u32, r: u32) -> u32;
    // Combine two actions using or. This is using the stack of actions already
    // produced.
    pub(crate) fn combine_or(l: u32, r: u32) -> u32;
    // Get the size of the parameter to the method (either init or receive).
    pub(crate) fn get_parameter_size() -> u32;
    // Write a section of the parameter to the given location. Return the number
    // of bytes written. The location is assumed to contain enough memory to
    // write the requested length into.
    pub(crate) fn get_parameter_section(param_bytes: *mut u8, length: u32, offset: u32) -> u32;
    // Add a log item.
    pub(crate) fn log_event(start: *const u8, length: u32);
    // returns how many bytes were read.
    pub(crate) fn load_state(start: *mut u8, length: u32, offset: u32) -> u32;
    // returns how many bytes were written
    pub(crate) fn write_state(start: *const u8, length: u32, offset: u32) -> u32;
    // Resize state to the new value (truncate if new size is smaller). Return 0 if
    // this was unsuccesful (new state too big), or 1 if successful.
    pub(crate) fn resize_state(new_size: u32) -> u32; // returns 0 or 1.
                                                      // get current state size in bytes.
    pub(crate) fn state_size() -> u32;
    
    // Getter for the init context.
    /// Address of the sender, 32 bytes
    pub(crate) fn get_init_origin(start: *mut u8);
    
    // Getters for the receive context
    /// Invoker of the top-level transaction, AccountAddress.
    pub(crate) fn get_receive_invoker(start: *mut u8);
    /// Address of the contract itself, ContractAddress.
    pub(crate) fn get_receive_self_address(start: *mut u8);
    /// Self-balance of the contract.
    pub(crate) fn get_receive_self_balance() -> Amount;
    /// Immediate sender of the message (either contract or account).
    pub(crate) fn get_receive_sender(start: *mut u8);
    /// Owner of the contract, AccountAddress.
    pub(crate) fn get_receive_owner(start: *mut u8);

    // Getters for the chain meta data
    /// Slot number
    pub(crate) fn get_slot_number() -> SlotNumber;
    /// Block height
    pub(crate) fn get_block_height() -> BlockHeight;
    /// Finalized height
    pub(crate) fn get_finalized_height() -> FinalizedHeight;
    /// Slot time (in milliseconds)
    pub(crate) fn get_slot_time() -> SlotTime;

}
