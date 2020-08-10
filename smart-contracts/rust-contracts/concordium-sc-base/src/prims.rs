//! This internal module provides the primitive interface to the chain.
//! Functions here should be wrapped in safer wrappers when used from contracts.

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
