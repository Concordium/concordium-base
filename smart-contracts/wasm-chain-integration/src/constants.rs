/// Maximum size of a V0 contract state in bytes.
pub const MAX_CONTRACT_STATE: u32 = 16384; // 16kB

/// Maximum number of nested function calls.
pub const MAX_ACTIVATION_FRAMES: u32 = 1024;

/// Maximum size of the init/receive parameter.
pub const MAX_PARAMETER_SIZE: usize = 1024;

/// Maximum size of a log message.
pub const MAX_LOG_SIZE: u32 = 512;

/// Maximum number of log messages per execution.
/// This together with the previous constant limits the amount of data that can
/// be logged to 16kB.
pub const MAX_NUM_LOGS: usize = 64;

/// Base cost of a log event call.
pub const LOG_EVENT_BASE_COST: u64 = 500;

/// Base cost of any action. With this cost there can be at most
/// 3_000_000 actions produced in a block (with 3_000_000NRG maximum).
/// A memory representation of a single action is 16 bytes, which
/// would lead to 48MB memory being used temporarily for the buffer.
pub const BASE_ACTION_COST: u64 = 1000;

/// Base cost of a send action. There is more data and it also requires
/// allocations which are a significant cost. The fixed amount of data is 72
/// bytes.
pub const BASE_SEND_ACTION_COST: u64 = BASE_ACTION_COST + 72000;

/// Base cost of a simple_transfer action. There is more data (40 bytes) and it
/// also requires allocations which are a significant cost.
pub const BASE_SIMPLE_TRANSFER_ACTION_COST: u64 = BASE_ACTION_COST + 40000;

/// TODO: These should in principle be const fn, but rust in 1.45.2 u64::from
/// are not marked as const fn, so they are not.

/// Cost of copying the given amount of bytes from the host (e.g., parameter or
/// contract state) to the Wasm memory.
#[inline(always)]
pub fn copy_from_host_cost(x: u32) -> u64 { 10 + u64::from(x) }
/// Cost of copying the given amount of bytes from the host (e.g., parameter or
/// contract state) from the Wasm to host memory.
#[inline(always)]
pub fn copy_to_host_cost(x: u32) -> u64 { 10 + u64::from(x) }

/// Cost of allocating additional smart contract state. The argument is the
/// number of additional bytes.
#[inline(always)]
pub fn additional_state_size_cost(x: u32) -> u64 { u64::from(x) / 100 }

/// Cost of logging an event of a given size.
#[inline(always)]
pub fn log_event_cost(x: u32) -> u64 {
    // this corresponds to 1NRG per byte stored + base cost
    LOG_EVENT_BASE_COST + 1000 * u64::from(x)
}

/// Cost of a "send" action. `x` is the size of the parameter in bytes.
#[inline(always)]
pub fn action_send_cost(x: u32) -> u64 {
    // the 1000 factor corresponds to 1NRG per byte.
    // With this the maximum amount of data that would have to be stored would be
    // 3MB with the expected maximum of 3000000NRG per block
    BASE_SEND_ACTION_COST + 1000 * u64::from(x)
}

/// Cost of traversing a key in the instance state.
#[inline(always)]
pub fn traverse_key_cost(key_len: u32) -> u64 {
    BASE_STATE_COST + copy_to_host_cost(key_len) + u64::from(key_len)
}

/// Cost of updating/inserting an entry in the instance state.
#[inline(always)]
pub fn modify_key_cost(key_len: u32) -> u64 { 2 * traverse_key_cost(key_len) }

/// Cost of accessing the instance state.
pub const BASE_STATE_COST: u64 = 10;

/// Cost of allocation of one page of memory in relation to execution cost.
/// FIXME: It is unclear whether this is really necessary with the hard limit we
/// have on memory use.
/// If we keep it, the cost must be analyzed and put into perspective
pub const MEMORY_COST_FACTOR: u32 = 100;

/// Cost of the invoke action. This is just the base cost to cover
/// administrative costs of an invoke. Specific costs of the action are charged
/// later by the scheduler.
pub const INVOKE_BASE_COST: u64 = 500; // currently set as log event base cost. Revise based on benchmarks.

/// Step cost of a tree traversal when invalidating entries.
/// TODO: Needs benchmarking.
pub const TREE_TRAVERSAL_STEP_COST: u64 = 10;
