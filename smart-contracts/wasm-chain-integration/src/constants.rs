/// Maximum size of contract state in bytes.
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
