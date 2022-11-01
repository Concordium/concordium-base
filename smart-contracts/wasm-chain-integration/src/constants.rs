/// Maximum size of a V0 contract state in bytes.
pub const MAX_CONTRACT_STATE: u32 = 16384; // 16kB

/// Maximum number of nested function calls.
pub const MAX_ACTIVATION_FRAMES: u32 = 1024;

/// Maximum size of a log message.
pub const MAX_LOG_SIZE: u32 = 512;

/// Maximum number of log messages per execution in *protocol version 4 and
/// lower*. This, together with the previous constant, limits the amount of data
/// that can be logged to 16kB.
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

// TODO: These should in principle be const fn, but rust in 1.45.2 u64::from
// are not marked as const fn, so they are not.

/// Cost of copying the given amount of bytes from the host (e.g., policy or
/// contract state) to the Wasm memory. The 10 is to account for copying empty
/// buffers and is based on benchmarks.
#[inline(always)]
pub fn copy_from_host_cost(x: u32) -> u64 { 10 + u64::from(x) }

/// Cost of copying the given amount of bytes to the host (e.g., contract state)
/// from the Wasm to host memory. The 10 is to account for
/// copying empty buffers and is based on benchmarks.
#[inline(always)]
pub fn copy_to_host_cost(x: u32) -> u64 { 10 + u64::from(x) }

/// Cost of copying a V1 parameter between the Wasm memory and the host in
/// either direction.
///
/// - The cost for parameters <= 1kB is: base cost + 1NRG per *kilobyte*.
/// - The cost for parameters > 1kB is: base cost + 1NRG per *byte*.
///
/// Prior to P5, the parameters were limited to 1kB, which is why the cost
/// scheme is as it is.
///
/// Notes on the factors:
/// - The `10` is to account for copying empty buffers and is based on
///   benchmarks.
/// - The `1000` factor makes it so that the cost is 1NRG per byte.
#[inline(always)]
pub fn copy_parameter_cost(len: u32) -> u64 {
    let len = u64::from(len);
    if len <= 1024 {
        10 + len
    } else {
        10 + 1000 * len
    }
}

/// Cost of allocating additional smart contract state. The argument is the
/// number of additional bytes. The `/100` guarantees that with 3_000_000NRG
/// we can produce at most 30MB additional contract state per block.
#[inline(always)]
pub fn additional_state_size_cost(x: u64) -> u64 { x / 100 }

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

/// Cost of creating an entry in the instance state.
#[inline]
pub fn create_entry_cost(key_len: u32) -> u64 {
    // 48 accounts for overall administrative costs and storing the indirection
    // for the entry. The 8 and 100 come from experimentation and benchmarking.
    // We want to encourage short keys so we charge linearly for those.
    if key_len <= 64 {
        48 + 8 * copy_from_host_cost(key_len) + 100 * u64::from(key_len)
    } else {
        // And charge quadratically for larger keys (more than 64 bytes).
        // With this the largest key is around 40kB with 3_000_000NRG.
        let len = u64::from(key_len);
        let q = 100u64.checked_mul(len * len);
        if let Some(q) = q {
            48 + 8 * copy_from_host_cost(key_len) + q / 64
        } else {
            u64::MAX
        }
    }
}

/// Cost of looking up an entry in the instance state.
/// Compared to creating an entry this does not require extra storage for the
/// key. The only cost is tree traversal and storing an indirection, which is 8
/// bytes. With this cost we limit the amount of extra storage that is needed.
/// For each entry lookup we allocate a new pointer indirection. Which is 8
/// bytes. With these costs we limit the amount of memory needed to store these
/// indirections to 300MB for 3_000_000NRG (with current conversion rates of NRG
/// to InterpreterEnergy).
#[inline(always)]
pub fn lookup_entry_cost(key_len: u32) -> u64 {
    80 + 4 * copy_from_host_cost(key_len) + 16 * u64::from(key_len)
}

/// Cost of accessing the instance state.
pub const BASE_STATE_COST: u64 = 20;

/// Cost of allocation of one page of memory in relation to execution cost.
/// FIXME: It is unclear whether this is really necessary with the hard limit we
/// have on memory use.
/// If we keep it, the cost must be analyzed and put into perspective
pub const MEMORY_COST_FACTOR: u32 = 100;

/// Cost of the invoke action. This is just the base cost to cover
/// administrative costs of an invoke. Specific costs of the action are charged
/// later by the scheduler.
pub const INVOKE_BASE_COST: u64 = 500;

/// Cost of delete_prefix which accounts for finding the prefix. It is
/// parametrized by the length of the key.
#[inline(always)]
pub fn delete_prefix_find_cost(len: u32) -> u64 { 10 * u64::from(len) }

/// Cost of a new iterator. This accounts for tree traversal as well
/// as the storage the execution engine needs to keep for the iterator.
/// When looking up an iterator we construct a structure that keeps track of the
/// current position in the tree. This iterator is constructed for any key,
/// including the empty key. Hence the base cost of 80 is there to ensure we
/// don't run out of memory. It limits memory use to around 300MB in the worst
/// case.
///
/// Additionally, since we have to store the key for the iterator we have to
/// charge adequately so that memory use is bounded. This is the reason for the
/// 100 factor.
#[inline(always)]
pub fn new_iterator_cost(len: u32) -> u64 { 80 + 100 * u64::from(len) }

/// Basic administrative cost that is charged when an invalid iterator is
/// attempted to be deleted.
pub const DELETE_ITERATOR_BASE_COST: u64 = 10;

/// Delete an iterator. Since we need to unlock the region locked by it this
/// cost is based on the length of the key. The exact factor of 32 is estimated
/// based on benchmarks.
#[inline(always)]
pub fn delete_iterator_cost(len: u32) -> u64 { 32 + 32 * u64::from(len) }

/// Cost of return the size of the iterator key. This is constant since the
/// iterator key is readily available.
pub const ITERATOR_KEY_SIZE_COST: u64 = 10;

/// Basic administrative cost of advancing an iterator.
pub const ITERATOR_NEXT_COST: u64 = 32;

/// Step cost of a tree traversal when invalidating entries when deleting a
/// prefix, as well as when advancing an iterator.
pub const TREE_TRAVERSAL_STEP_COST: u64 = 40;

/// Cost of deleting an entry based on key length. This involves lookup in the
/// "locked" map so it is relatively expensive.
#[inline(always)]
pub fn delete_entry_cost(key_len: u32) -> u64 {
    80 + 4 * copy_from_host_cost(key_len) + 16 * u64::from(key_len)
}

/// Base cost of resizing an entry. This accounts for lookup of the entry.
/// When the entry is resized to a larger value there is additional cost charged
/// based on how much extra memory there is.
pub const RESIZE_ENTRY_BASE_COST: u64 = 10;

/// Maximum size (in bytes) of data in the entry. The execution engine relies on
/// this being strictly less than [u32::MAX].
/// Realistically this is much above any bound implied by energy, however it is
/// good to have it explicit since correctness of the implementation relies on
/// this.
pub const MAX_ENTRY_SIZE: usize = 1 << 30;

/// Maximum size of a key in V1 contract state. The execution engine relies on
/// this being strictly less than [u32::MAX].
/// Realistically this is much above any bound implied by energy, however it is
/// good to have it explicit since correctness of the implementation relies on
/// this.
pub const MAX_KEY_SIZE: usize = 1 << 30;

/// Cost of allocating additional data in the entry. The argument is the
/// number of additional bytes.
/// This is needed since we do allocate memory on entry_resize. As a result
/// we must bound how much can be allocated.
/// With `100` we have at most 30MB of memory allocated with 3000000NRG. We can
/// relax this a bit, but not much.
#[inline(always)]
pub fn additional_entry_size_cost(x: u64) -> u64 { 100 * x }

/// Cost of querying entry size.
pub const ENTRY_SIZE_COST: u64 = 32;

/// Cost of copying the given amount of bytes from the host (e.g., parameter or
/// contract state) to the Wasm memory.
#[inline(always)]
pub fn read_entry_cost(x: u32) -> u64 { 32 + u64::from(x / 8) }
/// Cost of copying the given amount of bytes to the host (e.g., parameter or
/// contract state) from the Wasm to host memory.
#[inline(always)]
pub fn write_entry_cost(x: u32) -> u64 { 32 + u64::from(x / 8) }

/// Cost of writing the given bytes of the return value.
#[inline(always)]
pub fn write_output_cost(x: u32) -> u64 { 10 + u64::from(x) }

/// Cost of adding an additional byte to the output. With the factor of 30
/// and 3000000NRG there can be at most 100MB of output produced.
#[inline(always)]
pub fn additional_output_size_cost(x: u64) -> u64 { 30 * x }

/// Cost of verification of an ed25519 with the Zebra implementation.
/// The cost depends on the size of the message and is based on benchmarking.
pub fn verify_ed25519_cost(message_len: u32) -> u64 { 100_000 + 100 * u64::from(message_len) }

/// Cost of verification of an ecdsa over secp256k1 with the bitcoin-core
/// implementation. Since signature verification only works on 32 byte messages
/// (which are meant to be hashes) the cost is constant.
pub const VERIFY_ECDSA_SECP256K1_COST: u64 = 100_000;

/// Cost of computing a SHA2-256 digest of the message of the given length.
pub fn hash_sha2_256_cost(data_len: u32) -> u64 { 500 + 7 * u64::from(data_len) }

/// Cost of computing a SHA3-256 digest of the message of the given length.
pub fn hash_sha3_256_cost(data_len: u32) -> u64 { 500 + 5 * u64::from(data_len) }

/// Cost of computing a Keccak-256 digest of the message of the given length.
pub fn hash_keccak_256_cost(data_len: u32) -> u64 { 500 + 5 * u64::from(data_len) }
