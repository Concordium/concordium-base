//! Core constants used in parsing and validation.

/// The number of allowed locals in a function.
/// This includes parameters and declared locals.
pub const ALLOWED_LOCALS: u32 = 1 << 15;

/// Maximum number of bytes we will preallocate when parsing vector-like things.
/// Preallocation is more efficient than starting from 0, but we need to be
/// careful not to explode by maliciously crafted input.
pub const MAX_PREALLOCATED_BYTES: usize = 1000;

/// The maximum allowed initial table size.
/// In the version of Wasm we support there is no way to grow tables, so
/// the initial size is the size of the table.
/// Due to restrictions on module size, it is infeasible to have more than 1000
/// Functions in the table.
pub const MAX_INIT_TABLE_SIZE: u32 = 1000;

/// Size of a Wasm page in bytes.
/// This constant must be such that
/// [MAX_INIT_MEMORY_SIZE](./constant.MAX_INIT_MEMORY_SIZE.html) *
/// [PAGE_SIZE](./constant.PAGE_SIZE.html) does not overflow a u32;
pub const PAGE_SIZE: u32 = 65536;

/// Maximum number of pages for the initial memory size.
/// Corresponds to 2MB.
/// This constant must be such that
/// [MAX_INIT_MEMORY_SIZE](./constant.MAX_INIT_MEORY_SIZE.html) *
/// [PAGE_SIZE](./constant.PAGE_SIZE.html) does not overflow a u32;
pub const MAX_INIT_MEMORY_SIZE: u32 = 32;

/// Maximum number of pages allowed by our contracts.
pub const MAX_NUM_PAGES: u32 = 1024; // corresponds to 64MB memory at most.

/// Maximum number of globals allowed in a module.
/// This allows us to use a u16 for indexing and is relied upon by the
/// interpreter.
pub const MAX_NUM_GLOBALS: usize = 1000;

/// Maximum number of branches in the switch statement without the default
/// branch.
pub const MAX_SWITCH_SIZE: usize = 1 << 16;

/// Maximum height of the stack inside a single function. Checked during
/// validation. This is relied upon by the interpreter to be less than 2^31.
pub const MAX_STACK_HEIGHT: usize = 1 << 24;

/// The Wasm binary format magic hash.
pub const MAGIC_HASH: [u8; 4] = [0x00, 0x61, 0x73, 0x6D];

/// The supported Wasm version.
pub const VERSION: [u8; 4] = [0x01, 0x00, 0x00, 0x00];
