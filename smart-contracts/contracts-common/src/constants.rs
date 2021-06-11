/// Maximum size of function names.
/// A contract name is defined by its init name, so this also limits the size
/// of contract names.
pub const MAX_FUNC_NAME_SIZE: usize = 100;

pub(crate) static MAX_PREALLOCATED_CAPACITY: usize = 4096;
