use core::cmp;

static MAX_PREALLOCATED_CAPACITY: usize = 4096;

/// As Vec::with_capacity, but only allocate maximum MAX_PREALLOCATED_CAPACITY
/// elements.
#[inline]
pub fn safe_with_capacity<T>(capacity: usize) -> Vec<T> {
    Vec::with_capacity(cmp::min(capacity, MAX_PREALLOCATED_CAPACITY))
}
