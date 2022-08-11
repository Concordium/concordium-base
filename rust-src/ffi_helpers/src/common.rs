#[no_mangle]
/// Free an array that was converted to a pointer from a vector.
/// This assumes the vector's capacity and length were the same.
extern "C" fn free_array_len(ptr: *mut u8, len: u64) {
    unsafe {
        Vec::from_raw_parts(ptr, len as usize, len as usize);
    }
}
