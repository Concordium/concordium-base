#[no_mangle]
/// Free an array that was converted to a pointer from a vector.
/// This assumes the vector's capacity and length were the same.
#[deprecated(note="use [`free_array_len_cap`] instead since it correctly frees the whole capacity size of the vector.")]
extern "C" fn free_array_len(ptr: *mut u8, len: u64) {
    unsafe {
        Vec::from_raw_parts(ptr, len as usize, len as usize);
    }
}

#[no_mangle]
/// Free an array that was converted to a pointer from a vector.
extern "C" fn free_array_len_cap(ptr: *mut u8, len: u64, cap: u64) {
    unsafe {
        Vec::from_raw_parts(ptr, len as usize, cap as usize);
    }
}
