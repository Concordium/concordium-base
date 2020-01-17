#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn free_array_len(ptr: *mut u8, len: usize) {
    unsafe {
        Box::from_raw(std::slice::from_raw_parts_mut(ptr, len));
    }
}
