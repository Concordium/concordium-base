use libc::size_t;
use std::slice;

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn free_array_len(ptr: *mut u8, len: size_t) {
    let s = mut_slice_from_c_bytes!(ptr, len as usize);
    unsafe {
        Box::from_raw(s.as_mut_ptr());
    }
}
