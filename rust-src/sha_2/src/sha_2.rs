use sha2::*;
use std::slice;

#[no_mangle]
extern "C" fn sha256_new() -> *mut Sha256 { Box::into_raw(Box::new(Sha256::new())) }

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
extern "C" fn sha256_free(ptr: *mut Sha256) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        Box::from_raw(ptr);
    }
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
extern "C" fn sha256_input(ptr: *mut Sha256, a: *const u8, len: usize) {
    assert!(!ptr.is_null());
    let hasher: &mut Sha256 = unsafe { &mut *ptr };

    // in case length == 0 the input string pointer can point to arbitrary data
    // since we ought not to read any of it.
    if len != 0 {
        assert!(!a.is_null(), "Null pointer in sha256_input()");
        let data: &[u8] = unsafe { slice::from_raw_parts(a, len) };
        hasher.update(data);
    } else {
        hasher.update([]);
    }
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
extern "C" fn sha256_result(hash: &mut [u8; 32], ptr: *mut Sha256) {
    let hasher = unsafe { Box::from_raw(ptr) };
    // let hasher  = unsafe {
    //    assert!(!ptr.is_null());
    //    &mut *ptr
    //};
    // let s = hasher.result();
    // hash.copy_from_slice(&[0u8;32]);
    hash.copy_from_slice(hasher.finalize().as_slice());
}
