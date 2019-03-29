use sha2::*;

use std::slice;

#[no_mangle]
pub extern fn sha256_new() -> *mut Sha256 {
    Box::into_raw(Box::new(Sha256::new()))
}

#[no_mangle]
pub extern fn sha256_free(ptr: *mut Sha256) {
    if ptr.is_null() { return }
    unsafe { Box::from_raw(ptr); }
}

#[no_mangle]
pub extern fn sha256_input(ptr: *mut Sha256, a: *const u8, len: usize) {
    let hasher: &mut Sha256 = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };

    assert!(!a.is_null(), "Null pointer in sha256_input()");
    let data: &[u8]= unsafe { slice::from_raw_parts(a, len)};
    hasher.input(data);
}

#[no_mangle]
pub extern fn sha256_result(hash: &mut[u8;32], ptr: *mut Sha256){
    let hasher = unsafe{ Box::from_raw(ptr)};
    //let hasher  = unsafe {
    //    assert!(!ptr.is_null());
    //    &mut *ptr
    //};
    //let s = hasher.result();
    //hash.copy_from_slice(&[0u8;32]);
    hash.copy_from_slice(hasher.result().as_slice());
}


#[no_mangle]
pub extern fn sha224_new() -> *mut Sha224 {
    Box::into_raw(Box::new(Sha224::new()))
}

#[no_mangle]
pub extern fn sha224_free(ptr: *mut Sha224) {
    if ptr.is_null() { return }
    unsafe { Box::from_raw(ptr); }
}

#[no_mangle]
pub extern fn sha224_input(ptr: *mut Sha224, a: *const u8, len: usize) {
    let hasher: &mut Sha224 = unsafe {
        assert!(!ptr.is_null());
        &mut *ptr
    };

    assert!(!a.is_null(), "Null pointer in sha224_input()");
    let data: &[u8]= unsafe { slice::from_raw_parts(a, len)};
    hasher.input(data);
}

#[no_mangle]
pub extern fn sha224_result(hash: &mut[u8;28], ptr: *mut Sha224){
    let hasher = unsafe{ Box::from_raw(ptr)};
    //let hasher  = unsafe {
    //    assert!(!ptr.is_null());
    //    &mut *ptr
    //};
    //let s = hasher.result();
    //hash.copy_from_slice(&[0u8;32]);
    hash.copy_from_slice(hasher.result().as_slice());
}
