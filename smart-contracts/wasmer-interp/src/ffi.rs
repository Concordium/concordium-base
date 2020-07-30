use libc::size_t;

use crate::*;

// After refactoring to have a common dependency with crypto, replace this
// with the version from crypto.
macro_rules! slice_from_c_bytes {
    ($cstr:expr, $length:expr) => {
        if $length != 0 {
            assert!(!$cstr.is_null(), "Null pointer in `slice_from_c_bytes`.");
            std::slice::from_raw_parts($cstr, $length)
        } else {
            &[]
        }
    };
}

#[no_mangle]
pub unsafe extern "C" fn call_init(
    wasm_bytes: *const u8,
    wasm_bytes_len: size_t,
    init_ctx_bytes: *const u8,
    init_ctx_bytes_len: size_t,
    amount: u64,
    init_name: *const u8,
    init_name_len: size_t,
    param_bytes: *const u8,
    param_bytes_len: size_t,
    output_len: *mut size_t,
) -> *mut u8 {
    let wasm = slice_from_c_bytes!(wasm_bytes, wasm_bytes_len as usize);
    let init_name = slice_from_c_bytes!(init_name, init_name_len as usize);
    let parameter = slice_from_c_bytes!(param_bytes, param_bytes_len as usize).to_vec();
    let init_ctx = from_bytes(slice_from_c_bytes!(init_ctx_bytes, init_ctx_bytes_len as usize))
        .expect("Precondition violation: invalid init ctx given by host.");
    match std::str::from_utf8(init_name) {
        Ok(name) => {
            let res = invoke_init(wasm, amount, init_ctx, name, parameter);
            match res {
                Ok(result) => {
                    let mut out = result.to_bytes();
                    *output_len = out.len() as size_t;
                    let ptr = out.as_mut_ptr();
                    std::mem::forget(out);
                    ptr
                }
                Err(_trap) => std::ptr::null_mut(),
            }
        }
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn call_receive(
    wasm_bytes: *const u8,
    wasm_bytes_len: size_t,
    receive_ctx_bytes: *const u8,
    receive_ctx_bytes_len: size_t,
    amount: u64,
    receive_name: *const u8,
    receive_name_len: size_t,
    state_bytes: *const u8,
    state_bytes_len: size_t,
    param_bytes: *const u8,
    param_bytes_len: size_t,
    output_len: *mut size_t,
) -> *mut u8 {
    let wasm = slice_from_c_bytes!(wasm_bytes, wasm_bytes_len as usize);
    let receive_ctx =
        from_bytes(slice_from_c_bytes!(receive_ctx_bytes, receive_ctx_bytes_len as usize))
            .expect("Precondition violation: Should be given a valid receive context.");
    let receive_name = slice_from_c_bytes!(receive_name, receive_name_len as usize);
    let state = slice_from_c_bytes!(state_bytes, state_bytes_len as usize);
    let parameter = slice_from_c_bytes!(param_bytes, param_bytes_len as usize).to_vec();
    match std::str::from_utf8(receive_name) {
        Ok(name) => {
            let res = invoke_receive(wasm, amount, receive_ctx, state, name, parameter);
            match res {
                Ok(result) => {
                    let mut out = result.to_bytes();
                    *output_len = out.len() as size_t;
                    let ptr = out.as_mut_ptr();
                    std::mem::forget(out);
                    ptr
                }
                Err(_trap) => std::ptr::null_mut(),
            }
        }
        Err(_) => std::ptr::null_mut(), // should not happen.
    }
}
