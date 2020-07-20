use libc::size_t;
use std::{convert::TryInto, slice, str};

use crate::*;
use types::*;

#[no_mangle]
pub unsafe extern "C" fn call_init(
    wasm_bytes: *const u8,
    wasm_bytes_len: size_t,
    addr_bytes: *const u8,
    amount: u64,
    init_name: *const u8,
    init_name_len: size_t,
    output_len: *mut size_t,
) -> *mut u8 {
    let wasm = slice::from_raw_parts(wasm_bytes, wasm_bytes_len as usize);
    let init_origin = slice::from_raw_parts(addr_bytes, 32).try_into().expect("32 byte array");
    let init_name = slice::from_raw_parts(init_name, init_name_len as usize);
    match str::from_utf8(init_name) {
        Ok(name) => {
            let res = invoke_init(
                wasm,
                amount,
                InitContext {
                    init_origin,
                },
                name,
            );
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
    amount: u64,
    receive_name: *const u8,
    receive_name_len: size_t,
    state_bytes: *const u8,
    state_bytes_len: size_t,
    output_len: *mut size_t,
) -> *mut u8 {
    let wasm = slice::from_raw_parts(wasm_bytes, wasm_bytes_len as usize);
    let receive_ctx = ReceiveContext::from_bytes(slice::from_raw_parts(receive_ctx_bytes, 56))
        .expect("Should be given valid context.");
    let receive_name = slice::from_raw_parts(receive_name, receive_name_len as usize);
    let state = slice::from_raw_parts(state_bytes, state_bytes_len as usize);
    match str::from_utf8(receive_name) {
        Ok(name) => {
            let res = invoke_receive(wasm, amount, receive_ctx, state, name);
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
