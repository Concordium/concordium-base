#![cfg(target_os = "ios")]

use libc::c_char;
use wallet::{
    create_credential_ext, create_id_request_and_private_data_ext, free_response_string_ext,
};

#[no_mangle]
/// # Safety
/// The input pointer must point to a null-terminated buffer, otherwise this
/// function will fail in unspecified ways.
pub unsafe extern "C" fn create_id_request_and_private_data(
    input_ptr: *const c_char,
    success: *mut u8,
) -> *mut c_char {
    create_id_request_and_private_data_ext(input_ptr, success)
}

#[no_mangle]
/// # Safety
/// The input pointer must point to a null-terminated buffer, otherwise this
/// function will fail in unspecified ways.
pub unsafe extern "C" fn create_credential(
    input_ptr: *const c_char,
    success: *mut u8,
) -> *mut c_char {
    create_credential_ext(input_ptr, success)
}

#[no_mangle]
/// # Safety
/// This function is unsafe in the sense that if the argument pointer was not
/// Constructed via CString::into_raw its behaviour is undefined.
pub unsafe extern "C" fn free_response_string(ptr: *mut c_char) { free_response_string_ext(ptr) }
