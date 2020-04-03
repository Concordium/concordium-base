#![cfg(target_os = "ios")]

use libc::c_char;
use wallet::{
    create_credential_ext, create_id_request_and_private_data_ext, create_transfer_ext,
    free_response_string_ext,
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
/// Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
/// UTF8-encoded string. The returned string must be freed by the caller by
/// calling the function 'free_response_string'. In case of failure the function
/// returns an error message as the response, and sets the 'success' flag to 0.
///
/// See rust-bins/wallet-notes/README.md for the description of input and output
/// formats.
///
/// # Safety
/// The input pointer must point to a null-terminated buffer, otherwise this
/// function will fail in unspecified ways.
pub unsafe extern "C" fn create_transfer(
    input_ptr: *const c_char,
    success: *mut u8,
) -> *mut c_char {
    create_transfer_ext(input_ptr, success)
}

#[no_mangle]
/// # Safety
/// This function is unsafe in the sense that if the argument pointer was not
/// Constructed via CString::into_raw its behaviour is undefined.
pub unsafe extern "C" fn free_response_string(ptr: *mut c_char) {
    free_response_string_ext(ptr)
}
