use libc::c_char;
use crate::{
    check_account_address_ext, combine_encrypted_amounts_ext, create_credential_ext,
    create_encrypted_transfer_ext, create_id_request_and_private_data_ext,
    create_pub_to_sec_transfer_ext, create_sec_to_pub_transfer_ext, create_transfer_ext,
    decrypt_encrypted_amount_ext, free_response_string_ext, generate_accounts_ext,
};

#[no_mangle]
/// # Safety
/// The input pointer must point to a null-terminated buffer, otherwise this
/// function will fail in unspecified ways.
pub unsafe extern "C" fn generate_accounts(
    input_ptr: *const c_char,
    success: *mut u8,
) -> *mut c_char {
    generate_accounts_ext(input_ptr, success)
}

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
/// Take a pointer to a NUL-terminated UTF8-string and return whether this is
/// a correct format for a concordium address.
/// A non-zero return value signals success.
/// #Safety
/// The input must be NUL-terminated.
pub unsafe extern "C" fn check_account_address(input_ptr: *const c_char) -> u8 {
    check_account_address_ext(input_ptr)
}

#[no_mangle]
/// # Safety
/// This function is unsafe in the sense that if the argument pointer was not
/// Constructed via CString::into_raw its behaviour is undefined.
pub unsafe extern "C" fn free_response_string(ptr: *mut c_char) { free_response_string_ext(ptr) }

#[no_mangle]
/// Take a pointer to two NUL-terminated UTF8-strings and return a
/// NUL-terminated UTF8-encoded string. The returned string must be freed by the
/// caller by calling the function 'free_response_string'. In case of failure
/// the function returns an error message as the response, and sets the
/// 'success' flag to 0.
///
/// See rust-bins/wallet-notes/README.md for the description of input and output
/// formats.
///
/// # Safety
/// The input pointer must point to a null-terminated buffer, otherwise this
/// function will fail in unspecified ways.
pub unsafe extern "C" fn combine_encrypted_amounts(
    input_ptr_1: *const c_char,
    input_ptr_2: *const c_char,
    success: *mut u8,
) -> *mut c_char {
    combine_encrypted_amounts_ext(input_ptr_1, input_ptr_2, success)
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
pub unsafe extern "C" fn create_encrypted_transfer(
    input_ptr: *const c_char,
    success: *mut u8,
) -> *mut c_char {
    create_encrypted_transfer_ext(input_ptr, success)
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
pub unsafe extern "C" fn create_pub_to_sec_transfer(
    input_ptr: *const c_char,
    success: *mut u8,
) -> *mut c_char {
    create_pub_to_sec_transfer_ext(input_ptr, success)
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
pub unsafe extern "C" fn create_sec_to_pub_transfer(
    input_ptr: *const c_char,
    success: *mut u8,
) -> *mut c_char {
    create_sec_to_pub_transfer_ext(input_ptr, success)
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
pub unsafe extern "C" fn decrypt_encrypted_amount(
    input_ptr: *const c_char,
    success: *mut u8,
) -> u64 {
    decrypt_encrypted_amount_ext(input_ptr, success)
}
