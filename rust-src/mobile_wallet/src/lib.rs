use libc::c_char;
use wallet::{
    create_credential as cr, create_id_request_and_private_data as cirp,
    free_response_string as free,
};

#[cfg(target_os = "android")]
mod android;

#[no_mangle]
/// # Safety
/// The input pointer must point to a null-terminated buffer, otherwise this
/// function will fail in unspecified ways.
pub unsafe extern "C" fn create_id_request_and_private_data(
    input_ptr: *const c_char,
    success: *mut u8,
) -> *mut c_char {
    cirp(input_ptr, success)
}

#[no_mangle]
/// # Safety
/// The input pointer must point to a null-terminated buffer, otherwise this
/// function will fail in unspecified ways.
pub unsafe extern "C" fn create_credential(
    input_ptr: *const c_char,
    success: *mut u8,
) -> *mut c_char {
    cr(input_ptr, success)
}

#[no_mangle]
/// # Safety
/// This function is unsafe in the sense that if the argument pointer was not
/// Constructed via CString::into_raw its behaviour is undefined.
pub unsafe extern "C" fn free_response_string(ptr: *mut c_char) { free(ptr) }
