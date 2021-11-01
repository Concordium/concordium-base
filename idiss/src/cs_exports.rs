use crate::*;
use ffi_helpers::*;

#[no_mangle]
pub unsafe extern "C" fn validate_request_cs(
    ctx_ptr: *const u8,
    ctx_len: i32,
    ip_info_ptr: *const u8,
    ip_info_len: i32,
    ars_infos_ptr: *const u8,
    ars_len: i32,
    request_ptr: *const u8,
    request_len: i32,
    out_length: *mut i32,
    out_success: *mut i32,
) -> *mut u8 {
    let global_context_bytes = slice_from_c_bytes!(ctx_ptr, ctx_len as usize);
    let ip_info_bytes = slice_from_c_bytes!(ip_info_ptr, ip_info_len as usize);
    let ars_infos_bytes = slice_from_c_bytes!(ars_infos_ptr, ars_len as usize);
    let request_bytes = slice_from_c_bytes!(request_ptr, request_len as usize);
    let result = validate_request(
        global_context_bytes,
        ip_info_bytes,
        ars_infos_bytes,
        request_bytes,
    );
    match result {
        Ok(addr) => {
            let mut bytes = format!("{}", addr).into_bytes();
            *out_length = bytes.len() as i32;
            *out_success = 1;
            let ptr = bytes.as_mut_ptr();
            std::mem::forget(bytes);
            ptr
        }
        Err(e) => {
            let mut bytes = format!("{}", e).into_bytes();
            *out_length = bytes.len() as i32;
            *out_success = -1;
            let ptr = bytes.as_mut_ptr();
            std::mem::forget(bytes);
            ptr
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn create_identity_object_cs(
    ip_info_ptr: *const u8,
    ip_info_len: i32,
    alist_ptr: *const u8,
    alist_len: i32,
    request_ptr: *const u8,
    request_len: i32,
    expiry: u64,
    ip_private_key_ptr: *const u8,
    ip_private_key_len: i32,
    ip_cdi_private_key_ptr: *const u8,
    ip_cdi_private_key_len: i32,
    out_length: *mut i32,
    out_success: *mut i32,
) -> *mut u8 {
    let ip_info_bytes = slice_from_c_bytes!(ip_info_ptr, ip_info_len as usize);
    let alist_bytes = slice_from_c_bytes!(alist_ptr, alist_len as usize);
    let ip_private_key_bytes = slice_from_c_bytes!(ip_private_key_ptr, ip_private_key_len as usize);
    let ip_cdi_private_key_bytes =
        slice_from_c_bytes!(ip_cdi_private_key_ptr, ip_cdi_private_key_len as usize);
    let request_bytes = slice_from_c_bytes!(request_ptr, request_len as usize);

    let response = create_identity_object(
        ip_info_bytes,
        alist_bytes,
        request_bytes,
        expiry,
        ip_private_key_bytes,
        ip_cdi_private_key_bytes,
    );
    let (mut bytes, success) = match response {
        Ok(id_creation) => match serde_json::to_vec(&id_creation) {
            Ok(bytes) => (bytes, 1),
            Err(e) => (format!("{}", e).into_bytes(), -1),
        },
        Err(e) => (format!("{}", e).into_bytes(), -1),
    };
    *out_length = bytes.len() as i32;
    *out_success = success;
    let ptr = bytes.as_mut_ptr();
    std::mem::forget(bytes);
    ptr
}
