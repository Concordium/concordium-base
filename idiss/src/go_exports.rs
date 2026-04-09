use std::mem::ManuallyDrop;

use crate::*;

/// Like [`std::slice::from_raw_parts`] but with special handling of empty
/// arrays. The same caveats as for [`std::slice::from_raw_parts`] apply in
/// relation to safety and lifetimes.
unsafe fn slice_from_ptr<'a>(data: *const u8, len: usize) -> &'a [u8] {
    if len != 0 {
        std::slice::from_raw_parts(data, len)
    } else {
        &[]
    }
}

/// Validate a version 1 request.
///
/// On success the returned pointer is null and both `out_length` and
/// `out_capacity` are set to 0. On failure the caller owns the returned
/// allocation and must free it with `free_array_len_cap(ptr, len, cap)` using
/// the values written to `out_length` and `out_capacity`.
#[no_mangle]
pub unsafe extern "C" fn validate_request_v1_go(
    ctx_ptr: *const u8,
    ctx_len: i32,
    ip_info_ptr: *const u8,
    ip_info_len: i32,
    ars_infos_ptr: *const u8,
    ars_len: i32,
    request_ptr: *const u8,
    request_len: i32,
    out_length: *mut i32,
    out_capacity: *mut i32,
) -> *const u8 {
    *out_length = 0;
    *out_capacity = 0;

    let global_context_bytes = slice_from_ptr(ctx_ptr, ctx_len as usize);
    let ip_info_bytes = slice_from_ptr(ip_info_ptr, ip_info_len as usize);
    let ars_infos_bytes = slice_from_ptr(ars_infos_ptr, ars_len as usize);
    let request_bytes = slice_from_ptr(request_ptr, request_len as usize);

    match validate_request_v1(
        global_context_bytes,
        ip_info_bytes,
        ars_infos_bytes,
        request_bytes,
    ) {
        Ok(()) => std::ptr::null(),
        Err(e) => {
            let bytes = format!("{}", e).into_bytes();
            *out_length = bytes.len() as i32;
            *out_capacity = bytes.capacity() as i32;
            let wrapper = ManuallyDrop::new(bytes);
            wrapper.as_ptr()
        }
    }
}

/// Create a version 1 identity object and anonymity revocation record.
///
/// The caller owns the returned allocation and must free it with
/// `free_array_len_cap(ptr, len, cap)` using the values written to
/// `out_length` and `out_capacity`.
#[no_mangle]
pub unsafe extern "C" fn create_identity_object_v1_go(
    ip_info_ptr: *const u8,
    ip_info_len: i32,
    request_ptr: *const u8,
    request_len: i32,
    alist_ptr: *const u8,
    alist_len: i32,
    ip_private_key_ptr: *const u8,
    ip_private_key_len: i32,
    out_length: *mut i32,
    out_capacity: *mut i32,
    out_success: *mut i32,
) -> *const u8 {
    *out_length = 0;
    *out_capacity = 0;

    let ip_info_bytes = slice_from_ptr(ip_info_ptr, ip_info_len as usize);
    let request_bytes = slice_from_ptr(request_ptr, request_len as usize);
    let alist_bytes = slice_from_ptr(alist_ptr, alist_len as usize);
    let ip_private_key_bytes = slice_from_ptr(ip_private_key_ptr, ip_private_key_len as usize);

    let response = create_identity_object_v1(
        ip_info_bytes,
        request_bytes,
        alist_bytes,
        ip_private_key_bytes,
    );

    let (bytes, success) = match response {
        Ok(id_creation) => match serde_json::to_vec(&id_creation) {
            Ok(bytes) => (bytes, 1),
            Err(e) => (format!("{}", e).into_bytes(), -1),
        },
        Err(e) => (format!("{}", e).into_bytes(), -1),
    };

    *out_length = bytes.len() as i32;
    *out_capacity = bytes.capacity() as i32;
    *out_success = success;
    let wrapper = ManuallyDrop::new(bytes);
    wrapper.as_ptr()
}

/// Validate an identity recovery request.
///
/// On success the returned pointer is null and both `out_length` and
/// `out_capacity` are set to 0. On failure the caller owns the returned
/// allocation and must free it with `free_array_len_cap(ptr, len, cap)` using
/// the values written to `out_length` and `out_capacity`.
#[no_mangle]
pub unsafe extern "C" fn validate_recovery_request_go(
    ctx_ptr: *const u8,
    ctx_len: i32,
    ip_info_ptr: *const u8,
    ip_info_len: i32,
    request_ptr: *const u8,
    request_len: i32,
    out_length: *mut i32,
    out_capacity: *mut i32,
) -> *const u8 {
    *out_length = 0;
    *out_capacity = 0;

    let global_context_bytes = slice_from_ptr(ctx_ptr, ctx_len as usize);
    let ip_info_bytes = slice_from_ptr(ip_info_ptr, ip_info_len as usize);
    let request_bytes = slice_from_ptr(request_ptr, request_len as usize);

    match validate_recovery_request(global_context_bytes, ip_info_bytes, request_bytes) {
        Ok(()) => std::ptr::null(),
        Err(e) => {
            let bytes = format!("{}", e).into_bytes();
            *out_length = bytes.len() as i32;
            *out_capacity = bytes.capacity() as i32;
            let wrapper = ManuallyDrop::new(bytes);
            wrapper.as_ptr()
        }
    }
}
