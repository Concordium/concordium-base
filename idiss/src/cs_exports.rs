use crate::*;
use ffi_helpers::*;

/// This function takes pointers to bytearrays and use the library function
/// `validate_request`` on these. The arguments are
/// - `ctx_ptr` - A pointer to a bytearray, assumed to represent the JSON
///   serialization of the global context
/// - `ctx_len` - The length of the bytearray that `ctx_ptr` points to
/// - `ip_info_ptr` - A pointer to a bytearray, assumed to represent the JSON
///   serialization of the IpInfo
/// - `ip_info_len` - The length of the bytearray that `ip_info_ptr` points to
/// - `ars_infos_ptr` - A pointer to a bytearray, assumed to represent the JSON
///   serialization of the ArInfos
/// - `ars_len` - The length of the bytearray that `ars_infos_ptr` points to
/// - `request_ptr` - A pointer to a bytearray, assumed to represent JSON of the
///   form
/// `{
///     "idObjectRequest": ...
/// }`,
/// where `...` denotes the JSON serialization of the versioned pre-identity
/// object.
/// - `request_len` - The length of the bytearray that `request_ptr` points to
/// - `out_length` - Pointer to an i32 to write the length of the resulting
///   bytearray to
/// - `out_success` - Pointer to an i32 to write an integer indicating success
///   or failure
///
/// The function returns a pointer to a bytearray that either
/// - represents the address of the initial account, if validation was
///   successful, or
/// - represents an error describing what went wrong.
/// The length of this bytearray is written to the integer that `out_length`
/// points to. Either 1 or -1 (indicating success/failure) is written to the
/// integer that `out_success` points to.
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

/// This function takes pointers to bytearrays and use the library function
/// `validate_request_v1`` on these. The arguments are
/// - `ctx_ptr` - A pointer to a bytearray, assumed to represent the JSON
///   serialization of the global context
/// - `ctx_len` - The length of the bytearray that `ctx_ptr` points to
/// - `ip_info_ptr` - A pointer to a bytearray, assumed to represent the JSON
///   serialization of the IpInfo
/// - `ip_info_len` - The length of the bytearray that `ip_info_ptr` points to
/// - `ars_infos_ptr` - A pointer to a bytearray, assumed to represent the JSON
///   serialization of the ArInfos
/// - `ars_len` - The length of the bytearray that `ars_infos_ptr` points to
/// - `request_ptr` - A pointer to a bytearray, assumed to represent JSON of the
///   form
/// `{
///     "idObjectRequest": ...
/// }`,
/// where `...` denotes the JSON serialization of the versioned pre-identity
/// object.
/// - `request_len` - The length of the bytearray that `request_ptr` points to
/// - `out_length` - Pointer to an i32 to write the length of the resulting
///   bytearray to, in case of failure
///
/// The function returns a pointer that either
/// - is the null pointer, if validation was successful, or
/// - is a pointer to a bytearray representing an error describing what went
///   wrong. The length of this bytearray is written to the integer that
///   `out_length` points to.
#[no_mangle]
pub unsafe extern "C" fn validate_request_v1_cs(
    ctx_ptr: *const u8,
    ctx_len: i32,
    ip_info_ptr: *const u8,
    ip_info_len: i32,
    ars_infos_ptr: *const u8,
    ars_len: i32,
    request_ptr: *const u8,
    request_len: i32,
    out_length: *mut i32,
) -> *mut u8 {
    let global_context_bytes = slice_from_c_bytes!(ctx_ptr, ctx_len as usize);
    let ip_info_bytes = slice_from_c_bytes!(ip_info_ptr, ip_info_len as usize);
    let ars_infos_bytes = slice_from_c_bytes!(ars_infos_ptr, ars_len as usize);
    let request_bytes = slice_from_c_bytes!(request_ptr, request_len as usize);
    let result = validate_request_v1(
        global_context_bytes,
        ip_info_bytes,
        ars_infos_bytes,
        request_bytes,
    );
    match result {
        Ok(()) => std::ptr::null_mut(),
        Err(e) => {
            let mut bytes = format!("{}", e).into_bytes();
            *out_length = bytes.len() as i32;
            let ptr = bytes.as_mut_ptr();
            std::mem::forget(bytes);
            ptr
        }
    }
}

/// This function takes pointers to bytearrays and use the library function
/// `create_identity_object`` on these. The arguments are
/// - `ip_info_ptr` - A pointer to a bytearray, assumed to represent the JSON
///   serialization of the IpInfo
/// - `ip_info_len` - The length of the bytearray that `ip_info_ptr` points to
/// - `alist_ptr` - A pointer to a bytearray, assumed to represent the JSON
///   serialization of the attribute list
/// - `alist_len` - The length of the bytearray that `alist_ptr` points to
/// - `request_ptr` - A pointer to a bytearray, assumed to represent JSON of the
///   form
/// `{
///     idObjectRequest: ...
/// }`,
/// where `...` denotes the JSON serialization of the pre-identity object.
/// - `request_len` - The length of the bytearray that `request_ptr` points to
/// - `expiry` - the expiry time of the account creation message sent to the
///   chain.
/// - `ip_private_key_ptr` - A pointer to a bytearray, assumed to represent the
///   JSON serialization of the private key used to sign the identity object
/// - `ip_private_key_len` - The length of the bytearray that
///   `ip_private_key_ptr` points to
/// - `ip_cdi_private_key_ptr` - A pointer to a bytearray, assumed to represent
///   the JSON serialization of the private key used to sign the initial account
///   creation message
/// - `ip_cdi_private_key_len` - The length of the bytearray that
///   `ip_cdi_private_key_ptr` points to
/// - `out_length` - Pointer to an i32 to write the length of the resulting
///   bytearray to
/// - `out_success` - Pointer to an i32 to write an integer indicating success
///   or failure
///
/// The function returns a pointer to a bytearray that either
/// - represents the JSON serialization of an IdentityCreation instance, i.e. it
///   contains
///     * the identity object that is returned to the user
///     * the anonymity revocation record
///     * the initial account creation object that is sent to the chain
///     * the address of the inital account, or
/// - represents an error describing what went wrong.
/// The length of this bytearray is written to the integer that `out_length`
/// points to. Either 1 or -1 (indicating success/failure) is written to the
/// integer that `out_success` points to.
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

/// This function takes pointers to bytearrays and use the library function
/// `create_identity_object_v1`` on these. The arguments are
/// - `ip_info_ptr` - A pointer to a bytearray, assumed to represent the JSON
///   serialization of the IpInfo
/// - `ip_info_len` - The length of the bytearray that `ip_info_ptr` points to
/// - `alist_ptr` - A pointer to a bytearray, assumed to represent the JSON
///   serialization of the attribute list
/// - `alist_len` - The length of the bytearray that `alist_ptr` points to
/// - `request_ptr` - A pointer to a bytearray, assumed to represent JSON of the
///   form
/// `{
///     idObjectRequest: ...
/// }`,
/// where `...` denotes the JSON serialization of the version 1 pre-identity
/// object.
/// - `request_len` - The length of the bytearray that `request_ptr` points to
/// - `expiry` - the expiry time of the account creation message sent to the
///   chain.
/// - `ip_private_key_ptr` - A pointer to a bytearray, assumed to represent the
///   JSON serialization of the private key used to sign the identity object
/// - `ip_private_key_len` - The length of the bytearray that
///   `ip_private_key_ptr` points to
/// - `out_length` - Pointer to an i32 to write the length of the resulting
///   bytearray to
/// - `out_success` - Pointer to an i32 to write an integer indicating success
///   or failure
///
/// The function returns a pointer to a bytearray that either
/// - represents the JSON serialization of an IdentityCreationV1 instance, i.e.
///   it contains
///     * the version 1 identity object that is returned to the user
///     * the anonymity revocation record or
/// - represents an error describing what went wrong.
/// The length of this bytearray is written to the integer that `out_length`
/// points to. Either 1 or -1 (indicating success/failure) is written to the
/// integer that `out_success` points to.
#[no_mangle]
pub unsafe extern "C" fn create_identity_object_v1_cs(
    ip_info_ptr: *const u8,
    ip_info_len: i32,
    alist_ptr: *const u8,
    alist_len: i32,
    request_ptr: *const u8,
    request_len: i32,
    ip_private_key_ptr: *const u8,
    ip_private_key_len: i32,
    out_length: *mut i32,
    out_success: *mut i32,
) -> *mut u8 {
    let ip_info_bytes = slice_from_c_bytes!(ip_info_ptr, ip_info_len as usize);
    let alist_bytes = slice_from_c_bytes!(alist_ptr, alist_len as usize);
    let ip_private_key_bytes = slice_from_c_bytes!(ip_private_key_ptr, ip_private_key_len as usize);
    let request_bytes = slice_from_c_bytes!(request_ptr, request_len as usize);

    let response = create_identity_object_v1(
        ip_info_bytes,
        alist_bytes,
        request_bytes,
        ip_private_key_bytes,
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

/// This function takes pointers to bytearrays and use the library function
/// `validate_recovery_request`` on these. The arguments are
/// - `ctx_ptr` - A pointer to a bytearray, assumed to represent the JSON
///   serialization of the global context
/// - `ctx_len` - The length of the bytearray that `ctx_ptr` points to
/// - `ip_info_ptr` - A pointer to a bytearray, assumed to represent the JSON
///   serialization of the IpInfo
/// - `ip_info_len` - The length of the bytearray that `ip_info_ptr` points to
/// - `request_ptr` - A pointer to a bytearray, assumed to represent JSON of the
///   form
/// `{
///     "idRecoveryRequest": ...
/// }`,
/// where `...` denotes the JSON serialization of the versioned identity
/// recovery request.
/// - `request_len` - The length of the bytearray that `request_ptr` points to
/// - `out_length` - Pointer to an i32 to write the length of the resulting
///   bytearray to, in case of failure
///
/// The function returns a pointer that either
/// - is the null pointer, if validation was successful, or
/// - is a pointer to a bytearray representing an error describing what went
///   wrong. The length of this bytearray is written to the integer that
///   `out_length` points to.
#[no_mangle]
pub unsafe extern "C" fn validate_recovery_request_cs(
    ctx_ptr: *const u8,
    ctx_len: i32,
    ip_info_ptr: *const u8,
    ip_info_len: i32,
    request_ptr: *const u8,
    request_len: i32,
    out_length: *mut i32,
) -> *mut u8 {
    let global_context_bytes = slice_from_c_bytes!(ctx_ptr, ctx_len as usize);
    let ip_info_bytes = slice_from_c_bytes!(ip_info_ptr, ip_info_len as usize);
    let request_bytes = slice_from_c_bytes!(request_ptr, request_len as usize);
    let result = validate_recovery_request(global_context_bytes, ip_info_bytes, request_bytes);
    match result {
        Ok(()) => std::ptr::null_mut(),
        Err(e) => {
            let mut bytes = format!("{}", e).into_bytes();
            *out_length = bytes.len() as i32;
            let ptr = bytes.as_mut_ptr();
            std::mem::forget(bytes);
            ptr
        }
    }
}
