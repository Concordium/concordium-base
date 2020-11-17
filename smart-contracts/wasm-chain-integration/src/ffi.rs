use crate::*;
use libc::size_t;
use wasm_transform::output::Output;

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
unsafe extern "C" fn call_init(
    artifact_bytes: *const u8,
    artifact_bytes_len: size_t,
    init_ctx_bytes: *const u8,
    init_ctx_bytes_len: size_t,
    amount: u64,
    init_name: *const u8,
    init_name_len: size_t,
    param_bytes: *const u8,
    param_bytes_len: size_t,
    energy: u64,
    output_len: *mut size_t,
) -> *mut u8 {
    let res = std::panic::catch_unwind(|| {
        let wasm = slice_from_c_bytes!(artifact_bytes, artifact_bytes_len as usize);
        let init_name = slice_from_c_bytes!(init_name, init_name_len as usize);
        let parameter = slice_from_c_bytes!(param_bytes, param_bytes_len as usize).to_vec();
        let init_ctx = from_bytes(slice_from_c_bytes!(init_ctx_bytes, init_ctx_bytes_len as usize))
            .expect("Precondition violation: invalid init ctx given by host.");
        match std::str::from_utf8(init_name) {
            Ok(name) => {
                let res =
                    invoke_init_from_artifact(wasm, amount, init_ctx, name, parameter, energy);
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
    });
    res.unwrap_or_else(|_| std::ptr::null_mut())
}

#[no_mangle]
unsafe extern "C" fn call_receive(
    artifact_bytes: *const u8,
    artifact_bytes_len: size_t,
    receive_ctx_bytes: *const u8,
    receive_ctx_bytes_len: size_t,
    amount: u64,
    receive_name: *const u8,
    receive_name_len: size_t,
    state_bytes: *const u8,
    state_bytes_len: size_t,
    param_bytes: *const u8,
    param_bytes_len: size_t,
    energy: u64,
    output_len: *mut size_t,
) -> *mut u8 {
    let res = std::panic::catch_unwind(|| {
        let wasm = slice_from_c_bytes!(artifact_bytes, artifact_bytes_len as usize);
        let receive_ctx =
            from_bytes(slice_from_c_bytes!(receive_ctx_bytes, receive_ctx_bytes_len as usize))
                .expect("Precondition violation: Should be given a valid receive context.");
        let receive_name = slice_from_c_bytes!(receive_name, receive_name_len as usize);
        let state = slice_from_c_bytes!(state_bytes, state_bytes_len as usize);
        let parameter = slice_from_c_bytes!(param_bytes, param_bytes_len as usize).to_vec();
        match std::str::from_utf8(receive_name) {
            Ok(name) => {
                let res = invoke_receive_from_artifact(
                    wasm,
                    amount,
                    receive_ctx,
                    state,
                    name,
                    parameter,
                    energy,
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
            Err(_) => std::ptr::null_mut(), // should not happen.
        }
    });
    res.unwrap_or_else(|_| std::ptr::null_mut())
}

#[no_mangle]
/// Validate the module from source and process it into a runnable artifact
/// that can be used in calls to [call_receive](./fn.call_receive.html) and
/// [call_init](./fn.call_init.html).
///
/// The arguments are as follows
/// - `wasm_bytes_ptr` a pointer to the Wasm module in Wasm binary format,
///   version 1.
/// - `wasm_bytes_len` the length of the data pointed to by `wasm_bytes_ptr`
/// - `artifact_len` a pointer where the length of the artifact that is
///   generated will be written.
/// - `output_len` a pointer where the total length of the output will be
///   written
///
/// The return value is either a null pointer if validation fails, or a pointer
/// to a byte array of length `*output_len`. The byte array starts with
/// `*artifact_len` bytes for the artifact, followed by a list of export item
/// names. The length of the list is encoded as u16, big endian, and each name
/// is encoded as u16, big endian.
///
/// # Safety
/// This function is safe provided all the supplied pointers are not null and
/// the `wasm_bytes_ptr` points to an array of length at least `wasm_bytes_len`.
unsafe extern "C" fn validate_and_process(
    wasm_bytes_ptr: *const u8,
    wasm_bytes_len: size_t,
    artifact_len: *mut size_t, // this is the length of the artifact
    output_len: *mut size_t,   // this is the total length of the output, artifact + exports.
) -> *mut u8 {
    let wasm_bytes = slice_from_c_bytes!(wasm_bytes_ptr, wasm_bytes_len as usize);
    match utils::instantiate_with_metering::<ProcessedImports, _>(
        &ConcordiumAllowedImports,
        wasm_bytes,
    ) {
        Ok(artifact) => {
            let mut out_buf = Vec::new();
            match artifact.output(&mut out_buf) {
                Ok(()) => {
                    *artifact_len = out_buf.len() as size_t;
                    let num_exports = artifact.export.len(); // this can be at most MAX_NUM_EXPORTS
                    out_buf.extend_from_slice(&(num_exports as u16).to_be_bytes());
                    for name in artifact.export.keys() {
                        let len = name.as_ref().as_bytes().len();
                        out_buf.extend_from_slice(&(len as u16).to_be_bytes());
                        out_buf.extend_from_slice(name.as_ref().as_bytes());
                    }
                    *output_len = out_buf.len() as size_t;
                    let ptr = out_buf.as_mut_ptr();
                    std::mem::forget(out_buf);
                    ptr
                }
                Err(_) => std::ptr::null_mut(),
            }
        }
        Err(_) => std::ptr::null_mut(),
    }
}
