use crate::v0::*;
use ffi_helpers::{slice_from_c_bytes, slice_from_c_bytes_worker};
use libc::size_t;
use wasm_transform::{artifact::CompiledFunctionBytes, output::Output, utils::parse_artifact};

/// All functions in this module operate on serialized artifact bytes. For
/// execution, these bytes are parsed into a `BorrowedArtifactV0`, which
/// does as much zero-copy deserialization as possible. As V0 smart contracts
/// are not interruptable/resumable, no references to or copies of the artifact
/// are retained after execution.
type BorrowedArtifactV0<'a> = Artifact<ProcessedImports, CompiledFunctionBytes<'a>>;

#[no_mangle]
unsafe extern "C" fn call_init_v0(
    artifact_ptr: *const u8,
    artifact_bytes_len: size_t,
    init_ctx_bytes: *const u8,
    init_ctx_bytes_len: size_t,
    amount: u64,
    init_name: *const u8,
    init_name_len: size_t,
    param_bytes: *const u8,
    param_bytes_len: size_t,
    limit_logs_and_return_values: u8,
    energy: InterpreterEnergy,
    output_len: *mut size_t,
) -> *mut u8 {
    let artifact_bytes = slice_from_c_bytes!(artifact_ptr, artifact_bytes_len as usize);
    let artifact: BorrowedArtifactV0 = if let Ok(borrowed_artifact) = parse_artifact(artifact_bytes)
    {
        borrowed_artifact
    } else {
        return std::ptr::null_mut();
    };
    let res = std::panic::catch_unwind(|| {
        let init_name = slice_from_c_bytes!(init_name, init_name_len as usize);
        let parameter = slice_from_c_bytes!(param_bytes, param_bytes_len as usize);
        let limit_logs_and_return_values = limit_logs_and_return_values != 0;
        let init_ctx =
            deserial_init_context(slice_from_c_bytes!(init_ctx_bytes, init_ctx_bytes_len as usize))
                .expect("Precondition violation: invalid init ctx given by host.");
        match std::str::from_utf8(init_name) {
            Ok(name) => {
                let res = invoke_init(
                    &artifact,
                    init_ctx,
                    InitInvocation {
                        amount,
                        init_name: name,
                        parameter: parameter.into(),
                        energy,
                    },
                    limit_logs_and_return_values,
                );
                match res {
                    Ok(result) => {
                        let mut out = result.to_bytes();
                        out.shrink_to_fit();
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
    // and return the value
    res.unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
unsafe extern "C" fn call_receive_v0(
    artifact_ptr: *const u8,
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
    max_parameter_size: size_t,
    limit_logs_and_return_values: u8,
    energy: InterpreterEnergy,
    output_len: *mut size_t,
) -> *mut u8 {
    let artifact_bytes = slice_from_c_bytes!(artifact_ptr, artifact_bytes_len as usize);
    let artifact: BorrowedArtifactV0 = if let Ok(borrowed_artifact) = parse_artifact(artifact_bytes)
    {
        borrowed_artifact
    } else {
        return std::ptr::null_mut();
    };
    let res = std::panic::catch_unwind(|| {
        let receive_ctx = deserial_receive_context(slice_from_c_bytes!(
            receive_ctx_bytes,
            receive_ctx_bytes_len as usize
        ))
        .expect("Precondition violation: Should be given a valid receive context.");
        let receive_name = slice_from_c_bytes!(receive_name, receive_name_len as usize);
        let state = slice_from_c_bytes!(state_bytes, state_bytes_len as usize);
        let parameter = slice_from_c_bytes!(param_bytes, param_bytes_len as usize);
        let limit_logs_and_return_values = limit_logs_and_return_values != 0;
        match std::str::from_utf8(receive_name) {
            Ok(name) => {
                let res = invoke_receive(
                    &artifact,
                    receive_ctx,
                    ReceiveInvocation {
                        amount,
                        receive_name: name,
                        parameter: parameter.into(),
                        energy,
                    },
                    state,
                    max_parameter_size,
                    limit_logs_and_return_values,
                );
                match res {
                    Ok(result) => {
                        let mut out = result.to_bytes();
                        out.shrink_to_fit();
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
    // and return the value
    res.unwrap_or(std::ptr::null_mut())
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
/// - `output_len` a pointer where the total length of the output will be
///   written.
/// - `output_artifact_len` a pointer where the length of the serialized
///   artifact will be written.
/// - `output_artifact_bytes` a pointer where the pointer to the serialized
///   artifact will be written.
///
/// The return value is either a null pointer if validation fails, or a pointer
/// to a byte array of length `*output_len`. The byte array starts with
/// `*artifact_len` bytes for the artifact, followed by a list of export item
/// names. The length of the list is encoded as u16, big endian, and each name
/// is encoded prefixed by its length as u16, big endian.
///
/// If validation succeeds, the serialized artifact is at
/// `*output_artifact_bytes` and should be freed with `rs_free_array_len`.
///
/// # Safety
/// This function is safe provided all the supplied pointers are not null and
/// the `wasm_bytes_ptr` points to an array of length at least `wasm_bytes_len`.
unsafe extern "C" fn validate_and_process_v0(
    wasm_bytes_ptr: *const u8,
    wasm_bytes_len: size_t,
    output_len: *mut size_t, // this is the total length of the output byte array
    output_artifact_len: *mut size_t, // the length of the artifact byte array
    output_artifact_bytes: *mut *const u8, /* location where the pointer to the artifact will
                              * be written. */
) -> *mut u8 {
    let wasm_bytes = slice_from_c_bytes!(wasm_bytes_ptr, wasm_bytes_len as usize);
    match utils::instantiate_with_metering::<ProcessedImports, _>(
        &ConcordiumAllowedImports,
        wasm_bytes,
    ) {
        Ok(artifact) => {
            let mut out_buf = Vec::new();
            let num_exports = artifact.export.len(); // this can be at most MAX_NUM_EXPORTS
            out_buf.extend_from_slice(&(num_exports as u16).to_be_bytes());
            for name in artifact.export.keys() {
                let len = name.as_ref().as_bytes().len();
                out_buf.extend_from_slice(&(len as u16).to_be_bytes());
                out_buf.extend_from_slice(name.as_ref().as_bytes());
            }
            out_buf.shrink_to_fit();
            *output_len = out_buf.len() as size_t;
            let ptr = out_buf.as_mut_ptr();
            std::mem::forget(out_buf);

            let mut artifact_bytes = Vec::new();
            artifact.output(&mut artifact_bytes).expect("Artifact serialization does not fail.");
            artifact_bytes.shrink_to_fit();
            *output_artifact_len = artifact_bytes.len() as size_t;
            *output_artifact_bytes = artifact_bytes.as_mut_ptr();
            std::mem::forget(artifact_bytes);

            ptr
        }
        Err(_) => std::ptr::null_mut(),
    }
}
