use super::trie::{
    low_level::{Loadable, Reference},
    MutableState, PersistentState,
};
use crate::{slice_from_c_bytes, v1::*};
use libc::size_t;
use std::sync::Arc;
use wasm_transform::{
    artifact::{CompiledFunction, OwnedArtifact},
    output::Output,
    utils::parse_artifact,
};

/// All functions in this module operate on an Arc<ArtifactV1>. The reason for
/// choosing an Arc as opposed to Box or Rc is that we need to sometimes share
/// this artifact to support resumable executions, and we might have to access
/// it concurrently since these functions are called from Haskell.
type ArtifactV1 = OwnedArtifact<ProcessedImports>;

type ReturnValue = Vec<u8>;

#[no_mangle]
unsafe extern "C" fn call_init_v1(
    loader: LoadCallBack, // This is not really needed since nothing is loaded.
    artifact_ptr: *const ArtifactV1,
    init_ctx_bytes: *const u8,
    init_ctx_bytes_len: size_t,
    amount: u64,
    init_name: *const u8,
    init_name_len: size_t,
    param_bytes: *const u8,
    param_bytes_len: size_t,
    energy: u64,
    output_return_value: *mut *mut ReturnValue,
    output_len: *mut size_t,
    output_state_ptr: *mut *mut MutableState,
) -> *mut u8 {
    let artifact = Arc::from_raw(artifact_ptr);
    let res = std::panic::catch_unwind(|| {
        let init_name = slice_from_c_bytes!(init_name, init_name_len as usize);
        let parameter = slice_from_c_bytes!(param_bytes, param_bytes_len as usize);
        let init_ctx = v0::deserial_init_context(slice_from_c_bytes!(
            init_ctx_bytes,
            init_ctx_bytes_len as usize
        ))
        .expect("Precondition violation: invalid init ctx given by host.");
        let mut initial_state = PersistentState::Empty.thaw();
        let instance_state = InstanceState::new(0, loader, initial_state.get_inner());
        match std::str::from_utf8(init_name) {
            Ok(name) => {
                let res = invoke_init(
                    artifact.as_ref(),
                    amount,
                    init_ctx,
                    name,
                    parameter,
                    energy,
                    instance_state,
                );
                match res {
                    Ok(result) => {
                        let (mut out, return_value) = result.extract();
                        out.shrink_to_fit();
                        *output_len = out.len() as size_t;
                        let ptr = out.as_mut_ptr();
                        std::mem::forget(out);
                        if let Some((success, return_value)) = return_value {
                            *output_return_value = Box::into_raw(Box::new(return_value));
                            if success {
                                // the lock has been dropped at this point
                                let initial_state = Box::into_raw(Box::new(initial_state));
                                *output_state_ptr = initial_state;
                            }
                        } else {
                            *output_return_value = std::ptr::null_mut();
                        }
                        ptr
                    }
                    Err(_trap) => std::ptr::null_mut(),
                }
            }
            Err(_) => std::ptr::null_mut(),
        }
    });
    // do not drop the pointer, we are not the owner
    Arc::into_raw(artifact);
    // and return the value
    res.unwrap_or_else(|_| std::ptr::null_mut())
}

#[no_mangle]
unsafe extern "C" fn call_receive_v1(
    loader: LoadCallBack,
    artifact_ptr: *const ArtifactV1,
    receive_ctx_bytes: *const u8,
    receive_ctx_bytes_len: size_t,
    amount: u64,
    receive_name: *const u8,
    receive_name_len: size_t,
    state_ptr_ptr: *mut *mut MutableState,
    param_bytes: *const u8,
    param_bytes_len: size_t,
    energy: u64,
    output_return_value: *mut *mut ReturnValue,
    output_config: *mut *mut ReceiveInterruptedState<CompiledFunction>,
    output_len: *mut size_t,
) -> *mut u8 {
    let artifact = Arc::from_raw(artifact_ptr);
    let res = std::panic::catch_unwind(|| {
        let receive_ctx = v0::deserial_receive_context(slice_from_c_bytes!(
            receive_ctx_bytes,
            receive_ctx_bytes_len as usize
        ))
        .expect("Precondition violation: Should be given a valid receive context.");
        let receive_name = slice_from_c_bytes!(receive_name, receive_name_len as usize);
        let parameter = slice_from_c_bytes!(param_bytes, param_bytes_len as usize);
        let state_ptr = std::mem::replace(&mut *state_ptr_ptr, std::ptr::null_mut());
        let mut state = (&mut *state_ptr).make_fresh_generation();
        let inner = state.get_inner();
        let instance_state = InstanceState::new(0, loader, inner);
        match std::str::from_utf8(receive_name) {
            Ok(name) => {
                let res = invoke_receive(
                    artifact.clone(),
                    amount,
                    receive_ctx,
                    name,
                    parameter,
                    energy,
                    instance_state,
                );
                match res {
                    Ok(result) => {
                        let (mut out, store_state, config, return_value) = result.extract();
                        out.shrink_to_fit();
                        *output_len = out.len() as size_t;
                        let ptr = out.as_mut_ptr();
                        std::mem::forget(out);
                        if let Some(config) = config {
                            std::ptr::replace(output_config, Box::into_raw(config));
                        } else {
                            // make sure to set it to null to make the finalizer work correctly.
                            *output_config = std::ptr::null_mut();
                        }
                        if let Some(return_value) = return_value {
                            *output_return_value = Box::into_raw(Box::new(return_value));
                        } else {
                            *output_return_value = std::ptr::null_mut();
                        }
                        if store_state {
                            let new_state = Box::into_raw(Box::new(state));
                            *state_ptr_ptr = new_state;
                        }
                        ptr
                    }
                    Err(_trap) => std::ptr::null_mut(),
                }
            }
            Err(_) => std::ptr::null_mut(), // should not happen.
        }
    });
    // do not drop the pointer, we are not the owner
    Arc::into_raw(artifact);
    // and return the value
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
/// - `artifact_out` a pointer where the pointer to the artifact will be
///   written.
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
unsafe extern "C" fn validate_and_process_v1(
    wasm_bytes_ptr: *const u8,
    wasm_bytes_len: size_t,
    output_len: *mut size_t, // this is the total length of the output byte array
    output_artifact: *mut *const ArtifactV1, /* location where the pointer to the artifact will
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
            // move the artifact to the arc.
            let arc = Arc::new(artifact);
            // and forget it.
            *output_artifact = Arc::into_raw(arc);
            ptr
        }
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
// TODO: Signal whether the state was updated.
unsafe extern "C" fn resume_receive_v1(
    loader: LoadCallBack,
    // mutable pointer, we will mutate this, either to a new state or null
    config_ptr: *mut *mut ReceiveInterruptedState<CompiledFunction>,
    // whether the state has been updated (non-zero) or not (zero)
    new_state_tag: u8,
    state_ptr_ptr: *mut *mut MutableState,
    new_amount: u64,
    // whether the call succeeded or not.
    response_status: u64,
    // response from the call.
    response: *mut ReturnValue,
    // remaining energy available for execution
    energy: u64,
    output_return_value: *mut *mut ReturnValue,
    output_len: *mut size_t,
) -> *mut u8 {
    let res = std::panic::catch_unwind(|| {
        let data = {
            if response.is_null() {
                None
            } else {
                let mut response_data = Box::from_raw(response);
                let data = std::mem::take(response_data.as_mut()); // write empty vector to the pointer.
                Box::into_raw(response_data); // make it safe to reclaim data
                Some(data)
            }
        };
        // NB: This must match the response encoding in V1.hs in consensus
        // If the first 3 bytes are all set that indicates an error.
        let response = if response_status & 0xffff_ff00_0000_0000 == 0xffff_ff00_0000_0000 {
            if response_status & 0x0000_00ff_0000_0000 != 0 {
                // this is an environment error. No return value is produced.
                InvokeResponse::Failure {
                    code: response_status & 0x0000_00ff_0000_0000,
                    data: None,
                }
            } else {
                // The return value is present since this was a logic error.
                if response_status & 0x0000_0000_ffff_ffff == 0 {
                    // Host violated precondition. There must be a non-zero error code.
                    return std::ptr::null_mut();
                }
                InvokeResponse::Failure {
                    code: response_status & 0x0000_0000_ffff_ffff,
                    data,
                }
            }
        } else if new_state_tag == 0 {
            InvokeResponse::Success {
                new_state: false,
                new_balance: Amount::from_micro_ccd(new_amount),
                data,
            }
        } else {
            InvokeResponse::Success {
                new_state: true,
                new_balance: Amount::from_micro_ccd(new_amount),
                data,
            }
        };
        // mark the interrupted state as consumed in case any panics happen from here to
        // the end. this means the state is in a consistent state and the
        // finalizer (`receive_interrupted_state_free`) will not end up double
        // freeing.
        let config = std::ptr::replace(config_ptr, std::ptr::null_mut());
        // since we will never roll back past this point, other than to the beginning of
        // execution, we do not need to make a new generation for checkpoint
        // reasons. We are not the owner of the state, so we make a clone of it.
        // The clone is cheap since this is reference counted.
        let state_ref = &mut **state_ptr_ptr;
        let mut state = state_ref.clone();
        // it is important to invalidate all previous iterators and entries we have
        // given out. so we start a new generation.
        let config = Box::from_raw(config);
        let instance_state =
            InstanceState::new(config.host.latest_generation + 1, loader, state.get_inner());
        let res = resume_receive(config, response, energy.into(), instance_state);
        // FIXME: Reduce duplication with call_receive
        match res {
            Ok(result) => {
                let (mut out, store_state, new_config, return_value) = result.extract();
                out.shrink_to_fit();
                *output_len = out.len() as size_t;
                let ptr = out.as_mut_ptr();
                std::mem::forget(out);
                if let Some(config) = new_config {
                    std::ptr::replace(config_ptr, Box::into_raw(config));
                } // otherwise leave config_ptr pointing to null
                if let Some(return_value) = return_value {
                    *output_return_value = Box::into_raw(Box::new(return_value));
                } else {
                    *output_return_value = std::ptr::null_mut();
                }
                if store_state {
                    *state_ptr_ptr = Box::into_raw(Box::new(state))
                }
                ptr
            }
            Err(_trap) => std::ptr::null_mut(),
        }
    });
    res.unwrap_or(std::ptr::null_mut())
}

// # Administrative functions.

#[no_mangle]
/// # Safety
/// This function is safe provided the supplied pointer is
/// constructed with [Arc::into_raw].
unsafe extern "C" fn artifact_v1_free(artifact_ptr: *const ArtifactV1) {
    if !artifact_ptr.is_null() {
        // decrease the reference count
        Arc::from_raw(artifact_ptr);
    }
}

#[no_mangle]
/// # Safety
/// This function is safe provided the supplied pointer is
/// constructed with [Box::into_raw] and  the function is only called once on
/// the pointer.
unsafe extern "C" fn box_vec_u8_free(vec_ptr: *mut Vec<u8>) {
    if !vec_ptr.is_null() {
        // consume the vector
        Box::from_raw(vec_ptr);
    }
}

#[no_mangle]
/// # Safety
/// This function is safe provided the supplied pointer is
/// constructed with [Box::into_raw].
unsafe extern "C" fn receive_interrupted_state_free(
    ptr_ptr: *mut *mut ReceiveInterruptedState<CompiledFunction>,
) {
    if !ptr_ptr.is_null() && !(*ptr_ptr).is_null() {
        // drop
        let _: Box<ReceiveInterruptedState<CompiledFunction>> = Box::from_raw(*ptr_ptr);
        // and store null so that future calls (which there should not be any) are safe.
        *ptr_ptr = std::ptr::null_mut();
    }
}

#[no_mangle]
/// Convert an artifact to a byte array and return a pointer to it, storing its
/// length in `output_len`. To avoid leaking memory the return value should be
/// freed with `rs_free_array_len`.
///
/// # Safety
/// This function is safe provided the `artifact_ptr` was obtained with
/// `Arc::into_raw` and `output_len` points to a valid memory location.
unsafe extern "C" fn artifact_v1_to_bytes(
    artifact_ptr: *const ArtifactV1,
    output_len: *mut size_t,
) -> *mut u8 {
    let artifact = Arc::from_raw(artifact_ptr);
    let mut bytes = Vec::new();
    artifact.output(&mut bytes).expect("Artifact serialization does not fail.");
    bytes.shrink_to_fit();
    *output_len = bytes.len() as size_t;
    let ptr = bytes.as_mut_ptr();
    std::mem::forget(bytes);
    Arc::into_raw(artifact);
    ptr
}

#[no_mangle]
/// Deserialize an artifact from bytes and return a pointer to it.
/// If deserialization fails this returns [None](https://doc.rust-lang.org/std/option/enum.Option.html#variant.None)
/// and otherwise it returns a valid pointer to the artifact. To avoid leaking
/// memory the memory must be freed using [artifact_v1_free].
///
/// # Safety
/// This function is safe provided
/// - either the `input_len` is greater than 0 and the `bytes_ptr` points to
///   data of the given size
/// - or `input_len` = 0
unsafe extern "C" fn artifact_v1_from_bytes(
    bytes_ptr: *const u8,
    input_len: size_t,
) -> *const ArtifactV1 {
    let bytes = slice_from_c_bytes!(bytes_ptr, input_len as usize);
    if let Ok(borrowed_artifact) = parse_artifact(&bytes) {
        Arc::into_raw(Arc::new(borrowed_artifact.into()))
    } else {
        std::ptr::null()
    }
}

#[no_mangle]
/// Convert the return value to a byte array that will be managed externally.
/// To avoid memory leaks the return byte array must be deallocated using
/// rs_free_array_len.
///
/// # Safety
/// This function is safe provided the return value is construted using
/// Box::into_raw.
unsafe extern "C" fn return_value_to_byte_array(
    rv_ptr: *mut Vec<u8>,
    output_len: *mut size_t,
) -> *mut u8 {
    let mut bytes = (&*rv_ptr).clone();
    bytes.shrink_to_fit();
    *output_len = bytes.len() as size_t;
    let ptr = bytes.as_mut_ptr();
    std::mem::forget(bytes);
    ptr
}

type LoadCallBack = extern "C" fn(Reference) -> *mut Vec<u8>;
type StoreCallBack = extern "C" fn(data: *const u8, len: libc::size_t) -> Reference;

#[no_mangle]
extern "C" fn load_persistent_tree_v1(
    mut loader: LoadCallBack,
    location: Reference,
) -> *mut PersistentState {
    let tree = PersistentState::load_from_location(&mut loader, location);
    match tree {
        Ok(tree) => Box::into_raw(Box::new(tree)),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
extern "C" fn store_persistent_tree_v1(
    mut writer: StoreCallBack,
    tree: *mut PersistentState,
) -> Reference {
    let tree = unsafe { &mut *tree };
    match tree.store_update(&mut writer) {
        Ok(r) => r,
        Err(_) => unreachable!(
            "Storing the tree can only fail if the writer fails. This is assumed not to happen."
        ),
    }
}

#[no_mangle]
extern "C" fn free_persistent_state_v1(tree: *mut PersistentState) {
    unsafe { Box::from_raw(tree) };
}

#[no_mangle]
extern "C" fn free_mutable_state_v1(tree: *mut MutableState) { unsafe { Box::from_raw(tree) }; }

#[no_mangle]
extern "C" fn freeze_mutable_state_v1(
    mut loader: LoadCallBack,
    tree: *mut MutableState,
    hash_buf: *mut u8,
) -> *mut PersistentState {
    let tree = unsafe { &mut *tree };
    let persistent = tree.freeze(&mut loader);
    let hash = persistent.hash();
    let hash: &[u8] = hash.as_ref();
    unsafe { std::ptr::copy_nonoverlapping(hash.as_ptr(), hash_buf, 32) };
    Box::into_raw(Box::new(persistent))
}

#[no_mangle]
extern "C" fn thaw_persistent_state_v1(tree: *mut PersistentState) -> *mut MutableState {
    let tree = unsafe { &*tree };
    let thawed = tree.thaw();
    Box::into_raw(Box::new(thawed))
}

#[no_mangle]
extern "C" fn get_new_state_size_v1(tree: *mut MutableState) -> u64 {
    // TODO: Actually implement meaningfully
    0
}

#[no_mangle]
extern "C" fn cache_persistent_state_v1(mut loader: LoadCallBack, tree: *mut PersistentState) {
    let tree = unsafe { &mut *tree };
    tree.cache(&mut loader)
}

#[no_mangle]
extern "C" fn hash_persistent_state_v1(tree: *mut PersistentState, hash_buf: *mut u8) {
    let tree = unsafe { &mut *tree };
    let hash = tree.hash();
    let hash: &[u8] = hash.as_ref();
    unsafe { std::ptr::copy_nonoverlapping(hash.as_ptr(), hash_buf, 32) };
}

#[no_mangle]
extern "C" fn serialize_persistent_state_v1(
    loader: LoadCallBack,
    tree: *mut PersistentState,
    out_len: *mut size_t,
) -> *mut u8 {
    todo!()
}

#[no_mangle]
extern "C" fn deserialize_persistent_state_v1(
    source: *const u8,
    len: size_t,
) -> *mut PersistentState {
    todo!()
}

#[no_mangle]
/// Take the byte array and copy it into a vector.
/// The vector must be passed to Rust to be deallocated.
extern "C" fn copy_to_vec_ffi(data: *const u8, len: libc::size_t) -> *mut Vec<u8> {
    Box::into_raw(Box::new(unsafe { std::slice::from_raw_parts(data, len) }.to_vec()))
}
