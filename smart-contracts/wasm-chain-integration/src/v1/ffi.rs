//! This module provides, via C ABI, foreign access to validation and execution
//! of smart contracts. It is only available if `enable-ffi` feature is enabled.
//!
//! A number of objects are exchanged between Rust and foreign code, and their
//! lifetimes and ownership is fairly complex. The general design is that
//! structured objects related to smart contract execution are allocated in
//! Rust, and pointers to these objects are passed to foreign code. The foreign
//! code is also given a "free_*" function it can use to deallocate the objects
//! once they are no longer needed. Everything in this module is unsafe, in the
//! sense that if functions are not used correctly undefined behaviour can
//! occur, null-pointer dereferencing, double free, or worse. Each of the types
//! that is passed through the boundary documents its intended use.
//!
//! In addition to pointers to structured objects, the remaining data passed
//! between foreign code and Rust is mainly byte-arrays. The main reason for
//! this is that this is cheap and relatively easy to do.
use super::trie::{
    foreign::{LoadCallback, StoreCallback},
    EmptyCollector, Loadable, MutableState, PersistentState, Reference, SizeCollector,
};
use crate::v1::*;
use concordium_contracts_common::OwnedReceiveName;
use ffi_helpers::{slice_from_c_bytes, slice_from_c_bytes_worker};
use libc::size_t;
use sha2::Digest;
use wasm_transform::{
    artifact::{BorrowedArtifact, CompiledFunction},
    output::Output,
    utils::parse_artifact,
};

/// Creating or updating a contract instance requires access to code to execute.
/// This code is passed across the FFI boundary as serialized bytes, which are
/// deserialized into a `BorrowedArtifactV1` using as much zero-copy
/// deserialization as possible. The Rust code cannot retain a reference to the
/// artifact after the call returns. However, for handling of interrupts, it is
/// necessary to retain the artifact so that the function can later be resumed.
/// In this case, the `BorrowedArtifactV1` is converted to an `OwnedArtifact`
/// (creating a copy of the artifact), which is then retained by a
/// `ReceiveInterruptedStateV1`.
type BorrowedArtifactV1<'a> = BorrowedArtifact<'a, ProcessedImports>;

/// A value that is returned from a V1 contract in case of either successful
/// termination, or logic error. If contract execution traps with an illegal
/// instruction, or illegal host access then no return value is returned.
///
/// We allocate this vector on the Rust side. The main reason for this is that
/// it essentially only needs to be accessed from the smart contract execution
/// environment, so this avoids copying byte arrays back and forth. This also
/// helps in the analysis of costs, and allows us to charge relatively cheaply
/// for producing return values since the cost of handling them is immediately
/// clear when they are produced. This does unfortunately mean we have to deal
/// with the ugly Box<Vec<u8>> with the double indirection.
type ReturnValue = Vec<u8>;

/// Interrupted state of execution. This is needed to resume execution.
/// The lifetime of this is relatively complex. What is exchanged with foreign
/// code is not a pointer to this state, but rather a pointer to a pointer.
/// The reason for this is that this state must always have a unique owner. The
/// first time we allocate this state is in the [call_receive_v1] function.
/// Then if we resume execution we take ownership of the state in the
/// [resume_receive_v1] and substitute a null pointer for it. This state is then
/// **mutated** during execution of the [resume_receive_v1] function. If another
/// interrupt occurs then we again write a pointer to the struct into the
/// provided, thereby giving ownership to the foreign code.
/// [receive_interrupted_state_free] must be called to deallocate the state in
/// case execution of the smart contract was terminated by foreign code for any
/// reason.
type ReceiveInterruptedStateV1 = ReceiveInterruptedState<CompiledFunction>;

/// Invoke an init function creating the contract instance.
/// # Safety
/// This function is safe provided the following preconditions hold
/// - the `artifact_pointer` points to a valid serialized artifact of length
///   `artifact_bytes_len`.
/// - the `init_ctx_bytes`/`init_name`/`param_bytes` point to valid memory
///   addresses which contain
///   `init_ctx_bytes_len`/`init_name_len`/`param_bytes_len` bytes of data
/// - `output_return_value` points to a memory location that can store a pointer
/// - `output_len` points to a memory location that can store a [libc::size_t]
///   value
/// # Return value
/// The return value is a pointer to a byte array buffer of size `*output_len`.
/// To avoid leaking memory the buffer should be deallocated with
/// `rs_free_array_len` (available in the crypto-common crate).
/// The data in the buffer is produced by the [InitResult::extract] function and
/// contains the serialization of the return value. The value of the out
/// parameters depends on the result of initialization.
/// - In case of [InitResult::OutOfEnergy] the `output_return_value` parameter
///   is left unchanged.
/// - In the remaining two cases the `output_return_value` is set to a pointer
///   to a freshly allocated vector. This vector must be deallocated with
///   [box_vec_u8_free] otherwise memory will be leaked.
/// In case of execution failure, a panic, or failure to parse a null pointer is
/// returned.
#[no_mangle]
unsafe extern "C" fn call_init_v1(
    // Operationally this is not really needed since nothing is loaded, since a fresh empty state
    // is initialized. However reflecting this in types would be a lot of extra work for no
    // real gain. So we require it.
    loader: LoadCallback,
    artifact_ptr: *const u8,    // pointer to the artifact
    artifact_bytes_len: size_t, // length of the artifact
    init_ctx_bytes: *const u8,  // pointer to an initcontext
    init_ctx_bytes_len: size_t,
    amount: u64,
    init_name: *const u8, // the name of the contract init method
    init_name_len: size_t,
    param_bytes: *const u8, // parameters to the init method
    param_bytes_len: size_t,
    limit_logs_and_return_values: u8,
    energy: InterpreterEnergy,
    output_return_value: *mut *mut ReturnValue,
    output_len: *mut size_t,
    output_state_ptr: *mut *mut MutableState,
) -> *mut u8 {
    let artifact_bytes = slice_from_c_bytes!(artifact_ptr, artifact_bytes_len as usize);
    let artifact: BorrowedArtifactV1 = if let Ok(borrowed_artifact) = parse_artifact(artifact_bytes)
    {
        borrowed_artifact
    } else {
        return std::ptr::null_mut();
    };

    let res = std::panic::catch_unwind(|| {
        let init_name = slice_from_c_bytes!(init_name, init_name_len as usize);
        let parameter = slice_from_c_bytes!(param_bytes, param_bytes_len as usize);
        let limit_logs_and_return_values = limit_logs_and_return_values != 0;
        let init_ctx = v0::deserial_init_context(slice_from_c_bytes!(
            init_ctx_bytes,
            init_ctx_bytes_len as usize
        ))
        .expect("Precondition violation: invalid init ctx given by host.");
        match std::str::from_utf8(init_name) {
            Ok(name) => {
                let res = invoke_init(
                    &artifact,
                    init_ctx,
                    InitInvocation {
                        amount: Amount::from_micro_ccd(amount),
                        init_name: name,
                        parameter,
                        energy,
                    },
                    limit_logs_and_return_values,
                    loader,
                );
                match res {
                    Ok(result) => {
                        let (mut out, initial_state, return_value) = result.extract();
                        out.shrink_to_fit();
                        *output_len = out.len() as size_t;
                        let ptr = out.as_mut_ptr();
                        std::mem::forget(out);
                        if let Some(return_value) = return_value {
                            *output_return_value = Box::into_raw(Box::new(return_value));
                        } else {
                            *output_return_value = std::ptr::null_mut();
                        }
                        if let Some(initial_state) = initial_state {
                            let initial_state = Box::into_raw(Box::new(initial_state));
                            *output_state_ptr = initial_state;
                        }
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

/// Invoke a receive function, updating the contract instance.
/// # Safety
/// This function is safe provided the following preconditions hold
/// - the `artifact_pointer` points to a valid serialized artifact of length
///   `artifact_bytes_len`.
/// - the `receive_ctx_bytes`/`receive_name`/`param_bytes`/`state_bytes` point
///   to valid memory addresses which contain
///   `receive_ctx_bytes_len`/`receive_name_len`/`param_bytes_len`/
///   `state_bytes_len` bytes of data
/// - `output_return_value` points to a memory location that can store a pointer
/// - `output_config` points to a memory location that can store a pointer
/// - `output_len` points to a memory location that can store a [libc::size_t]
///   value
/// # Return value
/// The return value is a pointer to a byte array buffer of size `*output_len`.
/// To avoid leaking memory the buffer should be deallocated with
/// `rs_free_array_len` (available in the crypto-common crate).
///
/// The data in the buffer is produced by the [ReceiveResult::extract] function
/// and contains the serialization of the return value. The value of the out
/// parameters depends on the result of execution
/// - In case of [ReceiveResult::OutOfEnergy] or [ReceiveResult::Trap] the
///   `output_return_value` parameter is left unchanged.
/// - In case of [ReceiveResult::Interrupt] the `output_config` pointer is set
///   to a freshly allocated [ReceiveInterruptedState] structure. This should be
///   deallocated with [receive_interrupted_state_free] so that memory is not
///   leaked.
/// - In the remaining two cases the `output_return_value` is set to a pointer
///   to a freshly allocated vector and `output_config` is __not__ changed. This
///   vector must be deallocated with [box_vec_u8_free] otherwise memory will be
///   leaked.
/// In case of execution failure, a panic, or failure to parse a null pointer is
/// returned.
#[no_mangle]
unsafe extern "C" fn call_receive_v1(
    loader: LoadCallback,
    artifact_ptr: *const u8,      // pointer to the artifact
    artifact_bytes_len: size_t,   // length of the artifact
    receive_ctx_bytes: *const u8, // receive context
    receive_ctx_bytes_len: size_t,
    amount: u64,
    // name of the entrypoint that was named. If `call_default` is set below than this will be
    // different from the entrypoint that is actually invoked.
    receive_name: *const u8,
    receive_name_len: size_t,
    call_default: u8, // non-zero if to call the default/fallback instead
    state_ptr_ptr: *mut *mut MutableState,
    param_bytes: *const u8, // parameters to the entrypoint
    param_bytes_len: size_t,
    max_parameter_size: size_t,
    limit_logs_and_return_values: u8, // non-zero means to limit
    energy: InterpreterEnergy,
    output_return_value: *mut *mut ReturnValue,
    output_config: *mut *mut ReceiveInterruptedStateV1,
    output_len: *mut size_t,
    support_queries_tag: u8, // non-zero to enable support of chain queries.
) -> *mut u8 {
    let artifact_bytes = slice_from_c_bytes!(artifact_ptr, artifact_bytes_len as usize);
    let artifact: BorrowedArtifactV1 = if let Ok(borrowed_artifact) = parse_artifact(artifact_bytes)
    {
        borrowed_artifact
    } else {
        return std::ptr::null_mut();
    };
    let res = std::panic::catch_unwind(|| -> *mut u8 {
        // For FFI we only pass v0 contexts to keep the other end simpler.
        let receive_ctx_common = v0::deserial_receive_context(slice_from_c_bytes!(
            receive_ctx_bytes,
            receive_ctx_bytes_len as usize
        ))
        .expect("Precondition violation: Should be given a valid receive context.");
        let receive_name = slice_from_c_bytes!(receive_name, receive_name_len as usize);
        let parameter = slice_from_c_bytes!(param_bytes, param_bytes_len as usize);
        let limit_logs_and_return_values = limit_logs_and_return_values != 0;
        let state_ptr = std::mem::replace(&mut *state_ptr_ptr, std::ptr::null_mut());
        let mut loader = loader;
        let mut state = (&mut *state_ptr).make_fresh_generation(&mut loader);
        let instance_state = InstanceState::new(loader, state.get_inner(&mut loader));
        match std::str::from_utf8(receive_name)
            .ok()
            .and_then(|s| OwnedReceiveName::new(s.into()).ok())
        {
            Some(name) => {
                let entrypoint: OwnedEntrypointName =
                    name.as_receive_name().entrypoint_name().into();
                // the actual name to invoke
                let actual_name = if call_default != 0 {
                    let mut actual_name: String = name.as_receive_name().contract_name().into();
                    actual_name.push('.');
                    OwnedReceiveName::new_unchecked(actual_name)
                } else {
                    name
                };

                let receive_ctx = ReceiveContext {
                    common: receive_ctx_common,
                    entrypoint,
                };

                let support_queries = support_queries_tag != 0;

                let params = ReceiveParams {
                    max_parameter_size,
                    limit_logs_and_return_values,
                    support_queries,
                };

                let res = invoke_receive(
                    artifact,
                    receive_ctx,
                    ReceiveInvocation {
                        amount: Amount::from_micro_ccd(amount),
                        energy,
                        receive_name: actual_name.as_receive_name(),
                        parameter,
                    },
                    instance_state,
                    params,
                );
                match res {
                    Ok(result) => {
                        let ReceiveResultExtract {
                            mut status,
                            state_changed,
                            interrupt_state,
                            return_value,
                        } = result.extract();
                        status.shrink_to_fit();
                        *output_len = status.len() as size_t;
                        let ptr = status.as_mut_ptr();
                        std::mem::forget(status);
                        if let Some(config) = interrupt_state {
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
                        if state_changed {
                            let new_state = Box::into_raw(Box::new(state));
                            *state_ptr_ptr = new_state;
                        }
                        ptr
                    }
                    Err(_trap) => std::ptr::null_mut(),
                }
            }
            // should not happen, unless the caller violated the precondition and invoked an
            // incorrect entrypoint.
            None => std::ptr::null_mut(),
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
/// - `support_upgrade` whether to allow (1) the `upgrade` host call or not (0).
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
/// is encoded as u16, big endian.
///
/// If validation succeeds, the serialized artifact is at
/// `*output_artifact_bytes` and should be freed with `rs_free_array_len`.
///
/// # Safety
/// This function is safe provided all the supplied pointers are not null and
/// the `wasm_bytes_ptr` points to an array of length at least `wasm_bytes_len`.
unsafe extern "C" fn validate_and_process_v1(
    // Whether the current protocol version supports smart contract upgrades.
    support_upgrade: u8,
    wasm_bytes_ptr: *const u8,
    wasm_bytes_len: size_t,
    // this is the total length of the output byte array
    output_len: *mut size_t,
    // the length of the artifact byte array
    output_artifact_len: *mut size_t,
    // location where the pointer to the artifact will
    // be written.
    output_artifact_bytes: *mut *const u8,
) -> *mut u8 {
    let wasm_bytes = slice_from_c_bytes!(wasm_bytes_ptr, wasm_bytes_len as usize);
    match utils::instantiate_with_metering::<ProcessedImports, _>(
        &ConcordiumAllowedImports {
            support_upgrade: support_upgrade == 1,
        },
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

#[no_mangle]
/// Resume execution of a contract after an interrupt.
///
/// # Safety
/// This function is safe provided
/// - `config_ptr` points to a memory location which in turn points to a
///   ReceiveInterruptedState structure. the latter pointer must have been
///   constructed with [Box::into_raw] and must be non-null.
/// - the remaing arguments have the same requirements as they do for
///   [call_receive_v1]....
///
/// # Return value
/// The return value has the same semantics as
unsafe extern "C" fn resume_receive_v1(
    loader: LoadCallback,
    // mutable pointer, we will mutate this, either to a new state in case another interrupt
    // occurred, or null
    config_ptr: *mut *mut ReceiveInterruptedStateV1,
    // whether the state has been updated (non-zero) or not (zero)
    state_updated_tag: u8,
    state_ptr_ptr: *mut *mut MutableState,
    new_amount: u64,
    // whether the call succeeded or not.
    response_status: u64,
    // response from the call.
    response: *mut ReturnValue,
    // remaining energy available for execution
    energy: InterpreterEnergy,
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
        let response = if let Ok(r) = InvokeResponse::try_from_ffi_response(
            response_status,
            Amount::from_micro_ccd(new_amount),
            data,
        ) {
            r
        } else {
            return std::ptr::null_mut();
        };
        // mark the interrupted state as consumed in case any panics happen from here to
        // the end. this means the state is in a consistent state and the
        // finalizer (`receive_interrupted_state_free`) will not end up double
        // freeing.
        let config = std::ptr::replace(config_ptr, std::ptr::null_mut());
        // since we will never roll back past this point, other than to the beginning of
        // execution, we do not need to make a new generation for checkpoint
        // reasons. We are not the owner of the state, so we make a clone of it.
        // Before cloning we replace the contents of the pointer with a null pointer.
        // Whether the contents is null or not at the end of execution signals whether
        // the state has changed, so this is crucial.
        let state_ref = std::mem::replace(&mut *state_ptr_ptr, std::ptr::null_mut());
        // The clone is cheap since this is reference counted.
        let mut state = (&*state_ref).clone();
        // it is important to invalidate all previous iterators and entries we have
        // given out. so we start a new generation.
        let config = Box::from_raw(config);
        let state_updated = state_updated_tag != 0;
        let res = resume_receive(config, response, energy, &mut state, state_updated, loader);
        match res {
            Ok(result) => {
                let ReceiveResultExtract {
                    mut status,
                    state_changed,
                    interrupt_state,
                    return_value,
                } = result.extract();
                status.shrink_to_fit();
                *output_len = status.len() as size_t;
                let ptr = status.as_mut_ptr();
                std::mem::forget(status);
                if let Some(config) = interrupt_state {
                    std::ptr::replace(config_ptr, Box::into_raw(config));
                } // otherwise leave config_ptr pointing to null
                if let Some(return_value) = return_value {
                    *output_return_value = Box::into_raw(Box::new(return_value));
                }
                if state_changed {
                    *state_ptr_ptr = Box::into_raw(Box::new(state))
                }
                ptr
            }
            Err(_trap) => std::ptr::null_mut(),
        }
    });
    res.unwrap_or(std::ptr::null_mut())
}

// Administrative functions.

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
unsafe extern "C" fn receive_interrupted_state_free(ptr_ptr: *mut *mut ReceiveInterruptedStateV1) {
    if !ptr_ptr.is_null() && !(*ptr_ptr).is_null() {
        // drop
        let _: Box<ReceiveInterruptedStateV1> = Box::from_raw(*ptr_ptr);
        // and store null so that future calls (which there should not be any) are safe.
        *ptr_ptr = std::ptr::null_mut();
    }
}

#[no_mangle]
/// Convert the return value to a byte array that will be managed externally.
/// To avoid memory leaks the return byte array must be deallocated using
/// rs_free_array_len.
///
/// # Safety
/// This function is safe provided the return value is constructed using
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

#[no_mangle]
/// Load the persistent state from a given location in the backing store. The
/// store is accessed via the provided function pointer.
extern "C" fn load_persistent_tree_v1(
    mut loader: LoadCallback,
    location: Reference,
) -> *mut PersistentState {
    let tree = PersistentState::load_from_location(&mut loader, location);
    match tree {
        Ok(tree) => Box::into_raw(Box::new(tree)),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
/// Store the tree into a backing store, writing parts of the tree using the
/// provided callback. The return value is a reference in the backing store that
/// can be used to load the tree using [load_persistent_tree_v1].
extern "C" fn store_persistent_tree_v1(
    mut writer: StoreCallback,
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
/// Migrate the persistent tree from one backing store to another.
extern "C" fn migrate_persistent_tree_v1(
    mut loader: LoadCallback,
    mut writer: StoreCallback,
    tree: *mut PersistentState,
) -> *mut PersistentState {
    let tree = unsafe { &mut *tree };
    match tree.migrate(&mut writer, &mut loader) {
        Ok(new_tree) => Box::into_raw(Box::new(new_tree)),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
/// Deallocate the persistent state, freeing as much memory as possible.
extern "C" fn free_persistent_state_v1(tree: *mut PersistentState) {
    unsafe { Box::from_raw(tree) };
}

#[no_mangle]
/// Deallocate the mutable state.
extern "C" fn free_mutable_state_v1(tree: *mut MutableState) { unsafe { Box::from_raw(tree) }; }

#[no_mangle]
/// Convert the mutable state to a persistent one. Return a pointer to the
/// persistent state, and in addition write the hash of the resulting persistent
/// state to the provided byte buffer. The byte buffer must be sufficient to
/// hold 32 bytes.
/// The returned persistent state must be deallocated using
/// [free_persistent_state_v1] in order to not leak memory.
extern "C" fn freeze_mutable_state_v1(
    mut loader: LoadCallback,
    tree: *mut MutableState,
    hash_buf: *mut u8,
) -> *mut PersistentState {
    let tree = unsafe { &mut *tree };
    let persistent = tree.freeze(&mut loader, &mut EmptyCollector);
    let hash = persistent.hash(&mut loader);
    let hash: &[u8] = hash.as_ref();
    unsafe { std::ptr::copy_nonoverlapping(hash.as_ptr(), hash_buf, 32) };
    Box::into_raw(Box::new(persistent))
}

#[no_mangle]
/// Create a mutable state from a persistent one. This is generative, it creates
/// independent mutable states in different calls.
extern "C" fn thaw_persistent_state_v1(tree: *mut PersistentState) -> *mut MutableState {
    let tree = unsafe { &*tree };
    let thawed = tree.thaw();
    Box::into_raw(Box::new(thawed))
}

#[no_mangle]
/// Freeze the tree and get the new state size.
/// The frozen tree is not returned, but it is stored in the "origin" field so
/// that a call to freeze later on is essentially free.
/// The mutable state should not be used after a call to this function.
extern "C" fn get_new_state_size_v1(mut loader: LoadCallback, tree: *mut MutableState) -> u64 {
    let tree = unsafe { &mut *tree };
    let mut collector = SizeCollector::default();
    let _ = tree.freeze(&mut loader, &mut collector);
    collector.collect()
}

#[no_mangle]
/// Compute the hash of the persistent state and write it to the provided
/// buffer which is assumed to be able to hold 32 bytes.
/// The hash of the tree is cached, so this is generally a cheap function.
extern "C" fn hash_persistent_state_v1(
    mut loader: LoadCallback,
    tree: *mut PersistentState,
    hash_buf: *mut u8,
) {
    let tree = unsafe { &mut *tree };
    let hash = tree.hash(&mut loader);
    let hash: &[u8] = hash.as_ref();
    unsafe { std::ptr::copy_nonoverlapping(hash.as_ptr(), hash_buf, 32) };
}

#[no_mangle]
/// Serialize persistent state into a byte buffer. If any of the state is in the
/// backing store it is loaded using the provided callback.
/// The returned byte array should be freed with `rs_free_array_len` from
/// crypto-common.
extern "C" fn serialize_persistent_state_v1(
    mut loader: LoadCallback,
    tree: *mut PersistentState,
    out_len: *mut size_t,
) -> *mut u8 {
    let tree = unsafe { &*tree };
    let mut out = Vec::new();
    match tree.serialize(&mut loader, &mut out) {
        Ok(_) => {
            out.shrink_to_fit();
            unsafe { *out_len = out.len() as size_t };
            let ptr = out.as_mut_ptr();
            std::mem::forget(out);
            ptr
        }
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
/// Dual to [serialize_persistent_state_v1].
extern "C" fn deserialize_persistent_state_v1(
    source: *const u8,
    len: size_t,
) -> *mut PersistentState {
    let slice = unsafe { std::slice::from_raw_parts(source, len) };
    let mut source = std::io::Cursor::new(slice);
    match PersistentState::deserialize(&mut source) {
        // make sure to consume the entire input.
        Ok(state) if source.position() == len as u64 => Box::into_raw(Box::new(state)),
        _ => std::ptr::null_mut(),
    }
}

#[no_mangle]
/// Take the byte array and copy it into a vector.
/// The vector must be passed to Rust to be deallocated.
extern "C" fn copy_to_vec_ffi(data: *const u8, len: libc::size_t) -> *mut Vec<u8> {
    Box::into_raw(Box::new(unsafe { std::slice::from_raw_parts(data, len) }.to_vec()))
}

#[no_mangle]
/// Lookup in the persistent state. **This should only be used for testing the
/// integration**. It is not efficient compared to thawing and looking up.
extern "C" fn persistent_state_v1_lookup(
    mut loader: LoadCallback,
    key: *const u8,
    key_len: libc::size_t,
    tree: *mut PersistentState,
    out_len: *mut size_t,
) -> *mut u8 {
    let tree = unsafe { &*tree };
    let key = unsafe { std::slice::from_raw_parts(key, key_len) };
    match tree.lookup(&mut loader, key) {
        Some(mut out) => {
            out.shrink_to_fit();
            unsafe { *out_len = out.len() as size_t };
            let ptr = out.as_mut_ptr();
            std::mem::forget(out);
            ptr
        }
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
/// Generate a persistent tree from a seed for testing. **This should only be
/// used for testing.**
extern "C" fn generate_persistent_state_from_seed(seed: u64, len: u64) -> *mut PersistentState {
    let res = std::panic::catch_unwind(|| {
        let mut mutable = PersistentState::Empty.thaw();
        let mut loader = trie::Loader::new(&[]);
        {
            let mut state_lock = mutable.get_inner(&mut loader).lock();
            let mut hasher = sha2::Sha512::new();
            hasher.update(&seed.to_be_bytes());
            for i in 0..len {
                let data = hasher.finalize_reset();
                hasher.update(&data);
                state_lock.insert(&mut loader, &data, i.to_be_bytes().to_vec()).unwrap();
            }
        }
        Box::new(mutable.freeze(&mut loader, &mut trie::EmptyCollector))
    });
    if let Ok(r) = res {
        Box::into_raw(r)
    } else {
        std::ptr::null_mut()
    }
}
