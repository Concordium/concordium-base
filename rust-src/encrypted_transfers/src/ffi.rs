//! This module provides FFI exports of functions, intended to be used by the
//! scheduler, and the mobile wallet.

use crate::*;
use ffi_helpers::*;

type Group = pairing::bls12_381::G1;

/// # Safety
/// This function is safe if the pointers are all non-null, and produced
/// by `Box::into_raw` for the input pointers.
#[no_mangle]
unsafe extern "C" fn aggregate_encrypted_amounts(
    first_high_ptr: *const Cipher<Group>,
    first_low_ptr: *const Cipher<Group>,
    second_high_ptr: *const Cipher<Group>,
    second_low_ptr: *const Cipher<Group>,
    out_high_ptr: *mut *mut Cipher<Group>,
    out_low_ptr: *mut *mut Cipher<Group>,
) {
    let first_high = from_ptr!(first_high_ptr);
    let first_low = from_ptr!(first_low_ptr);
    let second_high = from_ptr!(second_high_ptr);
    let second_low = from_ptr!(second_low_ptr);
    let out_high = first_high.combine(second_high);
    let out_low = first_low.combine(second_low);
    *out_high_ptr = Box::into_raw(Box::new(out_high));
    *out_low_ptr = Box::into_raw(Box::new(out_low));
}

/// # Safety
/// This function is safe if the pointers to structures are all non-null, and
/// produced by `Box::into_raw`. The `transfer_proof_ptr` can be null in case
/// the length is 0, but otherwise it must be non-null and dereferenceable.
#[no_mangle]
unsafe extern "C" fn verify_encrypted_transfer(
    ctx_ptr: *const GlobalContext<Group>,
    initial_high_ptr: *const Cipher<Group>,
    initial_low_ptr: *const Cipher<Group>,
    remaining_high_ptr: *const Cipher<Group>,
    remaining_low_ptr: *const Cipher<Group>,
    transfer_high_ptr: *const Cipher<Group>,
    transfer_low_ptr: *const Cipher<Group>,
    transfer_proof_len: libc::size_t,
    transfer_proof_ptr: *const u8,
) -> u8 {
    let ctx = from_ptr!(ctx_ptr);
    let initial_high = from_ptr!(initial_high_ptr);
    let initial_low = from_ptr!(initial_low_ptr);
    let remaining_high = from_ptr!(remaining_high_ptr);
    let remaining_low = from_ptr!(remaining_low_ptr);
    let transfer_high = from_ptr!(transfer_high_ptr);
    let transfer_low = from_ptr!(transfer_low_ptr);
    let transfer_proof = slice_from_c_bytes!(transfer_proof_ptr, transfer_proof_len as usize);
    todo!()
}
