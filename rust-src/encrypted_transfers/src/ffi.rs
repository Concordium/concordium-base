//! This module provides FFI exports of functions, intended to be used by the
//! scheduler, and the mobile wallet.

use crate::*;
use crypto_common::{size_t, Get};
use ffi_helpers::*;
use std::io::Cursor;

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
/// produced by `Box::into_raw`. The `transfer_bytes_ptr` can be null in case
/// the length is 0, but otherwise it must be non-null and dereferenceable.
///
/// Return 0 in case verification was unsuccesful, and a non-zero value otherwise.
#[no_mangle]
unsafe extern "C" fn verify_encrypted_transfer(
    ctx_ptr: *const GlobalContext<Group>,
    receiver_pk_ptr: *const PublicKey<Group>,
    sender_pk_ptr: *const PublicKey<Group>,
    initial_high_ptr: *const Cipher<Group>,
    initial_low_ptr: *const Cipher<Group>,
    transfer_bytes_ptr: *const u8,
    transfer_bytes_len: size_t,
) -> u8 {
    let ctx = from_ptr!(ctx_ptr);
    let initial_high = from_ptr!(initial_high_ptr);
    let initial_low = from_ptr!(initial_low_ptr);
    let transfer_bytes = slice_from_c_bytes!(transfer_bytes_ptr, transfer_bytes_len as usize);

    let receiver_pk = from_ptr!(receiver_pk_ptr);
    let sender_pk = from_ptr!(sender_pk_ptr);

    let initial = EncryptedAmount {
        encryptions: [*initial_high, *initial_low],
    };

    let transfer_data = if let Ok(td) = (&mut Cursor::new(transfer_bytes)).get() {
        td
    } else {
        return 0;
    };

    if verify_transfer_data(ctx, receiver_pk, sender_pk, &initial, &transfer_data) {
        1
    } else {
        0
    }
}
