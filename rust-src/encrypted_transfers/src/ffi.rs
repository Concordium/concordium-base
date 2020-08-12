//! This module provides FFI exports of functions, intended to be used by the
//! scheduler, and the mobile wallet.

use crate::*;
use ffi_helpers::*;

type Group = pairing::bls12_381::G1;

pub extern "C" fn aggregate_encrypted_amounts(
    first_high_ptr: *const Cipher<Group>,
    first_low_ptr: *const Cipher<Group>,
    second_high_ptr: *const Cipher<Group>,
    second_low_ptr: *const Cipher<Group>,
    out_high_ptr: *mut *mut Cipher<Group>,
    out_low_ptr: *mut *mut Cipher<Group>,
) {
    unsafe {
        let first_high = from_ptr!(first_high_ptr);
        let first_low = from_ptr!(first_low_ptr);
        let second_high = from_ptr!(second_high_ptr);
        let second_low = from_ptr!(second_low_ptr);
        let out_high = first_high.combine(second_high);
        let out_low = first_low.combine(second_low);
        *out_high_ptr = Box::into_raw(Box::new(out_high));
        *out_low_ptr = Box::into_raw(Box::new(out_low));
    }
}
