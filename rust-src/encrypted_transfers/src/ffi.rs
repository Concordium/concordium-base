//! This module provides FFI exports of functions, intended to be used by the
//! scheduler, and the mobile wallet.

use crate::*;
use crypto_common::*;
use ffi_helpers::*;
use prelude::StdRng;
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

#[derive(Serialize)]
/// Second component of the elgamal public key, i.e., the public key
/// minus the generator.
/// FIXME: We should probably change the elgamal struct to have a fixed
/// generator, globally defined, instead of this way of doing it.
pub struct ElgamalPublicKeySecond(Group);

macro_derive_from_bytes!(
    Box elgamal_second_from_bytes,
    ElgamalPublicKeySecond
);
macro_derive_to_bytes!(Box elgamal_second_to_bytes, ElgamalPublicKeySecond);
macro_free_ffi!(Box elgamal_second_free, ElgamalPublicKeySecond);

#[derive(Serialize)]
/// Analogue of the above, should be removed once we revise the secret keys of
/// elgamal with a fixed generator.
pub struct ElgamalSecretKeySecond(<Group as Curve>::Scalar);

macro_derive_from_bytes!(
    Box elgamal_second_secret_from_bytes,
    ElgamalSecretKeySecond
);
macro_derive_to_bytes!(Box elgamal_second_secret_to_bytes, ElgamalSecretKeySecond);
macro_free_ffi!(Box elgamal_second_secret_free, ElgamalSecretKeySecond);

/// This is used for testing in haskell, providing deterministic key generation
/// from seed.
#[no_mangle]
extern "C" fn elgamal_second_secret_gen_seed(seed: u64) -> *mut ElgamalSecretKeySecond {
    let mut rng: StdRng = SeedableRng::seed_from_u64(seed);
    Box::into_raw(Box::new(ElgamalSecretKeySecond(Group::generate_scalar(
        &mut rng,
    ))))
}

/// Derive public key, only meant for testing.
/// FIXME: Should be replaced and optimized once the elgamal public and secret
/// keys do not have an explicit generator attached to them.
///
/// # Safety
///
/// This function assumes the pointer is safe to dereference with the given
/// type, i.e., it is non-null and produced via Box::into_raw.
#[no_mangle]
unsafe extern "C" fn derive_elgamal_second_public(
    sec: *mut ElgamalSecretKeySecond,
) -> *mut ElgamalPublicKeySecond {
    let gc = GlobalContext::<Group>::generate();
    Box::into_raw(Box::new(ElgamalPublicKeySecond(
        gc.elgamal_generator().mul_by_scalar(&from_ptr!(sec).0),
    )))
}

/// # Safety
/// This function is safe if the pointers to structures are all non-null, and
/// produced by `Box::into_raw`. The `transfer_bytes_ptr` can be null in case
/// the length is 0, but otherwise it must be non-null and dereferenceable.
///
/// Return 0 in case verification was unsuccesful, and a non-zero value
/// otherwise.
#[no_mangle]
unsafe extern "C" fn verify_encrypted_transfer(
    ctx_ptr: *const GlobalContext<Group>,
    receiver_pk_ptr: *const ElgamalPublicKeySecond,
    sender_pk_ptr: *const ElgamalPublicKeySecond,
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

    let receiver_pk = elgamal::PublicKey {
        generator: *ctx.elgamal_generator(),
        key:       receiver_pk.0,
    };

    let sender_pk = elgamal::PublicKey {
        generator: *ctx.elgamal_generator(),
        key:       sender_pk.0,
    };

    let initial = EncryptedAmount {
        encryptions: [*initial_high, *initial_low],
    };

    let transfer_data = if let Ok(td) = (&mut Cursor::new(transfer_bytes)).get() {
        td
    } else {
        return 0;
    };

    if verify_transfer_data(ctx, &receiver_pk, &sender_pk, &initial, &transfer_data) {
        1
    } else {
        0
    }
}

#[no_mangle]
unsafe extern "C" fn verify_sec_to_pub_transfer(
    ctx_ptr: *const GlobalContext<Group>,
    sender_pk_ptr: *const ElgamalPublicKeySecond,
    initial_high_ptr: *const Cipher<Group>,
    initial_low_ptr: *const Cipher<Group>,
    transfer_bytes_ptr: *const u8,
    transfer_bytes_len: size_t,
) -> u8 {
    let ctx = from_ptr!(ctx_ptr);
    let initial_high = from_ptr!(initial_high_ptr);
    let initial_low = from_ptr!(initial_low_ptr);
    let transfer_bytes = slice_from_c_bytes!(transfer_bytes_ptr, transfer_bytes_len as usize);

    let sender_pk = from_ptr!(sender_pk_ptr);

    let sender_pk = elgamal::PublicKey {
        generator: *ctx.elgamal_generator(),
        key:       sender_pk.0,
    };

    let initial = EncryptedAmount {
        encryptions: [*initial_high, *initial_low],
    };

    let transfer_data = if let Ok(td) = (&mut Cursor::new(transfer_bytes)).get() {
        td
    } else {
        return 0;
    };

    if verify_sec_to_pub_transfer_data(ctx, &sender_pk, &initial, &transfer_data) {
        1
    } else {
        0
    }
}

#[no_mangle]
unsafe extern "C" fn encrypt_amount_with_zero_randomness(
    ctx_ptr: *const GlobalContext<Group>,
    microgtu: u64,
    out_high_ptr: *mut *const Cipher<Group>,
    out_low_ptr: *mut *const Cipher<Group>,
) {
    let encrypted = encrypt_amount_with_fixed_randomness(from_ptr!(ctx_ptr), Amount { microgtu });
    *out_high_ptr = Box::into_raw(Box::new(encrypted.encryptions[1]));
    *out_low_ptr = Box::into_raw(Box::new(encrypted.encryptions[0]));
}
