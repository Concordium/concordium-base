#![cfg(feature = "ffi")]
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
unsafe extern "C" fn is_zero_encrypted_amount(
    high_ptr: *const Cipher<Group>,
    low_ptr: *const Cipher<Group>,
) -> u8 {
    let high = from_ptr!(high_ptr);
    let low = from_ptr!(low_ptr);
    let res = high.0.is_zero_point()
        && high.1.is_zero_point()
        && low.0.is_zero_point()
        && low.1.is_zero_point();
    u8::from(res)
}

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
/// A group element needed in FFI.
struct GroupElement(Group);

macro_derive_from_bytes!(
    Box group_element_from_bytes,
    GroupElement
);
macro_derive_to_bytes!(Box group_element_to_bytes, GroupElement);
macro_free_ffi!(Box group_element_free, GroupElement);

#[no_mangle]
/// Generate a new group element, using the
/// elgamal generator from the global context.
unsafe extern "C" fn group_element_from_seed(
    gc_ptr: *const GlobalContext<Group>,
    seed: u64,
) -> *mut GroupElement {
    let mut rng: StdRng = SeedableRng::seed_from_u64(seed);
    let gc = from_ptr!(gc_ptr);
    let pk = elgamal::PublicKey::from(&elgamal::SecretKey::generate(
        gc.elgamal_generator(),
        &mut rng,
    ));
    Box::into_raw(Box::new(GroupElement(pk.key)))
}

/// # Safety
/// This function is safe if the pointers to structures are all non-null, and
/// produced by `Box::into_raw`.
#[no_mangle]
unsafe extern "C" fn encrypt_amount_with_zero_randomness(
    ctx_ptr: *const GlobalContext<Group>,
    micro_ccd: u64,
    out_high_ptr: *mut *const Cipher<Group>,
    out_low_ptr: *mut *const Cipher<Group>,
) {
    let encrypted =
        encrypt_amount_with_fixed_randomness(from_ptr!(ctx_ptr), Amount::from_micro_ccd(micro_ccd));
    *out_high_ptr = Box::into_raw(Box::new(encrypted.encryptions[1]));
    *out_low_ptr = Box::into_raw(Box::new(encrypted.encryptions[0]));
}

/// # Safety
/// This function is safe if the pointers to structures are all non-null, and
/// produced by `Box::into_raw`.
#[no_mangle]
unsafe extern "C" fn make_encrypted_transfer_data(
    ctx_ptr: *const GlobalContext<Group>,
    receiver_pk_ptr: *const elgamal::PublicKey<Group>,
    sender_sk_ptr: *const elgamal::SecretKey<Group>,
    input_amount_ptr: *const AggregatedDecryptedAmount<Group>,
    micro_ccd: u64,
    high_remaining: *mut *const Cipher<Group>,
    low_remaining: *mut *const Cipher<Group>,
    high_transfer: *mut *const Cipher<Group>,
    low_transfer: *mut *const Cipher<Group>,
    out_index: *mut u64,
    proof_len: *mut u64,
) -> *mut u8 {
    let ctx = from_ptr!(ctx_ptr);

    let receiver_pk = from_ptr!(receiver_pk_ptr);

    let sender_sk = from_ptr!(sender_sk_ptr);

    let input_amount = from_ptr!(input_amount_ptr);

    let mut csprng = thread_rng();

    let data = match make_transfer_data(
        ctx,
        receiver_pk,
        sender_sk,
        input_amount,
        Amount::from_micro_ccd(micro_ccd),
        &mut csprng,
    ) {
        Some(it) => it,
        _ => return std::ptr::null_mut(),
    };

    *high_remaining = Box::into_raw(Box::new(data.remaining_amount.encryptions[1]));
    *low_remaining = Box::into_raw(Box::new(data.remaining_amount.encryptions[0]));
    *high_transfer = Box::into_raw(Box::new(data.transfer_amount.encryptions[1]));
    *low_transfer = Box::into_raw(Box::new(data.transfer_amount.encryptions[0]));
    *out_index = data.index.index;

    let mut bytes = to_bytes(&data.proof);
    *proof_len = bytes.len() as u64;
    let ptr = bytes.as_mut_ptr();
    std::mem::forget(bytes);
    ptr
}

/// # Safety
/// This function is safe if the pointers to structures are all non-null, and
/// produced by `Box::into_raw`. The `transfer_proof_ptr` can be null in case
/// the length is 0, but otherwise it must be non-null and dereferenceable.
///
/// Return 0 in case verification was unsuccesful, and a non-zero value
/// otherwise.
#[no_mangle]
unsafe extern "C" fn verify_encrypted_transfer(
    ctx_ptr: *const GlobalContext<Group>,
    receiver_pk_ptr: *const elgamal::PublicKey<Group>,
    sender_pk_ptr: *const elgamal::PublicKey<Group>,
    initial_high_ptr: *const Cipher<Group>,
    initial_low_ptr: *const Cipher<Group>,
    remaining_high_ptr: *const Cipher<Group>,
    remaining_low_ptr: *const Cipher<Group>,
    transfer_high_ptr: *const Cipher<Group>,
    transfer_low_ptr: *const Cipher<Group>,
    encrypted_agg_index: u64,
    transfer_proof_ptr: *const u8,
    transfer_proof_len: size_t,
) -> u8 {
    let ctx = from_ptr!(ctx_ptr);

    let receiver_pk = from_ptr!(receiver_pk_ptr);

    let sender_pk = from_ptr!(sender_pk_ptr);

    let initial_high = from_ptr!(initial_high_ptr);
    let initial_low = from_ptr!(initial_low_ptr);
    let initial = EncryptedAmount {
        encryptions: [*initial_low, *initial_high],
    };

    let remaining_high = from_ptr!(remaining_high_ptr);
    let remaining_low = from_ptr!(remaining_low_ptr);
    let remaining_amount = EncryptedAmount {
        encryptions: [*remaining_low, *remaining_high],
    };

    let transfer_high = from_ptr!(transfer_high_ptr);
    let transfer_low = from_ptr!(transfer_low_ptr);
    let transfer_amount = EncryptedAmount {
        encryptions: [*transfer_low, *transfer_high],
    };

    let transfer_proof = slice_from_c_bytes!(transfer_proof_ptr, transfer_proof_len as usize);
    let proof = if let Ok(td) = (&mut Cursor::new(transfer_proof)).get() {
        td
    } else {
        return 0;
    };

    let transfer_data = EncryptedAmountTransferData {
        remaining_amount,
        transfer_amount,
        index: encrypted_agg_index.into(),
        proof,
    };

    if verify_transfer_data(ctx, receiver_pk, sender_pk, &initial, &transfer_data) {
        1
    } else {
        0
    }
}

/// # Safety
/// This function is safe if the pointers to structures are all non-null, and
/// produced by `Box::into_raw`.
#[no_mangle]
unsafe extern "C" fn make_sec_to_pub_data(
    ctx_ptr: *const GlobalContext<Group>,
    sender_sk_ptr: *const elgamal::SecretKey<Group>,
    input_amount_ptr: *const AggregatedDecryptedAmount<Group>,
    micro_ccd: u64,
    high_remaining: *mut *const Cipher<Group>,
    low_remaining: *mut *const Cipher<Group>,
    out_index: *mut u64,
    proof_len: *mut u64,
) -> *mut u8 {
    let ctx = from_ptr!(ctx_ptr);

    let sender_sk = from_ptr!(sender_sk_ptr);

    let input_amount = from_ptr!(input_amount_ptr);

    let mut csprng = thread_rng();

    let data = match make_sec_to_pub_transfer_data(
        ctx,
        sender_sk,
        input_amount,
        Amount::from_micro_ccd(micro_ccd),
        &mut csprng,
    ) {
        Some(it) => it,
        _ => return std::ptr::null_mut(),
    };

    *high_remaining = Box::into_raw(Box::new(data.remaining_amount.encryptions[1]));
    *low_remaining = Box::into_raw(Box::new(data.remaining_amount.encryptions[0]));
    *out_index = data.index.index;

    let mut bytes = to_bytes(&data.proof);
    *proof_len = bytes.len() as u64;
    let ptr = bytes.as_mut_ptr();
    std::mem::forget(bytes);
    ptr
}

/// # Safety
/// This function is safe if the pointers to structures are all non-null, and
/// produced by `Box::into_raw`. The `transfer_proof_ptr` can be null in case
/// the length is 0, but otherwise it must be non-null and dereferenceable.
///
/// Return 0 in case verification was unsuccesful, and a non-zero value
/// otherwise.
#[no_mangle]
unsafe extern "C" fn verify_sec_to_pub_transfer(
    ctx_ptr: *const GlobalContext<Group>,
    sender_pk_ptr: *const elgamal::PublicKey<Group>,
    initial_high_ptr: *const Cipher<Group>,
    initial_low_ptr: *const Cipher<Group>,
    remaining_high_ptr: *const Cipher<Group>,
    remaining_low_ptr: *const Cipher<Group>,
    micro_ccd: u64,
    encrypted_agg_index: u64,
    transfer_proof_ptr: *const u8,
    transfer_proof_len: size_t,
) -> u8 {
    let ctx = from_ptr!(ctx_ptr);

    let sender_pk = from_ptr!(sender_pk_ptr);

    let initial_high = from_ptr!(initial_high_ptr);
    let initial_low = from_ptr!(initial_low_ptr);
    let initial = EncryptedAmount {
        encryptions: [*initial_low, *initial_high],
    };

    let remaining_high = from_ptr!(remaining_high_ptr);
    let remaining_low = from_ptr!(remaining_low_ptr);
    let remaining_amount = EncryptedAmount {
        encryptions: [*remaining_low, *remaining_high],
    };

    let transfer_proof = slice_from_c_bytes!(transfer_proof_ptr, transfer_proof_len as usize);
    let proof = if let Ok(td) = (&mut Cursor::new(transfer_proof)).get() {
        td
    } else {
        return 0;
    };

    let transfer_amount = Amount::from_micro_ccd(micro_ccd);

    let transfer_data = SecToPubAmountTransferData {
        remaining_amount,
        transfer_amount,
        index: encrypted_agg_index.into(),
        proof,
    };

    if verify_sec_to_pub_transfer_data(ctx, sender_pk, &initial, &transfer_data) {
        1
    } else {
        0
    }
}

/// # Safety
/// This function is safe if the pointers to structures are all non-null, and
/// produced by `Box::into_raw`.
#[no_mangle]
unsafe extern "C" fn make_aggregated_decrypted_amount(
    encrypted_high_ptr: *const Cipher<Group>,
    encrypted_low_ptr: *const Cipher<Group>,
    micro_ccd: u64,
    agg_index: u64,
) -> *mut AggregatedDecryptedAmount<Group> {
    let encrypted_high = from_ptr!(encrypted_high_ptr);
    let encrypted_low = from_ptr!(encrypted_low_ptr);
    let agg_encrypted_amount = EncryptedAmount {
        encryptions: [*encrypted_low, *encrypted_high],
    };
    Box::into_raw(Box::new(AggregatedDecryptedAmount {
        agg_encrypted_amount,
        agg_amount: Amount::from_micro_ccd(micro_ccd),
        agg_index: agg_index.into(),
    }))
}

macro_free_ffi!(Box free_aggregated_decrypted_amount, AggregatedDecryptedAmount<Group>);

/// # Safety
/// This function is safe if the input pointers are all non-null, and produce by
/// `Box::into_raw`.
#[no_mangle]
unsafe extern "C" fn compute_table(
    gc_ptr: *const GlobalContext<Group>,
    m: u64,
) -> *mut BabyStepGiantStep<Group> {
    Box::into_raw(Box::new(BabyStepGiantStep::new(
        from_ptr!(gc_ptr).encryption_in_exponent_generator(),
        m,
    )))
}
macro_free_ffi!(Box free_table, BabyStepGiantStep<Group>);

/// # Safety
/// This function is safe if the input pointers are all non-null, and produce by
/// `Box::into_raw`.
#[no_mangle]
unsafe extern "C" fn decrypt_amount(
    table_ptr: *const BabyStepGiantStep<Group>,
    sec_ptr: *const elgamal::SecretKey<Group>,
    high_ptr: *const elgamal::Cipher<Group>,
    low_ptr: *const elgamal::Cipher<Group>,
) -> u64 {
    let sk = from_ptr!(sec_ptr);
    let amount = EncryptedAmount {
        encryptions: [*from_ptr!(low_ptr), *from_ptr!(high_ptr)],
    };
    crate::decrypt_amount(from_ptr!(table_ptr), sk, &amount).micro_ccd()
}

/// # Safety
/// This function is safe if the pointers to structures are all non-null, and
/// produced by `Box::into_raw`.
#[no_mangle]
unsafe extern "C" fn encrypt_amount(
    ctx_ptr: *const GlobalContext<Group>,
    pk_ptr: *const elgamal::PublicKey<Group>,
    micro_ccd: u64,
    out_high_ptr: *mut *const Cipher<Group>,
    out_low_ptr: *mut *const Cipher<Group>,
) {
    let gc = from_ptr!(ctx_ptr);
    let pk = from_ptr!(pk_ptr);
    let encrypted = crate::encrypt_amount(
        gc,
        pk,
        Amount::from_micro_ccd(micro_ccd),
        &mut rand::thread_rng(),
    )
    .0;
    *out_high_ptr = Box::into_raw(Box::new(encrypted.encryptions[1]));
    *out_low_ptr = Box::into_raw(Box::new(encrypted.encryptions[0]));
}

macro_derive_from_bytes!(
    Box elgamal_pub_key_from_bytes,
    elgamal::PublicKey<Group>
);
macro_derive_to_bytes!(Box elgamal_pub_key_to_bytes, elgamal::PublicKey<Group>);
macro_free_ffi!(Box elgamal_pub_key_free, elgamal::PublicKey<Group>);

macro_derive_from_bytes!(
    Box elgamal_sec_key_from_bytes,
    elgamal::SecretKey<Group>
);
macro_derive_to_bytes!(Box elgamal_sec_key_to_bytes, elgamal::SecretKey<Group>);
macro_free_ffi!(Box elgamal_sec_key_free, elgamal::SecretKey<Group>);

/// This is used for testing in haskell, providing deterministic key generation
/// from seed.
///
/// # Safety
/// The input point must point to a valid global context.
#[no_mangle]
unsafe extern "C" fn elgamal_sec_key_gen_seed(
    gc_ptr: *const GlobalContext<Group>,
    seed: u64,
) -> *mut elgamal::SecretKey<Group> {
    let gc = from_ptr!(gc_ptr);
    let mut rng: StdRng = SeedableRng::seed_from_u64(seed);
    Box::into_raw(Box::new(elgamal::SecretKey::generate(
        gc.elgamal_generator(),
        &mut rng,
    )))
}

macro_derive_from_bytes!(
    Box elgamal_cipher_from_bytes,
    elgamal::Cipher<Group>
);
macro_derive_to_bytes!(Box elgamal_cipher_to_bytes, elgamal::Cipher<Group>);
macro_free_ffi!(Box elgamal_cipher_free, elgamal::Cipher<Group>);
#[no_mangle]
pub extern "C" fn elgamal_cipher_gen() -> *mut elgamal::Cipher<Group> {
    let mut csprng = thread_rng();
    Box::into_raw(Box::new(elgamal::Cipher::generate(&mut csprng)))
}

#[no_mangle]
pub extern "C" fn elgamal_cipher_zero() -> *mut elgamal::Cipher<Group> {
    Box::into_raw(Box::new(elgamal::Cipher(
        Group::zero_point(),
        Group::zero_point(),
    )))
}

#[no_mangle]
/// Convert from Group element to a valid public key, in a given global context.
unsafe extern "C" fn derive_public_key(
    gc_ptr: *const GlobalContext<Group>,
    group_ptr: *const GroupElement,
) -> *mut elgamal::PublicKey<Group> {
    let pk = elgamal::PublicKey {
        generator: *from_ptr!(gc_ptr).elgamal_generator(),
        key:       from_ptr!(group_ptr).0,
    };
    Box::into_raw(Box::new(pk))
}
