#![cfg(feature = "ffi")]
use ed25519_dalek::*;
use rand::*;

use crate::dlog_ed25519::*;
use crypto_common::*;
use ffi_helpers::*;
use std::{convert::TryFrom, io::Cursor};

use random_oracle::RandomOracle;

// foreign function interfacee
#[no_mangle]
extern "C" fn eddsa_priv_key() -> *mut SecretKey {
    let mut csprng = thread_rng();
    let sk = SecretKey::generate(&mut csprng);
    Box::into_raw(Box::new(sk))
}

// error encodeing
//-1 bad input
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
extern "C" fn eddsa_pub_key(sk_ptr: *mut SecretKey) -> *mut PublicKey {
    let sk = from_ptr!(sk_ptr);
    Box::into_raw(Box::new(PublicKey::from(sk)))
}

macro_free_ffi!(Box eddsa_sign_free, SecretKey);
macro_free_ffi!(Box eddsa_public_free, PublicKey);

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
extern "C" fn eddsa_sign_to_bytes(input_ptr: *mut SecretKey, output_len: *mut size_t) -> *const u8 {
    let input = from_ptr!(input_ptr);
    let bytes = input.to_bytes().to_vec();
    unsafe { *output_len = bytes.len() as size_t }
    let ret_ptr = bytes.as_ptr();
    ::std::mem::forget(bytes);
    ret_ptr
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
extern "C" fn eddsa_public_to_bytes(
    input_ptr: *mut PublicKey,
    output_len: *mut size_t,
) -> *const u8 {
    let input = from_ptr!(input_ptr);
    let bytes = input.to_bytes().to_vec();
    unsafe { *output_len = bytes.len() as size_t }
    let ret_ptr = bytes.as_ptr();
    ::std::mem::forget(bytes);
    ret_ptr
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
extern "C" fn eddsa_public_from_bytes(input_bytes: *mut u8, input_len: size_t) -> *mut PublicKey {
    let len = input_len as usize;
    let bytes = slice_from_c_bytes!(input_bytes, len);
    let e = PublicKey::from_bytes(bytes);
    match e {
        Ok(r) => Box::into_raw(Box::new(r)),
        Err(_) => ::std::ptr::null_mut(),
    }
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
extern "C" fn eddsa_sign_from_bytes(input_bytes: *mut u8, input_len: size_t) -> *mut SecretKey {
    let len = input_len as usize;
    let bytes = slice_from_c_bytes!(input_bytes, len);
    let e = SecretKey::from_bytes(bytes);
    match e {
        Ok(r) => Box::into_raw(Box::new(r)),
        Err(_) => ::std::ptr::null_mut(),
    }
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
extern "C" fn eddsa_sign(
    message: *const u8,
    len: usize,
    sk_ptr: *mut SecretKey,
    pk_ptr: *mut PublicKey,
    signature_bytes: &mut [u8; SIGNATURE_LENGTH],
) {
    let sk = from_ptr!(sk_ptr);
    let pk = from_ptr!(pk_ptr);
    let data: &[u8] = slice_from_c_bytes!(message, len);
    let expanded_sk = ExpandedSecretKey::from(sk);
    let signature = expanded_sk.sign(data, pk);
    signature_bytes.copy_from_slice(&signature.to_bytes());
}
// Error encoding
//-1 badly formatted signature
// 0 verification failed
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
extern "C" fn eddsa_verify(
    message: *const u8,
    len: usize,
    pk_ptr: *mut PublicKey,
    signature_bytes: &[u8; SIGNATURE_LENGTH],
) -> i32 {
    let sig = match Signature::try_from(&signature_bytes[..]) {
        Ok(sig) => sig,
        Err(_) => return 0,
    };
    let pk = from_ptr!(pk_ptr);
    let data: &[u8] = slice_from_c_bytes!(message, len);
    match pk.verify(data, &sig) {
        Ok(_) => 1,
        _ => 0,
    }
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
extern "C" fn eddsa_verify_dlog_ed25519(
    challenge_prefix_ptr: *const u8,
    challenge_len: size_t,
    public_key_bytes: *const u8,
    proof_bytes: *const u8,
) -> i32 {
    let challenge = slice_from_c_bytes!(challenge_prefix_ptr, challenge_len as usize);
    let public_key = {
        let pk_bytes = slice_from_c_bytes!(public_key_bytes, PUBLIC_KEY_LENGTH);
        match PublicKey::from_bytes(pk_bytes) {
            Err(_) => return -1,
            Ok(pk) => pk,
        }
    };
    let proof = {
        let proof_bytes = slice_from_c_bytes!(proof_bytes, PROOF_LENGTH);
        match Ed25519DlogProof::deserial(&mut Cursor::new(proof_bytes)) {
            Err(_) => return -2,
            Ok(proof) => proof,
        }
    };
    if verify_dlog_ed25519(&mut RandomOracle::domain(&challenge), &public_key, &proof) {
        1
    } else {
        0
    }
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
extern "C" fn eddsa_prove_dlog_ed25519(
    challenge_prefix_ptr: *const u8,
    challenge_len: size_t,
    public_key_bytes: *const u8,
    secret_key_bytes: *const u8,
    proof_ptr: *mut u8,
) -> i32 {
    let challenge = slice_from_c_bytes!(challenge_prefix_ptr, challenge_len as usize);
    let public_key = {
        let pk_bytes = slice_from_c_bytes!(public_key_bytes, PUBLIC_KEY_LENGTH);
        match PublicKey::from_bytes(pk_bytes) {
            Err(_) => return -1,
            Ok(pk) => pk,
        }
    };
    let secret_key = {
        let sk_bytes = slice_from_c_bytes!(secret_key_bytes, SECRET_KEY_LENGTH);
        match SecretKey::from_bytes(sk_bytes) {
            Err(_) => return -2,
            Ok(sk) => sk,
        }
    };
    let proof_bytes = mut_slice_from_c_bytes!(proof_ptr, PROOF_LENGTH);
    let mut csprng = thread_rng();
    let proof = prove_dlog_ed25519(
        &mut csprng,
        &mut RandomOracle::domain(&challenge),
        &public_key,
        &secret_key,
    );
    proof_bytes.copy_from_slice(&to_bytes(&proof));
    0
}
