#![cfg(feature = "ffi")]
use ed25519_dalek::*;
use rand::*;

use super::dlog_ed25519::*;
use crate::{common::*, ffi_helpers::*};
use std::{convert::TryFrom, io::Cursor};

use crate::random_oracle::RandomOracle;

// foreign function interfacee
#[no_mangle]
extern "C" fn eddsa_priv_key() -> *mut SecretKey {
    let mut csprng = thread_rng();
    let mut secret_key = SecretKey::default();
    csprng.fill_bytes(&mut secret_key);
    Box::into_raw(Box::new(secret_key))
}

// error encoding
//-1 bad input
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
extern "C" fn eddsa_pub_key(sk_ptr: *mut SecretKey) -> *mut VerifyingKey {
    let secret_key = from_ptr!(sk_ptr);
    let signing_key = SigningKey::from_bytes(secret_key);
    Box::into_raw(Box::new(signing_key.verifying_key()))
}

macro_free_ffi!(Box eddsa_sign_free, SecretKey);
macro_free_ffi!(Box eddsa_public_free, VerifyingKey);

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
extern "C" fn eddsa_sign_to_bytes(input_ptr: *mut SecretKey, output_len: *mut size_t) -> *const u8 {
    let input = from_ptr!(input_ptr);
    let bytes = input.to_vec();
    unsafe { *output_len = bytes.len() as size_t }
    let ret_ptr = bytes.as_ptr();
    ::std::mem::forget(bytes);
    ret_ptr
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
extern "C" fn eddsa_public_to_bytes(
    input_ptr: *mut VerifyingKey,
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
extern "C" fn eddsa_public_from_bytes(
    input_bytes: *mut u8,
    input_len: size_t,
) -> *mut VerifyingKey {
    let len = input_len;
    let bytes = slice_from_c_bytes!(input_bytes, len);
    let res: Result<[u8; 32], _> = bytes.try_into();
    if let Ok(byte_array) = res {
        let e = VerifyingKey::from_bytes(&byte_array);
        match e {
            Ok(r) => Box::into_raw(Box::new(r)),
            Err(_) => ::std::ptr::null_mut(),
        }
    } else {
        ::std::ptr::null_mut()
    }
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
extern "C" fn eddsa_sign_from_bytes(input_bytes: *mut u8, input_len: size_t) -> *mut SecretKey {
    let len = input_len;
    let bytes = slice_from_c_bytes!(input_bytes, len);
    let res: Result<[u8; 32], _> = bytes.try_into();
    match res {
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
    signature_bytes: &mut [u8; SIGNATURE_LENGTH],
) {
    let sk = from_ptr!(sk_ptr);
    let data: &[u8] = slice_from_c_bytes!(message, len);
    let expanded_sk = SigningKey::from(sk);
    let signature = expanded_sk.sign(data);
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
    pk_ptr: *mut VerifyingKey,
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
    let challenge = slice_from_c_bytes!(challenge_prefix_ptr, challenge_len);
    let public_key = {
        let pk_bytes = slice_from_c_bytes!(public_key_bytes, PUBLIC_KEY_LENGTH);
        let res: Result<[u8; 32], _> = pk_bytes.try_into();
        if let Ok(pk_byte_array) = res {
            match VerifyingKey::from_bytes(&pk_byte_array) {
                Err(_) => return -1,
                Ok(pk) => pk,
            }
        } else {
            return -1;
        }
    };
    let proof = {
        let proof_bytes = slice_from_c_bytes!(proof_bytes, PROOF_LENGTH);
        match Ed25519DlogProof::deserial(&mut Cursor::new(proof_bytes)) {
            Err(_) => return -2,
            Ok(proof) => proof,
        }
    };
    if verify_dlog_ed25519(&mut RandomOracle::domain(challenge), &public_key, &proof) {
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
    let challenge = slice_from_c_bytes!(challenge_prefix_ptr, challenge_len);
    let public_key = {
        let pk_bytes = slice_from_c_bytes!(public_key_bytes, PUBLIC_KEY_LENGTH);
        let res: Result<[u8; PUBLIC_KEY_LENGTH], _> = pk_bytes.try_into();
        if let Ok(pk_byte_array) = res {
            match VerifyingKey::from_bytes(&pk_byte_array) {
                Err(_) => return -1,
                Ok(pk) => pk,
            }
        } else {
            return -1;
        }
    };
    let secret_key = {
        let sk_bytes = slice_from_c_bytes!(secret_key_bytes, SECRET_KEY_LENGTH);
        let res: Result<[u8; 32], _> = sk_bytes.try_into();
        if let Ok(sk_byte_array) = res {
            sk_byte_array
        } else {
            return -2;
        }
    };
    let proof_bytes = mut_slice_from_c_bytes!(proof_ptr, PROOF_LENGTH);
    let mut csprng = thread_rng();
    let proof = prove_dlog_ed25519(
        &mut csprng,
        &mut RandomOracle::domain(challenge),
        &public_key,
        &secret_key,
    );
    proof_bytes.copy_from_slice(&to_bytes(&proof));
    0
}
