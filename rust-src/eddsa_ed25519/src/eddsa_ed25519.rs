use ed25519_dalek::*;
use rand::*;

use crate::dlog_ed25519::*;
use ffi_helpers::*;
use libc::size_t;
use std::{io::Cursor, slice};

/// FIXME: Hack to get around different requirements for rand versions
/// between the pairing crate and this one.
pub fn generate_keypair() -> Keypair {
    let mut csprng = thread_rng();
    Keypair::generate(&mut csprng)
}

// foreign function interfacee

#[no_mangle]
pub extern "C" fn eddsa_priv_key(secret_key_bytes: &mut [u8; SECRET_KEY_LENGTH]) -> i32 {
    let mut csprng = thread_rng();
    let sk = SecretKey::generate(&mut csprng);
    secret_key_bytes.copy_from_slice(&sk.to_bytes());
    1
}

// error encodeing
//-1 bad input
#[no_mangle]
pub extern "C" fn eddsa_pub_key(
    secret_key_bytes: &[u8; 32],
    public_key_bytes: &mut [u8; 32],
) -> i32 {
    let res_sk = SecretKey::from_bytes(secret_key_bytes);
    if res_sk.is_err() {
        return -1;
    };
    let sk = res_sk.unwrap();
    let pk = PublicKey::from(&sk);
    public_key_bytes.copy_from_slice(&pk.to_bytes());
    1
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn eddsa_sign(
    message: *const u8,
    len: usize,
    secret_key_bytes: &[u8; 32],
    public_key_bytes: &[u8; 32],
    signature_bytes: &mut [u8; SIGNATURE_LENGTH],
) {
    let sk = SecretKey::from_bytes(secret_key_bytes).expect("bad secret key bytes");
    let pk = PublicKey::from_bytes(public_key_bytes).expect("bad public key bytes");
    let data: &[u8] = slice_from_c_bytes!(message, len);
    let expanded_sk = ExpandedSecretKey::from(&sk);
    let signature = expanded_sk.sign(data, &pk);
    signature_bytes.copy_from_slice(&signature.to_bytes());
}
// Error encoding
//-2 bad public key
//-1 badly formatted signature
// 0 verification failed
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn eddsa_verify(
    message: *const u8,
    len: usize,
    public_key_bytes: &[u8; 32],
    signature_bytes: &[u8; SIGNATURE_LENGTH],
) -> i32 {
    let pk_res = PublicKey::from_bytes(public_key_bytes);
    if pk_res.is_err() {
        return -2;
    };
    let sig_res = Signature::from_bytes(signature_bytes);
    if sig_res.is_err() {
        return -1;
    };

    let pk = pk_res.unwrap();
    let sig = sig_res.unwrap();
    let data: &[u8] = slice_from_c_bytes!(message, len);
    match pk.verify(data, &sig) {
        Ok(_) => 1,
        _ => 0,
    }
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn eddsa_verify_dlog_ed25519(
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
        match Ed25519DlogProof::from_bytes(&mut Cursor::new(proof_bytes)) {
            Err(_) => return -2,
            Ok(proof) => proof,
        }
    };
    if verify_dlog_ed25519(challenge, &public_key, &proof) {
        return 1;
    } else {
        return 0;
    }
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn eddsa_prove_dlog_ed25519(
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
    let proof = prove_dlog_ed25519(challenge, &public_key, &secret_key);
    proof_bytes.copy_from_slice(&proof.to_bytes());
    return 0;
}
