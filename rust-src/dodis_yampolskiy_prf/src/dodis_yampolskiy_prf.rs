use crate::constants::*;
use crate::secret::*;
use pairing::{CurveAffine};
use rand::*;

//foreign interface

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern fn prf_key(secret_key_bytes: &mut[u8; SECRET_KEY_LENGTH]){
    let mut csprng= thread_rng();
    let sk = SecretKey::generate(&mut csprng);
    secret_key_bytes.copy_from_slice(&sk.to_bytes());
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern fn prf(prf_bytes: &mut[u8; PRF_LENGTH], secret_key_bytes: &[u8; SECRET_KEY_LENGTH], nonce:u8)-> i32{
    let res_sk = SecretKey::from_bytes(secret_key_bytes);
    if res_sk.is_err(){ return -1 };
    let sk = res_sk.unwrap();
    let res_prf = sk.prf(nonce);
    if res_prf.is_err() { return 0 };
    let prf = res_prf.unwrap();
    prf_bytes.copy_from_slice(&prf.into_compressed().as_ref());
    1
}

