use crate::aggregate_sig::*;
use ffi_helpers::*;
use libc::size_t;
use pairing::bls12_381::Bls12;
use rand::thread_rng;
use std::{io::Cursor, slice};

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn bls_generate_secretkey() -> *const SecretKey<Bls12> {
    let mut csprng = thread_rng();
    Box::into_raw(Box::new(SecretKey::generate(&mut csprng)))
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn bls_derive_publickey(sk_ptr: *const SecretKey<Bls12>) -> *const PublicKey<Bls12> {
    let sk = from_ptr!(sk_ptr);
    Box::into_raw(Box::new(PublicKey::from_secret(*sk)))
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn bls_sk_from_bytes(bytes_ptr: *const u8) -> *const SecretKey<Bls12> {
    let bytes = slice_from_c_bytes!(bytes_ptr, PublicKey::<Bls12>::len());
    let r = SecretKey::<Bls12>::from_bytes(&mut Cursor::new(&bytes));
    match r {
        Ok(sk) => Box::into_raw(Box::new(sk)),
        Err(_) => ::std::ptr::null(),
    }
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn bls_pk_from_bytes(bytes_ptr: *const u8) -> *const PublicKey<Bls12> {
    let bytes = slice_from_c_bytes!(bytes_ptr, PublicKey::<Bls12>::len());
    let r = PublicKey::<Bls12>::from_bytes(&mut Cursor::new(&bytes));
    match r {
        Ok(pk) => Box::into_raw(Box::new(pk)),
        Err(_) => ::std::ptr::null(),
    }
}

macro_free_ffi!(bls_free_pk, PublicKey<Bls12>);
macro_free_ffi!(bls_free_sk, SecretKey<Bls12>);
macro_free_ffi!(bls_free_sig, Signature<Bls12>);
macro_derive_to_bytes!(bls_pk_to_bytes, PublicKey<Bls12>);
macro_derive_to_bytes!(bls_sk_to_bytes, SecretKey<Bls12>);
macro_derive_to_bytes!(bls_sig_to_bytes, Signature<Bls12>);

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn bls_sign(
    m_ptr: *const u8,
    m_len: size_t,
    sk_ptr: *const SecretKey<Bls12>,
) -> *const Signature<Bls12> {
    let m_len = m_len as usize;
    let m_bytes = slice_from_c_bytes!(m_ptr, m_len);
    let sk = from_ptr!(sk_ptr);
    Box::into_raw(Box::new(sk.sign(m_bytes)))
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn bls_verify(
    m_ptr: *const u8,
    m_len: size_t,
    pk_ptr: *const PublicKey<Bls12>,
    sig_ptr: *const Signature<Bls12>,
) -> bool {
    let m_len = m_len as usize;
    let m_bytes = slice_from_c_bytes!(m_ptr, m_len);
    let pk = from_ptr!(pk_ptr);
    let sig = from_ptr!(sig_ptr);
    pk.verify(m_bytes, *sig)
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn bls_aggregate(
    sig1_ptr: *const Signature<Bls12>,
    sig2_ptr: *const Signature<Bls12>,
) -> *const Signature<Bls12> {
    let sig1 = from_ptr!(sig1_ptr);
    let sig2 = from_ptr!(sig2_ptr);
    Box::into_raw(Box::new(sig1.aggregate(*sig2)))
}

// #[no_mangle]
// #[allow(clippy::not_unsafe_ptr_arg_deref)]
// pub extern "C" fn bls_verify_aggregate(
//     m_ptr: *const u8,
//     m_len: size_t,
//     pks_ptr: *const PublicKey<Bls12>,
//     pks_len: size_t,
//     sig_ptr: *const Signature<Bls12>,
// ) -> bool {
//     let m_len = m_len as usize;
//     let m_bytes = slice_from_c_bytes!(m_ptr, m_len);
//     let pks = from_ptr!(pks_ptr);
//
//     let sig = from_ptr!(sig_ptr);
//     verify_aggregate_sig_trusted_keys(&m_bytes, pks, *sig)
// }
