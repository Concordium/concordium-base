use crate::aggregate_sig::*;
use pairing::bls12_381::Bls12;
use rand::thread_rng;
use std::io::Cursor;

macro_rules! from_ptr {
    ($ptr:expr) => {{
        assert!(!$ptr.is_null());
        unsafe { &*$ptr }
    }};
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn generate_secretkey() -> *const SecretKey<Bls12> {
    let mut csprng = thread_rng();
    Box::into_raw(Box::new(SecretKey::generate(&mut csprng)))
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn derive_publickey(sk_ptr: *const SecretKey<Bls12>) -> *const PublicKey<Bls12> {
    let sk = from_ptr!(sk_ptr);
    Box::into_raw(Box::new(PublicKey::from_secret(*sk)))
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn sk_to_bytes(sk_ptr: *const SecretKey<Bls12>) -> *const [u8] {
    let sk = from_ptr!(sk_ptr);
    Box::into_raw(sk.to_bytes())
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn sk_from_bytes(bytes_ptr: *const [u8]) -> *const SecretKey<Bls12> {
    let bytes = from_ptr!(bytes_ptr);
    match SecretKey::<Bls12>::from_bytes(&mut Cursor::new(&bytes)) {
        Ok(sk) => Box::into_raw(Box::new(sk)),
        Err(_) => ::std::ptr::null(),
    }
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn pk_to_bytes(sk_ptr: *const PublicKey<Bls12>) -> *const [u8] {
    let sk = from_ptr!(sk_ptr);
    Box::into_raw(sk.to_bytes())
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn pk_from_bytes(bytes_ptr: *const [u8]) -> *const PublicKey<Bls12> {
    let bytes = from_ptr!(bytes_ptr);
    match PublicKey::<Bls12>::from_bytes(&mut Cursor::new(&bytes)) {
        Ok(pk) => Box::into_raw(Box::new(pk)),
        Err(_) => ::std::ptr::null(),
    }
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn sign(
    m_ptr: *const [u8],
    sk_ptr: *const SecretKey<Bls12>,
) -> *const Signature<Bls12> {
    let m = from_ptr!(m_ptr);
    let sk = from_ptr!(sk_ptr);
    Box::into_raw(Box::new(sign_message(m, *sk)))
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn verify(
    m_ptr: *const [u8],
    pk_ptr: *const PublicKey<Bls12>,
    sig_ptr: *const Signature<Bls12>,
) -> bool {
    let m = from_ptr!(m_ptr);
    let pk = from_ptr!(pk_ptr);
    let sig = from_ptr!(sig_ptr);
    verify_signature(m, *pk, *sig)
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn aggregate(
    sig1_ptr: *const Signature<Bls12>,
    sig2_ptr: *const Signature<Bls12>,
) -> *const Signature<Bls12> {
    let sig1 = from_ptr!(sig1_ptr);
    let sig2 = from_ptr!(sig2_ptr);
    Box::into_raw(Box::new(aggregate_sig(*sig1, *sig2)))
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn verify_aggregate(
    m_ptr: *const [u8],
    pks_ptr: *const [PublicKey<Bls12>],
    sig_ptr: *const Signature<Bls12>,
) -> bool {
    let m = from_ptr!(m_ptr);
    let pks = from_ptr!(pks_ptr);
    let sig = from_ptr!(sig_ptr);
    verify_aggregate_sig_trusted_keys(m, pks, *sig)
}
