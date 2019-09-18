use crate::aggregate_sig::*;
use ffi_helpers::*;
use libc::size_t;
use pairing::bls12_381::Bls12;
use rand::{thread_rng, SeedableRng, StdRng};
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

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn bls_verify_aggregate(
    m_ptr: *const u8,
    m_len: size_t,
    pks_ptr: *const *const PublicKey<Bls12>,
    pks_len: size_t,
    sig_ptr: *const Signature<Bls12>,
) -> bool {
    let m_len = m_len as usize;
    let m_bytes = slice_from_c_bytes!(m_ptr, m_len);

    debug_assert!(!pks_ptr.is_null(), "null pointer");
    let pks_: &[*const PublicKey<Bls12>] = unsafe { slice::from_raw_parts(pks_ptr, pks_len) };
    // Collecting the public keys in a vector is currently necessary as
    // verify_aggregate_sig_trusted_keys takes an array of public keys.
    // It might be desirable to make it take references instead.
    let pks: Vec<PublicKey<Bls12>> = pks_.iter().map(|pk| *from_ptr!(*pk)).collect();
    let sig = from_ptr!(sig_ptr);
    verify_aggregate_sig_trusted_keys(&m_bytes, &pks, *sig)
}

// This is used for testing in haskell, providing deterministic key generation from seed
// The seed is mutated when called, so that it can be used to call again.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn bls_generate_secretkey_from_seed(seed: size_t) -> *const SecretKey<Bls12> {
    let s: &[_] = &[seed];
    let mut rng: StdRng = SeedableRng::from_seed(s);
    let key = Box::into_raw(Box::new(SecretKey::generate(&mut rng)));
    key
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::{Rng, SeedableRng, StdRng};

    #[test]
    fn test_verify_aggregate_ffi() {
        let seed: &[_] = &[1];
        let mut rng: StdRng = SeedableRng::from_seed(seed);

        for _ in 0..100 {
            let m = rng.gen::<[u8; 32]>();
            let sk1 = SecretKey::<Bls12>::generate(&mut rng);
            let sk2 = SecretKey::<Bls12>::generate(&mut rng);
            let pk1 = PublicKey::<Bls12>::from_secret(sk1);
            let pk2 = PublicKey::<Bls12>::from_secret(sk2);
            let mut sig = sk1.sign(&m);
            sig = sig.aggregate(sk2.sign(&m));

            let m_ptr: *const u8 = &m as *const _;
            let m_len: size_t = 32;
            let pks_ptr: *const *const PublicKey<Bls12> =
                &[&pk1 as *const _, &pk2 as *const _] as *const *const _;
            let pks_len: size_t = 2;
            let sig_ptr: *const Signature<Bls12> = &sig;
            assert!(bls_verify_aggregate(
                m_ptr, m_len, pks_ptr, pks_len, sig_ptr
            ));
        }
    }
}
