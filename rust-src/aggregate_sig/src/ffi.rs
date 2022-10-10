#![cfg(feature = "ffi")]

use crate::*;
use crypto_common::*;
use ffi_helpers::*;
use id::sigma_protocols::dlog;
use pairing::bls12_381::Bls12;
use rand::{rngs::StdRng, thread_rng, SeedableRng};
use random_oracle::RandomOracle;
use std::{cmp::Ordering, slice};

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn bls_generate_secretkey() -> *mut SecretKey<Bls12> {
    let mut csprng = thread_rng();
    Box::into_raw(Box::new(SecretKey::generate(&mut csprng)))
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn bls_derive_publickey(sk_ptr: *mut SecretKey<Bls12>) -> *mut PublicKey<Bls12> {
    let sk = from_ptr!(sk_ptr);
    Box::into_raw(Box::new(PublicKey::from_secret(sk)))
}

macro_derive_from_bytes!(Box bls_sk_from_bytes, SecretKey<Bls12>);
macro_derive_from_bytes!(Box bls_pk_from_bytes, PublicKey<Bls12>);
macro_derive_from_bytes!(Box bls_sig_from_bytes, Signature<Bls12>);
macro_derive_from_bytes!(Box bls_proof_from_bytes, Proof<Bls12>);
macro_free_ffi!(Box bls_free_pk, PublicKey<Bls12>);
macro_free_ffi!(Box bls_free_sk, SecretKey<Bls12>);
macro_free_ffi!(Box bls_free_sig, Signature<Bls12>);
macro_free_ffi!(Box bls_free_proof, Proof<Bls12>);
macro_derive_to_bytes!(Box bls_pk_to_bytes, PublicKey<Bls12>);
macro_derive_to_bytes!(Box bls_sk_to_bytes, SecretKey<Bls12>);
macro_derive_to_bytes!(Box bls_sig_to_bytes, Signature<Bls12>);
macro_derive_to_bytes!(Box bls_proof_to_bytes, Proof<Bls12>);
macro_derive_binary!(Box bls_sk_eq, SecretKey<Bls12>, SecretKey::eq);
macro_derive_binary!(Box bls_pk_eq, PublicKey<Bls12>, PublicKey::eq);
macro_derive_binary!(Box bls_sig_eq, Signature<Bls12>, Signature::eq);
macro_derive_binary!(Box bls_proof_eq, Proof<Bls12>, dlog::Proof::eq);

macro_rules! macro_cmp {
    (Arc $function_name:ident, $type:ty) => {
        macro_cmp!($function_name, $type, const);
    };
    (Box $function_name:ident, $type:ty) => {
        macro_cmp!($function_name, $type, mut);
    };
    ($function_name:ident, $type:ty, $mod:tt) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        // support ord instance needed in Haskell
        pub extern "C" fn $function_name(ptr1: *$mod $type, ptr2: *$mod $type) -> i32 {
            // optimistic check first.
            if ptr1 == ptr2 {
                return 0;
            }

            let p1 = from_ptr!(ptr1);
            let p2 = from_ptr!(ptr2);
            match to_bytes(p1).cmp(&to_bytes(p2)) {
                Ordering::Less => return -1,
                Ordering::Greater => return 1,
                Ordering::Equal => 0,
            }
        }
    };
}

macro_cmp!(Box bls_pk_cmp, PublicKey<Bls12>);
macro_cmp!(Box bls_sk_cmp, SecretKey<Bls12>);
macro_cmp!(Box bls_sig_cmp, Signature<Bls12>);
macro_cmp!(Box bls_proof_cmp, Proof<Bls12>);

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn bls_sign(
    m_ptr: *const u8,
    m_len: size_t,
    sk_ptr: *mut SecretKey<Bls12>,
) -> *mut Signature<Bls12> {
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
    pk_ptr: *mut PublicKey<Bls12>,
    sig_ptr: *mut Signature<Bls12>,
) -> u8 {
    let m_len = m_len as usize;
    let m_bytes = slice_from_c_bytes!(m_ptr, m_len);
    let pk = from_ptr!(pk_ptr);
    let sig = from_ptr!(sig_ptr);
    u8::from(pk.verify(m_bytes, *sig))
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn bls_aggregate(
    sig1_ptr: *mut Signature<Bls12>,
    sig2_ptr: *mut Signature<Bls12>,
) -> *mut Signature<Bls12> {
    let sig1 = from_ptr!(sig1_ptr);
    let sig2 = from_ptr!(sig2_ptr);
    Box::into_raw(Box::new(sig1.aggregate(*sig2)))
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn bls_verify_aggregate(
    m_ptr: *const u8,
    m_len: size_t,
    pks_ptr: *const *mut PublicKey<Bls12>,
    pks_len: size_t,
    sig_ptr: *mut Signature<Bls12>,
) -> u8 {
    let m_len = m_len as usize;
    let m_bytes = slice_from_c_bytes!(m_ptr, m_len);

    let pks_: &[*mut PublicKey<Bls12>] = if pks_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(pks_ptr, pks_len) }
    };
    // Collecting the public keys in a vector is currently necessary as
    // verify_aggregate_sig_trusted_keys takes an array of public keys.
    // It might be desirable to make it take references instead.
    let pks: Vec<PublicKey<Bls12>> = pks_.iter().map(|pk| *from_ptr!(*pk)).collect();
    let sig = from_ptr!(sig_ptr);
    u8::from(verify_aggregate_sig_trusted_keys(m_bytes, &pks, *sig))
}

// Only used for adding a dummy proof to the genesis block
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn bls_empty_sig() -> *mut Signature<Bls12> {
    Box::into_raw(Box::new(Signature::empty()))
}

// This is used for testing in haskell, providing deterministic key generation
// from seed.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn bls_generate_secretkey_from_seed(seed: size_t) -> *mut SecretKey<Bls12> {
    let s: usize = seed;
    let mut seed_ = [0u8; 32];
    for (i, byte) in s.to_le_bytes().iter().enumerate() {
        seed_[31 - i] = *byte;
    }
    let mut rng: StdRng = SeedableRng::from_seed(seed_);
    Box::into_raw(Box::new(SecretKey::generate(&mut rng)))
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn bls_prove(
    ro_ptr: *const u8,
    ro_len: size_t,
    sk_ptr: *mut SecretKey<Bls12>,
) -> *mut Proof<Bls12> {
    let ro_len = ro_len as usize;
    let ro_bytes = slice_from_c_bytes!(ro_ptr, ro_len);
    let sk = from_ptr!(sk_ptr);

    let mut ro = RandomOracle::domain(ro_bytes);
    let mut csprng = thread_rng();
    let prf = sk.prove(&mut csprng, &mut ro);
    Box::into_raw(Box::new(prf))
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn bls_check_proof(
    ro_ptr: *const u8,
    ro_len: size_t,
    proof_ptr: *mut Proof<Bls12>,
    pk_ptr: *mut PublicKey<Bls12>,
) -> u8 {
    let ro_len = ro_len as usize;
    let ro_bytes = slice_from_c_bytes!(ro_ptr, ro_len);
    let proof = from_ptr!(proof_ptr);
    let pk = from_ptr!(pk_ptr);

    let mut ro = RandomOracle::domain(ro_bytes);
    let check = pk.check_proof(&mut ro, proof);
    u8::from(check)
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    #[test]
    fn test_verify_aggregate_ffi() {
        let mut rng: StdRng = SeedableRng::from_rng(thread_rng()).unwrap();

        for _ in 0..100 {
            let m = rng.gen::<[u8; 32]>();
            let sk1 = SecretKey::<Bls12>::generate(&mut rng);
            let sk2 = SecretKey::<Bls12>::generate(&mut rng);
            let mut pk1 = PublicKey::<Bls12>::from_secret(&sk1);
            let mut pk2 = PublicKey::<Bls12>::from_secret(&sk2);
            let mut sig = sk1.sign(&m);
            sig = sig.aggregate(sk2.sign(&m));

            let m_ptr: *const u8 = &m as *const _;
            let m_len: size_t = 32;
            let pks_ptr: *const *mut PublicKey<Bls12> =
                &[&mut pk1 as *mut _, &mut pk2 as *mut _] as *const *mut _;
            let pks_len: size_t = 2;
            let sig_ptr: *mut Signature<Bls12> = &mut sig;
            assert_eq!(
                bls_verify_aggregate(m_ptr, m_len, pks_ptr, pks_len, sig_ptr),
                1
            );
        }
    }

    #[test]
    fn test_eq() {
        for _i in 0..10 {
            let mut rng: StdRng = SeedableRng::from_rng(thread_rng()).unwrap();

            let mut sk1 = SecretKey::<Bls12>::generate(&mut rng);
            let mut sk2 = SecretKey::<Bls12>::generate(&mut rng);
            let sk1_ptr = &mut sk1 as *mut _;
            let sk2_ptr = &mut sk2 as *mut _;
            let comparison = bls_sk_eq(sk1_ptr, sk2_ptr);
            assert!(comparison == 0)
        }
    }
}
