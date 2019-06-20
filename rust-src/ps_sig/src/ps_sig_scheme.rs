use crate::{known_message::*, public::*, secret::*, signature::*, unknown_message::*};
use curve_arithmetic::{bls12_381_instance::*, curve_arithmetic::*};
use pairing::bls12_381::Bls12;
use pedersen_scheme::{commitment::Commitment, key::CommitmentKey, value::*};
use rand::*;
use std::slice;

// A method to generate a commitment key from the public key
pub fn commitment_key<C: Pairing>(pk: &PublicKey<C>) -> CommitmentKey<C::G_1> {
    CommitmentKey::new(pk.0.clone(), C::G_1::one_point())
}

// transforms a commitment into an unknown message
// should be done better
// there should be a trait for commitment scheme
pub fn message<C: Pairing>(commitment: &Commitment<C::G_1>) -> UnknownMessage<C> {
    let point = commitment.0.clone();
    UnknownMessage(point)
}

pub fn commit_with_pk<C: Pairing>(
    pk: &PublicKey<C>,
    vs: &Value<C::G_1>,
) -> (UnknownMessage<C>, C::ScalarField) {
    let ck = commitment_key(&pk);
    let mut csprng = thread_rng();
    let (commitment, randomness) = ck.commit(&vs, &mut csprng);
    (message(&commitment), randomness)
}

// retrieves a signature on the original message from the signature on the
// commitment
pub fn retrieve_sig<C: Pairing>(
    sig: &Signature<C>,
    key: &CommitmentKey<C::G_1>,
    r: C::ScalarField,
) -> Signature<C> {
    let h = sig.0;
    let hr = h.mul_by_scalar(&r);
    let b = sig.1;
    Signature(sig.0, b.minus_point(&hr))
}

// test
macro_rules! macro_test_sign_verify_unknown_message{
      ($function_name:ident, $pairing_type:path) => {
          #[test]
          pub fn $function_name() {
              let mut csprng = thread_rng();
              for i in 0..20 {
                  let sk = SecretKey::<$pairing_type>::generate(i, &mut csprng);
                  let pk = PublicKey::<$pairing_type>::from(&sk);
                  let ck = commitment_key(&pk);
                  let vs = Value::generate(i, &mut csprng);
                  let (commitment, randomness) = ck.commit(&vs, &mut csprng);
                  let message = message(&commitment);
                  let sig_res = sk.sign_unknown_message(&message, &mut csprng);
                  let sig = sig_res.unwrap();
                  let sig2 = retrieve_sig(&sig, &ck, randomness);
                  let knownm : KnownMessage<$pairing_type>= KnownMessage(vs.0.clone());
                  let sig_res = sk.sign_known_message(&KnownMessage(vs.0), &mut csprng);
                  assert!(pk.verify(&sig2, &knownm);
                  assert!(!pk.verify(&sig2, &KnownMessage.arbitrary(csprng)));

              }
          }
      };
  }
macro_test_sign_verify_unknown_message!(unknown_message_sign_verify_bls12_381, Bls12);

// FFI

macro_rules! macro_generate_secret_key {
    ($function_name:ident, $pairing_type:path) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn $function_name(n: usize, key_bytes: *mut u8) {
            assert!(!key_bytes.is_null(), "Null pointer");
            let key_slice: &mut [u8] = unsafe {
                slice::from_raw_parts_mut(
                    key_bytes,
                    (n + 1) * <$pairing_type as Pairing>::SCALAR_LENGTH,
                )
            };
            let mut csprng = thread_rng();
            let ck = SecretKey::<$pairing_type>::generate(n, &mut csprng);
            key_slice.copy_from_slice(&*ck.to_bytes());
        }
    };
}

macro_generate_secret_key!(generate_secret_key_bls12_381, Bls12);

macro_rules! macro_public_key {
    ($function_name:ident, $pairing_type:path) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn $function_name(n: usize, sk_bytes: *const u8, pk_bytes: *mut u8) -> i32 {
            assert!(!sk_bytes.is_null(), "Null pointer");
            let sk_slice: &[u8] = unsafe {
                slice::from_raw_parts(
                    sk_bytes,
                    (n + 1) * <$pairing_type as Pairing>::SCALAR_LENGTH,
                )
            };
            assert!(!pk_bytes.is_null(), "Null pointer");
            let pk_slice: &mut [u8] = unsafe {
                slice::from_raw_parts_mut(
                    pk_bytes,
                    (n + 1) * <$pairing_type as Pairing>::G_2::GROUP_ELEMENT_LENGTH
                        + n * <$pairing_type as Pairing>::G_1::GROUP_ELEMENT_LENGTH,
                )
            };
            let sk = SecretKey::<$pairing_type>::from_bytes(sk_slice);
            if !sk.is_ok() {
                return -1;
            }
            let pk = PublicKey::<$pairing_type>::from(&sk.unwrap());
            pk_slice.copy_from_slice(&*pk.to_bytes());
            1
        }
    };
}

macro_public_key!(public_key_bls12_381, Bls12);

macro_rules! macro_sign_known_message {
    ($function_name:ident, $pairing_type:path) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn $function_name(
            n: usize,
            sk_bytes: *const u8,
            message_bytes: *const u8,
            signature_bytes: *mut u8,
        ) -> i32 {
            assert!(!sk_bytes.is_null(), "Null pointer");
            let sk_slice: &[u8] = unsafe {
                slice::from_raw_parts(
                    sk_bytes,
                    (n + 1) * <$pairing_type as Pairing>::SCALAR_LENGTH,
                )
            };
            let sk_res = SecretKey::<$pairing_type>::from_bytes(sk_slice);
            if !sk_res.is_ok() {
                return -1;
            }
            let sk = sk_res.unwrap();

            assert!(!message_bytes.is_null(), "Null pointer");
            let message_slice: &[u8] = unsafe {
                slice::from_raw_parts(message_bytes, n * <$pairing_type as Pairing>::SCALAR_LENGTH)
            };
            let msg_res = KnownMessage::<$pairing_type>::from_bytes(message_slice);
            if !msg_res.is_ok() {
                return -2;
            }
            let msg = msg_res.unwrap();

            let mut csprng = thread_rng();
            let sig_res = sk.sign_known_message(&msg, &mut csprng);
            if !sig_res.is_ok() {
                return -3;
            }
            let sig = sig_res.unwrap();

            let sig_slice: &mut [u8] = unsafe {
                slice::from_raw_parts_mut(
                    signature_bytes,
                    2 * <$pairing_type as Pairing>::G_1::GROUP_ELEMENT_LENGTH,
                )
            };
            sig_slice.copy_from_slice(&*sig.to_bytes());
            1
        }
    };
}

macro_sign_known_message!(sign_known_message_bls12_381, Bls12);

//#[test] sign verify known message
macro_rules! macro_test_sign_verify_known_message_ffi {
    (
        $function_name:ident,
        $sign_func_name:ident,
        $sec_key_func_name:ident,
        $pub_key_func_name:ident,
        $verify_func_name:ident,
        $pairing_type:path
    ) => {
        #[test]
        pub fn $function_name() {
            let mut sk_bytes = [0u8; 21 * <$pairing_type as Pairing>::SCALAR_LENGTH];
            let mut pk_bytes = [0u8; 21 * <$pairing_type as Pairing>::G_2::GROUP_ELEMENT_LENGTH
                + 20 * <$pairing_type as Pairing>::G_1::GROUP_ELEMENT_LENGTH];
            let mut sig_bytes = [0u8; 40 * <$pairing_type as Pairing>::G_1::GROUP_ELEMENT_LENGTH];
            let mut csprng = thread_rng();
            for i in 1..20 {
                $sec_key_func_name(i, sk_bytes.as_mut_ptr());
                // let msg_slice = &mut msg_bytes[..(i + 1) * <$curve_type as
                // Curve>::SCALAR_LENGTH];
                let m = KnownMessage::<$pairing_type>::generate(i, &mut csprng);
                let m_bytes = m.to_bytes();
                $pub_key_func_name(i, sk_bytes.as_ptr(), pk_bytes.as_mut_ptr());
                $sign_func_name(
                    i,
                    sk_bytes.as_ptr(),
                    m_bytes.as_ptr(),
                    sig_bytes.as_mut_ptr(),
                );
                let mut res = 0i32;
                res = $verify_func_name(i, pk_bytes.as_ptr(), sig_bytes.as_ptr(), m_bytes.as_ptr());
                assert_eq!(res, 1 as i32);

                let wrong_msg = KnownMessage::<$pairing_type>::generate(i, &mut csprng);
                res = $verify_func_name(i, pk_bytes.as_ptr(), sig_bytes.as_ptr(), wrong_msg.to_bytes().as_ptr());
                assert_ne!(res, 1 as i32);

                let wrong_sig = Signature::<$pairing_type>::arbitrary(&mut csprng);
                res = $verify_func_name(i, pk_bytes.as_ptr(), sig_bytes.as_ptr(), wrong_sig.to_bytes().as_ptr());
            }
        }
    };
}

macro_test_sign_verify_known_message_ffi!(
    sign_verify_known_message_ffi_bls12_381,
    sign_known_message_bls12_381,
    generate_secret_key_bls12_381,
    public_key_bls12_381,
    verify_bls12_381,
    Bls12
);
macro_rules! macro_sign_unknown_message {
    ($function_name:ident, $pairing_type:path) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn $function_name(
            sk_bytes: *const u8,
            message_bytes: *const u8,
            signature_bytes: *mut u8,
        ) -> i32 {
            assert!(!sk_bytes.is_null(), "Null pointer");
            let sk_slice: &[u8] = unsafe {
                slice::from_raw_parts(sk_bytes, <$pairing_type as Pairing>::SCALAR_LENGTH)
            };
            let sk_res = SecretKey::<$pairing_type>::from_bytes(sk_slice);
            if !sk_res.is_ok() {
                return -1;
            }
            let sk = sk_res.unwrap();

            assert!(!message_bytes.is_null(), "Null pointer");
            let message_slice: &[u8] = unsafe {
                slice::from_raw_parts(
                    message_bytes,
                    <$pairing_type as Pairing>::G_1::GROUP_ELEMENT_LENGTH,
                )
            };
            let msg_res = UnknownMessage::<$pairing_type>::from_bytes(message_slice);
            if !msg_res.is_ok() {
                return -2;
            }
            let msg = msg_res.unwrap();

            let mut csprng = thread_rng();
            let sig_res = sk.sign_unknown_message(&msg, &mut csprng);
            if !sig_res.is_ok() {
                return -3;
            }
            let sig = sig_res.unwrap();

            let sig_slice: &mut [u8] = unsafe {
                slice::from_raw_parts_mut(
                    signature_bytes,
                    2 * <$pairing_type as Pairing>::G_1::GROUP_ELEMENT_LENGTH,
                )
            };
            sig_slice.copy_from_slice(&*sig.to_bytes());
            1
        }
    };
}

macro_sign_unknown_message!(sign_unknown_message_bls12_381, Bls12);

macro_rules! macro_verify {
    ($function_name:ident, $pairing_type:path) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn $function_name(
            n: usize,
            pk_bytes: *const u8,
            sig_bytes: *const u8,
            msg_bytes: *const u8,
        ) -> i32 {
            assert!(!pk_bytes.is_null(), "Null pointer");
            let pk_slice: &[u8] = unsafe {
                slice::from_raw_parts(
                    pk_bytes,
                    (n + 1) * <$pairing_type as Pairing>::G_2::GROUP_ELEMENT_LENGTH
                        + n * <$pairing_type as Pairing>::G_1::GROUP_ELEMENT_LENGTH,
                )
            };
            let pk_res = PublicKey::<$pairing_type>::from_bytes(pk_slice);
            if !pk_res.is_ok() {
                return -1;
            }
            let pk = pk_res.unwrap();

            assert!(!sig_bytes.is_null(), "Null pointer");
            let sig_slice: &[u8] = unsafe {
                slice::from_raw_parts(
                    sig_bytes,
                    2 * <$pairing_type as Pairing>::G_1::GROUP_ELEMENT_LENGTH,
                )
            };
            let sig_res = Signature::<$pairing_type>::from_bytes(&sig_slice);
            if !sig_res.is_ok() {
                return -2;
            }
            let sig = sig_res.unwrap();
            assert!(!msg_bytes.is_null(), "Null pointer");
            let msg_slice: &[u8] = unsafe {
                slice::from_raw_parts(msg_bytes, n * <$pairing_type as Pairing>::SCALAR_LENGTH)
            };
            let msg_res = KnownMessage::<$pairing_type>::from_bytes(msg_slice);
            if !msg_res.is_ok() {
                return -3;
            }
            let msg = msg_res.unwrap();
            if pk.verify(&sig, &msg) {
                1
            } else {
                0
            }
        }
    };
}
macro_verify!(verify_bls12_381, Bls12);
//#[test] sign verify unknown message

// generate a commitmentkey from public key
macro_rules! macro_commitment_key {
    ($function_name:ident, $pairing_type:path) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn $function_name(
            n: usize,
            pk_bytes: *const u8,
            commitment_key_bytes: *mut u8,
            randomness: *mut u8,
        ) -> i32 {
            assert!(!pk_bytes.is_null(), "Null pointer");
            let pk_slice: &[u8] = unsafe {
                slice::from_raw_parts(
                    pk_bytes,
                    (n + 1) * <$pairing_type as Pairing>::G_2::GROUP_ELEMENT_LENGTH
                        + n * <$pairing_type as Pairing>::G_1::GROUP_ELEMENT_LENGTH,
                )
            };
            let pk_res = PublicKey::<$pairing_type>::from_bytes(pk_slice);
            if !pk_res.is_ok() {
                return -1;
            }
            let pk = pk_res.unwrap();
            let ck = commitment_key(&pk);
            let ck_slice: &mut [u8] = unsafe {
                slice::from_raw_parts_mut(
                    commitment_key_bytes,
                    (n + 1) * <$pairing_type as Pairing>::G_1::GROUP_ELEMENT_LENGTH,
                )
            };
            ck_slice.copy_from_slice(&*ck.to_bytes());
            1
        }
    };
}

macro_commitment_key!(commitment_key_bls12_381, Bls12);

macro_rules! macro_retrieve_sig {
    ($function_name:ident, $pairing_type:path) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn $function_name(
            n: usize,
            orig_sig_bytes: *const u8,
            ck_bytes: *const u8,
            randomness_bytes: *const u8,
            retrieved_sig_bytes: *mut u8,
        ) -> i32 {
            assert!(!orig_sig_bytes.is_null(), "Null pointer");
            assert!(!ck_bytes.is_null(), "Null pointer");
            assert!(!randomness_bytes.is_null(), "Null pointer");
            assert!(!retrieved_sig_bytes.is_null(), "Null pointer");
            let orig_sig_slice: &[u8] = unsafe {
                slice::from_raw_parts(
                    orig_sig_bytes,
                    2 * <$pairing_type as Pairing>::G_1::GROUP_ELEMENT_LENGTH,
                )
            };
            let orig_sig_res = Signature::<$pairing_type>::from_bytes(&orig_sig_slice);
            if !orig_sig_res.is_ok() {
                return -1;
            }
            let orig_sig = orig_sig_res.unwrap();
            let ck_slice: &[u8] = unsafe {
                slice::from_raw_parts(
                    ck_bytes,
                    (n + 1) * <$pairing_type as Pairing>::G_1::GROUP_ELEMENT_LENGTH,
                )
            };
            let ck_res = CommitmentKey::<<$pairing_type as Pairing>::G_1>::from_bytes(&ck_slice);
            if !ck_res.is_ok() {
                return -2;
            }
            let ck = ck_res.unwrap();
            let randomness_slice: &[u8] = unsafe {
                slice::from_raw_parts(randomness_bytes, <$pairing_type as Pairing>::SCALAR_LENGTH)
            };
            let randomness_res = <$pairing_type>::bytes_to_scalar(&randomness_slice);
            if !randomness_res.is_ok() {
                return -3;
            }
            let randomness = randomness_res.unwrap();
            let retrieved_sig_slice: &mut [u8] = unsafe {
                slice::from_raw_parts_mut(
                    retrieved_sig_bytes,
                    2 * <$pairing_type as Pairing>::G_1::GROUP_ELEMENT_LENGTH,
                )
            };

            let sig = retrieve_sig(&orig_sig, &ck, randomness);
            retrieved_sig_slice.copy_from_slice(&*sig.to_bytes());
            1
        }
    };
}
macro_retrieve_sig!(retrieve_sig_bls12_381, Bls12);

macro_rules! macro_commit_with_pk {
    ($function_name:ident, $pairing_type:path) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn $function_name(
            n: usize,
            pk_bytes: *const u8,
            value_bytes: *const u8,
            unknown_msg_bytes: *mut u8,
            randomness_bytes: *mut u8,
        ) -> i32 {
            assert!(!pk_bytes.is_null(), "Null pointer");
            assert!(!value_bytes.is_null(), "Null pointer");
            assert!(!unknown_msg_bytes.is_null(), "Null pointer");
            assert!(!randomness_bytes.is_null(), "Null pointer");
            let pk_slice: &[u8] = unsafe {
                slice::from_raw_parts(
                    pk_bytes,
                    (n + 1) * <$pairing_type as Pairing>::G_2::GROUP_ELEMENT_LENGTH
                        + n * <$pairing_type as Pairing>::G_1::GROUP_ELEMENT_LENGTH,
                )
            };
            let pk_res = PublicKey::<$pairing_type>::from_bytes(pk_slice);
            if !pk_res.is_ok() {
                return -1;
            }
            let pk = pk_res.unwrap();
            let value_slice: &[u8] = unsafe {
                slice::from_raw_parts(value_bytes, n * <$pairing_type as Pairing>::SCALAR_LENGTH)
            };
            let val_res = Value::from_bytes(value_slice);
            if !val_res.is_ok() {
                return -2;
            }
            let val = val_res.unwrap();
            let (unknown_msg, randomness) = commit_with_pk(&pk, &val);

            let randomness_slice: &mut [u8] = unsafe {
                slice::from_raw_parts_mut(
                    randomness_bytes,
                    <$pairing_type as Pairing>::SCALAR_LENGTH,
                )
            };
            randomness_slice.copy_from_slice(&*<$pairing_type>::scalar_to_bytes(&randomness));
            let unknown_msg_slice: &mut [u8] = unsafe {
                slice::from_raw_parts_mut(
                    unknown_msg_bytes,
                    <$pairing_type as Pairing>::G_1::GROUP_ELEMENT_LENGTH,
                )
            };
            unknown_msg_slice.copy_from_slice(&*unknown_msg.to_bytes());
            1
        }
    };
}

macro_commit_with_pk!(commit_with_pk_bls12_381, Bls12);
