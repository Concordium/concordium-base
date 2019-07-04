use crate::{known_message::*, public::*, secret::*, signature::*, unknown_message::*};
use curve_arithmetic::curve_arithmetic::*;
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
    let point = commitment.0;
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
pub fn retrieve_sig<C: Pairing>(sig: &Signature<C>, r: C::ScalarField) -> Signature<C> {
    let h = sig.0;
    let hr = h.mul_by_scalar(&r);
    let b = sig.1;
    Signature(sig.0, b.minus_point(&hr))
}

// FFI

macro_rules! slice_from_c_bytes_worker {
    ($cstr:expr, $length:expr, $null_ptr_error:expr, $reader:expr) => {{
        assert!(!$cstr.is_null(), $null_ptr_error);
        unsafe { $reader($cstr, $length) }
    }};
}

macro_rules! slice_from_c_bytes {
    ($cstr:expr, $length:expr) => {
        slice_from_c_bytes_worker!($cstr, $length, "Null pointer.", slice::from_raw_parts)
    };
    ($cstr:expr, $length:expr, $null_ptr_error:expr) => {
        slice_from_c_bytes_worker!($cstr, $length, $null_ptr_error, slice::from_raw_parts)
    };
}

macro_rules! mut_slice_from_c_bytes {
    ($cstr:expr, $length:expr) => {
        slice_from_c_bytes_worker!($cstr, $length, "Null pointer.", slice::from_raw_parts_mut)
    };
    ($cstr:expr, $length:expr, $null_ptr_error:expr) => {
        slice_from_c_bytes_worker!($cstr, $length, $null_ptr_error, slice::from_raw_parts_mut)
    };
}

macro_rules! macro_generate_secret_key {
    ($function_name:ident, $pairing_type:path) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn $function_name(n: usize, key_bytes: *mut u8) {
            let key_slice: &mut [u8] = mut_slice_from_c_bytes!(
                key_bytes,
                (n + 1) * <$pairing_type as Pairing>::SCALAR_LENGTH
            );
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
            let sk_slice: &[u8] = slice_from_c_bytes!(
                sk_bytes,
                (n + 1) * <$pairing_type as Pairing>::SCALAR_LENGTH
            );
            let pk_slice: &mut [u8] = mut_slice_from_c_bytes!(
                pk_bytes,
                (n + 1) * <$pairing_type as Pairing>::G_2::GROUP_ELEMENT_LENGTH
                    + n * <$pairing_type as Pairing>::G_1::GROUP_ELEMENT_LENGTH
            );
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
            let sk_slice: &[u8] = slice_from_c_bytes!(
                sk_bytes,
                (n + 1) * <$pairing_type as Pairing>::SCALAR_LENGTH
            );
            let sk_res = SecretKey::<$pairing_type>::from_bytes(sk_slice);
            if !sk_res.is_ok() {
                return -1;
            }
            let sk = sk_res.unwrap();

            let message_slice: &[u8] =
                slice_from_c_bytes!(message_bytes, n * <$pairing_type as Pairing>::SCALAR_LENGTH);
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

macro_rules! macro_sign_unknown_message {
    ($function_name:ident, $pairing_type:path) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn $function_name(
            sk_bytes: *const u8,
            message_bytes: *const u8,
            signature_bytes: *mut u8,
        ) -> i32 {
            let sk_slice: &[u8] =
                slice_from_c_bytes!(sk_bytes, <$pairing_type as Pairing>::SCALAR_LENGTH);
            let sk_res = SecretKey::<$pairing_type>::from_bytes(sk_slice);
            if !sk_res.is_ok() {
                return -1;
            }
            let sk = sk_res.unwrap();

            let message_slice: &[u8] = slice_from_c_bytes!(
                message_bytes,
                <$pairing_type as Pairing>::G_1::GROUP_ELEMENT_LENGTH
            );
            let msg_res = UnknownMessage::<$pairing_type>::from_bytes(message_slice);
            if !msg_res.is_ok() {
                return -2;
            }
            let msg = msg_res.unwrap();

            let mut csprng = thread_rng();
            let sig = sk.sign_unknown_message(&msg, &mut csprng);
            // if !sig_res.is_ok() {
            //    return -3;
            // }
            // let sig = sig_res.unwrap();
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
            let pk_slice: &[u8] = slice_from_c_bytes!(
                pk_bytes,
                (n + 1) * <$pairing_type as Pairing>::G_2::GROUP_ELEMENT_LENGTH
                    + n * <$pairing_type as Pairing>::G_1::GROUP_ELEMENT_LENGTH
            );
            let pk_res = PublicKey::<$pairing_type>::from_bytes(pk_slice);
            if !pk_res.is_ok() {
                return -1;
            }
            let pk = pk_res.unwrap();

            let sig_slice: &[u8] = slice_from_c_bytes!(
                sig_bytes,
                2 * <$pairing_type as Pairing>::G_1::GROUP_ELEMENT_LENGTH
            );
            let sig_res = Signature::<$pairing_type>::from_bytes(&sig_slice);
            if !sig_res.is_ok() {
                return -2;
            }
            let sig = sig_res.unwrap();
            let msg_slice: &[u8] =
                slice_from_c_bytes!(msg_bytes, n * <$pairing_type as Pairing>::SCALAR_LENGTH);
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

// generate a commitmentkey from public key
macro_rules! macro_commitment_key {
    ($function_name:ident, $pairing_type:path) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn $function_name(
            n: usize,
            pk_bytes: *const u8,
            commitment_key_bytes: *mut u8,
        ) -> i32 {
            let pk_slice: &[u8] = slice_from_c_bytes!(
                pk_bytes,
                (n + 1) * <$pairing_type as Pairing>::G_2::GROUP_ELEMENT_LENGTH
                    + n * <$pairing_type as Pairing>::G_1::GROUP_ELEMENT_LENGTH
            );
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
            orig_sig_bytes: *const u8,
            randomness_bytes: *const u8,
            retrieved_sig_bytes: *mut u8,
        ) -> i32 {
            let orig_sig_slice: &[u8] = slice_from_c_bytes!(
                orig_sig_bytes,
                2 * <$pairing_type as Pairing>::G_1::GROUP_ELEMENT_LENGTH
            );
            let orig_sig_res = Signature::<$pairing_type>::from_bytes(&orig_sig_slice);
            if !orig_sig_res.is_ok() {
                return -1;
            }
            let orig_sig = orig_sig_res.unwrap();
            let randomness_slice: &[u8] =
                slice_from_c_bytes!(randomness_bytes, <$pairing_type as Pairing>::SCALAR_LENGTH);
            let randomness_res = <$pairing_type>::bytes_to_scalar(&randomness_slice);
            if !randomness_res.is_ok() {
                return -2;
            }
            let randomness = randomness_res.unwrap();
            let retrieved_sig_slice: &mut [u8] = mut_slice_from_c_bytes!(
                retrieved_sig_bytes,
                2 * <$pairing_type as Pairing>::G_1::GROUP_ELEMENT_LENGTH
            );

            let sig = retrieve_sig(&orig_sig, randomness);
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
            let pk_slice: &[u8] = slice_from_c_bytes!(
                pk_bytes,
                (n + 1) * <$pairing_type as Pairing>::G_2::GROUP_ELEMENT_LENGTH
                    + n * <$pairing_type as Pairing>::G_1::GROUP_ELEMENT_LENGTH
            );
            let pk_res = PublicKey::<$pairing_type>::from_bytes(pk_slice);
            if !pk_res.is_ok() {
                return -1;
            }
            let pk = pk_res.unwrap();
            let value_slice: &[u8] =
                slice_from_c_bytes!(value_bytes, n * <$pairing_type as Pairing>::SCALAR_LENGTH);
            let val_res = Value::from_bytes(value_slice);
            if !val_res.is_ok() {
                return -2;
            }
            let val = val_res.unwrap();
            let (unknown_msg, randomness) = commit_with_pk(&pk, &val);
            let randomness_slice: &mut [u8] = mut_slice_from_c_bytes!(
                randomness_bytes,
                <$pairing_type as Pairing>::SCALAR_LENGTH
            );
            randomness_slice.copy_from_slice(&*<$pairing_type>::scalar_to_bytes(&randomness));
            let unknown_msg_slice: &mut [u8] = mut_slice_from_c_bytes!(
                unknown_msg_bytes,
                <$pairing_type as Pairing>::G_1::GROUP_ELEMENT_LENGTH
            );
            unknown_msg_slice.copy_from_slice(&*unknown_msg.to_bytes());
            1
        }
    };
}

macro_commit_with_pk!(commit_with_pk_bls12_381, Bls12);

#[cfg(test)]
mod tests {
    use super::*;
    use pedersen_scheme::random_values_bls12_381_g1_proj;
    // test
    macro_rules! macro_test_sign_verify_unknown_message {
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
                    let sig = sk.sign_unknown_message(&message, &mut csprng);
                    // let sig = sig_res.unwrap();
                    let sig2 = retrieve_sig(&sig, randomness);
                    let knownm: KnownMessage<$pairing_type> = KnownMessage(vs.0.clone());
                    let sig_res = sk.sign_known_message(&KnownMessage(vs.0), &mut csprng);
                    assert!(sig_res.is_ok());
                    assert!(pk.verify(&sig2, &knownm));
                    let knownm_other = KnownMessage::generate(i, &mut csprng);
                    let res_other = pk.verify(&sig2, &knownm_other);
                    if res_other {
                        assert_eq!(knownm, knownm_other)
                    }

                    // using a randomly generated signature should fail (with extremely high
                    // probability)
                    let random_sig = Signature::<$pairing_type>::arbitrary(&mut csprng);
                    assert!(!pk.verify(&random_sig, &knownm));

                    // using a randomly generated public key should also fail
                    let random_pk = PublicKey::<$pairing_type>::arbitrary(i, &mut csprng);
                    assert!(!random_pk.verify(&sig, &knownm));
                }
            }
        };
    }
    macro_test_sign_verify_unknown_message!(unknown_message_sign_verify_bls12_381, Bls12);

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
                let mut pk_bytes = [0u8; 21
                    * <$pairing_type as Pairing>::G_2::GROUP_ELEMENT_LENGTH
                    + 20 * <$pairing_type as Pairing>::G_1::GROUP_ELEMENT_LENGTH];
                let mut sig_bytes =
                    [0u8; 2 * <$pairing_type as Pairing>::G_1::GROUP_ELEMENT_LENGTH];
                let mut csprng = thread_rng();
                for i in 1..20 {
                    $sec_key_func_name(i, sk_bytes.as_mut_ptr());
                    let m = KnownMessage::<$pairing_type>::generate(i, &mut csprng);
                    let m_bytes = m.to_bytes();
                    $pub_key_func_name(i, sk_bytes.as_ptr(), pk_bytes.as_mut_ptr());
                    $sign_func_name(
                        i,
                        sk_bytes.as_ptr(),
                        m_bytes.as_ptr(),
                        sig_bytes.as_mut_ptr(),
                    );
                    let mut res = $verify_func_name(
                        i,
                        pk_bytes.as_ptr(),
                        sig_bytes.as_ptr(),
                        m_bytes.as_ptr(),
                    );
                    assert_eq!(res, 1 as i32);

                    let wrong_msg = KnownMessage::<$pairing_type>::generate(i, &mut csprng);
                    res = $verify_func_name(
                        i,
                        pk_bytes.as_ptr(),
                        sig_bytes.as_ptr(),
                        wrong_msg.to_bytes().as_ptr(),
                    );
                    assert_ne!(res, 1 as i32);

                    let wrong_sig = Signature::<$pairing_type>::arbitrary(&mut csprng);
                    res = $verify_func_name(
                        i,
                        pk_bytes.as_ptr(),
                        wrong_sig.to_bytes().as_ptr(),
                        m_bytes.as_ptr(),
                    );
                    assert_eq!(res, 0);
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

    macro_rules! macro_test_sign_verify_unknown_message_ffi {
        (
            $function_name:ident,
            $sign_func_name:ident,
            $sec_key_func_name:ident,
            $pub_key_func_name:ident,
            $commitment_with_pk_func_name:ident,
            $commitment_key_func_name:ident,
            $random_values_func_name:ident,
            $verify_func_name:ident,
            $retrieve_sig_func_name:ident,
            $pairing_type:path
        ) => {
            #[test]
            pub fn $function_name() {
                let mut sk_bytes = [0u8; 21 * <$pairing_type as Pairing>::SCALAR_LENGTH];
                let mut pk_bytes = [0u8; 21
                    * <$pairing_type as Pairing>::G_2::GROUP_ELEMENT_LENGTH
                    + 20 * <$pairing_type as Pairing>::G_1::GROUP_ELEMENT_LENGTH];
                let mut value_bytes = [0u8; 21 * <$pairing_type as Pairing>::SCALAR_LENGTH];
                let mut sig_bytes =
                    [0u8; 2 * <$pairing_type as Pairing>::G_1::GROUP_ELEMENT_LENGTH];
                let mut retrieved_sig_bytes =
                    [0u8; 2 * <$pairing_type as Pairing>::G_1::GROUP_ELEMENT_LENGTH];
                let mut unknown_msg_bytes =
                    [0u8; <$pairing_type as Pairing>::G_1::GROUP_ELEMENT_LENGTH];
                let mut randomness_bytes = [0u8; <$pairing_type as Pairing>::SCALAR_LENGTH];
                let mut csprng = thread_rng();
                for i in 1..20 {
                    $sec_key_func_name(i, sk_bytes.as_mut_ptr());
                    $pub_key_func_name(i, sk_bytes.as_ptr(), pk_bytes.as_mut_ptr());
                    $random_values_func_name(i, value_bytes.as_mut_ptr());
                    $commitment_with_pk_func_name(
                        i,
                        pk_bytes.as_ptr(),
                        value_bytes.as_ptr(),
                        unknown_msg_bytes.as_mut_ptr(),
                        randomness_bytes.as_mut_ptr(),
                    );
                    let sk_slice = &sk_bytes[i * <$pairing_type as Pairing>::SCALAR_LENGTH
                        ..(i + 1) * <$pairing_type as Pairing>::SCALAR_LENGTH];
                    $sign_func_name(
                        sk_slice.as_ptr(),
                        unknown_msg_bytes.as_ptr(),
                        sig_bytes.as_mut_ptr(),
                    );
                    $retrieve_sig_func_name(
                        sig_bytes.as_ptr(),
                        randomness_bytes.as_ptr(),
                        retrieved_sig_bytes.as_mut_ptr(),
                    );

                    let mut res = $verify_func_name(
                        i,
                        pk_bytes.as_ptr(),
                        retrieved_sig_bytes.as_ptr(),
                        value_bytes.as_ptr(),
                    );
                    assert_eq!(res, 1 as i32);

                    let wrong_msg = KnownMessage::<$pairing_type>::generate(i, &mut csprng);
                    res = $verify_func_name(
                        i,
                        pk_bytes.as_ptr(),
                        retrieved_sig_bytes.as_ptr(),
                        wrong_msg.to_bytes().as_ptr(),
                    );
                    assert_ne!(res, 1 as i32);

                    let wrong_sig = Signature::<$pairing_type>::arbitrary(&mut csprng);
                    res = $verify_func_name(
                        i,
                        pk_bytes.as_ptr(),
                        wrong_sig.to_bytes().as_ptr(),
                        value_bytes.as_ptr(),
                    );
                    assert_ne!(res, 1 as i32);
                }
            }
        };
    }

    macro_test_sign_verify_unknown_message_ffi!(
        sign_verify_unknown_message_ffi_bls12_381,
        sign_unknown_message_bls12_381,
        generate_secret_key_bls12_381,
        public_key_bls12_381,
        commit_with_pk_bls12_381,
        commitment_key_bls12_381,
        random_values_bls12_381_g1_proj,
        verify_bls12_381,
        retrieve_sig_bls12_381,
        Bls12
    );
}
