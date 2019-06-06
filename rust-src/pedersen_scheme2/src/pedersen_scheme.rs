// Authors:
// - bm@concordium.com

use crate::{commitment::*, constants::*, key::*, value::*};
use curve_arithmetic::{bls12_381_instance::*, curve_arithmetic::*};
use pairing::bls12_381::{G1Affine, G2Affine};
use rand::*;
use std::slice;

macro_rules! macro_generate_commitment_key {
    ($function_name:ident, $curve_type:path) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn $function_name(n: usize, key_bytes: *mut u8) {
            assert!(!key_bytes.is_null(), "Null pointer");
            let key_slice: &mut [u8] = unsafe {
                slice::from_raw_parts_mut(
                    key_bytes,
                    (n + 1) * <$curve_type as Curve>::GROUP_ELEMENT_LENGTH,
                )
            };
            let mut csprng = thread_rng();
            let ck = CommitmentKey::<$curve_type>::generate(n, &mut csprng);
            key_slice.copy_from_slice(&*ck.to_bytes());
        }
    };
}

macro_generate_commitment_key!(pedersen_commitment_key_bls12_381_g2_affine, G2Affine);
macro_generate_commitment_key!(pedersen_commitment_key_bls12_381_g1_affine, G1Affine);

macro_rules! macro_commit {
    ($function_name:ident, $curve_type:path, $commitment_len:expr, $randomness_len:expr) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn $function_name(
            n: usize,
            key_bytes: *const u8,
            values: *const u8,
            commitment: &mut [u8; $commitment_len],
            randomness: &mut [u8; $randomness_len],
        ) -> i32 {
            assert!(!key_bytes.is_null(), "Null pointer");
            assert!(!values.is_null(), "Null pointer");
            let key_slice: &[u8] = unsafe {
                slice::from_raw_parts(
                    key_bytes,
                    (n + 1) * <$curve_type as Curve>::GROUP_ELEMENT_LENGTH,
                )
            };
            let values_slice: &[u8] = unsafe {
                slice::from_raw_parts(values, (n) * <$curve_type as Curve>::SCALAR_LENGTH)
            };
            match CommitmentKey::<$curve_type>::from_bytes(key_slice) {
                Err(_) => -1,
                Ok(ck) => match Value::<$curve_type>::from_bytes(values_slice) {
                    Err(_) => -2,
                    Ok(vs) => {
                        let mut csprng = thread_rng();
                        let (c, r) = ck.commit(&vs, &mut csprng);
                        randomness.copy_from_slice(&Value::<$curve_type>::value_to_bytes(&r));
                        commitment.copy_from_slice(&c.to_bytes());
                        1
                    }
                },
            }
        }
    };
}

macro_commit!(
    commit_bls12_381_g2_affine,
    G2Affine,
    G2Affine::GROUP_ELEMENT_LENGTH,
    G2Affine::SCALAR_LENGTH
);
macro_commit!(
    commit_bls12_381_g1_affine,
    G1Affine,
    G1Affine::GROUP_ELEMENT_LENGTH,
    G1Affine::SCALAR_LENGTH
);

macro_rules! macro_open {
    ($function_name:ident, $curve_type:path, $commitment_len:expr, $randomness_len:expr) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn $function_name(
            n: usize,
            key_bytes: *const u8,
            values: *const u8,
            commitment: &[u8; $commitment_len],
            randomness: &[u8; $randomness_len],
        ) -> i32 {
            assert!(!key_bytes.is_null(), "Null pointer");
            assert!(!values.is_null(), "Null pointer");
            let key_slice: &[u8] = unsafe {
                slice::from_raw_parts(
                    key_bytes,
                    (n + 1) * <$curve_type as Curve>::GROUP_ELEMENT_LENGTH,
                )
            };
            unsafe {
                slice::from_raw_parts(
                    key_bytes,
                    (n + 1) * <$curve_type as Curve>::GROUP_ELEMENT_LENGTH,
                )
            };
            let values_slice: &[u8] = unsafe {
                slice::from_raw_parts(values, (n) * <$curve_type as Curve>::SCALAR_LENGTH)
            };
            match CommitmentKey::<$curve_type>::from_bytes(key_slice) {
                Err(_) => -1,
                Ok(ck) => match Value::<$curve_type>::from_bytes(values_slice) {
                    Err(_) => -2,
                    Ok(vs) => match Value::<$curve_type>::value_from_bytes(randomness) {
                        Err(_) => -3,
                        Ok(r) => match Commitment::<$curve_type>::from_bytes(commitment) {
                            Err(_) => -4,
                            Ok(c) => {
                                if ck.open(&vs, &r, &c) {
                                    1
                                } else {
                                    0
                                }
                            }
                        },
                    },
                },
            }
        }
    };
}

macro_open!(
    open_bls12_381_g2_affine,
    G2Affine,
    G2Affine::GROUP_ELEMENT_LENGTH,
    G2Affine::SCALAR_LENGTH
);
macro_open!(
    open_bls12_381_g1_affine,
    G1Affine,
    G1Affine::GROUP_ELEMENT_LENGTH,
    G1Affine::SCALAR_LENGTH
);

macro_rules! macro_random_values {
    ($function_name:ident, $curve_type:path) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn $function_name(n: usize, value_bytes: *mut u8) {
            let mut csprng = thread_rng();
            let vs = Value::<$curve_type>::generate(n, &mut csprng);
            let v_slice: &mut [u8] = unsafe {
                slice::from_raw_parts_mut(value_bytes, n * <$curve_type as Curve>::SCALAR_LENGTH)
            };
            v_slice.copy_from_slice(&*vs.to_bytes());
        }
    };
}

macro_random_values!(random_values_bls12_381_g1_affine, G1Affine);

macro_random_values!(random_values_bls12_381_g2_affine, G2Affine);

macro_rules! macro_test_commit_open {
    (
        $function_name:ident,
        $commit_func_name:ident,
        $key_func_name:ident,
        $open_func_name:ident,
        $rand_value_func_name:ident,
        $curve_type:path
    ) => {
        #[test]
        pub fn $function_name() {
            let mut key_bytes = [0u8; 11 * <$curve_type as Curve>::GROUP_ELEMENT_LENGTH];
            let mut values = [0u8; 10 * <$curve_type as Curve>::SCALAR_LENGTH];
            let mut commitment_bytes = [0u8; <$curve_type as Curve>::GROUP_ELEMENT_LENGTH];
            let mut randomness_bytes = [0u8; <$curve_type as Curve>::SCALAR_LENGTH];
            for i in 1..10 {
                let key_slice =
                    &mut key_bytes[..(i + 1) * <$curve_type as Curve>::GROUP_ELEMENT_LENGTH];
                $key_func_name(i, key_slice.as_mut_ptr());
                let v_slice = &mut values[..(i + 1) * <$curve_type as Curve>::SCALAR_LENGTH];
                $rand_value_func_name(i, v_slice.as_mut_ptr());
                let suc1 = $commit_func_name(
                    i,
                    key_slice.as_ptr(),
                    v_slice.as_ptr(),
                    &mut commitment_bytes,
                    &mut randomness_bytes,
                );
                assert!(suc1 > 0);
                assert!(
                    $open_func_name(
                        i,
                        key_slice.as_ptr(),
                        v_slice.as_ptr(),
                        &commitment_bytes,
                        &randomness_bytes
                    ) > 0
                );
            }
        }
    };
}

macro_test_commit_open!(
    commit_open_bls12_381_g1_affine,
    commit_bls12_381_g1_affine,
    pedersen_commitment_key_bls12_381_g1_affine,
    open_bls12_381_g1_affine,
    random_values_bls12_381_g1_affine,
    G1Affine
);

macro_test_commit_open!(
    commit_open_bls12_381_g2_affine,
    commit_bls12_381_g2_affine,
    pedersen_commitment_key_bls12_381_g2_affine,
    open_bls12_381_g2_affine,
    random_values_bls12_381_g2_affine,
    G2Affine
);
