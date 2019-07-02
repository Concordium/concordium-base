use crate::dlog::*;

use rand::*;

use curve_arithmetic::curve_arithmetic::*;
use ffi_macros::*;
use libc::size_t;
use pairing::bls12_381::{G1Affine, G2Affine, G1};
use std::slice;

macro_rules! generate_dlog_prove {
    ($function_name:ident, $curve_type:path) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn $function_name(
            public_ptr: *const $curve_type,
            secret_ptr: *const <$curve_type as Curve>::Scalar,
            base_ptr: *const $curve_type,
        ) -> *mut DlogProof<$curve_type> {
            let public = from_ptr!(public_ptr);
            let secret = from_ptr!(secret_ptr);
            let base = from_ptr!(base_ptr);
            let mut csprng = thread_rng();
            let proof = prove_dlog(&mut csprng, public, secret, base);
            Box::into_raw(Box::new(proof))
        }
    };
}

macro_rules! generate_dlog_verify {
    ($function_name:ident, $curve_type:path) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn $function_name(
            base_ptr: *const $curve_type,
            public_ptr: *const $curve_type,
            proof_ptr: *const DlogProof<$curve_type>,
        ) -> i32 {
            let base = from_ptr!(base_ptr);
            let public = from_ptr!(public_ptr);
            let proof = from_ptr!(proof_ptr);
            let res = verify_dlog(base, public, proof);
            if res {
                1
            } else {
                0
            }
        }
    };
}

macro_rules! derive_dlog_public {
    ($function_name:ident, $curve_type:path) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn $function_name(
            base_ptr: *const $curve_type,
            secret_ptr: *const <$curve_type as Curve>::Scalar,
        ) -> *const $curve_type {
            let base = from_ptr!(base_ptr);
            let secret = from_ptr!(secret_ptr);
            let public = base.mul_by_scalar(&secret);
            Box::into_raw(Box::new(public))
        }
    };
}

derive_dlog_public!(derive_public_g1, G1);
generate_dlog_verify!(verify_dlog_g1, G1);
macro_free_ffi!(free_dlog_proof_g1, DlogProof<G1>);
generate_dlog_prove!(prove_dlog_g1, G1);
macro_derive_to_bytes!(dlog_proof_to_bytes_g1, DlogProof<G1>);
macro_derive_from_bytes!(
    dlog_proof_from_bytes_g1,
    DlogProof<G1>,
    DlogProof::from_bytes
);

derive_dlog_public!(derive_public_g1_affine, G1Affine);
generate_dlog_verify!(verify_dlog_g1_affine, G1Affine);
macro_free_ffi!(free_dlog_proof_g1_affine, DlogProof<G1Affine>);
generate_dlog_prove!(prove_dlog_g1_affine, G1Affine);
macro_derive_to_bytes!(dlog_proof_to_bytes_affine_g1, DlogProof<G1Affine>);
macro_derive_from_bytes!(
    dlog_proof_from_bytes_affine_g1,
    DlogProof<G1Affine>,
    DlogProof::from_bytes
);

derive_dlog_public!(derive_public_g2_affine, G2Affine);
generate_dlog_verify!(verify_dlog_g2_affine, G2Affine);
macro_free_ffi!(free_dlog_proof_g2_affine, DlogProof<G2Affine>);
generate_dlog_prove!(prove_dlog_g2_affine, G2Affine);
macro_derive_to_bytes!(dlog_proof_to_bytes_affine_g2, DlogProof<G2Affine>);
macro_derive_from_bytes!(
    dlog_proof_from_bytes_affine_g2,
    DlogProof<G2Affine>,
    DlogProof::from_bytes
);
