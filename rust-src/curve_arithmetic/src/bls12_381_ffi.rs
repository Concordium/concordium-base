// use ffi_macros::*;

// use crate::curve_arithmetic::*;
// use libc::size_t;
// use pairing::bls12_381::G1;
// use rand::thread_rng;
// use std::slice;

// // macro_free_ffi!(bls_free_g1, G1);
// // macro_free_ffi!(bls_free_scalar, <G1 as Curve>::Scalar);

// // macro_derive_to_bytes!(bls_to_bytes_g1, G1, <G1 as
// Curve>::curve_to_bytes); // macro_derive_to_bytes!(
// //     bls_to_bytes_scalar,
// //     <G1 as Curve>::Scalar,
// //     <G1 as Curve>::scalar_to_bytes
// // );

// // macro_derive_from_bytes!(bls_from_bytes_g1, G1, <G1 as
// Curve>::bytes_to_curve); // macro_derive_from_bytes!(
// //     bls_from_bytes_scalar,
// //     <G1 as Curve>::Scalar,
// //     <G1 as Curve>::bytes_to_scalar
// // );

// // #[no_mangle]
// // #[allow(clippy::not_unsafe_ptr_arg_deref)]
// // pub extern "C" fn free_array_len(ptr: *mut u8, len: size_t) {
// //     let s = mut_slice_from_c_bytes!(ptr, len as usize);
// //     unsafe {
// //         Box::from_raw(s.as_mut_ptr());
// //     }
// // }

// // #[no_mangle]
// // #[allow(clippy::not_unsafe_ptr_arg_deref)]
// // pub extern "C" fn bls_generate_g1() -> *const G1 {
// //     let mut csrng = thread_rng();
// //     Box::into_raw(Box::new(<G1 as Curve>::generate(&mut csrng)))
// // }

// // #[no_mangle]
// // #[allow(clippy::not_unsafe_ptr_arg_deref)]
// // pub extern "C" fn bls_generate_scalar() -> *const <G1 as Curve>::Scalar {
// //     let mut csrng = thread_rng();
// //     Box::into_raw(Box::new(<G1 as Curve>::generate_scalar(&mut csrng)))
// // }
