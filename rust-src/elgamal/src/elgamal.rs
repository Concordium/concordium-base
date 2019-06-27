// Authors:
// - bm@concordium.com
use crate::{cipher::*, errors::*, message::*, public::*, secret::*};
use bitvec::Bits;
use rand::*;
use rayon::prelude::*;
use std::slice;

// #[cfg(test)]
// use pairing::bls12_381::FrRepr;
// #[cfg(test)]
// use pairing::PrimeField;
use curve_arithmetic::curve_arithmetic::Curve;
use pairing::bls12_381::{G1, G2};

// foreign function interface
macro_rules! macro_new_secret_key_ffi {
    ($function_name:ident, $curve_type:path) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn $function_name() -> *mut SecretKey<$curve_type> {
            let mut csprng = thread_rng();
            Box::into_raw(Box::new(SecretKey::generate(&mut csprng)))
        }
    };
}

macro_new_secret_key_ffi!(new_secret_key_g1, G1);
macro_new_secret_key_ffi!(new_secret_key_g2, G2);

macro_rules! macro_free_ffi {
    ($function_name:ident, $type:path) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn $function_name(ptr: *mut $type) {
            if ptr.is_null() {
                return;
            }
            unsafe {
                Box::from_raw(ptr);
            }
        }
    };
}

macro_free_ffi!(free_secret_key_g1, SecretKey<G1>);
macro_free_ffi!(free_secret_key_g2, SecretKey<G2>);

macro_rules! macro_derive_public_key_ffi {
    ($function_name:ident, $curve_type:path) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn $function_name(
            ptr: *mut SecretKey<$curve_type>,
        ) -> *mut PublicKey<$curve_type> {
            let sk: &SecretKey<$curve_type> = unsafe {
                assert!(!ptr.is_null());
                &*ptr
            };
            Box::into_raw(Box::new(PublicKey::from(sk)))
        }
    };
}

macro_derive_public_key_ffi!(derive_public_key_g1, G1);
macro_derive_public_key_ffi!(derive_public_key_g2, G2);

// TODO: Duplicated from ps_sig!
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

pub fn encrypt_u64_bitwise_iter<C: Curve>(
    pk: PublicKey<C>,
    e: u64,
) -> impl IndexedParallelIterator<Item = Cipher<C>> {
    (0..64).into_par_iter().map(move |i| {
        let mut csprng = thread_rng();
        pk.hide_binary_exp(&C::generate_scalar(&mut csprng), e.get(i as u8))
    })
}

/// Generate code to encrypt a single 64 bit integer bitwise.
macro_rules! macro_encrypt_u64_ffi {
    ($function_name:ident, $curve_type:path) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn $function_name(ptr: *mut PublicKey<$curve_type>, e: u64, out: *mut u8) {
            let pk: &PublicKey<$curve_type> = unsafe {
                assert!(!ptr.is_null());
                &*ptr
            };
            let elen = 2 * 64 * <$curve_type as Curve>::GROUP_ELEMENT_LENGTH;
            let out_bytes = mut_slice_from_c_bytes!(out, elen);
            out_bytes.par_chunks_mut(2 * <$curve_type as Curve>::GROUP_ELEMENT_LENGTH) // each ciphertext is of this length
                                        .zip(encrypt_u64_bitwise_iter(*pk, e))
                                        .for_each(|(out_chunk, cipher)| {
                                            let mut cipher_bytes = Cipher::to_bytes(&cipher);
                                            out_chunk.swap_with_slice(&mut cipher_bytes);
                                        })
        }
    };
}

macro_encrypt_u64_ffi!(encrypt_u64_g1, G1);
macro_encrypt_u64_ffi!(encrypt_u64_g2, G2);

pub fn encrypt_u64_bitwise<C: Curve>(pk: PublicKey<C>, e: u64) -> Vec<Cipher<C>> {
    encrypt_u64_bitwise_iter(pk, e).collect()
}

// take an array of zero's and ones and returns a u64
pub fn group_bits_to_u64<'a, C, I>(v: I) -> u64
where
    C: Curve,
    I: Iterator<Item = &'a C>, {
    let mut r = 0u64;
    let one = C::one_point();
    for (i, &e) in v.enumerate() {
        r.set(i as u8, e == one);
    }
    r
}

/// Generate code to decrypt a single 64 bit integer bitwise.
macro_rules! macro_decrypt_u64_ffi {
    ($function_name:ident, $curve_type:path) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn $function_name(
            ptr: *mut SecretKey<$curve_type>,
            cipher_bytes: *const u8,
            result_ptr: *mut u64,
        ) -> i32 {
            assert!(!result_ptr.is_null());
            assert!(!ptr.is_null());
            let cipher_len = 2 * <$curve_type as Curve>::GROUP_ELEMENT_LENGTH;
            let clen = 64 * cipher_len;
            let cipher = slice_from_c_bytes!(cipher_bytes, clen);
            let sk: &SecretKey<$curve_type> = unsafe { &*ptr };
            let v: Result<Vec<$curve_type>, ElgamalError> = cipher
                .par_chunks(cipher_len)
                .map(|x| {
                    let c = Cipher::from_bytes(x)?;
                    let Message(m) = sk.decrypt(&c);
                    Ok(m)
                })
                .collect();
            match v {
                Err(_) => -2,
                Ok(vv) => {
                    let result = group_bits_to_u64(vv.iter());
                    unsafe { *result_ptr = result }
                    0
                }
            }
        }
    };
}

macro_decrypt_u64_ffi!(decrypt_u64_g1, G1);
macro_decrypt_u64_ffi!(decrypt_u64_g2, G2);

/// Generate code to decrypt a single 64 bit integer bitwise. This function
/// not check that the cipher is valid. It uses the unchecked conversion
/// bytes to group elements. It will panic if the ciphertext is invalid.
macro_rules! macro_decrypt_u64_unsafe_ffi {
    ($function_name:ident, $curve_type:path) => {
        #[no_mangle]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn $function_name(
            ptr: *mut SecretKey<$curve_type>,
            cipher_bytes: *const u8,
        ) -> u64 {
            assert!(!ptr.is_null());
            let cipher_len = 2 * <$curve_type as Curve>::GROUP_ELEMENT_LENGTH;
            let clen = 64 * cipher_len;
            let cipher = slice_from_c_bytes!(cipher_bytes, clen);
            let sk: &SecretKey<$curve_type> = unsafe { &*ptr };
            let v: Vec<$curve_type> = cipher
                .par_chunks(cipher_len)
                .map(|x| {
                    let c = Cipher::from_bytes_unchecked(x).unwrap();
                    let Message(m) = sk.decrypt(&c);
                    m
                })
                .collect();
            group_bits_to_u64(v.iter())
        }
    };
}

macro_decrypt_u64_unsafe_ffi!(decrypt_u64_unsafe_g1, G1);
macro_decrypt_u64_unsafe_ffi!(decrypt_u64_unsafe_g2, G2);

pub fn decrypt_u64_bitwise<C: Curve>(sk: &SecretKey<C>, v: &[Cipher<C>]) -> u64 {
    let dr: Vec<C> = v
        .par_iter()
        .map(|x| {
            let Message(m) = sk.decrypt(&x);
            m
        })
        .collect();
    group_bits_to_u64(dr.iter())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::Field;
    macro_rules! macro_test_encrypt_decrypt_success {
        ($function_name:ident, $curve_type:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                for _i in 1..100 {
                    let sk: SecretKey<$curve_type> = SecretKey::generate(&mut csprng);
                    let pk = PublicKey::from(&sk);
                    let m = Message::generate(&mut csprng);
                    let c = pk.encrypt(&mut csprng, &m);
                    let mm = sk.decrypt(&c);
                    assert_eq!(m, mm);

                    // encrypting again gives a different ciphertext (very likely at least)
                    let canother = pk.encrypt(&mut csprng, &m);
                    assert_ne!(c, canother);
                }
            }
        };
    }

    macro_test_encrypt_decrypt_success!(encrypt_decrypt_success_g1, G1);
    macro_test_encrypt_decrypt_success!(encrypt_decrypt_success_g2, G2);

    macro_rules! macro_test_encrypt_decrypt_exponent_success {
        ($function_name:ident, $curve_type:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                let sk: SecretKey<$curve_type> = SecretKey::generate(&mut csprng);
                let pk = PublicKey::from(&sk);
                for _i in 1..100 {
                    let n = u64::rand(&mut csprng);
                    let mut e = <$curve_type as Curve>::Scalar::zero();
                    let one_scalar = <$curve_type as Curve>::Scalar::one();
                    for _ in 0..(n % 1000) {
                        e.add_assign(&one_scalar);
                    }
                    let c = pk.encrypt_exponent(&mut csprng, &e);
                    let e2 = sk.decrypt_exponent(&c);
                    assert_eq!(e, e2);
                }
            }
        };
    }

    macro_test_encrypt_decrypt_exponent_success!(encrypt_decrypt_exponent_success_g1, G1);
    macro_test_encrypt_decrypt_exponent_success!(encrypt_decrypt_exponent_success_g2, G2);

    macro_rules! macro_test_encrypt_decrypt_bitwise_vec_success {
        ($function_name:ident, $curve_type:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                let sk: SecretKey<$curve_type> = SecretKey::generate(&mut csprng);
                let pk = PublicKey::from(&sk);
                for _i in 1..100 {
                    let n = u64::rand(&mut csprng);
                    let c = encrypt_u64_bitwise(pk, n);
                    let n2 = decrypt_u64_bitwise(&sk, &c);
                    assert_eq!(n, n2);
                }
            }
        };
    }

    macro_test_encrypt_decrypt_bitwise_vec_success!(encrypt_decrypt_bitwise_vec_success_g1, G1);
    macro_test_encrypt_decrypt_bitwise_vec_success!(encrypt_decrypt_bitwise_vec_success_g2, G2);

    macro_rules! macro_test_encrypt_decrypt_u64_ffi {
        (
            $function_name:ident,
            $new_secret_key_name:ident,
            $derive_public_name:ident,
            $encrypt_name:ident,
            $decrypt_name:ident,
            $size:expr
        ) => {
            #[test]
            pub fn $function_name() {
                let byte_size = $size * 2 * 64;
                let sk = $new_secret_key_name();
                let pk = $derive_public_name(sk);
                let mut xs = Vec::with_capacity(byte_size);
                let mut csprng = thread_rng();
                for _i in 1..100 {
                    let n = u64::rand(&mut csprng);
                    $encrypt_name(pk, n, xs.as_mut_ptr());
                    let result_ptr = Box::into_raw(Box::new(0));
                    let m = $decrypt_name(sk, xs.as_ptr(), result_ptr);
                    assert_eq!(m, 0);
                    assert_eq!(unsafe { *result_ptr }, n);
                }
            }
        };
    }

    macro_test_encrypt_decrypt_u64_ffi! {
        encrypt_decrypt_u64_g1_ffi,
        new_secret_key_g1,
        derive_public_key_g1,
        encrypt_u64_g1,
        decrypt_u64_g1,
        <G1 as Curve>::GROUP_ELEMENT_LENGTH
    }

    macro_test_encrypt_decrypt_u64_ffi! {
        encrypt_decrypt_u64_g2_ffi,
        new_secret_key_g2,
        derive_public_key_g2,
        encrypt_u64_g2,
        decrypt_u64_g2,
        <G2 as Curve>::GROUP_ELEMENT_LENGTH
    }

    macro_rules! macro_test_encrypt_decrypt_u64_unchecked_ffi {
        (
            $function_name:ident,
            $new_secret_key_name:ident,
            $derive_public_name:ident,
            $encrypt_name:ident,
            $decrypt_name:ident,
            $size:expr
        ) => {
            #[test]
            pub fn $function_name() {
                let byte_size = $size * 2 * 64;
                let sk = $new_secret_key_name();
                let pk = $derive_public_name(sk);
                let mut xs = vec![0; byte_size];
                let mut csprng = thread_rng();
                for _i in 1..100 {
                    let n = u64::rand(&mut csprng);
                    $encrypt_name(pk, n, xs.as_mut_ptr());
                    let m = $decrypt_name(sk, xs.as_ptr());
                    assert_eq!(m, n);
                }
            }
        };
    }

    macro_test_encrypt_decrypt_u64_unchecked_ffi! {
        encrypt_decrypt_u64_g1_ffi_unsafe,
        new_secret_key_g1,
        derive_public_key_g1,
        encrypt_u64_g1,
        decrypt_u64_unsafe_g1,
        <G1 as Curve>::GROUP_ELEMENT_LENGTH
    }

    macro_test_encrypt_decrypt_u64_unchecked_ffi! {
        encrypt_decrypt_u64_g2_ffi_unsafe,
        new_secret_key_g2,
        derive_public_key_g2,
        encrypt_u64_g2,
        decrypt_u64_unsafe_g2,
        <G2 as Curve>::GROUP_ELEMENT_LENGTH
    }

}
