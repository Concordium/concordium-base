// -*- mode: rust; -*-
//
// Authors:
// - bm@concordium.com

//! A known message

#[cfg(feature = "serde")]
use serde::de::Error as SerdeError;
#[cfg(feature = "serde")]
use serde::de::Visitor;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde::{Deserializer, Serializer};

use crate::errors::{
    InternalError::{CurveDecodingError, FieldDecodingError, SecretKeyLengthError},
    *,
};
use curve_arithmetic::curve_arithmetic::*;

use pairing::bls12_381::{Bls12};

use curve_arithmetic::bls12_381_instance::*;
use rand::*;

/// A message
#[derive(Debug )]
pub struct SecretKey<C: Pairing>(pub(crate) Vec<C::ScalarField>, pub(crate) C::ScalarField);

impl<C:Pairing> PartialEq for SecretKey<C> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0 && self.1 == other.1
    }
}

impl<C:Pairing> Eq for SecretKey<C>{}


impl<C: Pairing> SecretKey<C> {
    // turn message vector into a byte aray
    #[inline]
    pub fn to_bytes(&self) -> Box<[u8]> {
        let vs = &self.0;
        let u  = &self.1;
        let mut bytes: Vec<u8> = Vec::new();
        for v in vs.iter() {
            bytes.extend_from_slice(&*Self::value_to_bytes(&v));
        }
        bytes.extend_from_slice(&*Self::value_to_bytes(u));
        bytes.into_boxed_slice()
    }

    #[inline]
    pub fn value_to_bytes(scalar: &C::ScalarField) -> Box<[u8]> { C::scalar_to_bytes(scalar) }

    /// Construct a message vec from a slice of bytes.
    ///
    /// A `Result` whose okay value is a message vec  or whose error value
    /// is an `SignatureError` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey<C>, SignatureError> {
        let l = bytes.len();
        if l == 0 || l < C::SCALAR_LENGTH * 2 || l % C::SCALAR_LENGTH != 0 {
            return Err(SignatureError(SecretKeyLengthError));
        }
        let vlen = (l / C::SCALAR_LENGTH) - 1;
        let mut vs: Vec<C::ScalarField> = Vec::new();
        for i in 0..vlen {
            let j = i * C::SCALAR_LENGTH;
            let k = j + C::SCALAR_LENGTH;
            match C::bytes_to_scalar(&bytes[j..k]) {
                Err(x) => return Err(SignatureError(FieldDecodingError)),
                Ok(fr) => vs.push(fr),
            }
        }
        match C::bytes_to_scalar(&bytes[(l - C::SCALAR_LENGTH)..]){
            Err(x) => Err(SignatureError(FieldDecodingError)),
            Ok(fr) => Ok(SecretKey(vs, fr))
        }

    }


    /// Generate a secret key  from a `csprng`.
    pub fn generate<T>(n: usize, csprng: &mut T) -> SecretKey<C>
    where
        T: Rng, {
        let mut vs: Vec<C::ScalarField> = Vec::new();
        for _i in 0..n {
            vs.push(C::generate_scalar(csprng));
        }

        SecretKey(vs, C::generate_scalar(csprng))
    }
}

macro_rules! macro_test_secret_key_to_byte_conversion {
    ($function_name:ident, $pairing_type:path) => {
        #[test]
        pub fn $function_name() {
            let mut csprng = thread_rng();
            for i in 1..20 {
                let val = SecretKey::<$pairing_type>::generate(i, &mut csprng);
                let res_val2 = SecretKey::<$pairing_type>::from_bytes(&*val.to_bytes());
                assert!(res_val2.is_ok());
                let val2 = res_val2.unwrap();
                assert_eq!(val2, val);
            }
        }
    };
}

macro_test_secret_key_to_byte_conversion!(secret_key_to_byte_conversion_bls12_381, Bls12);
