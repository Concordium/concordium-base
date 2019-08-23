// -*- mode: rust; -*-
//
// Authors:
// - bm@concordium.com

//! Elgamal secret key types

#[cfg(feature = "serde")]
use serde::de::Error as SerdeError;
#[cfg(feature = "serde")]
use serde::de::Visitor;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde::{Deserializer, Serializer};
#[cfg(feature = "serde")]
use std::marker::PhantomData;

use crate::{cipher::*, errors::*, message::*};
use rand::*;

use curve_arithmetic::Curve;
use ff::Field;

use std::io::Cursor;

/// elgamal secret  key.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SecretKey<C: Curve>(pub C::Scalar);

// THIS IS COMMENTED FOR NOW FOR COMPATIBILITY WITH BLS CURVE IMPLEMENTATION
// ONCE WE HAVE TAKEN OVER THE SOURCE OF THE CURVE THIS SHOULD BE IMPLEMENTED
// Overwrite secret key material with null bytes when it goes out of scope.
//
// impl Drop for SecretKey {
// fn drop(&mut self) {
// (self.0).into_repr().0.clear();
// }
// }

impl<C: Curve> SecretKey<C> {
    /// Convert a secret key into bytes
    #[inline]
    pub fn to_bytes(&self) -> Box<[u8]> { C::scalar_to_bytes(&self.0) }

    /// Construct a `SecretKey` from a slice of bytes.
    ///
    /// A `Result` whose okay value is a secret key or whose error value
    /// is an `ElgamalError` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes(bytes: &mut Cursor<&[u8]>) -> Result<SecretKey<C>, ElgamalError> {
        let x = C::bytes_to_scalar(bytes)?;
        Ok(SecretKey(x))
    }

    pub fn decrypt(&self, c: &Cipher<C>) -> Message<C> {
        let x = c.0; // k * g
        let kag = x.mul_by_scalar(&self.0); // k * a * g
        let y = c.1; // m + k * a * g
        let m = y.minus_point(&kag); // m
        Message(m)
    }

    pub fn decrypt_exponent(&self, c: &Cipher<C>) -> C::Scalar {
        let Message(m) = self.decrypt(c);
        let mut a = <C::Scalar as Field>::zero();
        let mut i = C::zero_point();
        let one = C::one_point();
        let field_one = <C::Scalar as Field>::one();
        while m != i {
            i = i.plus_point(&one);
            a.add_assign(&field_one);
        }
        a
    }

    pub fn decrypt_exponent_vec(&self, v: &[Cipher<C>]) -> Vec<C::Scalar> {
        v.iter().map(|y| self.decrypt_exponent(y)).collect()
    }

    /// Generate a `SecretKey` from a `csprng`.
    pub fn generate<T>(csprng: &mut T) -> Self
    where
        T: Rng, {
        SecretKey(C::generate_scalar(csprng))
    }
}

#[cfg(feature = "serde")]
impl<C: Curve> Serialize for SecretKey<C> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer, {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

#[cfg(feature = "serde")]
impl<'d, C: Curve> Deserialize<'d> for SecretKey<C> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>, {
        struct SecretKeyVisitor<C: Curve>(PhantomData<C>);

        impl<'d, C: Curve> Visitor<'d> for SecretKeyVisitor<C> {
            type Value = SecretKey<C>;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                formatter.write_str("An Elgamal  secret key as 32 bytes")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<SecretKey<C>, E>
            where
                E: SerdeError, {
                SecretKey::from_bytes(bytes).or(Err(SerdeError::invalid_length(bytes.len(), &self)))
            }
        }
        deserializer.deserialize_bytes(SecretKeyVisitor(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::{G1, G2};
    macro_rules! macro_test_secret_key_to_byte_conversion {
        ($function_name:ident, $curve_type:path) => {
            #[test]
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                for _i in 1..100 {
                    let sk: SecretKey<$curve_type> = SecretKey::generate(&mut csprng);
                    let r = sk.to_bytes();
                    let res_sk2 = SecretKey::from_bytes(&mut Cursor::new(&r));
                    assert!(res_sk2.is_ok());
                    let sk2 = res_sk2.unwrap();
                    assert_eq!(sk2, sk);
                }
            }
        };
    }

    macro_test_secret_key_to_byte_conversion!(secret_key_to_byte_conversion_g1, G1);
    macro_test_secret_key_to_byte_conversion!(secret_key_to_byte_conversion_g2, G2);
}
