// -*- mode: rust; -*-
//
// This file is part of concordium_crypto
// Copyright (c) 2019 -
// See LICENSE for licensing information.
//
// Authors:
// - bm@concordium.com

//! Elgamal  public keys.

use core::fmt::Debug;
use rand::*;

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

use crate::{cipher::*, errors::*, message::*, secret::*};

use curve_arithmetic::Curve;

use std::io::Cursor;

/// Elgamal public key .
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct PublicKey<C: Curve> {
    pub generator: C,
    pub key:       C,
}

impl<C: Curve> Debug for PublicKey<C> {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "PublicKey({:?}, {:?})", self.generator, self.key)
    }
}

impl<'a, C: Curve> From<&'a SecretKey<C>> for PublicKey<C> {
    /// Derive this public key from its corresponding `SecretKey`.
    fn from(secret_key: &SecretKey<C>) -> PublicKey<C> {
        let generator: C = secret_key.generator;
        let key = generator.mul_by_scalar(&secret_key.scalar);
        PublicKey { generator, key }
    }
}

impl<C: Curve> PublicKey<C> {
    /// Convert this public key to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> Box<[u8]> {
        let mut out = Vec::with_capacity(2 * C::GROUP_ELEMENT_LENGTH);
        out.extend_from_slice(&C::curve_to_bytes(&self.generator));
        out.extend_from_slice(&C::curve_to_bytes(&self.key));
        out.into_boxed_slice()
    }

    /// Construct a public key from a slice of bytes.
    ///
    /// A `Result` whose okay value is a public key or whose error value
    /// is an `ElgamalError` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes(bytes: &mut Cursor<&[u8]>) -> Result<Self, ElgamalError> {
        let generator = C::bytes_to_curve(bytes)?;
        let key = C::bytes_to_curve(bytes)?;
        Ok(PublicKey { generator, key })
    }

    #[inline]
    /// Encrypt and returned the randomness used. NB: Randomness must be kept
    /// private.
    pub fn encrypt_rand<T>(&self, csprng: &mut T, m: &Message<C>) -> (Cipher<C>, Randomness<C>)
    where
        T: Rng, {
        let k = Randomness::generate(csprng);
        let g = self.generator.mul_by_scalar(&k.randomness);
        let s = self.key.mul_by_scalar(&k.randomness).plus_point(&m.value);
        (Cipher(g, s), k)
    }

    #[inline]
    pub fn encrypt<T>(&self, csprng: &mut T, m: &Message<C>) -> Cipher<C>
    where
        T: Rng, {
        self.encrypt_rand(csprng, m).0
    }

    pub fn hide(&self, k: &C::Scalar, message: &Message<C>) -> Cipher<C> {
        let t = self.generator.mul_by_scalar(k);
        let s = self.key.mul_by_scalar(&k).plus_point(&message.value);
        Cipher(t, s)
    }

    pub fn hide_binary_exp(&self, h: &C::Scalar, e: bool) -> Cipher<C> {
        if !e {
            self.hide(h, &Message {
                value: C::zero_point(),
            })
        } else {
            self.hide(h, &Message {
                value: self.generator,
            })
        }
    }

    /// Encrypt as an exponent, and return the randomness used.
    pub fn encrypt_exponent_rand<T>(
        &self,
        csprng: &mut T,
        e: &C::Scalar,
    ) -> (Cipher<C>, Randomness<C>)
    where
        T: Rng, {
        let value = self.generator.mul_by_scalar(e);
        self.encrypt_rand(csprng, &Message { value })
    }

    pub fn encrypt_exponent<T>(&self, csprng: &mut T, e: &C::Scalar) -> Cipher<C>
    where
        T: Rng, {
        self.encrypt_exponent_rand(csprng, e).0
    }

    pub fn encrypt_exponent_vec<T>(&self, csprng: &mut T, e: &[C::Scalar]) -> Vec<Cipher<C>>
    where
        T: Rng, {
        e.iter()
            .map(|x| self.encrypt_exponent(csprng, &x))
            .collect()
    }
}

#[cfg(feature = "serde")]
impl<C: Curve> Serialize for PublicKey<C> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer, {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

#[cfg(feature = "serde")]
impl<'d, C: Curve> Deserialize<'d> for PublicKey<C> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>, {
        struct PublicKeyVisitor<C: Curve>(PhantomData<C>);

        impl<'d, C: Curve> Visitor<'d> for PublicKeyVisitor<C> {
            type Value = PublicKey<C>;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                formatter.write_str("An Elgamal public key as a 48-bytes")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<PublicKey<C>, E>
            where
                E: SerdeError, {
                PublicKey::from_bytes(bytes).or(Err(SerdeError::invalid_length(bytes.len(), &self)))
            }
        }
        deserializer.deserialize_bytes(PublicKeyVisitor(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::{G1, G2};

    macro_rules! macro_test_key_to_byte_conversion {
        ($function_name:ident, $curve_type:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                for _i in 1..100 {
                    let sk: SecretKey<$curve_type> = SecretKey::generate_all(&mut csprng);
                    let pk = PublicKey::from(&sk);
                    let r = pk.to_bytes();
                    let res_pk2 = PublicKey::from_bytes(&mut Cursor::new(&r));
                    assert!(res_pk2.is_ok());
                    let pk2 = res_pk2.unwrap();
                    assert_eq!(pk2, pk);
                }
            }
        };
    }

    macro_test_key_to_byte_conversion!(key_to_byte_conversion_g1, G1);
    macro_test_key_to_byte_conversion!(key_to_byte_conversion_g2, G2);
}
