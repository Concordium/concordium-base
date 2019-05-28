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

use pairing::{
    bls12_381::{Fr, G1Compressed, G1},
    CurveAffine, CurveProjective, EncodedPoint,
};

use crate::{
    cipher::*,
    constants::*,
    errors::{
        InternalError::{GDecodingError, PublicKeyLengthError},
        *,
    },
    message::*,
    secret::*,
};

/// Elgamal public key .
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct PublicKey(pub(crate) G1);

impl Debug for PublicKey {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "PublicKey({:?})", self.0)
    }
}

impl<'a> From<&'a SecretKey> for PublicKey {
    /// Derive this public key from its corresponding `SecretKey`.
    fn from(secret_key: &SecretKey) -> PublicKey {
        let mut t = G1::one();
        t.mul_assign(secret_key.0);
        PublicKey(t)
    }
}

impl PublicKey {
    /// Convert this public key to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        let mut ar = [0u8; PUBLIC_KEY_LENGTH];
        ar.copy_from_slice(self.0.into_affine().into_compressed().as_ref());
        ar
    }

    /// Construct a public key from a slice of bytes.
    ///
    /// A `Result` whose okay value is a public key or whose error value
    /// is an `ElgamalError` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, ElgamalError> {
        if bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(ElgamalError(PublicKeyLengthError));
        }
        let mut g = G1Compressed::empty();
        g.as_mut().copy_from_slice(&bytes);
        match g.into_affine() {
            Err(x) => Err(ElgamalError(GDecodingError(x))),
            Ok(g_affine) => Ok(PublicKey(G1::from(g_affine))),
        }
    }

    #[inline]
    pub fn encrypt<T>(&self, csprng: &mut T, m: &Message) -> Cipher
    where
        T: Rng, {
        let fr = Fr::rand(csprng); // k
        let mut t = G1::one(); // g
        t.mul_assign(fr); // kg
        let mut s = self.0;
        s.mul_assign(fr); // kag
        s.add_assign(&m.0); // kag + m
        Cipher(t, s)
    }

    // pub fn encrypt_bin_exp<T>(&self, csprng: &mut T, e: &bool) -> Cipher
    // where T:Rng{
    // if !e {
    // self.encrypt(csprng, &Message(G1::zero()))
    // } else{
    // self.encrypt(csprng, &Message(G1::one()))
    // }
    // }
    // pub fn encrypt_binary_exp<T>(&self, csprng: &mut T, e: &bool) -> Cipher
    // where T:Rng {
    // let mut csprng = thread_rng();
    // if !e {
    // self.encrypt(&mut csprng, &Message(G1::zero()))
    // } else{
    // self.encrypt(&mut csprng, &Message(G1::one()))
    // }
    // }
    pub fn hide(&self, k: Fr, m: &Message) -> Cipher {
        let mut t = G1::one(); // g
        t.mul_assign(k); // kg
        let mut s = self.0;
        s.mul_assign(k); // kag
        s.add_assign(&m.0); // kag + m
        Cipher(t, s)
    }

    pub fn hide_binary_exp(&self, h: Fr, e: bool) -> Cipher {
        if !e {
            self.hide(h, &Message(G1::zero()))
        } else {
            self.hide(h, &Message(G1::one()))
        }
    }

    pub fn encrypt_exponent<T>(&self, csprng: &mut T, e: &Fr) -> Cipher
    where
        T: Rng, {
        let mut m = G1::one(); // g
        let e2 = *e;
        m.mul_assign(e2); // g^e
        self.encrypt(csprng, &Message(m))
    }

    pub fn encrypt_exponent_vec<T>(&self, csprng: &mut T, e: &[Fr]) -> Vec<Cipher>
    where
        T: Rng, {
        e.iter()
            .map(|x| self.encrypt_exponent(csprng, &x))
            .collect()
    }
}

#[cfg(feature = "serde")]
impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer, {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

#[cfg(feature = "serde")]
impl<'d> Deserialize<'d> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>, {
        struct PublicKeyVisitor;

        impl<'d> Visitor<'d> for PublicKeyVisitor {
            type Value = PublicKey;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                formatter.write_str("An Elgamal public key as a 48-bytes")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<PublicKey, E>
            where
                E: SerdeError, {
                PublicKey::from_bytes(bytes).or(Err(SerdeError::invalid_length(bytes.len(), &self)))
            }
        }
        deserializer.deserialize_bytes(PublicKeyVisitor)
    }
}

#[test]
pub fn key_to_byte_conversion() {
    let mut csprng = thread_rng();
    for _i in 1..100 {
        let sk = SecretKey::generate(&mut csprng);
        let pk = PublicKey::from(&sk);
        let r = pk.to_bytes();
        let res_pk2 = PublicKey::from_bytes(&r);
        assert!(res_pk2.is_ok());
        let pk2 = res_pk2.unwrap();
        assert_eq!(pk2, pk);
    }
}
