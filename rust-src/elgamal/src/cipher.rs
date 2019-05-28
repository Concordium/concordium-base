// -*- mode: rust; -*-
//
// Authors:
// - bm@concordium.com

//! Elgamal cipher  types

#[cfg(feature = "serde")]
use serde::de::Error as SerdeError;
#[cfg(feature = "serde")]
use serde::de::Visitor;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde::{Deserializer, Serializer};

use crate::{
    constants::*,
    errors::{InternalError::*, *},
};
use pairing::{
    bls12_381::{G1Compressed, G1},
    CurveAffine, CurveProjective, EncodedPoint,
};
#[cfg(test)]
use rand::*;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Cipher(pub(crate) G1, pub(crate) G1);

impl Cipher {
    /// Convert this cipher key to a byte array.

    #[inline]
    pub fn to_bytes(&self) -> [u8; CIPHER_LENGTH] {
        let mut ar = [0u8; CIPHER_LENGTH];
        ar[..CIPHER_LENGTH / 2].copy_from_slice(self.0.into_affine().into_compressed().as_ref());
        ar[CIPHER_LENGTH / 2..].copy_from_slice(self.1.into_affine().into_compressed().as_ref());
        ar
    }

    /// Construct a cipher from a slice of bytes.
    /// only use if you know that the bytes are an encoding fo a cipher
    /// A `Result` whose okay value is a cipher key or whose error value
    /// is an `ElgamalError` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Result<Cipher, ElgamalError> {
        if bytes.len() != CIPHER_LENGTH {
            return Err(ElgamalError(CipherLengthError));
        }
        let mut g = G1Compressed::empty();
        let mut h = G1Compressed::empty();
        g.as_mut().copy_from_slice(&bytes[0..CIPHER_LENGTH / 2]);
        h.as_mut()
            .copy_from_slice(&bytes[CIPHER_LENGTH / 2..CIPHER_LENGTH]);

        match g.into_affine_unchecked() {
            Err(x) => Err(ElgamalError(GDecodingError(x))),
            Ok(g_affine) => match h.into_affine_unchecked() {
                Err(x) => Err(ElgamalError(GDecodingError(x))),
                Ok(h_affine) => Ok(Cipher(G1::from(g_affine), G1::from(h_affine))),
            },
        }
    }

    /// Construct a cipher from a slice of bytes.
    ///
    /// A `Result` whose okay value is a cipher key or whose error value
    /// is an `ElgamalError` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Cipher, ElgamalError> {
        if bytes.len() != CIPHER_LENGTH {
            return Err(ElgamalError(CipherLengthError));
        }
        let mut g = G1Compressed::empty();
        let mut h = G1Compressed::empty();
        g.as_mut().copy_from_slice(&bytes[0..CIPHER_LENGTH / 2]);
        h.as_mut()
            .copy_from_slice(&bytes[CIPHER_LENGTH / 2..CIPHER_LENGTH]);

        match g.into_affine() {
            Err(x) => Err(ElgamalError(GDecodingError(x))),
            Ok(g_affine) => match h.into_affine() {
                Err(x) => Err(ElgamalError(GDecodingError(x))),
                Ok(h_affine) => Ok(Cipher(G1::from(g_affine), G1::from(h_affine))),
            },
        }
    }
}

// serialization feature for cipher
#[cfg(feature = "serde")]
impl Serialize for Cipher {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer, {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

#[cfg(feature = "serde")]
impl<'d> Deserialize<'d> for Cipher {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>, {
        struct CipherVisitor;

        impl<'d> Visitor<'d> for CipherVisitor {
            type Value = Cipher;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                formatter.write_str("An Elgamal Cipher key as a 96-bytes")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Cipher, E>
            where
                E: SerdeError, {
                Cipher::from_bytes(bytes).or(Err(SerdeError::invalid_length(bytes.len(), &self)))
            }
        }
        deserializer.deserialize_bytes(CipherVisitor)
    }
}
#[test]
pub fn cipher_to_byte_conversion() {
    let mut csprng = thread_rng();
    for _i in 1..100 {
        let a = G1::rand(&mut csprng);
        let b = G1::rand(&mut csprng);
        let c = Cipher(a, b);
        let s = Cipher::from_bytes(&c.to_bytes());
        assert!(s.is_ok());
        assert_eq!(c, s.unwrap());
        // let sk = SecretKey::generate(&mut csprng);
        // let pk = PublicKey::from(&sk);
        // let r = pk.to_bytes();
        // let res_pk2= PublicKey::from_bytes(&r);
        // assert!(res_pk2.is_ok());
        // let pk2= res_pk2.unwrap();
        // assert_eq!(pk2, pk);
    }
}
