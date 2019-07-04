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
#[cfg(feature = "serde")]
use std::marker::PhantomData;

use crate::errors::{InternalError::*, *};

use curve_arithmetic::curve_arithmetic::*;

use rand::*;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Cipher<C: Curve>(pub C, pub C);

impl<C: Curve> Cipher<C> {
    /// Convert this cipher key to a byte array.

    #[inline]
    pub fn to_bytes(&self) -> Box<[u8]> {
        let mut ar = Vec::with_capacity(2 * C::GROUP_ELEMENT_LENGTH);
        ar.extend_from_slice(&self.0.curve_to_bytes());
        ar.extend_from_slice(&self.1.curve_to_bytes());
        ar.into_boxed_slice()
    }

    /// Construct a cipher from a slice of bytes.
    /// only use if you know that the bytes are an encoding fo a cipher
    /// A `Result` whose okay value is a cipher key or whose error value
    /// is an `ElgamalError` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Result<Cipher<C>, ElgamalError> {
        if bytes.len() != 2 * C::GROUP_ELEMENT_LENGTH {
            return Err(ElgamalError(CipherLength));
        }

        let g = C::bytes_to_curve_unchecked(&bytes[..C::GROUP_ELEMENT_LENGTH])?;
        let h = C::bytes_to_curve_unchecked(&bytes[C::GROUP_ELEMENT_LENGTH..])?;
        Ok(Cipher(g, h))
    }

    /// Construct a cipher from a slice of bytes.
    ///
    /// A `Result` whose okay value is a cipher key or whose error value
    /// is an `ElgamalError` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Cipher<C>, ElgamalError> {
        if bytes.len() != 2 * C::GROUP_ELEMENT_LENGTH {
            return Err(ElgamalError(CipherLength));
        }

        let g = C::bytes_to_curve(&bytes[..C::GROUP_ELEMENT_LENGTH])?;
        let h = C::bytes_to_curve(&bytes[C::GROUP_ELEMENT_LENGTH..])?;
        Ok(Cipher(g, h))
    }

    /// Generate a random cipher.
    pub fn generate<T>(csprng: &mut T) -> Self
    where
        T: Rng, {
        Cipher(C::generate(csprng), C::generate(csprng))
    }
}

// serialization feature for cipher
#[cfg(feature = "serde")]
impl<C: Curve> Serialize for Cipher<C> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer, {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

#[cfg(feature = "serde")]
impl<'d, C: Curve> Deserialize<'d> for Cipher<C> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>, {
        struct CipherVisitor<C: Curve>(PhantomData<C>);

        impl<'d, C: Curve> Visitor<'d> for CipherVisitor<C> {
            type Value = Cipher<C>;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                formatter.write_str("An Elgamal Cipher key as a 96-bytes")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Cipher<C>, E>
            where
                E: SerdeError,
                C: Curve, {
                Cipher::from_bytes(bytes).or(Err(SerdeError::invalid_length(bytes.len(), &self)))
            }
        }
        deserializer.deserialize_bytes(CipherVisitor(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::{G1, G2};

    macro_rules! macro_test_cipher_to_byte_conversion {
        ($function_name:ident, $curve_type:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                for _i in 1..100 {
                    let c: Cipher<$curve_type> = Cipher::generate(&mut csprng);
                    let s = Cipher::from_bytes(&c.to_bytes());
                    assert!(s.is_ok());
                    assert_eq!(c, s.unwrap());
                }
            }
        };
    }

    macro_test_cipher_to_byte_conversion!(key_to_cipher_conversion_g1, G1);
    macro_test_cipher_to_byte_conversion!(key_to_cipher_conversion_g2, G2);
}
