// -*- mode: rust; -*-

#[cfg(feature = "serde")]
use serde::de::Error as SerdeError;
#[cfg(feature = "serde")]
use serde::de::Visitor;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde::{Deserializer, Serializer};

use crate::{
    errors::{InternalError::CurveDecodingError, *},
    unknown_message::SigRetrievalRandomness,
};
use curve_arithmetic::curve_arithmetic::*;
use failure::Error;
use rand::*;

use std::{io::Cursor, ops::Deref};

/// Randomness used to blind a signature.
#[derive(Debug, Eq)]
pub struct BlindingRandomness<P: Pairing>(pub P::ScalarField, pub P::ScalarField);

/// Manual implementation to relax the requirements on `P`. The derived
/// instance would have required P to have `PartialEq`.
impl<P: Pairing> PartialEq for BlindingRandomness<P> {
    fn eq(&self, other: &Self) -> bool { self.0 == other.0 && self.1 == other.1 }
}

#[repr(transparent)]
#[derive(Debug, Eq, PartialEq)]
/// Type wrapper around a signature, indicating that it is a blinded variant.
pub struct BlindedSignature<P: Pairing> {
    pub sig: Signature<P>,
}

/// This trait allows automatic conversion of &BlindedSignature<P> to
/// &Signature<P>.
impl<P: Pairing> Deref for BlindedSignature<P> {
    type Target = Signature<P>;

    fn deref(&self) -> &Signature<P> { &self.sig }
}

impl<C: Pairing> BlindedSignature<C> {
    pub fn to_bytes(&self) -> Box<[u8]> { self.sig.to_bytes() }

    pub fn from_bytes(bytes: &mut Cursor<&[u8]>) -> Result<Self, Error> {
        let sig = Signature::from_bytes(bytes)?;
        Ok(BlindedSignature { sig })
    }
}

/// A signature
#[derive(Debug, Clone, Copy)]
pub struct Signature<C: Pairing>(pub C::G_1, pub C::G_1);

impl<C: Pairing> PartialEq for Signature<C> {
    fn eq(&self, other: &Self) -> bool { self.0 == other.0 && self.1 == other.1 }
}

impl<C: Pairing> Eq for Signature<C> {}

impl<C: Pairing> Signature<C> {
    pub fn to_bytes(&self) -> Box<[u8]> {
        let mut bytes: Vec<u8> = Vec::with_capacity(2 * C::G_1::GROUP_ELEMENT_LENGTH);
        bytes.extend_from_slice(&*self.0.curve_to_bytes());
        bytes.extend_from_slice(&*self.1.curve_to_bytes());
        bytes.into_boxed_slice()
    }

    pub fn from_bytes(bytes: &mut Cursor<&[u8]>) -> Result<Signature<C>, SignatureError> {
        match C::G_1::bytes_to_curve(bytes) {
            Err(_) => Err(SignatureError(CurveDecodingError)),
            Ok(g) => match C::G_1::bytes_to_curve(bytes) {
                Err(_) => Err(SignatureError(CurveDecodingError)),
                Ok(h) => Ok(Signature(g, h)),
            },
        }
    }

    /// Generate a valid (in the sense of representation) but otherwise
    /// arbitrary signature. Exposed because it is useful for testing protocols
    /// on top of the signature scheme.
    pub fn arbitrary<T: Rng>(csprng: &mut T) -> Signature<C> {
        // not a proper signature to be used for testing serialization
        Signature(C::G_1::generate(csprng), C::G_1::generate(csprng))
    }

    /// Retrieves a signature on the original message from the signature on the
    /// commitment, and the randomness used in the commitment.
    pub fn retrieve(&self, r: &SigRetrievalRandomness<C>) -> Self {
        let h = self.0;
        let hr = h.mul_by_scalar(&r);
        let b = self.1;
        Signature(h, b.minus_point(&hr))
    }

    /// Blind a signature.
    pub fn blind<R: Rng>(&self, csprng: &mut R) -> (BlindedSignature<C>, BlindingRandomness<C>) {
        let r = C::generate_non_zero_scalar(csprng);
        let t = C::generate_non_zero_scalar(csprng);
        let Signature(a, b) = self;
        let a_hid = a.mul_by_scalar(&r);
        let b_hid = b.plus_point(&a.mul_by_scalar(&t)).mul_by_scalar(&r);
        let sig = Signature(a_hid, b_hid);
        let randomness = BlindingRandomness(r, t);
        (BlindedSignature { sig }, randomness)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::Bls12;

    macro_rules! macro_test_signature_to_byte_conversion {
        ($function_name:ident, $pairing_type:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                for _i in 0..20 {
                    let x = Signature::<$pairing_type>::arbitrary(&mut csprng);
                    let y = Signature::<$pairing_type>::from_bytes(&mut Cursor::new(&x.to_bytes()));
                    assert!(y.is_ok());
                    assert_eq!(x, y.unwrap());
                }
            }
        };
    }

    macro_test_signature_to_byte_conversion!(signature_to_byte_conversion_bls12_381, Bls12);
}
