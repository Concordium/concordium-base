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
    InternalError::{CurveDecodingError, SignatureLengthError},
    *,
};
use curve_arithmetic::curve_arithmetic::*;
use rand::*;

/// A signature
#[derive(Debug)]
pub struct Signature<C: Pairing>(pub(crate) C::G_1, pub(crate) C::G_1);

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

    pub fn from_bytes(bytes: &[u8]) -> Result<Signature<C>, SignatureError> {
        if bytes.len() != C::G_1::GROUP_ELEMENT_LENGTH * 2 {
            return Err(SignatureError(SignatureLengthError));
        }
        match C::G_1::bytes_to_curve(&bytes[..C::G_1::GROUP_ELEMENT_LENGTH]) {
            Err(_) => Err(SignatureError(CurveDecodingError)),
            Ok(g) => match C::G_1::bytes_to_curve(&bytes[C::G_1::GROUP_ELEMENT_LENGTH..]) {
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
                    let y = Signature::<$pairing_type>::from_bytes(&*x.to_bytes());
                    assert!(y.is_ok());
                    assert_eq!(x, y.unwrap());
                }
            }
        };
    }

    macro_test_signature_to_byte_conversion!(signature_to_byte_conversion_bls12_381, Bls12);
}
