// -*- mode: rust; -*-
//
// Authors:
// - bm@concordium.com

//! A known message

use rand::*;
#[cfg(feature = "serde")]
use serde::de::Error as SerdeError;
#[cfg(feature = "serde")]
use serde::de::Visitor;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde::{Deserializer, Serializer};

use crate::errors::{
    InternalError::{FieldDecodingError, MessageVecLengthError},
    *,
};
use curve_arithmetic::{curve_arithmetic::*, serialization::*};

use std::io::Cursor;

/// A message
#[derive(Debug)]
pub struct KnownMessage<C: Pairing>(pub(crate) Vec<C::ScalarField>);

impl<C: Pairing> PartialEq for KnownMessage<C> {
    fn eq(&self, other: &Self) -> bool { self.0 == other.0 }
}

impl<C: Pairing> Eq for KnownMessage<C> {}

impl<C: Pairing> KnownMessage<C> {
    // turn message vector into a byte aray
    #[inline]
    pub fn to_bytes(&self) -> Box<[u8]> {
        let vs = &self.0;
        let mut bytes: Vec<u8> = Vec::with_capacity(4 + vs.len() * C::SCALAR_LENGTH);
        write_pairing_scalars::<C>(vs, &mut bytes);
        bytes.into_boxed_slice()
    }

    #[inline]
    pub fn value_to_bytes(scalar: &C::ScalarField) -> Box<[u8]> { C::scalar_to_bytes(scalar) }

    /// Construct a message vec from a slice of bytes.
    ///
    /// A `Result` whose okay value is a message vec  or whose error value
    /// is an `SignatureError` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes(bytes: &mut Cursor<&[u8]>) -> Result<KnownMessage<C>, SignatureError> {
        let vs = read_pairing_scalars::<C>(bytes);
        match vs {
            Err(_) => Err(SignatureError(MessageVecLengthError)),
            Ok(vs) => Ok(KnownMessage(vs)),
        }
    }

    /// Construct a single `KnownMessage` from a slice of bytes.
    ///
    /// A `Result` whose okay value is a Message  or whose error value
    /// is an `SignatureError` wrapping the internal error that occurred.
    #[inline]
    pub fn message_from_bytes(bytes: &mut Cursor<&[u8]>) -> Result<C::ScalarField, SignatureError> {
        match C::bytes_to_scalar(bytes) {
            Ok(scalar) => Ok(scalar),
            Err(_) => Err(SignatureError(FieldDecodingError)),
        }
    }

    /// Generate a valid `Message` from a `csprng`.
    pub fn generate<T>(n: usize, csprng: &mut T) -> KnownMessage<C>
    where
        T: Rng, {
        let mut vs: Vec<C::ScalarField> = Vec::with_capacity(n);
        for _i in 0..n {
            vs.push(C::generate_scalar(csprng));
        }

        KnownMessage(vs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::Bls12;

    macro_rules! macro_test_message_to_byte_conversion {
        ($function_name:ident, $pairing_type:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                for i in 1..20 {
                    let val = KnownMessage::<$pairing_type>::generate(i, &mut csprng);
                    let res_val2 = KnownMessage::<$pairing_type>::from_bytes(&mut Cursor::new(
                        &val.to_bytes(),
                    ));
                    assert!(res_val2.is_ok());
                    let val2 = res_val2.unwrap();
                    assert_eq!(val2, val);
                }
            }
        };
    }
    macro_test_message_to_byte_conversion!(message_to_byte_conversion_bls12_381, Bls12);
}
