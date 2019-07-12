// -*- mode: rust; -*-
//
// Authors:
// - bm@concordium.com

//! A value
//! The object being commitmed to

#[cfg(feature = "serde")]
use serde::de::Error as SerdeError;
#[cfg(feature = "serde")]
use serde::de::Visitor;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde::{Deserializer, Serializer};

use crate::errors::{InternalError::FieldDecodingError, *};
use curve_arithmetic::{curve_arithmetic::*, serialization::*};

use failure::Error;
use rand::*;
use std::io::Cursor;

/// A  value
#[derive(Debug, PartialEq, Eq)]
pub struct Value<C: Curve>(pub Vec<C::Scalar>);

// Overwrite value  material with null bytes when it goes out of scope.
// impl Drop for Value {
// fn drop(&mut self) {
// (self.0).into_repr().0.clear();
// }
// }

impl<C: Curve> Value<C> {
    // turn value vector into a byte aray
    #[inline]
    pub fn to_bytes(&self) -> Box<[u8]> {
        let vs = &self.0;
        let mut bytes: Vec<u8> = Vec::with_capacity(vs.len() * C::SCALAR_LENGTH);
        write_curve_scalars::<C>(vs, &mut bytes);
        bytes.into_boxed_slice()
    }

    #[inline]
    pub fn value_to_bytes(scalar: &C::Scalar) -> Box<[u8]> { C::scalar_to_bytes(scalar) }

    /// Construct a value vec from a slice of bytes.
    ///
    /// A `Result` whose okay value is a Value vec  or whose error value
    /// is an `CommitmentError` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Result<Value<C>, Error> {
        let vs = read_curve_scalars::<C>(cur)?;
        Ok(Value(vs))
    }

    /// Construct a single `Value` from a slice of bytes.
    ///
    /// A `Result` whose okay value is an Value  or whose error value
    /// is an `CommitmentError` wrapping the internal error that occurred.
    #[inline]
    pub fn value_from_bytes(bytes: &mut Cursor<&[u8]>) -> Result<C::Scalar, CommitmentError> {
        match C::bytes_to_scalar(bytes) {
            Ok(scalar) => Ok(scalar),
            Err(_) => Err(CommitmentError(FieldDecodingError)),
        }
    }

    /// Generate a sing `Value` from a `csprng`.
    pub fn generate<T>(n: usize, csprng: &mut T) -> Value<C>
    where
        T: Rng, {
        let mut vs: Vec<C::Scalar> = Vec::with_capacity(n);
        for _i in 0..n {
            vs.push(C::generate_scalar(csprng));
        }

        Value(vs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::{G1Affine, G2Affine};
    macro_rules! macro_test_value_to_byte_conversion {
        ($function_name:ident, $curve_type:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                for i in 1..20 {
                    let val = Value::<$curve_type>::generate(i, &mut csprng);
                    let res_val2 =
                        Value::<$curve_type>::from_bytes(&mut Cursor::new(&val.to_bytes()));
                    assert!(res_val2.is_ok());
                    let val2 = res_val2.unwrap();
                    assert_eq!(val2, val);
                }
            }
        };
    }

    macro_test_value_to_byte_conversion!(value_to_byte_conversion_bls12_381_g1_affine, G1Affine);

    macro_test_value_to_byte_conversion!(value_to_byte_conversion_bls12_381_g2_affine, G2Affine);
}
