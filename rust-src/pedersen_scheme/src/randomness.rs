// -*- mode: rust; -*-
//
// Authors:
// - bm@concordium.com

//! Randomness 
//! The randomness used in commitment

#[cfg(feature = "serde")]
use serde::de::Error as SerdeError;
#[cfg(feature = "serde")]
use serde::de::Visitor;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde::{Deserializer, Serializer};

//use crate::errors::{InternalError::FieldDecodingError};
use curve_arithmetic::{curve_arithmetic::*, serialization::*};

use failure::Error;
use rand::*;
use std::io::Cursor;

/// A  value
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Randomness<C: Curve>(pub C::Scalar);

impl<C: Curve> Randomness<C> {
    // turn value vector into a byte aray
    #[inline]
    pub fn to_bytes(&self) -> Box<[u8]> {
        let v = &self.0;
        let mut bytes: Vec<u8> = Vec::with_capacity(C::SCALAR_LENGTH);
        write_curve_scalar::<C>(v, &mut bytes);
        bytes.into_boxed_slice()
    }

    /// Construct a value  from a slice of bytes.
    ///
    /// A `Result` whose okay value is a Value vec  or whose error value
    /// is an `CommitmentError` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Result<Randomness<C>, Error> {
        let vs = read_curve_scalar::<C>(cur)?;
        Ok(Randomness(vs))
    }

    /// Generate a sing `Value` from a `csprng`.
    pub fn generate<T>(csprng: &mut T) -> Randomness<C>
    where
        T: Rng, {

        Randomness(C::generate_scalar(csprng))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::{G1Affine, G2Affine};
    macro_rules! macro_test_randomness_to_byte_conversion {
        ($function_name:ident, $curve_type:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                for _i in 1..20 {
                    let val = Randomness::<$curve_type>::generate(&mut csprng);
                    let res_val2 =
                        Randomness::<$curve_type>::from_bytes(&mut Cursor::new(&val.to_bytes()));
                    assert!(res_val2.is_ok());
                    let val2 = res_val2.unwrap();
                    assert_eq!(val2, val);
                }
            }
        };
    }

    macro_test_randomness_to_byte_conversion!(randomness_to_byte_conversion_bls12_381_g1_affine, G1Affine);

    macro_test_randomness_to_byte_conversion!(randomness_to_byte_conversion_bls12_381_g2_affine, G2Affine);
}
