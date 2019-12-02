// -*- mode: rust; -*-

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

// use crate::errors::{InternalError::FieldDecodingError};
use curve_arithmetic::{curve_arithmetic::*, serialization::*};
use ff::Field;

use failure::Error;
use rand::*;
use std::{io::Cursor, ops::Deref};

/// Randomness used in the commitment.
/// Secret by default.
#[repr(transparent)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Randomness<C: Curve> {
    pub randomness: C::Scalar,
}

/// This trait allows automatic conversion of &Randomness<C> to &C::Scalar.
impl<C: Curve> Deref for Randomness<C> {
    type Target = C::Scalar;

    fn deref(&self) -> &C::Scalar { &self.randomness }
}

impl<C: Curve> Randomness<C> {
    // turn value vector into a byte aray
    #[inline]
    pub fn to_bytes(&self) -> Box<[u8]> {
        let v = &self.randomness;
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
        let randomness = read_curve_scalar::<C>(cur)?;
        Ok(Randomness { randomness })
    }

    /// Zero randomness.
    #[inline]
    pub fn zero() -> Self {
        Randomness {
            randomness: C::Scalar::zero(),
        }
    }

    /// Generate a scalar as randomness.
    pub fn generate<T>(csprng: &mut T) -> Randomness<C>
    where
        T: Rng, {
        Randomness {
            randomness: C::generate_scalar(csprng),
        }
    }

    /// Generate a non-zero scalar as randomness.
    pub fn generate_non_zero<T>(csprng: &mut T) -> Randomness<C>
    where
        T: Rng, {
        Randomness {
            randomness: C::generate_non_zero_scalar(csprng),
        }
    }

    /// View a scalar as randomness.
    #[inline]
    pub fn view_scalar(scalar: &C::Scalar) -> &Self {
        unsafe { &*(scalar as *const C::Scalar as *const Randomness<C>) }
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

    macro_test_randomness_to_byte_conversion!(
        randomness_to_byte_conversion_bls12_381_g1_affine,
        G1Affine
    );

    macro_test_randomness_to_byte_conversion!(
        randomness_to_byte_conversion_bls12_381_g2_affine,
        G2Affine
    );
}
