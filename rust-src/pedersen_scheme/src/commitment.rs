// -*- mode: rust; -*-
//
// Authors:
// - bm@concordium.com

//! Commitment type

#[cfg(feature = "serde")]
use serde::de::Error as SerdeError;
#[cfg(feature = "serde")]
use serde::de::Visitor;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde::{Deserializer, Serializer};

use crate::errors::{InternalError::CurveDecodingError, *};

use curve_arithmetic::curve_arithmetic::*;

use std::io::Cursor;

use std::ops::Deref;

/// A Commitment is a group element .
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Commitment<C: Curve>(pub C);

impl<C: Curve> Commitment<C> {
    // turn commitment key into a byte aray
    #[inline]
    pub fn to_bytes(&self) -> Box<[u8]> { self.0.curve_to_bytes() }

    /// Construct a commitment from a slice of bytes.
    ///
    /// A `Result` whose okay value is an commitment key or whose error value
    /// is an `CommitmentError` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes(bytes: &mut Cursor<&[u8]>) -> Result<Commitment<C>, CommitmentError> {
        match C::bytes_to_curve(bytes) {
            Ok(point) => Ok(Commitment(point)),
            Err(_) => Err(CommitmentError(CurveDecodingError)),
        }
    }
}

/// This trait allows automatic conversion of &Commitment<C> to &C. In
/// particular this means that we can simply write `c.mul_by_scalar`, for
/// example.
impl<C: Curve> Deref for Commitment<C> {
    type Target = C;

    fn deref(&self) -> &C { &self.0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::{G1Affine, G2Affine};
    use rand::*;
    impl<C: Curve> Commitment<C> {
        pub fn generate<T: Rng>(csprng: &mut T) -> Commitment<C> { Commitment(C::generate(csprng)) }
    }

    macro_rules! macro_test_commitment_to_byte_conversion {
        ($function_name:ident, $curve_type:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                for _i in 0..20 {
                    let x = Commitment::<$curve_type>::generate(&mut csprng);
                    let y = Commitment::<$curve_type>::from_bytes(&mut Cursor::new(&x.to_bytes()));
                    assert!(y.is_ok());
                    assert_eq!(x, y.unwrap());
                }
            }
        };
    }
    macro_test_commitment_to_byte_conversion!(
        commitment_to_byte_conversion_bls12_381_g1_affine,
        G1Affine
    );

    macro_test_commitment_to_byte_conversion!(
        commitment_to_byte_conversion_bls12_381_g2_affine,
        G2Affine
    );
}
