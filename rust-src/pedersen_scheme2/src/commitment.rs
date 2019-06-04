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

use crate::{
    constants::*,
    errors::{
        InternalError::{CurveDecodingError},
        *,
    },
};

use pairing::bls12_381::{G1Affine, G2Affine};


use curve_arithmetic::curve_arithmetic::*;
use curve_arithmetic::bls12_381_instance::*;
use rand::*;

/// A Commitment is a group element .
#[derive(Debug, PartialEq, Eq)]
pub struct Commitment<C: Curve>(pub(crate) C);

impl <C:Curve> Commitment<C> {
    // turn commitment key into a byte aray
    #[inline]
    pub fn to_bytes(&self) -> Box<[u8]> {
        self.0.curve_to_bytes()
    }

    /// Construct a commitment from a slice of bytes.
    ///
    /// A `Result` whose okay value is an commitment key or whose error value
    /// is an `CommitmentError` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Commitment<C>, CommitmentError> {
        match C::bytes_to_curve(bytes){
            Ok(point) => Ok(Commitment(point)),
            Err(x) => Err(CommitmentError(CurveDecodingError))
        }
    }

    pub fn generate<T: Rng>(csprng: &mut T) -> Commitment<C> { Commitment(C::generate(csprng)) }
}


#[test]
pub fn byte_conversion() {
    let mut csprng = thread_rng();
    for _i in 0..20 {
        let x = Commitment::<G2Affine>::generate(&mut csprng);
        let y = Commitment::<G2Affine>::from_bytes(&*x.to_bytes());
        assert!(y.is_ok());
        assert_eq!(x, y.unwrap());
    }
}
