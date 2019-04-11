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

use crate::constants::*;
use crate::errors::*;
use crate::errors::InternalError::{DecodingError, CommitmentLengthError};
use pairing::bls12_381::{G1Compressed,G1Affine, FrRepr, Fr};
use pairing::{EncodedPoint,CurveProjective, CurveAffine,Field,PrimeField};

/// A Commitment is a group element .
#[derive( Debug,PartialEq, Eq)]
pub struct Commitment(pub(crate) G1Affine);


impl Commitment {
    //turn commitment key into a byte aray
    #[inline]
    pub fn to_bytes(&self) -> [u8; COMMITMENT_LENGTH] {
         let g = self.0.into_compressed();
         let g_bytes  = g.as_ref(); 
         let mut bytes = [0u8; COMMITMENT_LENGTH];
         bytes.copy_from_slice(&g_bytes);
         bytes
     }

    /// Construct a commitment from a slice of bytes.
    ///
    /// A `Result` whose okay value is an commitment key or whose error value
    /// is an `CommitmentError` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Commitment, CommitmentError> {
          if bytes.len() != COMMITMENT_LENGTH { return Err(CommitmentError(CommitmentLengthError))}
          let mut g = G1Compressed::empty();
          g.as_mut().copy_from_slice(&bytes);
          match g.into_affine() {
              Err(x) => Err(CommitmentError(DecodingError(x))),
              Ok(g_affine) => Ok(Commitment (g_affine))
          }
    }

}


#[cfg(feature = "serde")]
impl Serialize for Commitment{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_bytes())
    }
}

#[cfg(feature = "serde")]
impl<'d> Deserialize<'d> for Commitment{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        struct CommitmentVisitor;

        impl<'d> Visitor<'d> for CommitmentVisitor {
            type Value = Commitment;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                formatter.write_str("An BLS12 Commitment  as 48  bytes.")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Commitment, E>
            where
                E: SerdeError,
            {
                Commitment::from_bytes(bytes).or(Err(SerdeError::invalid_length(bytes.len(), &self)))
            }
        }
        deserializer.deserialize_bytes(CommitmentVisitor)
    }
}



