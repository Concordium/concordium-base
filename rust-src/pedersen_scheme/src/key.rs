// -*- mode: rust; -*-
//
// Authors:
// - bm@concordium.com

//! Commitment key type



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
use crate::errors::InternalError::{DecodingError, CommitmentKeyLengthError};
use pairing::bls12_381::{G1Compressed,G1Affine, FrRepr, Fr};
use pairing::{EncodedPoint,CurveProjective, CurveAffine,Field,PrimeField};
use rand::*;

/// A PRF  key.
#[derive( Debug,PartialEq, Eq)]
pub struct CommitmentKey(pub(crate) G1Affine, pub(crate) G1Affine);

/*
impl Drop for SecretKey {
    fn drop(&mut self) {
        (self.0).into_repr().0.clear();
    }
}
*/


impl CommitmentKey {
    //turn commitment key into a byte aray
    #[inline]
    pub fn to_bytes(&self) -> [u8; COMMITMENT_KEY_LENGTH] {
         let (g,h) = (self.0.into_compressed(),self.1.into_compressed());
         let g_bytes = g.as_ref(); 
         let h_bytes = h.as_ref();
         let mut bytes = [0u8; COMMITMENT_KEY_LENGTH];
         bytes.copy_from_slice(&g_bytes);
         bytes[COMMITMENT_KEY_LENGTH/2 ..].copy_from_slice(&h_bytes);
         bytes
     }

    /// Construct a commitmentkey from a slice of bytes.
    ///
    /// A `Result` whose okay value is an commitment key or whose error value
    /// is an `CommitmentError` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<CommitmentKey, CommitmentError> {
          if bytes.len() != COMMITMENT_KEY_LENGTH { return Err(CommitmentError(CommitmentKeyLengthError))}
          let mut g = G1Compressed::empty();
          let mut h = G1Compressed::empty();
          g.as_mut().copy_from_slice(&bytes[..COMMITMENT_KEY_LENGTH/2]);
          h.as_mut().copy_from_slice(&bytes[COMMITMENT_KEY_LENGTH/2..]);
          match g.into_affine() {
              Err(x) => Err(CommitmentError(DecodingError(x))),
              Ok(g_affine) => match h.into_affine(){
                  Err(y) =>Err(CommitmentError(DecodingError(y))),
                  Ok(h_affine) => Ok(CommitmentKey (g_affine, h_affine))
              }
          }
    }

    pub fn commit<T>(&self, s: Fr, csprng: &mut T)-> G1Affine
        where T: Rng,{
        let g = self.0;
        let h = self.1;

        g.mul(s);
        let r = Fr::rand(csprng);
        h.mul(r);
        let mut res = g.into_projective();
        res.add_assign_mixed(&h);
        res.into_affine()

     }


    /// Generate a `CommitmentKey` from a `csprng`.
    ///
    pub fn generate<T>(csprng: &mut T)-> CommitmentKey
      where T:  Rng,{
          let g_fr = Fr::rand(csprng);
          let h_fr = Fr::rand(csprng); 
          let g = G1Affine::one().mul(g_fr);
          let h = G1Affine::one().mul(h_fr);
          CommitmentKey(g.into_affine(),h.into_affine())
      }
}


#[cfg(feature = "serde")]
impl Serialize for CommitmentKey{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_bytes())
    }
}

#[cfg(feature = "serde")]
impl<'d> Deserialize<'d> for CommitmentKey{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        struct CommitmentKeyVisitor;

        impl<'d> Visitor<'d> for CommitmentKeyVisitor {
            type Value = CommitmentKey;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                formatter.write_str("An BLS12 Commitment Key as 96  bytes.")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<CommitmentKey, E>
            where
                E: SerdeError,
            {
                CommitmentKey::from_bytes(bytes).or(Err(SerdeError::invalid_length(bytes.len(), &self)))
            }
        }
        deserializer.deserialize_bytes(CommitmentKeyVisitor)
    }
}


#[test]
pub fn key_to_byte_conversion(){
    let mut csprng = thread_rng();
    for i in 1..100{
        let sk = CommitmentKey::generate(&mut csprng);
        let r = sk.to_bytes();
        let res_sk2= CommitmentKey::from_bytes(&r);
        assert!(res_sk2.is_ok());
        let sk2= res_sk2.unwrap(); 
        assert_eq!(sk2, sk);
    }
}

