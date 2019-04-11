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

use crate::commitment::*;
use crate::constants::*;
use crate::errors::*;
use crate::errors::InternalError::{DecodingError, CommitmentKeyLengthError};
use pairing::bls12_381::{G1Compressed,G1Affine, G1, FrRepr, Fr};
use pairing::{EncodedPoint,CurveProjective, CurveAffine,Field,PrimeField};
use rand::*;

/// A commitment  key.
#[derive( Debug,PartialEq, Eq)]
pub struct CommitmentKey(pub(crate) Vec<G1Affine>, pub(crate) G1Affine);

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
    pub fn to_bytes(&self) -> Box<[u8]> {
         let gs = &self.0;
         let h = &self.1;
         let mut bytes: Vec<u8> = Vec::new();
         for g in gs.iter(){
             bytes.extend_from_slice(g.into_compressed().as_ref().clone());
         }
         bytes.extend_from_slice(h.into_compressed().as_ref().clone());
         bytes.into_boxed_slice()
     }
    /// Construct a commitmentkey from a slice of bytes.
    ///
    /// A `Result` whose okay value is an commitment key or whose error value
    /// is an `CommitmentError` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<CommitmentKey, CommitmentError> {
          let l = bytes.len();
          if (l==0 || l < GROUP_ELEMENT_LENGTH * 2 || l % GROUP_ELEMENT_LENGTH !=0){
              return Err(CommitmentError(CommitmentKeyLengthError));
          }
          let glen = (l/GROUP_ELEMENT_LENGTH) - 1;
          let mut gs:Vec<G1Affine> = Vec::new();
          for i in 0..glen{
              let j = i*GROUP_ELEMENT_LENGTH;
              let k = j + GROUP_ELEMENT_LENGTH;
              let mut g = G1Compressed::empty();
              g.as_mut().copy_from_slice(&bytes[j..k]);
              match g.into_affine(){
                  Err(x) => return (Err(CommitmentError(DecodingError(x)))),
                  Ok(g_affine) => gs.push(g_affine)
              }
          }
          let mut h = G1Compressed::empty();
          h.as_mut().copy_from_slice(&bytes[(l-GROUP_ELEMENT_LENGTH)..]);

          match h.into_affine() {
              Err(x) => Err(CommitmentError(DecodingError(x))),
              Ok(h_affine) => Ok(CommitmentKey (gs, h_affine))
         }
    }

    pub fn commit<T>(&self, ss: &Vec<Fr>, csprng: &mut T)-> (Commitment , Fr)
        where T: Rng,{
        let r = Fr::rand(csprng);
        (self.hide(ss, r),r)

     }


    fn hide(&self, ss:&Vec<Fr>, r:Fr) -> Commitment{
        assert_eq!(self.0.len(),ss.len());
        let mut h = self.1.into_projective();
        h.mul_assign(r);
        let g = &self.0;
        let mut res = h;
        let mut gs = G1::zero();
        for i in 0..self.0.len(){
            gs = g[i].into_projective();
            gs.mul_assign(ss[i]);
            res.add_assign(&gs);
        }
        Commitment(res.into_affine())
    }
    
    pub fn open(&self, ss:&Vec<Fr>, r: Fr, c: Commitment)-> bool{
        self.hide(ss,r) == c

    }

    /// Generate a `CommitmentKey` for `n` values from a `csprng`.
    ///
    pub fn generate<T>(n: usize, csprng: &mut T)-> CommitmentKey
      where T:  Rng,{
          let mut gs: Vec<G1Affine> = Vec::new();
          for i in 0..n {
              let g_fr = Fr::rand(csprng);
              let g = G1Affine::one().mul(g_fr);
              gs.push(g.into_affine());
          }
          let h_fr = Fr::rand(csprng); 
          let h = G1Affine::one().mul(h_fr);
          CommitmentKey(gs,h.into_affine())
      }
}


#[cfg(feature = "serde")]
impl Serialize for CommitmentKey{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&*self.to_bytes())
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
    for i in 1..2{
        let sk = CommitmentKey::generate(i,  &mut csprng);
        let res_sk2= CommitmentKey::from_bytes(&*sk.to_bytes());
        assert!(res_sk2.is_ok());
        let sk2= res_sk2.unwrap(); 
        assert_eq!(sk2, sk);
    }
}

#[test]
pub fn commit_open(){
    let mut csprng = thread_rng();
    for i in 1..20{
        let sk = CommitmentKey::generate(i,  &mut csprng);
        let mut ss= Vec::new();
        for j in 0..i{
            let s = Fr::rand(&mut csprng);
            ss.push(s);
        }
        let (c, r)= sk.commit(&ss, &mut csprng);
        assert!(sk.open(&ss, r, c))
    }
}

