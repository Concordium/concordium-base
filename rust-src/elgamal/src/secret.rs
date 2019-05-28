// -*- mode: rust; -*-
//
// Authors:
// - bm@concordium.com

//! Elgamal secret key types 



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
use crate::cipher::*;
use crate::message::*;
use crate::errors::InternalError::{DecodingError};
use pairing::{CurveProjective, Field,PrimeField};
use pairing::bls12_381::{G1, FrRepr, Fr};
use rand::*;

/// elgamal secret  key.
#[derive(Debug,PartialEq, Eq, Clone)]
pub struct SecretKey(pub(crate) Fr);

/* THIS IS COMMENTED FOR NOW FOR COMPATIBILITY WITH BLS CURVE IMPLEMENTATION
 * ONCE WE HAVE TAKEN OVER THE SOURCE OF THE CURVE THIS SHOULD BE IMPLEMENTED
*/
/*
/// Overwrite secret key material with null bytes when it goes out of scope.
///
impl Drop for SecretKey {
    fn drop(&mut self) {
        (self.0).into_repr().0.clear();
    }
}
*/

impl SecretKey {
    /// Convert a secret key into bytes
    #[inline]
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
         let frpr = &self.0.into_repr();
         let xs = frpr.as_ref(); //array of 64 bit integers (limbs) least significant first
         assert!(xs.len()*8 <= SECRET_KEY_LENGTH);
         let mut bytes = [0u8; SECRET_KEY_LENGTH];
         let mut i = 0;
         for a in frpr.as_ref().iter().rev(){
             bytes[i..(i+8)].copy_from_slice(&a.to_be_bytes());
             i += 8;
         }
         bytes
     }

    /// Construct a `SecretKey` from a slice of bytes.
    ///
    /// A `Result` whose okay value is a secret key or whose error value
    /// is an `ElgamalError` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey, ElgamalError> {
          let mut frrepr: FrRepr=FrRepr ([0u64;4]);
          let mut tmp = [0u8; 8];
          let mut i = 0;
          for digit in frrepr.as_mut().iter_mut().rev(){
            tmp.copy_from_slice(&bytes[i..(i+8)]);
            *digit =u64::from_be_bytes(tmp);
            i += 8;
          }
          match Fr::from_repr(frrepr){
              Ok(fr) => Ok(SecretKey(fr)),
              Err(x) => Err (ElgamalError(DecodingError(x)))
          }
    }

    pub fn decrypt(&self, c: &Cipher)-> Message{
        let mut x = c.0; //k * g
        let mut y = c.1; // m + k * a * g
        x.mul_assign(self.0 ); //k * a * g
        y.sub_assign(&x); //m
        Message(y)
    }
    
    // TODO : Rename variable names more appropriately
    #[allow(clippy::many_single_char_names)]
    pub fn decrypt_exponent(&self, c: & Cipher) -> Fr{
        let Message(m) = self.decrypt(c);
        let mut a = Fr::zero();
        let mut i = G1::zero(); 
        let mut x = m==G1::zero();
        while !x {
            i.add_assign(&G1::one());
            a.add_assign(&Fr::one());
            x = m== i;
        }
        a
    }

    pub fn decrypt_exponent_vec(&self, v: &[Cipher]) -> Vec<Fr>{
        v.iter().map(|y| self.decrypt_exponent(y)).collect()
    }


    /// Generate a `SecretKey` from a `csprng`.
    ///
    pub fn generate<T>(csprng: &mut T)-> SecretKey
      where T:  Rng,{
          SecretKey(Fr::rand(csprng))
      }


}

#[cfg(feature = "serde")]
impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

#[cfg(feature = "serde")]
impl<'d> Deserialize<'d> for SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        struct SecretKeyVisitor;

        impl<'d> Visitor<'d> for SecretKeyVisitor {
            type Value = SecretKey;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                formatter.write_str("An Elgamal  secret key as 32 bytes")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<SecretKey, E>
            where
                E: SerdeError,
            {
                SecretKey::from_bytes(bytes).or(Err(SerdeError::invalid_length(bytes.len(), &self)))
            }
        }
        deserializer.deserialize_bytes(SecretKeyVisitor)
    }
}


#[test]
pub fn key_to_byte_conversion(){
    let mut csprng = thread_rng();
    for _i in 1..100{
        let sk = SecretKey::generate(&mut csprng);
        let r = sk.to_bytes();
        let res_sk2= SecretKey::from_bytes(&r);
        assert!(res_sk2.is_ok());
        let sk2= res_sk2.unwrap(); 
        assert_eq!(sk2, sk);
    }
}

