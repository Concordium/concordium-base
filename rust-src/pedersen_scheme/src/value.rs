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

use crate::constants::*;
use crate::errors::*;
use crate::errors::InternalError::{FDecodingError, ValueVecLengthError};
use pairing::bls12_381::{FrRepr, Fr};
use pairing::{PrimeField};
use rand::*;

/// A  value
#[derive(Debug,PartialEq, Eq)]
pub struct Value(pub(crate) Vec<Fr>);

/*
/// Overwrite value  material with null bytes when it goes out of scope.
impl Drop for Value {
    fn drop(&mut self) {
        (self.0).into_repr().0.clear();
    }
}
*/


impl Value{
      //turn value vector into a byte aray
      #[inline]
      pub fn to_bytes(&self) -> Box<[u8]> {
           let vs = &self.0;
           let mut bytes: Vec<u8> = Vec::new();
           for v in vs.iter(){
               bytes.extend_from_slice(&Self::value_to_bytes(&v));
           }
           bytes.into_boxed_slice()
       }

      #[inline]
      pub fn value_to_bytes(fe: &Fr) -> [u8; FIELD_ELEMENT_LENGTH] {
           let frpr = &fe.into_repr();
           let xs = frpr.as_ref(); //array of 64 bit integers (limbs) least significant first
           assert!(xs.len()*8 <= FIELD_ELEMENT_LENGTH);
           let mut bytes = [0u8; FIELD_ELEMENT_LENGTH];
           let mut i = 0;
           for a in frpr.as_ref().iter().rev(){
               bytes[i..(i+8)].copy_from_slice(&a.to_be_bytes());
               i += 8;
           }
           bytes
       }


      /// Construct a value vec from a slice of bytes.
      ///
      /// A `Result` whose okay value is a Value vec  or whose error value
      /// is an `CommitmentError` wrapping the internal error that occurred.
      #[inline]
      pub fn from_bytes(bytes: &[u8]) -> Result<Value, CommitmentError> {
            let l = bytes.len();
            if l==0 ||  l % FIELD_ELEMENT_LENGTH !=0{
                return Err(CommitmentError(ValueVecLengthError));
            }
            let vlen = l/FIELD_ELEMENT_LENGTH;
            let mut vs:Vec<Fr> = Vec::new();
            for i in 0..vlen{
                let j = i*FIELD_ELEMENT_LENGTH;
                let k = j + FIELD_ELEMENT_LENGTH;
                match Self::value_from_bytes(&bytes[j..k]){
                    Err(x) => return Err(x),
                    Ok(fr) => vs.push(fr)
                }
            }
            Ok(Value(vs))
      }

    /// Construct a single `Value` from a slice of bytes.
    ///
    /// A `Result` whose okay value is an Value  or whose error value
    /// is an `CommitmentError` wrapping the internal error that occurred.
    #[inline]
    pub fn value_from_bytes(bytes: &[u8]) -> Result<Fr,CommitmentError> {
          let mut frrepr: FrRepr=FrRepr ([0u64;4]);
          let mut tmp = [0u8; 8];
          let mut i = 0;
          for digit in frrepr.as_mut().iter_mut().rev(){
            tmp.copy_from_slice(&bytes[i..(i+8)]);
            *digit =u64::from_be_bytes(tmp);
            i += 8;
          }
          match Fr::from_repr(frrepr){
              Ok(fr) => Ok(fr),
              Err(x) => Err (CommitmentError(FDecodingError(x)))
          }
    }


    /// Generate a sing `Value` from a `csprng`.
    ///
    pub fn generate<T>(n: usize, csprng: &mut T)-> Value 
      where T:  Rng,{
          let mut vs : Vec<Fr> = Vec::new();
          for _i in 0..n {
              vs.push(Fr::rand(csprng));
          }

          Value(vs)
     }
      

}

#[cfg(feature = "serde")]
impl Serialize for Value{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

#[cfg(feature = "serde")]
impl<'d> Deserialize<'d> for Value{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        struct ValueVisitor;

        impl<'d> Visitor<'d> for ValueVisitor {
            type Value = Value;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                formatter.write_str("An value is 32 bytes ")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Value, E>
            where
                E: SerdeError,
            {
                Value::from_bytes(bytes).or(Err(SerdeError::invalid_length(bytes.len(), &self)))
            }
        }
        deserializer.deserialize_bytes(ValueVisitor)
    }
}

#[test]
pub fn value_to_byte_conversion(){
    let mut csprng = thread_rng();
    for i in 1..20{
        let val = Value::generate(i, &mut csprng);
        let res_val2= Value::from_bytes(&*val.to_bytes());
        assert!(res_val2.is_ok());
        let val2= res_val2.unwrap(); 
        assert_eq!(val2, val);
    }
}

