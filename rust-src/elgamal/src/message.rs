use pairing::{EncodedPoint, bls12_381::G1, bls12_381::G1Compressed, CurveProjective, CurveAffine};
use rand::*;

use crate::errors::{*, InternalError::*};
use crate::constants::*;

#[derive(Debug,PartialEq, Eq)]
pub struct Message (pub(crate) G1);

impl Message{
    pub fn generate<T>(csprng: &mut T)-> Message
        where T:  Rng,{
            Message(G1::rand(csprng))
        }
    /// Convert this message key to a byte array.
    
    #[inline]
    pub fn to_bytes(&self) -> [u8; MESSAGE_LENGTH] {
        let mut ar = [0u8; MESSAGE_LENGTH];
        ar.copy_from_slice(self.0.into_affine().into_compressed().as_ref());
        ar
    }


    /// Construct a message from a slice of bytes.
    ///
    /// A `Result` whose okay value is a message key or whose error value
    /// is an `ElgamalError` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Message, ElgamalError> {
          if bytes.len() != MESSAGE_LENGTH { return Err(ElgamalError(MessageLengthError))}
          let mut g = G1Compressed::empty();
          g.as_mut().copy_from_slice(&bytes);
          match g.into_affine() {
              Err(x) => Err(ElgamalError(GDecodingError(x))),
              Ok(g_affine) => Ok(Message (G1::from(g_affine)))
          }
    }
}

