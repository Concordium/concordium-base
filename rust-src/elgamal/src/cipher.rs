use pairing::{EncodedPoint, bls12_381::G1, bls12_381::G1Compressed, CurveProjective, CurveAffine};
use crate::errors::{*, InternalError::*};
use crate::constants::*;

#[derive(Debug,PartialEq, Eq)]
pub struct Cipher (pub(crate) G1, pub(crate) G1);

impl Cipher{
    /// Convert this cipher key to a byte array.

    #[inline]
    pub fn to_bytes(&self) -> [u8; CIPHER_LENGTH] {
        let mut ar = [0u8; CIPHER_LENGTH];
        ar[..CIPHER_LENGTH/2].copy_from_slice(self.0.into_affine().into_compressed().as_ref());
        ar[CIPHER_LENGTH/2..].copy_from_slice(self.1.into_affine().into_compressed().as_ref());
        ar
    }


    /// Construct a cipher from a slice of bytes.
    ///
    /// A `Result` whose okay value is a cipher key or whose error value
    /// is an `ElgamalError` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Cipher, ElgamalError> {
          if bytes.len() != CIPHER_LENGTH { return Err(ElgamalError(CipherLengthError))}
          let mut g = G1Compressed::empty();
          let mut h = G1Compressed::empty();
          g.as_mut().copy_from_slice(&bytes[0..CIPHER_LENGTH/2]);
          h.as_mut().copy_from_slice(&bytes[CIPHER_LENGTH/2..CIPHER_LENGTH]);

          match g.into_affine() {
              Err(x) => Err(ElgamalError(GDecodingError(x))),
              Ok(g_affine) => match h.into_affine(){
                  Err(x) => Err(ElgamalError(GDecodingError(x))),
                  Ok(h_affine) => Ok(Cipher((G1::from(g_affine)), G1::from(h_affine)))
              }
          }
    }
}

