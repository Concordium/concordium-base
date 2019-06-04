// Authors:
// - bm@concordium.com
//

use crate::curve_arithmetic::*;
use pairing::{bls12_381::{G2, G2Affine, G2Compressed, 
                          G1, G1Affine, G1Compressed,
                          FrRepr, Fr, Fq}, 
              PrimeField, CurveAffine, CurveProjective, EncodedPoint};
use rand::*;


impl Curve for G1Affine
{
    type Base = Fq;
    type Compressed = G1Compressed; 
    type Scalar = Fr;

    const SCALAR_LENGTH: usize = 32;
    const GROUP_ELEMENT_LENGTH : usize = 48;

    fn zero_point() -> Self { G1Affine::zero() }

    fn one_point() -> Self { G1Affine::one() }

    fn inverse_point(&self) -> Self {
        let mut x = self.into_projective().clone();
        x.negate();
        x.into_affine()
    }

    fn is_zero_point(&self) -> bool { self.is_zero() }

    fn double_point(&self) -> Self {
        let mut x = self.into_projective().clone();
        &x.double();
        x.into_affine()
    }

    fn plus_point(&self, other: &Self) -> Self {
        let mut x = self.into_projective().clone();
        &x.add_assign_mixed(other);
        x.into_affine()
    }

    fn minus_point(&self, other: &Self) -> Self {
        let mut x = self.into_projective().clone();
        &x.sub_assign(&other.into_projective());
        x.into_affine()
    }

    fn mul_by_scalar(&self, scalar: &Self::Scalar) -> Self { 
        let s = scalar.clone(); 
        self.mul(s).into_affine() 
    }

    fn compress(&self) -> Self::Compressed { self.into_compressed() }

    fn decompress(c: &Self::Compressed) -> Result<G1Affine, CurveDecodingError> {
        match c.into_affine() {
            Ok(t) => Ok(t),
            Err(_) => Err(CurveDecodingError::NotOnCurve),
        }
    }

    fn decompress_unchecked(c: &Self::Compressed) -> Result<Self, CurveDecodingError> {
        match c.into_affine_unchecked() {
            Ok(t) => Ok(t),
            Err(_) => Err(CurveDecodingError::NotOnCurve),
        }
    }

    fn scalar_to_bytes(e:&Self::Scalar)-> Box<[u8]>{
        let frpr = &e.into_repr();
        let mut bytes = [0u8; 32];
        let mut i = 0;
        for a in frpr.as_ref().iter().rev(){
            bytes[i..(i+8)].copy_from_slice(&a.to_be_bytes());
            i += 8;
        }
        Box::new(bytes)
    }

    fn bytes_to_scalar(bytes: &[u8]) -> Result<Self::Scalar, FieldDecodingError>{
       if bytes.len() != Self::SCALAR_LENGTH{ 
           return Err(FieldDecodingError::NotFieldElement);
       }
       let mut frrepr: FrRepr = FrRepr([0u64;4]);
       let mut tmp = [0u8; 8];
       let mut i = 0;
       for digit in frrepr.as_mut().iter_mut().rev(){
           tmp.copy_from_slice(&bytes[i..(i+8)]);
           *digit = u64::from_be_bytes(tmp);
           i += 8;
       }
       match Fr::from_repr(frrepr){
           Ok(fr) => Ok(fr),
           Err(x) => Err(FieldDecodingError::NotFieldElement)
       }
    }

    fn curve_to_bytes(&self) -> Box<[u8]>{
        let g = self.into_compressed();
        let g_bytes = g.as_ref();
        let mut bytes = [0u8;48];
        bytes.copy_from_slice(&g_bytes);
        Box::new(bytes)
    }

    fn bytes_to_curve(bytes: &[u8]) -> Result<Self, CurveDecodingError>{
        if bytes.len() != Self::GROUP_ELEMENT_LENGTH{
            return Err(CurveDecodingError::NotOnCurve);
        }
        let mut g = G1Compressed::empty();
        g.as_mut().copy_from_slice(&bytes);
        match g.into_affine(){
            Err(x) => Err(CurveDecodingError::NotOnCurve),
            Ok(g_affine) => Ok(g_affine)
        }
    }

    fn generate<T:Rng>(csprng: &mut T) -> Self{
        G1::rand(csprng).into_affine()
    }

    fn generate_scalar<T:Rng>(csprng: &mut T) -> Self::Scalar{
        Fr::rand(csprng)
    }

}

impl Curve for G2Affine
{
     type Base = Fq;
     type Compressed = G2Compressed;
     type Scalar = Fr;

      const SCALAR_LENGTH: usize = 32;
      const GROUP_ELEMENT_LENGTH : usize = 96;

      fn zero_point() -> Self { G2Affine::zero() }

      fn one_point() -> Self { G2Affine::one() }

      fn inverse_point(&self) -> Self {
          let mut x = self.into_projective().clone();
          x.negate();
          x.into_affine()
      }

      fn is_zero_point(&self) -> bool { self.is_zero() }

      fn double_point(&self) -> Self {
          let mut x = self.into_projective().clone();
          &x.double();
          x.into_affine()
      }

      fn plus_point(&self, other: &Self) -> Self {
          let mut x = self.into_projective().clone();
          &x.add_assign_mixed(other);
          x.into_affine()
      }

      fn minus_point(&self, other: &Self) -> Self {
          let mut x = self.into_projective().clone();
          &x.sub_assign(&other.into_projective());
          x.into_affine()
      }

      fn mul_by_scalar(&self, scalar: &Self::Scalar) -> Self {
          let s = scalar.clone();
          self.mul(s).into_affine()
      }

      fn compress(&self) -> Self::Compressed { self.into_compressed() }

      fn decompress(c: &Self::Compressed) -> Result<G2Affine, CurveDecodingError> {
          match c.into_affine() {
              Ok(t) => Ok(t),
              Err(_) => Err(CurveDecodingError::NotOnCurve),
          }
       }
      fn decompress_unchecked(c: &Self::Compressed) -> Result<Self, CurveDecodingError> {
          match c.into_affine_unchecked() {
              Ok(t) => Ok(t),
              Err(_) => Err(CurveDecodingError::NotOnCurve),
          }
      }

      fn scalar_to_bytes(e:&Self::Scalar)-> Box<[u8]>{
          let frpr = &e.into_repr();
          let mut bytes = [0u8; 32];
          let mut i = 0;
          for a in frpr.as_ref().iter().rev(){
              bytes[i..(i+8)].copy_from_slice(&a.to_be_bytes());
              i += 8;
          }
          Box::new(bytes)
      }

      fn bytes_to_scalar(bytes: &[u8]) -> Result<Self::Scalar, FieldDecodingError>{
         if bytes.len() != Self::SCALAR_LENGTH{
             return Err(FieldDecodingError::NotFieldElement);
         }
         let mut frrepr: FrRepr = FrRepr([0u64;4]);
         let mut tmp = [0u8; 8];
         let mut i = 0;
         for digit in frrepr.as_mut().iter_mut().rev(){
             tmp.copy_from_slice(&bytes[i..(i+8)]);
             *digit = u64::from_be_bytes(tmp);
             i += 8;
         }
         match Fr::from_repr(frrepr){
             Ok(fr) => Ok(fr),
             Err(x) => Err(FieldDecodingError::NotFieldElement)
         }
      }

      fn curve_to_bytes(&self) -> Box<[u8]>{
          let g = self.into_compressed();
          let g_bytes = g.as_ref();
          let mut bytes = [0u8;96];
          bytes.copy_from_slice(&g_bytes);
          Box::new(bytes)
      }
      fn bytes_to_curve(bytes: &[u8]) -> Result<Self, CurveDecodingError>{
          if bytes.len() != Self::GROUP_ELEMENT_LENGTH{
              return Err(CurveDecodingError::NotOnCurve);
          }
          let mut g = G2Compressed::empty();
          g.as_mut().copy_from_slice(&bytes);
          match g.into_affine(){
              Err(x) => Err(CurveDecodingError::NotOnCurve),
              Ok(g_affine) => Ok(g_affine)
          }
      }

      fn generate<T:Rng>(csprng: &mut T) -> Self{
          G2::rand(csprng).into_affine()
      }

      fn generate_scalar<T:Rng>(csprng: &mut T) -> Self::Scalar{
          Fr::rand(csprng)
      }
}
