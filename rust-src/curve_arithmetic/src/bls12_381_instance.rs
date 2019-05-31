// Authors:
// - bm@concordium.com
//

use crate::curve_arithmetic::*;
use pairing::{CurveAffine, EncodedPoint, CurveProjective};

impl<T> Curve for T
    where T: CurveAffine
{
    type Scalar = T::Scalar;
    type Base  = T::Base;
    type Compressed = T::Compressed;
    fn zero()-> Self {T::zero()}
    fn one()-> Self {T::one()}
    fn inverse(&self)-> Self{
        let mut x = self.into_projective().clone();
        x.negate();
        x.into_affine()
    }

    fn is_zero(&self) -> bool{
        self.is_zero()
    }

    fn double(&self)-> Self{
        let mut x = self.into_projective().clone();
        &x.double();
        x.into_affine()
    }

    fn add(&self, other:&Self)-> Self{
        let mut x = self.into_projective().clone();
        &x.add_assign_mixed(other);
        x.into_affine()
    }

    fn sub(&self, other:&Self)-> Self{
        let mut x = self.into_projective().clone();
        &x.sub_assign(&other.into_projective());
        x.into_affine()
    }

    fn scalar_mul(&self, scalar:Self::Scalar)-> Self{
        self.mul(scalar).into_affine()
    }

    fn into_compressed(&self)-> Self::Compressed{
        self.into_compressed()
    }

    fn from_compressed(c: &Self::Compressed)-> Result<T, CurveDecodingError>{
        match c.into_affine(){
            Ok(t) => Ok(t),
            Err(_) => Err(CurveDecodingError::NotOnCurve)
        }
    }

    fn from_compressed_unchecked(c: &Self::Compressed)-> Result<Self, CurveDecodingError>{
        match c.into_affine_unchecked(){
            Ok(t) => Ok(t),
            Err(_) => Err(CurveDecodingError::NotOnCurve)
        }
    }
}

