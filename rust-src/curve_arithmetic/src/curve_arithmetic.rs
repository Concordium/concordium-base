// Authors:
// - bm@concordium.com
//

use failure::Fail;
use ff::{Field, PrimeField, PrimeFieldDecodingError};
use rand::*;
use std::{
    fmt::{Debug, Display, Formatter},
    io::Cursor,
};

#[derive(Debug)]
pub enum FieldDecodingError {
    NotFieldElement,
}

impl From<PrimeFieldDecodingError> for FieldDecodingError {
    fn from(_err: PrimeFieldDecodingError) -> Self {
        FieldDecodingError::NotFieldElement
    }
}

impl Display for FieldDecodingError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "Not a field element.")
    }
}

impl Fail for FieldDecodingError {}

#[derive(Debug)]
pub enum CurveDecodingError {
    NotOnCurve,
}

impl Display for CurveDecodingError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "Not a point on the curve.")
    }
}

impl Fail for CurveDecodingError {}

pub trait Curve:
    Copy + Clone + Sized + Send + Sync + Debug + Display + PartialEq + Eq + 'static
{
    type Scalar: Field;
    type Base: Field;
    type Compressed;
    const SCALAR_LENGTH: usize;
    const GROUP_ELEMENT_LENGTH: usize;
    fn zero_point() -> Self;
    fn one_point() -> Self; // generator
    fn is_zero_point(&self) -> bool;
    fn inverse_point(&self) -> Self;
    fn double_point(&self) -> Self;
    fn plus_point(&self, other: &Self) -> Self;
    fn minus_point(&self, other: &Self) -> Self;
    fn mul_by_scalar(&self, scalar: &Self::Scalar) -> Self;
    fn compress(&self) -> Self::Compressed;
    fn decompress(c: &Self::Compressed) -> Result<Self, CurveDecodingError>;
    fn decompress_unchecked(c: &Self::Compressed) -> Result<Self, CurveDecodingError>;
    fn scalar_to_bytes(s: &Self::Scalar) -> Box<[u8]>;
    fn bytes_to_scalar(b: &mut Cursor<&[u8]>) -> Result<Self::Scalar, FieldDecodingError>;
    fn curve_to_bytes(&self) -> Box<[u8]>;
    fn bytes_to_curve(b: &mut Cursor<&[u8]>) -> Result<Self, CurveDecodingError>;
    fn bytes_to_curve_unchecked(b: &mut Cursor<&[u8]>) -> Result<Self, CurveDecodingError>;
    fn generate<R: Rng>(rng: &mut R) -> Self;
    fn generate_scalar<R: Rng>(rng: &mut R) -> Self::Scalar;
    fn scalar_from_u64(n: u64) -> Result<Self::Scalar, FieldDecodingError>;
    fn hash_to_group_element(m: &[u8]) -> Self;
}

pub trait Pairing: Sized + 'static + Clone {
    type ScalarField: PrimeField;
    type G_1: Curve<Base = Self::BaseField, Scalar = Self::ScalarField>;
    type G_2: Curve<Base = Self::BaseField, Scalar = Self::ScalarField>;
    type BaseField: PrimeField;
    type TargetField: Field;
    fn pair(p: Self::G_1, q: Self::G_2) -> Self::TargetField;
    const SCALAR_LENGTH: usize;
    fn scalar_to_bytes(s: &Self::ScalarField) -> Box<[u8]>;
    fn bytes_to_scalar(b: &mut Cursor<&[u8]>) -> Result<Self::ScalarField, FieldDecodingError>;
    fn generate_scalar<R: Rng>(rng: &mut R) -> Self::ScalarField;
    //    fn target_field_to_bytes(f: &Self::TargetField) -> Box<[u8]>;
    //    fn bytes_to_target_field(b: &[u8]) -> Result<Self::TargetField,
    // FieldDecodingError>;
}
