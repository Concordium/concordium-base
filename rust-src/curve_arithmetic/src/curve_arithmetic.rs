// Authors:
// - bm@concordium.com
//

use pairing::Field;
use std::fmt::{Debug, Display};

pub enum CurveDecodingError {
    NotOnCurve,
}

pub trait Curve:
    Copy + Clone + Sized + Send + Sync + Debug + Display + PartialEq + Eq + 'static {
    type Scalar: Field;
    type Base: Field;
    type Compressed;

    fn zero() -> Self;
    fn one() -> Self; // generator
    fn is_zero(&self) -> bool;
    fn inverse(&self) -> Self;
    fn double(&self) -> Self;
    fn add(&self, other: &Self) -> Self;
    fn sub(&self, other: &Self) -> Self;
    fn scalar_mul(&self, scalar: Self::Scalar) -> Self;
    fn into_compressed(&self) -> Self::Compressed;
    fn from_compressed(c: &Self::Compressed) -> Result<Self, CurveDecodingError>;
    fn from_compressed_unchecked(c: &Self::Compressed) -> Result<Self, CurveDecodingError>;
}
