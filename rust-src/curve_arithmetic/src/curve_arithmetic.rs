use failure::{Fail, Fallible};
use ff::{Field, PrimeField};
use rand::*;
use std::fmt::{Debug, Display, Formatter};

use byteorder::ReadBytesExt;

use crypto_common::{Serial, Serialize};

#[derive(Debug)]
pub enum CurveDecodingError {
    NotOnCurve,
}

impl Display for CurveDecodingError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result { write!(f, "Not a point on the curve.") }
}

impl Fail for CurveDecodingError {}

pub trait Curve:
    Serialize + Copy + Clone + Sized + Send + Sync + Debug + Display + PartialEq + Eq + 'static {
    type Scalar: Field + Serialize;
    type Base: Field;
    type Compressed;
    const SCALAR_LENGTH: usize;
    const GROUP_ELEMENT_LENGTH: usize;
    fn zero_point() -> Self;
    fn one_point() -> Self; // generator
    fn is_zero_point(&self) -> bool;
    #[must_use]
    fn inverse_point(&self) -> Self;
    #[must_use]
    fn double_point(&self) -> Self;
    #[must_use]
    fn plus_point(&self, other: &Self) -> Self;
    #[must_use]
    fn minus_point(&self, other: &Self) -> Self;
    #[must_use]
    fn mul_by_scalar(&self, scalar: &Self::Scalar) -> Self;
    #[must_use]
    fn compress(&self) -> Self::Compressed;
    fn decompress(c: &Self::Compressed) -> Result<Self, CurveDecodingError>;
    fn decompress_unchecked(c: &Self::Compressed) -> Result<Self, CurveDecodingError>;
    fn bytes_to_curve_unchecked<R: ReadBytesExt>(b: &mut R) -> Fallible<Self>;
    fn generate<R: Rng>(rng: &mut R) -> Self;
    fn generate_scalar<R: Rng>(rng: &mut R) -> Self::Scalar;
    /// Generate a non-zero scalar. The default implementation does repeated
    /// sampling until a non-zero scalar is reached.
    fn generate_non_zero_scalar<R: Rng>(rng: &mut R) -> Self::Scalar {
        loop {
            let s = Self::generate_scalar(rng);
            if !s.is_zero() {
                return s;
            }
        }
    }
    fn scalar_from_u64(n: u64) -> Self::Scalar;
    fn hash_to_group(m: &[u8]) -> Self;
}

pub trait Pairing: Sized + 'static + Clone {
    type ScalarField: PrimeField + Serialize;
    type G1: Curve<Base = Self::BaseField, Scalar = Self::ScalarField>;
    type G2: Curve<Base = Self::BaseField, Scalar = Self::ScalarField>;
    type G1Prepared;
    type G2Prepared;
    type BaseField: PrimeField;
    type TargetField: Field + Serial;

    fn miller_loop<'a, I>(i: I) -> Self::TargetField
    where
        I: IntoIterator<Item = &'a (&'a Self::G1Prepared, &'a Self::G2Prepared)>;

    /// Check whether the pairing equation holds given the left and right-hand
    /// sides.
    fn check_pairing_eq(g1x: &Self::G1, g2x: &Self::G2, g1y: &Self::G1, g2y: &Self::G2) -> bool {
        let pairs = [
            (&Self::g1_prepare(g1x), &Self::g2_prepare(g2x)),
            (
                &Self::g1_prepare(&g1y.inverse_point()),
                &Self::g2_prepare(g2y),
            ),
        ];
        let res = Self::miller_loop(pairs.iter());
        if let Some(mut y) = Self::final_exponentiation(&res) {
            y.sub_assign(&Self::TargetField::one());
            y.is_zero()
        } else {
            false
        }
    }

    // Compute the product of the pairings, but more efficiently.
    fn pairing_product(
        g1x: &Self::G1,
        g2x: &Self::G2,
        g1y: &Self::G1,
        g2y: &Self::G2,
    ) -> Option<Self::TargetField> {
        let pairs = [
            (&Self::g1_prepare(g1x), &Self::g2_prepare(g2x)),
            (&Self::g1_prepare(g1y), &Self::g2_prepare(g2y)),
        ];
        let res = Self::miller_loop(pairs.iter());
        Self::final_exponentiation(&res)
    }

    fn final_exponentiation(_: &Self::TargetField) -> Option<Self::TargetField>;

    fn g1_prepare(_: &Self::G1) -> Self::G1Prepared;
    fn g2_prepare(_: &Self::G2) -> Self::G2Prepared;

    fn pair(p: &Self::G1, q: &Self::G2) -> Self::TargetField {
        let g1p = Self::g1_prepare(p);
        let g2p = Self::g2_prepare(q);
        let x = Self::miller_loop([(&g1p, &g2p)].iter());
        if x.is_zero() {
            panic!("Cannot perform final exponentiation on 0.")
        } else {
            Self::final_exponentiation(&x).unwrap()
        }
    }

    const SCALAR_LENGTH: usize;
    fn generate_scalar<R: Rng>(rng: &mut R) -> Self::ScalarField;
    /// Generate non-zero scalar by repeated sampling. Can be overriden by a
    /// more efficient implementation.
    fn generate_non_zero_scalar<R: Rng>(rng: &mut R) -> Self::ScalarField {
        loop {
            let s = Self::generate_scalar(rng);
            if !s.is_zero() {
                return s;
            }
        }
    }
}
