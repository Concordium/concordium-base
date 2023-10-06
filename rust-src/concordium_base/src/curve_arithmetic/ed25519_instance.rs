
use std::fmt::Display;

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::Identity};
use crate::common::{Serial, Deserial, Buffer};

use super::{Curve, Field, PrimeField};

/// A wrapper to make it possible to implement external traits
/// and to avoid clashes with blacket implementations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RistrettoScalar(Scalar);

impl Serial for RistrettoScalar {
    fn serial<B: Buffer>(&self, out: &mut B) {
        todo!()
    }
}

impl Deserial for RistrettoScalar {

    fn deserial<R: byteorder::ReadBytesExt>(source: &mut R) -> crate::common::ParseResult<Self> {
        todo!()
    }
}


impl Display for RistrettoScalar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Use Debug as Display for now
        std::fmt::Debug::fmt(self, f)
    }
}

// Since we use a wrapper type, it is convenient to use `into()` to convert from Scalar.
impl From<Scalar> for RistrettoScalar {
    fn from(value: Scalar) -> Self {
        RistrettoScalar(value)
    }
}

impl Field for RistrettoScalar {
    fn random<R: rand_core::RngCore + ?std::marker::Sized>(rng: &mut R) -> Self {
        todo!()
    }

    fn zero() -> Self {
        Scalar::zero().into()
    }

    fn one() -> Self {
        todo!()
    }

    fn is_zero(&self) -> bool {
        todo!()
    }

    fn square(&mut self) {
        todo!()
    }

    fn double(&mut self) {
        todo!()
    }

    fn negate(&mut self) {
        todo!()
    }

    fn add_assign(&mut self, other: &Self) {
        todo!()
    }

    fn sub_assign(&mut self, other: &Self) {
        todo!()
    }

    fn mul_assign(&mut self, other: &Self) {
        todo!()
    }

    fn inverse(&self) -> Option<Self> {
        todo!()
    }

    fn frobenius_map(&mut self, power: usize) {
        todo!()
    }
}

impl PrimeField for RistrettoScalar {
    // TODO: check this, this numbers are here just to make the compiler happy.
    const NUM_BITS: u32 = 64 * 4;

    // TODO: check this, this numbers are here just to make the compiler happy.
    const CAPACITY: u32 = 64 * 4;

    fn into_repr(self) -> Vec<u64> {
        todo!()
    }

    fn from_repr(_: &[u64]) -> Result<Self, super::CurveDecodingError> {
        todo!()
    }
}

impl Serial for RistrettoPoint {
    fn serial<B: Buffer>(&self, out: &mut B) {
        todo!()
    }
} 

impl Deserial for RistrettoPoint {
    fn deserial<R: byteorder::ReadBytesExt>(source: &mut R) -> crate::common::ParseResult<Self> {
       todo!()
    }
} 


impl Curve for RistrettoPoint {
    type Scalar = RistrettoScalar;

    // TODO: copied from the BLS curve; update this.
    const SCALAR_LENGTH: usize = 32;

    // TODO: copied from the BLS curve; update this.
    const GROUP_ELEMENT_LENGTH: usize = 96;

    fn zero_point() -> Self {
        Self::identity()
    }

    fn one_point() -> Self {
        todo!()
    }

    fn is_zero_point(&self) -> bool {
        todo!()
    }

    fn inverse_point(&self) -> Self {
        todo!()
    }

    fn double_point(&self) -> Self {
        todo!()
    }

    fn plus_point(&self, other: &Self) -> Self {
        todo!()
    }

    fn minus_point(&self, other: &Self) -> Self {
        todo!()
    }

    fn mul_by_scalar(&self, scalar: &Self::Scalar) -> Self {
        todo!()
    }

    fn bytes_to_curve_unchecked<R: byteorder::ReadBytesExt>(b: &mut R) -> anyhow::Result<Self> {
        todo!()
    }

    fn generate<R: rand::Rng>(rng: &mut R) -> Self {
        todo!()
    }

    fn generate_scalar<R: rand::Rng>(rng: &mut R) -> Self::Scalar {
        todo!()
    }

    fn scalar_from_u64(n: u64) -> Self::Scalar {
        todo!()
    }

    fn scalar_from_bytes<A: AsRef<[u8]>>(bs: A) -> Self::Scalar {
        todo!()
    }

    fn hash_to_group(m: &[u8]) -> Self {
        todo!()
    }
}