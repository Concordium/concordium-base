use byteorder::ReadBytesExt;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::Identity};
use ff::{Field, PrimeField};
use std::{
    fmt::{Debug, Display},
    ops::{AddAssign, MulAssign, Neg, SubAssign},
};

use crate::common::{Deserial, Serial};

use super::curve_group::Group;

// Define a wrapper to make it possible to implement `ff::Field` and other
// traits from dependencies
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RistrettoScalar(Scalar);

impl Serial for RistrettoScalar {
    fn serial<B: crate::common::Buffer>(&self, _out: &mut B) { todo!() }
}

impl Deserial for RistrettoScalar {
    fn deserial<R: ReadBytesExt>(_source: &mut R) -> crate::common::ParseResult<Self> { todo!() }
}

impl Display for RistrettoScalar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { Debug::fmt(&self.0, f) }
}

impl From<Scalar> for RistrettoScalar {
    fn from(value: Scalar) -> Self { RistrettoScalar(value) }
}

impl RistrettoScalar {
    fn scalar(&self) -> Scalar { self.0 }
}

impl From<RistrettoScalar> for pairing::bls12_381::FqRepr {
    fn from(_value: RistrettoScalar) -> Self { todo!() }
}

// This one is hard to match with the ristretto implementation
impl PrimeField for RistrettoScalar {
    // This is just to make the typechecker happy
    type Repr = pairing::bls12_381::FqRepr;

    const CAPACITY: u32 = 255;
    const NUM_BITS: u32 = 255;
    // this is wrong, of course, it should be the actual value.
    const S: u32 = 7;

    fn from_repr(_: Self::Repr) -> Result<Self, ff::PrimeFieldDecodingError> { todo!() }

    fn into_repr(&self) -> Self::Repr { todo!() }

    fn char() -> Self::Repr { todo!() }

    fn multiplicative_generator() -> Self { todo!() }

    fn root_of_unity() -> Self { todo!() }
}

impl Field for RistrettoScalar {
    fn random<R: rand_core::RngCore + ?std::marker::Sized>(rng: &mut R) -> Self {
        // Calling Scalar::random(rng) doesn't work, because it requires `CryptoRng`
        // Pretty much all methods generating random values require `CryptoRng` in the
        // ristretto implementation.
        let mut scalar_bytes = [0u8; 64];
        rng.fill_bytes(&mut scalar_bytes);
        Scalar::from_bytes_mod_order_wide(&scalar_bytes).into()
    }

    fn zero() -> Self { Scalar::zero().into() }

    fn one() -> Self { Scalar::one().into() }

    fn is_zero(&self) -> bool { self.0 == Scalar::zero() }

    fn square(&mut self) { self.0.mul_assign(self.0) }

    fn double(&mut self) { self.0.add_assign(self.0) }

    fn negate(&mut self) {
        let v = self.0.neg();
        self.0 = v
    }

    fn add_assign(&mut self, other: &Self) { self.0.add_assign(other.0) }

    fn sub_assign(&mut self, other: &Self) { self.0.sub_assign(other.0) }

    fn mul_assign(&mut self, other: &Self) { self.0.mul_assign(other.0) }

    fn inverse(&self) -> Option<Self> {
        if self.is_zero() {
            None
        } else {
            Some(self.0.invert().into())
        }
    }

    fn frobenius_map(&mut self, _power: usize) {
        // Could not find anythitng like this in the curve25519-dalek repo
        todo!();
    }
}

impl Serial for RistrettoPoint {
    fn serial<B: crate::common::Buffer>(&self, _out: &mut B) { todo!() }
}

impl Deserial for RistrettoPoint {
    fn deserial<R: ReadBytesExt>(_source: &mut R) -> crate::common::ParseResult<Self> { todo!() }
}

impl Group for RistrettoPoint {
    type Scalar = RistrettoScalar;

    const GROUP_ELEMENT_LENGTH: usize = 48;
    const SCALAR_LENGTH: usize = 32;

    fn zero_point() -> Self { RistrettoPoint::identity() }

    fn is_zero_point(&self) -> bool { *self == RistrettoPoint::identity() }

    fn inverse_point(&self) -> Self { -self }

    fn double_point(&self) -> Self { self + self }

    fn plus_point(&self, other: &Self) -> Self { self + other }

    fn minus_point(&self, other: &Self) -> Self { self - other }

    fn mul_by_scalar(&self, scalar: &Self::Scalar) -> Self { self * scalar.scalar() }

    fn generate<R: rand::Rng>(rng: &mut R) -> Self {
        let mut uniform_bytes = [0u8; 64];
        rng.fill_bytes(&mut uniform_bytes);

        RistrettoPoint::from_uniform_bytes(&uniform_bytes)
    }

    fn generate_scalar<R: rand::Rng>(rng: &mut R) -> Self::Scalar {
        let mut scalar_bytes = [0u8; 64];
        rng.fill_bytes(&mut scalar_bytes);
        Scalar::from_bytes_mod_order_wide(&scalar_bytes).into()
    }

    fn scalar_from_u64(n: u64) -> Self::Scalar { Scalar::from(n).into() }

    fn scalar_from_bytes<A: AsRef<[u8]>>(bs: A) -> Self::Scalar {
        Scalar::hash_from_bytes::<ed25519_dalek::Sha512>(bs.as_ref()).into()
    }

    fn generator() -> Self { todo!() }

    fn hash_to_group(m: &[u8]) -> Self {
        // The input must be 64 bytes long.
        RistrettoPoint::hash_from_bytes::<ed25519_dalek::Sha512>(m)
    }
}
