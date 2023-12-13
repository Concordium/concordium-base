use std::{
    borrow::Borrow,
    fmt::Display,
    ops::{AddAssign, MulAssign, Neg, SubAssign},
};

use crate::common::{Buffer, Deserial, Serial};
use byteorder::{ByteOrder, LittleEndian};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint, VartimeRistrettoPrecomputation},
    scalar::Scalar,
    traits::{Identity, VartimeMultiscalarMul, VartimePrecomputedMultiscalarMul},
};

use super::{Curve, Field, MultiExp, PrimeField};

/// A wrapper to make it possible to implement external traits
/// and to avoid clashes with blacket implementations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RistrettoScalar(Scalar);

impl Serial for RistrettoScalar {
    fn serial<B: Buffer>(&self, out: &mut B) {
        let res: &[u8; 32] = self.0.as_bytes();
        out.write_all(res)
            .expect("Writing to a buffer should not fail.");
    }
}

impl Deserial for RistrettoScalar {
    fn deserial<R: byteorder::ReadBytesExt>(source: &mut R) -> crate::common::ParseResult<Self> {
        let mut buf: [u8; 32] = [0; 32];
        source.read_exact(&mut buf)?;
        let res = Scalar::from_canonical_bytes(buf).ok_or(anyhow::anyhow!(
            "Deserialization failed! Not a field value!"
        ))?;
        Ok(res.into())
    }
}

impl Display for RistrettoScalar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Use Debug as Display for now
        std::fmt::Debug::fmt(self, f)
    }
}

// Since we use a wrapper type, it is convenient to use `into()` to convert from
// Scalar.
impl From<Scalar> for RistrettoScalar {
    fn from(value: Scalar) -> Self { RistrettoScalar(value) }
}

impl Field for RistrettoScalar {
    fn random<R: rand_core::RngCore + ?std::marker::Sized>(rng: &mut R) -> Self {
        let mut scalar_bytes = [0u8; 64];
        rng.fill_bytes(&mut scalar_bytes);
        Scalar::from_bytes_mod_order_wide(&scalar_bytes).into()
    }

    fn zero() -> Self { Scalar::zero().into() }

    fn one() -> Self { Scalar::one().into() }

    fn is_zero(&self) -> bool { self.0 == Self::zero().0 }

    fn square(&mut self) { self.0.mul_assign(self.0) }

    fn double(&mut self) { self.0.add_assign(self.0) }

    fn negate(&mut self) {
        let v = self.0.neg();
        self.0 = v;
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
}

impl PrimeField for RistrettoScalar {
    // Taken from `curve25519-dalek` v.4.1.1 that implements `ff::PrimeField`
    const CAPACITY: u32 = 252;
    // Taken from `curve25519-dalek` v.4.1.1 that implements `ff::PrimeField``
    const NUM_BITS: u32 = 253;

    fn into_repr(self) -> Vec<u64> {
        let mut vec: Vec<u64> = Vec::new();
        let bytes = self.0.to_bytes();
        for chunk in bytes.chunks(8) {
            let x: [u8; 8] = chunk.try_into().unwrap();
            let x_64 = u64::from_le_bytes(x);
            vec.push(x_64);
        }
        vec
    }

    fn from_repr(r: &[u64]) -> Result<Self, super::CurveDecodingError> {
        let tmp: [u64; 4] = r
            .try_into()
            .map_err(|_| super::CurveDecodingError::NotInField(format!("{:?}", r)))?;
        let mut s_bytes = [0u8; 32];
        for x in tmp {
            LittleEndian::write_u64(&mut s_bytes, x);
        }
        let res = Scalar::from_canonical_bytes(s_bytes).ok_or(
            super::CurveDecodingError::NotInField(format!("{:?}", s_bytes)),
        )?;
        Ok(res.into())
    }
}

impl Serial for RistrettoPoint {
    fn serial<B: Buffer>(&self, out: &mut B) {
        let compressed_point = self.compress();
        let res: &[u8; 32] = compressed_point.as_bytes();
        out.write_all(res)
            .expect("Writing to a buffer should not fail.");
    }
}

impl Deserial for RistrettoPoint {
    fn deserial<R: byteorder::ReadBytesExt>(source: &mut R) -> crate::common::ParseResult<Self> {
        let mut buf: [u8; 32] = [0; 32];
        source.read_exact(&mut buf)?;
        let res = CompressedRistretto::from_slice(&buf)
            .decompress()
            .ok_or(anyhow::anyhow!("Failed!"))?;
        Ok(res)
    }
}

impl Curve for RistrettoPoint {
    type MultiExpType = RistrettoMultiExpNoPrecompute;
    type Scalar = RistrettoScalar;

    const GROUP_ELEMENT_LENGTH: usize = 32;
    
    const SCALAR_LENGTH: usize = 32;

    fn zero_point() -> Self { Self::identity() }

    fn one_point() -> Self { RISTRETTO_BASEPOINT_POINT }

    fn is_zero_point(&self) -> bool { self == &Self::zero_point() }

    fn inverse_point(&self) -> Self { -self }

    fn double_point(&self) -> Self { self + self }

    fn plus_point(&self, other: &Self) -> Self { self + other }

    fn minus_point(&self, other: &Self) -> Self { self - other }

    fn mul_by_scalar(&self, scalar: &Self::Scalar) -> Self { self * scalar.0 }

    fn bytes_to_curve_unchecked<R: byteorder::ReadBytesExt>(
        source: &mut R,
    ) -> anyhow::Result<Self> {
        let mut buf: [u8; 32] = [0; 32];
        source.read_exact(&mut buf)?;
        let res = CompressedRistretto::from_slice(&buf)
            .decompress()
            .ok_or(anyhow::anyhow!("Failed!"))?;
        Ok(res)
    }

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

    fn hash_to_group(m: &[u8]) -> Self {
        RistrettoPoint::hash_from_bytes::<ed25519_dalek::Sha512>(m)
    }
}

/// An instance of multiexp algorithm from the Dalek library that uses
/// precomputed table of points. Precomputing is slow, so it makes sense to use
/// this implementation when one wants to share the precomputed table with many
/// subsequent computations. For our current use cases it seems not relevant.
impl MultiExp for VartimeRistrettoPrecomputation {
    type CurvePoint = RistrettoPoint;

    fn new<X: Borrow<Self::CurvePoint>>(gs: &[X]) -> Self {
        <Self as VartimePrecomputedMultiscalarMul>::new(gs.iter().map(|p| p.borrow()))
    }

    fn multiexp<X: Borrow<<Self::CurvePoint as Curve>::Scalar>>(
        &self,
        exps: &[X],
    ) -> Self::CurvePoint {
        self.vartime_multiscalar_mul(exps.iter().map(|p| p.borrow().0))
    }
}

/// An instance of multiexp algorithm from the Dalek library.
/// It is instantiated with points, but no precomutations is done.
/// This way, it follows the same interface as our generic multiexp.
pub struct RistrettoMultiExpNoPrecompute {
    points: Vec<RistrettoPoint>,
}

impl MultiExp for RistrettoMultiExpNoPrecompute {
    type CurvePoint = RistrettoPoint;

    fn new<X: Borrow<Self::CurvePoint>>(gs: &[X]) -> Self {
        Self {
            points: gs.iter().map(|x| *x.borrow()).collect(),
        }
    }

    fn multiexp<X: Borrow<<Self::CurvePoint as Curve>::Scalar>>(
        &self,
        exps: &[X],
    ) -> Self::CurvePoint {
        Self::CurvePoint::vartime_multiscalar_mul(exps.iter().map(|p| p.borrow().0), &self.points)
    }
}
