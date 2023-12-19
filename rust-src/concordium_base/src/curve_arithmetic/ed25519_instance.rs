use super::{Curve, Field, MultiExp, PrimeField};
use crate::common::{Buffer, Deserial, Serial};
use byteorder::{ByteOrder, LittleEndian};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint, VartimeRistrettoPrecomputation},
    scalar::Scalar,
    traits::{Identity, VartimeMultiscalarMul, VartimePrecomputedMultiscalarMul},
};
use std::{
    borrow::Borrow,
    ops::{AddAssign, MulAssign, Neg, SubAssign},
};

/// A wrapper to make it possible to implement external traits
/// and to avoid clashes with blacket implementations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, derive_more::From)]
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
        let bytes: [u8; 32] = self.0.to_bytes();
        for chunk in bytes.chunks_exact(8) {
            // The chunk size is always 8 and there is no remider after chunking, since the
            // the the representation is a 32-byte array. That is why it is safe to unwrap
            // here.
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
        let mut offset = 0;
        for x in tmp {
            let max = offset + 8;
            LittleEndian::write_u64(&mut s_bytes[offset..max], x);
            offset = max;
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

#[cfg(test)]
pub(crate) mod tests {
    use super::{RistrettoScalar, *};
    use crate::common::*;
    use curve25519_dalek::ristretto::RistrettoPoint;
    use std::io::Cursor;

    // Test serialization for scalars
    #[test]
    fn test_scalar_serialization() {
        let mut csprng = rand::thread_rng();
        for _ in 0..1000 {
            let mut out = Vec::<u8>::new();
            let scalar = RistrettoScalar::random(&mut csprng);
            scalar.serial(&mut out);
            let scalar_res = RistrettoScalar::deserial(&mut Cursor::new(out));
            assert!(scalar_res.is_ok());
            assert_eq!(scalar, scalar_res.unwrap());
        }
    }

    // Test serialization for curve points
    #[test]
    fn test_point_serialization() {
        let mut csprng = rand::thread_rng();
        for _ in 0..1000 {
            let mut out = Vec::<u8>::new();
            let point = RistrettoPoint::generate(&mut csprng);
            point.serial(&mut out);
            let point_res = RistrettoPoint::deserial(&mut Cursor::new(out));
            assert!(point_res.is_ok());
            assert!(point_res.is_ok());
            assert_eq!(point, point_res.unwrap());
        }
    }

    // Turn scalar elements into representations and back again, and compare.
    #[test]
    fn test_into_from_rep() {
        let mut csprng = rand::thread_rng();
        for _ in 0..1000 {
            let scalar = RistrettoScalar::random(&mut csprng);
            let scalar_vec64 = scalar.into_repr();
            let scalar_res = RistrettoScalar::from_repr(&scalar_vec64);
            assert!(scalar_res.is_ok());
            assert_eq!(scalar, scalar_res.unwrap());
        }
    }

    // Turn curve points into representations and back again, and compare.
    #[test]
    fn test_point_byte_conversion_unchecked() {
        let mut csprng = rand::thread_rng();
        for _ in 0..1000 {
            let point = RistrettoPoint::generate(&mut csprng);
            let bytes = to_bytes(&point);
            let point_res = RistrettoPoint::bytes_to_curve_unchecked(&mut Cursor::new(&bytes));
            assert!(point_res.is_ok());
            assert_eq!(point, point_res.unwrap());
        }
    }

    /// Random element from the scalar field GF(2\^{252} +
    /// 27742317777372353535851937790883648493)
    /// a = 2238329342913194256032495932344128051776374960164957527413114840482143558222
    static A_BYTES: [u8; 32] = [
        0x4e, 0x5a, 0xb4, 0x34, 0x5d, 0x47, 0x08, 0x84, 0x59, 0x13, 0xb4, 0x64, 0x1b, 0xc2, 0x7d,
        0x52, 0x52, 0xa5, 0x85, 0x10, 0x1b, 0xcc, 0x42, 0x44, 0xd4, 0x49, 0xf4, 0xa8, 0x79, 0xd9,
        0xf2, 0x04,
    ];

    /// 1/a = 6859937278830797291664592131120606308688036382723378951768035303146619657244
    static AINV_BYTES: [u8; 32] = [
        0x1c, 0xdc, 0x17, 0xfc, 0xe0, 0xe9, 0xa5, 0xbb, 0xd9, 0x24, 0x7e, 0x56, 0xbb, 0x01, 0x63,
        0x47, 0xbb, 0xba, 0x31, 0xed, 0xd5, 0xa9, 0xbb, 0x96, 0xd5, 0x0b, 0xcd, 0x7a, 0x3f, 0x96,
        0x2a, 0x0f,
    ];

    /// a^2 = 7223459340038346301359662082310065231337362643762546120300009460524582755663
    static ASQ_BYTES: [u8; 32] = [
        0x4f, 0xdd, 0x54, 0x3d, 0xc3, 0x58, 0x8c, 0x8, 0x74, 0xd3, 0xde, 0xf1, 0x15, 0xeb, 0x46,
        0x1, 0x9e, 0x90, 0xcc, 0x16, 0x4a, 0xc2, 0x3c, 0x3, 0xe4, 0x52, 0x13, 0x22, 0x46, 0x55,
        0xf8, 0xf,
    ];

    #[test]
    fn test_scalar_mult() {
        let a: RistrettoScalar = Scalar::from_bytes_mod_order(A_BYTES).into();
        let mut aa = a.clone();
        aa.mul_assign(&a);
        let asq: RistrettoScalar = Scalar::from_bytes_mod_order(ASQ_BYTES).into();
        assert_eq!(asq, aa);
    }

    #[test]
    fn test_scalar_square() {
        let a: RistrettoScalar = Scalar::from_bytes_mod_order(A_BYTES).into();
        let mut aa = a.clone();
        aa.square();
        let asq: RistrettoScalar = Scalar::from_bytes_mod_order(ASQ_BYTES).into();
        assert_eq!(asq, aa);
    }

    #[test]
    fn test_scalar_inverse() {
        // Zero element has no inverse in a field
        let zero: RistrettoScalar = Scalar::zero().into();
        let zero_inv = zero.inverse();
        assert_eq!(zero_inv, None);
        // Every non-zero element 'a' should have an inverse computed as 'a.inverse()'
        let a: RistrettoScalar = Scalar::from_bytes_mod_order(A_BYTES).into();
        let ainv = a.inverse().unwrap();
        let should_be_inverse: RistrettoScalar = Scalar::from_bytes_mod_order(AINV_BYTES).into();
        let mut one = a.clone();
        one.mul_assign(&ainv);
        assert_eq!(ainv, should_be_inverse);
        assert_eq!(RistrettoScalar::one(), one);
    }
}
