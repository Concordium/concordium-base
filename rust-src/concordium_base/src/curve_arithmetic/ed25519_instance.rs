use super::{field_adapters::FFField, Curve, CurveDecodingError, Field, MultiExp, PrimeField};
use crate::common::{Buffer, Deserial, Serial};
use byteorder::{ByteOrder, LittleEndian};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint, VartimeRistrettoPrecomputation},
    scalar::Scalar,
    traits::{Identity, VartimeMultiscalarMul, VartimePrecomputedMultiscalarMul},
};
use sha2::Sha512;
use std::{borrow::Borrow, result::Result};

impl Serial for Scalar {
    fn serial<B: Buffer>(&self, out: &mut B) {
        let res: &[u8; 32] = self.as_bytes();
        out.write_all(res)
            .expect("Writing to a buffer should not fail.");
    }
}

impl Deserial for Scalar {
    fn deserial<R: byteorder::ReadBytesExt>(source: &mut R) -> crate::common::ParseResult<Self> {
        let mut buf: [u8; 32] = [0; 32];
        source.read_exact(&mut buf)?;
        let res: Option<_> = Scalar::from_canonical_bytes(buf).into();
        res.ok_or(anyhow::anyhow!(
            "Deserialization failed! Not a field value!"
        ))
    }
}

impl PrimeField for FFField<Scalar> {
    const CAPACITY: u32 = <Scalar as ff::PrimeField>::CAPACITY;
    const NUM_BITS: u32 = <Scalar as ff::PrimeField>::NUM_BITS;

    fn into_repr(self) -> Vec<u64> {
        let bytes = <Scalar as ff::PrimeField>::to_repr(&self.0);
        let mut vec: Vec<u64> = Vec::new();
        for chunk in bytes.chunks_exact(8) {
            // The chunk size is always 8 and there is no remainder after chunking, since
            // the representation is a 32-byte array. That is why it is safe to
            // unwrap here.
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
        let res: Option<_> = Scalar::from_canonical_bytes(s_bytes).into();
        let scalar: Scalar = res.ok_or(super::CurveDecodingError::NotInField(format!(
            "{:?}",
            s_bytes
        )))?;
        Ok(scalar.into())
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
        let res = CompressedRistretto::from_slice(&buf)?;
        let point = res.decompress().ok_or(anyhow::anyhow!("Failed!"))?;
        Ok(point)
    }
}

impl Curve for RistrettoPoint {
    type MultiExpType = RistrettoMultiExpNoPrecompute;
    type Scalar = FFField<Scalar>;

    const GROUP_ELEMENT_LENGTH: usize = 32;
    const SCALAR_LENGTH: usize = 32;

    fn zero_point() -> Self { Self::identity() }

    fn one_point() -> Self { RISTRETTO_BASEPOINT_POINT }

    fn is_zero_point(&self) -> bool { self == &Self::zero_point() }

    fn inverse_point(&self) -> Self { -self }

    // A doubling operation on the Ristretto representation is not available
    // directly. Moreover, v4.1.1 of `curve25519-dalek` implements `double()`
    // using addition.
    // https://docs.rs/curve25519-dalek/4.1.1/src/curve25519_dalek/ristretto.rs.html#1203-1205
    fn double_point(&self) -> Self { self + self }

    fn plus_point(&self, other: &Self) -> Self { self + other }

    fn minus_point(&self, other: &Self) -> Self { self - other }

    fn mul_by_scalar(&self, scalar: &Self::Scalar) -> Self { self * scalar.0 }

    fn generate<R: rand::Rng>(rng: &mut R) -> Self {
        let mut uniform_bytes = [0u8; 64];
        rng.fill_bytes(&mut uniform_bytes);

        RistrettoPoint::from_uniform_bytes(&uniform_bytes)
    }

    fn generate_scalar<R: rand::Rng>(rng: &mut R) -> Self::Scalar { Self::Scalar::random(rng) }

    fn scalar_from_u64(n: u64) -> Self::Scalar { Scalar::from(n).into() }

    fn scalar_from_bytes<A: AsRef<[u8]>>(bs: A) -> Self::Scalar {
        // Traverse at most 4 8-byte chunks, for a total of 256 bits.
        // The top-most four bits in the last chunk are set to 0.
        let mut fr = [0u64; 4];
        for (i, chunk) in bs.as_ref().chunks(8).take(4).enumerate() {
            let mut v = [0u8; 8];
            v[..chunk.len()].copy_from_slice(chunk);
            fr[i] = u64::from_le_bytes(v);
        }
        // unset four topmost bits in the last u64 limb.
        fr[3] &= !(1u64 << 63 | 1u64 << 62 | 1u64 << 61 | 1u64 << 60);
        <Self::Scalar as PrimeField>::from_repr(&fr)
            .expect("The scalar with top two bits erased should be valid.")
    }

    fn hash_to_group(m: &[u8]) -> Result<Self, CurveDecodingError> {
        Result::Ok(RistrettoPoint::hash_from_bytes::<Sha512>(m))
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
/// It is instantiated with points, but no precomputations is done.
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

/// In the tests we focus on the functionality related to conversion form/to
/// bytes or other representations. We do not test field/group operations here
/// since we delegate this functionality to the `curve25519-dalek`
/// implementation, which features its own test suite.
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        common::*,
        curve_arithmetic::{field_adapters::FFField, Field},
    };
    use curve25519_dalek::{ristretto::RistrettoPoint, Scalar};
    use rand::{Rng, RngCore};
    use std::io::Cursor;

    type RistrettoScalar = FFField<Scalar>;

    /// Test serialization for scalars
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

    /// Test serialization for curve points
    #[test]
    fn test_point_serialization() {
        let mut csprng = rand::thread_rng();
        for _ in 0..1000 {
            let mut out = Vec::<u8>::new();
            let point = RistrettoPoint::generate(&mut csprng);
            point.serial(&mut out);
            let point_res = RistrettoPoint::deserial(&mut Cursor::new(out));
            assert!(point_res.is_ok());
            assert_eq!(point, point_res.unwrap());
        }
    }

    /// Turn scalar elements into representations and back again, and compare.
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

    /// Test that `into_repr()` correclty converts a scalar constructed from a
    /// byte array to an array of limbs with least significant digits first.
    #[test]
    fn test_into() {
        let res: Option<Scalar> = Scalar::from_canonical_bytes([
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 254, 255, 255, 255, 255, 255, 255, 255,
            0, 0, 0, 0, 0, 0, 0, 0,
        ])
        .into();
        let s: RistrettoScalar = res.expect("Expected a valid scalar").into();
        assert_eq!(s.into_repr(), [1u64, 0u64, u64::MAX - 1, 0u64]);
    }

    // Check that scalar_from_bytes for ed25519 works on small values.
    #[test]
    fn test_scalar_from_bytes_small() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let n = <RistrettoScalar as Field>::random(&mut rng);
            let bytes = to_bytes(&n);
            let m = <RistrettoPoint as Curve>::scalar_from_bytes(&bytes);
            // Make sure that n and m only differ in the topmost bits;
            // `scalar_from_bytes_helper` resets the topmost bits to zeros.
            let n = n.into_repr();
            let m = m.into_repr();
            let mask = !(1u64 << 63 | 1u64 << 62 | 1u64 << 61 | 1u64 << 60);
            assert_eq!(n[0], m[0], "First limb.");
            assert_eq!(n[1], m[1], "Second limb.");
            assert_eq!(n[2], m[2], "Third limb.");
            // It is unlikely that the limbs will differ even without masking, because the
            // difference between the max number for `RistrettoScalar::CAPACITY` and the
            // curve order is quite small. We, however, keep the mask here,
            // because we're interesed in lower bytes in this test.
            assert_eq!(n[3] & mask, m[3], "Fourth limb with top bit masked.");
        }
    }

    /// Test that everything that exeeds `RistrettoScalar::CAPACITY` is ignored
    /// by `Curve::scalar_from_bytes()`
    #[test]
    fn test_scalar_from_bytes_big() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            // First, we generate 31 random bytes.
            let mut lower_bytes: [u8; 31] = [0u8; 31];
            rng.fill_bytes(&mut lower_bytes);
            let mut fits_capacity_bytes = [0u8; 32];
            // Next, we create a byte array that is filled with random lower bytes, the last
            // byte is in [0; 15], that is, of the form 0b0000XXXX (big-endian).
            fits_capacity_bytes[0..31].copy_from_slice(&lower_bytes);
            let n = rng.gen_range(0..16);
            fits_capacity_bytes[31] = n;
            let fits_capacity = <RistrettoPoint as Curve>::scalar_from_bytes(fits_capacity_bytes);
            let i = rng.gen_range(1..16);
            // Now, we create a byte array from lower bytes with the last byte being number
            // that is guaranteed to exceed `RistrettoScalar::CAPACITY`.
            let mut bytes: [u8; 32] = [0u8; 32];
            bytes[0..31].copy_from_slice(&lower_bytes);
            // Add 0bXXXX0000 that leaves the first four bits untouched.
            bytes[31] = n + (i << 4);
            let over_capacity = <RistrettoPoint as Curve>::scalar_from_bytes(bytes);
            // Check that four topmost bits are ignored.
            assert_eq!(fits_capacity, over_capacity);
        }
    }
}
