// Authors:

use crate::curve_arithmetic::*;
use byteorder::ReadBytesExt;
use ff::{Field, PrimeField};
use group::Group;//{CurveAffine, CurveProjective, EncodedPoint};
use pairing::{
    Engine, PairingCurveAffine, MultiMillerLoop, MillerLoopResult as MillerLoopResultTrait
};
use bls12_381::{
    Bls12, G1Affine, G2Affine,
    G2Prepared, G1Projective, G2Projective, Scalar as Fr,
    hash_to_curve::*, MillerLoopResult as MillerLoopResultType
};
use rand::*;
use std::ops::{Neg, AddAssign, SubAssign, MulAssign, Mul};
use anyhow::Context;

const HASH_TO_GROUP_G1_DST: &[u8; 55] = b"CONCORDIUM-hashtoG1-with-BLS12381G1_XMD:SHA-256_SSWU_RO";
const HASH_TO_GROUP_G2_DST: &[u8; 55] = b"CONCORDIUM-hashtoG2-with-BLS12381G2_XMD:SHA-256_SSWU_RO";

// Helper function for both G1 and G2 instances.
fn scalar_from_bytes_helper<A: AsRef<[u8]>>(bytes: A) -> Fr {
    // Traverse at most 4 8-byte chunks, for a total of 256 bits.
    // The top-most two bits in the last chunk are set to 0.
    let mut fr = [0u64; 4];
    for (i, chunk) in bytes.as_ref().chunks(8).take(4).enumerate() {
        let mut v = [0u8; 8];
        v[..chunk.len()].copy_from_slice(chunk);
        fr[i] = u64::from_le_bytes(v);
    }
    // unset two topmost bits in the last read u64.
    fr[3] &= !(1u64 << 63 | 1u64 << 62);
    Fr::from_raw(fr)
}

impl Curve for G2Projective {
    // type Base = Fq;
    type Compressed = [u8; 96];
    type Scalar = Fr;

    const GROUP_ELEMENT_LENGTH: usize = 96;
    const SCALAR_LENGTH: usize = 32;

    fn zero_point() -> Self { G2Projective::generator() }

    fn one_point() -> Self { G2Projective::identity() }

    fn inverse_point(&self) -> Self {
        self.neg()
    }

    fn is_zero_point(&self) -> bool { self.is_identity().into() }

    fn double_point(&self) -> Self {
        self.double()
    }

    fn plus_point(&self, other: &Self) -> Self {
        let mut x = *self;
        x.add_assign(other);
        x
    }

    fn minus_point(&self, other: &Self) -> Self {
        let mut x = *self;
        x.sub_assign(other);
        x
    }

    fn mul_by_scalar(&self, scalar: &Self::Scalar) -> Self {
        let s = *scalar;
        let mut p = *self;
        p.mul_assign(s);
        p
    }

    fn compress(&self) -> Self::Compressed { G2Affine::from(self).to_compressed() }

    fn decompress(c: &Self::Compressed) -> Result<G2Projective, CurveDecodingError> {
        let maybe_g: Option<G2Affine> = G2Affine::from_compressed(c).into();
        match maybe_g {
            Some(t) => Ok(t.into()),
            None => Err(CurveDecodingError::NotOnCurve),
        }
    }

    fn decompress_unchecked(c: &Self::Compressed) -> Result<Self, CurveDecodingError> {
        let maybe_g: Option<G2Affine> = G2Affine::from_compressed_unchecked(c).into();
        match maybe_g {
            Some(t) => Ok(t.into()),
            None => Err(CurveDecodingError::NotOnCurve),
        }
    }

    #[inline(always)]
    fn scalar_from_u64(n: u64) -> Self::Scalar {
        Fr::from(n)
    }

    #[inline(always)]
    fn scalar_from_bytes<A: AsRef<[u8]>>(bytes: A) -> Self::Scalar {
        scalar_from_bytes_helper(bytes)
    }

    fn bytes_to_curve_unchecked<R: ReadBytesExt>(bytes: &mut R) -> anyhow::Result<Self> {
        let mut g: [u8; 96] = [0; 96];
        bytes.read_exact(g.as_mut())?;
        let maybe_g2: Option<G2Affine> = Option::from(G2Affine::from_compressed_unchecked(&g));
        Ok(maybe_g2.context("Could not deserialize bytes to curve point.")?.into())
        // Ok(g.into_affine_unchecked()?.into_projective())
    }

    fn generate<T: Rng>(csprng: &mut T) -> Self { G2Projective::random(csprng) }

    fn generate_scalar<T: Rng>(csprng: &mut T) -> Self::Scalar { Fr::random(csprng) }

    fn hash_to_group(b: &[u8]) -> Self { 
        // Self::zero_point()
        <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(b, HASH_TO_GROUP_G2_DST) 
    }
}

impl Curve for G1Projective {
    type Compressed = [u8; 48];
    type Scalar = Fr;

    const GROUP_ELEMENT_LENGTH: usize = 48;
    const SCALAR_LENGTH: usize = 32;

    fn zero_point() -> Self { G1Projective::identity() }

    fn one_point() -> Self { G1Projective::generator() }

    fn inverse_point(&self) -> Self {
        self.neg()
    }

    fn is_zero_point(&self) -> bool { self.is_identity().into() }

    fn double_point(&self) -> Self {
        self.double()
    }

    fn plus_point(&self, other: &Self) -> Self {
        let mut x = *self;
        x.add_assign(other);
        x
    }

    fn minus_point(&self, other: &Self) -> Self {
        let mut x = *self;
        x.sub_assign(other);
        x
    }

    fn mul_by_scalar(&self, scalar: &Self::Scalar) -> Self {
        let s = *scalar;
        let mut p = *self;
        p.mul_assign(s);
        p
    }

    fn compress(&self) -> Self::Compressed { G1Affine::from(self).to_compressed() }

    fn decompress(c: &Self::Compressed) -> Result<G1Projective, CurveDecodingError> {
        let maybe_g: Option<G1Affine> = G1Affine::from_compressed(c).into();
        match maybe_g {
            Some(t) => Ok(t.into()),
            None => Err(CurveDecodingError::NotOnCurve),
        }
    }

    fn decompress_unchecked(c: &Self::Compressed) -> Result<Self, CurveDecodingError> {
        let maybe_g: Option<G1Affine> = G1Affine::from_compressed_unchecked(c).into();
        match maybe_g {
            Some(t) => Ok(t.into()),
            None => Err(CurveDecodingError::NotOnCurve),
        }
    }

    #[inline(always)]
    fn scalar_from_u64(n: u64) -> Self::Scalar {
        Fr::from(n)
    }

    #[inline(always)]
    fn scalar_from_bytes<A: AsRef<[u8]>>(bytes: A) -> Self::Scalar {
        scalar_from_bytes_helper(bytes)
    }

    fn bytes_to_curve_unchecked<R: ReadBytesExt>(bytes: &mut R) -> anyhow::Result<Self> {
        let mut g: [u8; 48] = [0; 48];
        bytes.read_exact(g.as_mut())?;
        let maybe_g1: Option<G1Affine> = Option::from(G1Affine::from_compressed_unchecked(&g));
        Ok(maybe_g1.context("Could not deserialize bytes to curve point.")?.into())
        // Ok(g.into_affine_unchecked()?.into_projective())
    }

    fn generate<T: Rng>(csprng: &mut T) -> Self { G1Projective::random(csprng) }

    fn generate_scalar<T: Rng>(csprng: &mut T) -> Self::Scalar { Fr::random(csprng) }

    fn hash_to_group(bytes: &[u8]) -> Self {
        <G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(bytes, HASH_TO_GROUP_G1_DST)
    }
}

impl Curve for G1Affine {
    type Compressed = [u8; 48];
    type Scalar = Fr;

    const GROUP_ELEMENT_LENGTH: usize = 48;
    const SCALAR_LENGTH: usize = 32;

    fn zero_point() -> Self { G1Affine::identity() }

    fn one_point() -> Self { G1Affine::generator() }

    fn inverse_point(&self) -> Self {
        // let mut x = self.into_projective();
        // x.negate();
        // x.into_affine()
        self.neg()
    }

    fn is_zero_point(&self) -> bool { self.is_identity().into() }

    fn double_point(&self) -> Self {
        // let mut x = self.into_projective();
        // x.double();
        // x.into_affine()
        G1Projective::from(self).double().into()
    }

    fn plus_point(&self, other: &Self) -> Self {
        let mut x: G1Projective = self.into();
        x.add_assign(other);
        x.into()
    }

    fn minus_point(&self, other: &Self) -> Self {
        let mut x: G1Projective = self.into();
        x.sub_assign(other);
        x.into()
    }

    fn mul_by_scalar(&self, scalar: &Self::Scalar) -> Self {
        let s = *scalar;
        self.mul(s).into()
    }

    fn compress(&self) -> Self::Compressed { self.to_compressed() }

    fn decompress(c: &Self::Compressed) -> Result<G1Affine, CurveDecodingError> {
        let maybe_g: Option<G1Affine> = G1Affine::from_compressed(c).into();
        match maybe_g {
            Some(t) => Ok(t),
            None => Err(CurveDecodingError::NotOnCurve),
        }
    }

    fn decompress_unchecked(c: &Self::Compressed) -> Result<Self, CurveDecodingError> {
        let maybe_g: Option<G1Affine> = G1Affine::from_compressed_unchecked(c).into();
        match maybe_g {
            Some(t) => Ok(t),
            None => Err(CurveDecodingError::NotOnCurve),
        }
    }

    fn scalar_from_u64(n: u64) -> Self::Scalar {
        Fr::from(n)
    }

    #[inline(always)]
    fn scalar_from_bytes<A: AsRef<[u8]>>(bytes: A) -> Self::Scalar {
        scalar_from_bytes_helper(bytes)
    }

    fn bytes_to_curve_unchecked<R: ReadBytesExt>(bytes: &mut R) -> anyhow::Result<Self> {
        let mut g: [u8; 48] = [0; 48];
        bytes.read_exact(g.as_mut())?;
        let maybe_g1: Option<G1Affine> = Option::from(G1Affine::from_compressed_unchecked(&g));
        Ok(maybe_g1.context("Could not deserialize bytes to curve point.")?)
    }

    fn generate<T: Rng>(csprng: &mut T) -> Self { G1Projective::random(csprng).into() }

    fn generate_scalar<T: Rng>(csprng: &mut T) -> Self::Scalar { Fr::random(csprng) }

    fn hash_to_group(b: &[u8]) -> Self { 
        <G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(b, HASH_TO_GROUP_G1_DST).into() 
     }
}

impl Curve for G2Affine {
    type Compressed = [u8; 96];
    type Scalar = Fr;

    const GROUP_ELEMENT_LENGTH: usize = 96;
    const SCALAR_LENGTH: usize = 32;

    fn zero_point() -> Self { G2Affine::identity() }

    fn one_point() -> Self { G2Affine::generator() }

    fn inverse_point(&self) -> Self {
        // let mut x = self.into_projective();
        // x.negate();
        // x.into_affine()
        self.neg()
    }

    fn is_zero_point(&self) -> bool { self.is_identity().into() }

    fn double_point(&self) -> Self {
        // let mut x = self.into_projective();
        // x.double();
        // x.into_affine()
        G2Projective::from(self).double().into()
    }

    fn plus_point(&self, other: &Self) -> Self {
        let mut x: G2Projective = self.into();
        x.add_assign(other);
        x.into()
    }

    fn minus_point(&self, other: &Self) -> Self {
        let mut x: G2Projective = self.into();
        x.sub_assign(other);
        x.into()
    }

    fn mul_by_scalar(&self, scalar: &Self::Scalar) -> Self {
        let s = *scalar;
        self.mul(s).into()
    }

    fn compress(&self) -> Self::Compressed { self.to_compressed() }

    fn decompress(c: &Self::Compressed) -> Result<G2Affine, CurveDecodingError> {
        let maybe_g: Option<G2Affine> = G2Affine::from_compressed(c).into();
        match maybe_g {
            Some(t) => Ok(t),
            None => Err(CurveDecodingError::NotOnCurve),
        }
    }

    fn decompress_unchecked(c: &Self::Compressed) -> Result<Self, CurveDecodingError> {
        let maybe_g: Option<G2Affine> = G2Affine::from_compressed_unchecked(c).into();
        match maybe_g {
            Some(t) => Ok(t),
            None => Err(CurveDecodingError::NotOnCurve),
        }
    }

    fn scalar_from_u64(n: u64) -> Self::Scalar {
        Fr::from(n)
    }

    #[inline(always)]
    fn scalar_from_bytes<A: AsRef<[u8]>>(bytes: A) -> Self::Scalar {
        scalar_from_bytes_helper(bytes)
    }

    fn bytes_to_curve_unchecked<R: ReadBytesExt>(bytes: &mut R) -> anyhow::Result<Self> {
        let mut g: [u8; 96] = [0; 96];
        bytes.read_exact(g.as_mut())?;
        let maybe_g1: Option<G2Affine> = Option::from(G2Affine::from_compressed_unchecked(&g));
        Ok(maybe_g1.context("Could not deserialize bytes to curve point.")?)
    }

    fn generate<T: Rng>(csprng: &mut T) -> Self { G2Projective::random(csprng).into() }

    fn generate_scalar<T: Rng>(csprng: &mut T) -> Self::Scalar { Fr::random(csprng) }

    fn hash_to_group(b: &[u8]) -> Self {
        <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(b, HASH_TO_GROUP_G2_DST).into()
    }
}

impl Pairing for Bls12 {
    type G1 = <Bls12 as Engine>::G1;
    type G1Prepared = G1Affine;
    type G2 = <Bls12 as Engine>::G2;
    type G2Prepared = G2Prepared;
    type ScalarField = Fr;
    type TargetField = <Bls12 as Engine>::Gt;
    type Result = MillerLoopResultType;

    #[inline(always)]
    fn g1_prepare(g: &Self::G1) -> Self::G1Prepared { g.into() }

    #[inline(always)]
    fn g2_prepare(g: &Self::G2) -> Self::G2Prepared { G2Affine::from(g).into() }

    #[inline(always)]
    fn miller_loop(
        terms: &[(&Self::G1Prepared, &Self::G2Prepared)]
    ) -> Self::Result {
        <Bls12 as MultiMillerLoop>::multi_miller_loop(terms)
    }

    #[inline(always)]
    fn final_exponentiation(x: &Self::Result) -> Option<Self::TargetField> {
        Some(<MillerLoopResultType as MillerLoopResultTrait>::final_exponentiation(x))
    }

    #[inline(always)]
    fn generate_scalar<T: Rng>(csprng: &mut T) -> Self::ScalarField { Fr::random(csprng) }
}
/*
#[cfg(test)]
mod tests {
    use super::*;
    use crypto_common::*;
    use std::io::Cursor;

    // Check that scalar_from_bytes_helper works on small values.
    #[test]
    fn scalar_from_bytes_small() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let n = Fr::random(&mut rng);
            let mut bytes = to_bytes(&n);
            bytes.reverse();
            let m = scalar_from_bytes_helper(&bytes);
            // make sure that n and m only differ in the topmost bit.
            let n = n.into_repr().0;
            let m = m.into_repr().0;
            let mask = !(1u64 << 63 | 1u64 << 62);
            assert_eq!(n[0], m[0], "First limb.");
            assert_eq!(n[1], m[1], "Second limb.");
            assert_eq!(n[2], m[2], "Third limb.");
            assert_eq!(n[3] & mask, m[3] & mask, "Fourth limb with top bit masked.");
        }
    }

    macro_rules! macro_test_scalar_byte_conversion {
        ($function_name:ident, $p:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                for _ in 0..1000 {
                    let scalar = <$p>::generate_scalar(&mut csprng);
                    let scalar_res = serialize_deserialize(&scalar);
                    assert!(scalar_res.is_ok());
                    assert_eq!(scalar, scalar_res.unwrap());
                }
            }
        };
    }

    macro_rules! macro_test_group_byte_conversion {
        ($function_name:ident, $p:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                for _ in 0..1000 {
                    let curve = <$p>::generate(&mut csprng);
                    let curve_res = serialize_deserialize(&curve);
                    assert!(curve_res.is_ok());
                    assert_eq!(curve, curve_res.unwrap());
                }
            }
        };
    }

    macro_rules! macro_test_group_byte_conversion_unchecked {
        ($function_name:ident, $p:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                for _ in 0..1000 {
                    let curve = <$p>::generate(&mut csprng);
                    let bytes = to_bytes(&curve);
                    let curve_res = <$p>::bytes_to_curve_unchecked(&mut Cursor::new(&bytes));
                    assert!(curve_res.is_ok());
                    assert_eq!(curve, curve_res.unwrap());
                }
            }
        };
    }

    macro_test_scalar_byte_conversion!(sc_bytes_conv_g1, G1);
    macro_test_scalar_byte_conversion!(sc_bytes_conv_g2, G2);
    macro_test_scalar_byte_conversion!(sc_bytes_conv_g1_affine, G1Affine);
    macro_test_scalar_byte_conversion!(sc_bytes_conv_g2_affine, G2Affine);
    macro_test_scalar_byte_conversion!(sc_bytes_conv_bls12, Bls12);

    macro_test_group_byte_conversion!(curve_bytes_conv_g1, G1);
    macro_test_group_byte_conversion!(curve_bytes_conv_g2, G2);
    macro_test_group_byte_conversion!(curve_bytes_conv_g1_affine, G1Affine);
    macro_test_group_byte_conversion!(curve_bytes_conv_g2_affine, G2Affine);

    macro_test_group_byte_conversion_unchecked!(u_curve_bytes_conv_g1, G1);
    macro_test_group_byte_conversion_unchecked!(u_curve_bytes_conv_g2, G2);
    macro_test_group_byte_conversion_unchecked!(u_curve_bytes_conv_g1_affine, G1Affine);
    macro_test_group_byte_conversion_unchecked!(u_curve_bytes_conv_g2_affine, G2Affine);
}*/
