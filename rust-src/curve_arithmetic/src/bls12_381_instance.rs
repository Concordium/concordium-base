// Authors:

use crate::{bls12_381_g1hash::*, bls12_381_g2hash::*, curve_arithmetic::*};
use byteorder::ReadBytesExt;
use ff::{Field, PrimeField};
use group::{CurveAffine, CurveProjective, EncodedPoint};
use pairing::{
    bls12_381::{
        Bls12, Fq, Fr, FrRepr, G1Affine, G1Compressed, G1Prepared, G2Affine, G2Compressed,
        G2Prepared, G1, G2,
    },
    Engine, PairingCurveAffine,
};
use rand::*;

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
    Fr::from_repr(FrRepr(fr)).expect("The scalar with top two bits erased should be valid.")
}

impl Curve for G2 {
    type Base = Fq;
    type Compressed = G2Compressed;
    type Scalar = Fr;

    const GROUP_ELEMENT_LENGTH: usize = 96;
    const SCALAR_LENGTH: usize = 32;

    fn zero_point() -> Self { G2::zero() }

    fn one_point() -> Self { G2::one() }

    fn inverse_point(&self) -> Self {
        let mut x = *self;
        x.negate();
        x
    }

    fn is_zero_point(&self) -> bool { self.is_zero() }

    fn double_point(&self) -> Self {
        let mut x = *self;
        x.double();
        x
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

    fn compress(&self) -> Self::Compressed { self.into_affine().into_compressed() }

    fn decompress(c: &Self::Compressed) -> Result<G2, CurveDecodingError> {
        match c.into_affine() {
            Ok(t) => Ok(t.into_projective()),
            Err(_) => Err(CurveDecodingError::NotOnCurve),
        }
    }

    fn decompress_unchecked(c: &Self::Compressed) -> Result<Self, CurveDecodingError> {
        match c.into_affine_unchecked() {
            Ok(t) => Ok(t.into_projective()),
            Err(_) => Err(CurveDecodingError::NotOnCurve),
        }
    }

    #[inline(always)]
    fn scalar_from_u64(n: u64) -> Self::Scalar {
        Fr::from_repr(FrRepr::from(n)).expect("Every u64 is representable.")
    }

    #[inline(always)]
    fn scalar_from_bytes<A: AsRef<[u8]>>(bytes: A) -> Self::Scalar {
        scalar_from_bytes_helper(bytes)
    }

    fn bytes_to_curve_unchecked<R: ReadBytesExt>(bytes: &mut R) -> anyhow::Result<Self> {
        let mut g = G2Compressed::empty();
        bytes.read_exact(g.as_mut())?;
        Ok(g.into_affine_unchecked()?.into_projective())
    }

    fn generate<T: Rng>(csprng: &mut T) -> Self { G2::random(csprng) }

    fn generate_scalar<T: Rng>(csprng: &mut T) -> Self::Scalar { Fr::random(csprng) }

    fn hash_to_group(b: &[u8]) -> Self { hash_to_curve_g2(b, HASH_TO_GROUP_G2_DST) }
}

impl Curve for G1 {
    type Base = Fq;
    type Compressed = G1Compressed;
    type Scalar = Fr;

    const GROUP_ELEMENT_LENGTH: usize = 48;
    const SCALAR_LENGTH: usize = 32;

    fn zero_point() -> Self { G1::zero() }

    fn one_point() -> Self { G1::one() }

    fn inverse_point(&self) -> Self {
        let mut x = *self;
        x.negate();
        x
    }

    fn is_zero_point(&self) -> bool { self.is_zero() }

    fn double_point(&self) -> Self {
        let mut x = *self;
        x.double();
        x
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

    fn compress(&self) -> Self::Compressed { self.into_affine().into_compressed() }

    fn decompress(c: &Self::Compressed) -> Result<G1, CurveDecodingError> {
        match c.into_affine() {
            Ok(t) => Ok(t.into_projective()),
            Err(_) => Err(CurveDecodingError::NotOnCurve),
        }
    }

    fn decompress_unchecked(c: &Self::Compressed) -> Result<Self, CurveDecodingError> {
        match c.into_affine_unchecked() {
            Ok(t) => Ok(t.into_projective()),
            Err(_) => Err(CurveDecodingError::NotOnCurve),
        }
    }

    #[inline(always)]
    fn scalar_from_u64(n: u64) -> Self::Scalar {
        Fr::from_repr(FrRepr::from(n)).expect("Every u64 is representable.")
    }

    #[inline(always)]
    fn scalar_from_bytes<A: AsRef<[u8]>>(bytes: A) -> Self::Scalar {
        scalar_from_bytes_helper(bytes)
    }

    fn bytes_to_curve_unchecked<R: ReadBytesExt>(bytes: &mut R) -> anyhow::Result<Self> {
        let mut g = G1Compressed::empty();
        bytes.read_exact(g.as_mut())?;
        Ok(g.into_affine_unchecked()?.into_projective())
    }

    fn generate<T: Rng>(csprng: &mut T) -> Self { G1::random(csprng) }

    fn generate_scalar<T: Rng>(csprng: &mut T) -> Self::Scalar { Fr::random(csprng) }

    fn hash_to_group(bytes: &[u8]) -> Self { hash_to_curve(bytes, HASH_TO_GROUP_G1_DST) }
}

impl Curve for G1Affine {
    type Base = Fq;
    type Compressed = G1Compressed;
    type Scalar = Fr;

    const GROUP_ELEMENT_LENGTH: usize = 48;
    const SCALAR_LENGTH: usize = 32;

    fn zero_point() -> Self { G1Affine::zero() }

    fn one_point() -> Self { G1Affine::one() }

    fn inverse_point(&self) -> Self {
        let mut x = self.into_projective();
        x.negate();
        x.into_affine()
    }

    fn is_zero_point(&self) -> bool { self.is_zero() }

    fn double_point(&self) -> Self {
        let mut x = self.into_projective();
        x.double();
        x.into_affine()
    }

    fn plus_point(&self, other: &Self) -> Self {
        let mut x = self.into_projective();
        x.add_assign_mixed(other);
        x.into_affine()
    }

    fn minus_point(&self, other: &Self) -> Self {
        let mut x = self.into_projective();
        x.sub_assign(&other.into_projective());
        x.into_affine()
    }

    fn mul_by_scalar(&self, scalar: &Self::Scalar) -> Self {
        let s = *scalar;
        self.mul(s).into_affine()
    }

    fn compress(&self) -> Self::Compressed { self.into_compressed() }

    fn decompress(c: &Self::Compressed) -> Result<G1Affine, CurveDecodingError> {
        match c.into_affine() {
            Ok(t) => Ok(t),
            Err(_) => Err(CurveDecodingError::NotOnCurve),
        }
    }

    fn decompress_unchecked(c: &Self::Compressed) -> Result<Self, CurveDecodingError> {
        match c.into_affine_unchecked() {
            Ok(t) => Ok(t),
            Err(_) => Err(CurveDecodingError::NotOnCurve),
        }
    }

    fn scalar_from_u64(n: u64) -> Self::Scalar {
        Fr::from_repr(FrRepr::from(n)).expect("Every u64 is representable.")
    }

    #[inline(always)]
    fn scalar_from_bytes<A: AsRef<[u8]>>(bytes: A) -> Self::Scalar {
        scalar_from_bytes_helper(bytes)
    }

    fn bytes_to_curve_unchecked<R: ReadBytesExt>(bytes: &mut R) -> anyhow::Result<Self> {
        let mut g = G1Compressed::empty();
        bytes.read_exact(g.as_mut())?;
        Ok(g.into_affine_unchecked()?)
    }

    fn generate<T: Rng>(csprng: &mut T) -> Self { G1::random(csprng).into_affine() }

    fn generate_scalar<T: Rng>(csprng: &mut T) -> Self::Scalar { Fr::random(csprng) }

    fn hash_to_group(b: &[u8]) -> Self { hash_to_curve(b, HASH_TO_GROUP_G1_DST).into_affine() }
}

impl Curve for G2Affine {
    type Base = Fq;
    type Compressed = G2Compressed;
    type Scalar = Fr;

    const GROUP_ELEMENT_LENGTH: usize = 96;
    const SCALAR_LENGTH: usize = 32;

    fn zero_point() -> Self { G2Affine::zero() }

    fn one_point() -> Self { G2Affine::one() }

    fn inverse_point(&self) -> Self {
        let mut x = self.into_projective();
        x.negate();
        x.into_affine()
    }

    fn is_zero_point(&self) -> bool { self.is_zero() }

    fn double_point(&self) -> Self {
        let mut x = self.into_projective();
        x.double();
        x.into_affine()
    }

    fn plus_point(&self, other: &Self) -> Self {
        let mut x = self.into_projective();
        x.add_assign_mixed(other);
        x.into_affine()
    }

    fn minus_point(&self, other: &Self) -> Self {
        let mut x = self.into_projective();
        x.sub_assign(&other.into_projective());
        x.into_affine()
    }

    fn mul_by_scalar(&self, scalar: &Self::Scalar) -> Self {
        let s = *scalar;
        self.mul(s).into_affine()
    }

    fn compress(&self) -> Self::Compressed { self.into_compressed() }

    fn decompress(c: &Self::Compressed) -> Result<G2Affine, CurveDecodingError> {
        match c.into_affine() {
            Ok(t) => Ok(t),
            Err(_) => Err(CurveDecodingError::NotOnCurve),
        }
    }

    fn decompress_unchecked(c: &Self::Compressed) -> Result<Self, CurveDecodingError> {
        match c.into_affine_unchecked() {
            Ok(t) => Ok(t),
            Err(_) => Err(CurveDecodingError::NotOnCurve),
        }
    }

    fn scalar_from_u64(n: u64) -> Self::Scalar {
        Fr::from_repr(FrRepr::from(n)).expect("Every u64 is representable.")
    }

    #[inline(always)]
    fn scalar_from_bytes<A: AsRef<[u8]>>(bytes: A) -> Self::Scalar {
        scalar_from_bytes_helper(bytes)
    }

    fn bytes_to_curve_unchecked<R: ReadBytesExt>(bytes: &mut R) -> anyhow::Result<Self> {
        let mut g = G2Compressed::empty();
        bytes.read_exact(g.as_mut())?;
        Ok(g.into_affine_unchecked()?)
    }

    fn generate<T: Rng>(csprng: &mut T) -> Self { G2::random(csprng).into_affine() }

    fn generate_scalar<T: Rng>(csprng: &mut T) -> Self::Scalar { Fr::random(csprng) }

    fn hash_to_group(b: &[u8]) -> Self { hash_to_curve_g2(b, HASH_TO_GROUP_G2_DST).into_affine() }
}

impl Pairing for Bls12 {
    type BaseField = <Bls12 as Engine>::Fq;
    type G1 = <Bls12 as Engine>::G1;
    type G1Prepared = G1Prepared;
    type G2 = <Bls12 as Engine>::G2;
    type G2Prepared = G2Prepared;
    type ScalarField = Fr;
    type TargetField = <Bls12 as Engine>::Fqk;

    #[inline(always)]
    fn g1_prepare(g: &Self::G1) -> Self::G1Prepared { g.into_affine().prepare() }

    #[inline(always)]
    fn g2_prepare(g: &Self::G2) -> Self::G2Prepared { g.into_affine().prepare() }

    #[inline(always)]
    fn miller_loop<'a, I>(i: I) -> Self::TargetField
    where
        I: IntoIterator<Item = &'a (&'a Self::G1Prepared, &'a Self::G2Prepared)>, {
        <Bls12 as Engine>::miller_loop(i)
    }

    #[inline(always)]
    fn final_exponentiation(x: &Self::TargetField) -> Option<Self::TargetField> {
        <Bls12 as Engine>::final_exponentiation(x)
    }

    #[inline(always)]
    fn generate_scalar<T: Rng>(csprng: &mut T) -> Self::ScalarField { Fr::random(csprng) }
}

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
}
