// Authors:

use crate::{bls12_381_g1hash::*, curve_arithmetic::*};
use byteorder::ReadBytesExt;
use failure::Fallible;
use ff::{Field, PrimeField};
use group::{CurveAffine, CurveProjective, EncodedPoint};
use pairing::{
    bls12_381::{Bls12, Fq, Fr, FrRepr, G1Affine, G1Compressed, G2Affine, G2Compressed, G1, G2},
    Engine,
};
use rand::*;

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
        x.sub_assign(&other);
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

    fn scalar_from_u64(n: u64) -> Self::Scalar {
        Fr::from_repr(FrRepr::from(n)).expect("Every u64 is representable.")
    }

    fn bytes_to_curve_unchecked<R: ReadBytesExt>(bytes: &mut R) -> Fallible<Self> {
        let mut g = G2Compressed::empty();
        bytes.read_exact(g.as_mut())?;
        Ok(g.into_affine_unchecked()?.into_projective())
    }

    fn generate<T: Rng>(csprng: &mut T) -> Self { G2::random(csprng) }

    fn generate_scalar<T: Rng>(csprng: &mut T) -> Self::Scalar { Fr::random(csprng) }

    fn hash_to_group(_b: &[u8]) -> Self {
        unimplemented!("hash_to_group_element for G2 of Bls12_381 is not implemented")
    }
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
        x.sub_assign(&other);
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

    fn scalar_from_u64(n: u64) -> Self::Scalar {
        Fr::from_repr(FrRepr::from(n)).expect("Every u64 is representable.")
    }

    fn bytes_to_curve_unchecked<R: ReadBytesExt>(bytes: &mut R) -> Fallible<Self> {
        let mut g = G1Compressed::empty();
        bytes.read_exact(g.as_mut())?;
        Ok(g.into_affine_unchecked()?.into_projective())
    }

    fn generate<T: Rng>(csprng: &mut T) -> Self { G1::random(csprng) }

    fn generate_scalar<T: Rng>(csprng: &mut T) -> Self::Scalar { Fr::random(csprng) }

    fn hash_to_group(bytes: &[u8]) -> Self { hash_to_g1(bytes) }
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

    fn bytes_to_curve_unchecked<R: ReadBytesExt>(bytes: &mut R) -> Fallible<Self> {
        let mut g = G1Compressed::empty();
        bytes.read_exact(g.as_mut())?;
        Ok(g.into_affine_unchecked()?)
    }

    fn generate<T: Rng>(csprng: &mut T) -> Self { G1::random(csprng).into_affine() }

    fn generate_scalar<T: Rng>(csprng: &mut T) -> Self::Scalar { Fr::random(csprng) }

    fn hash_to_group(b: &[u8]) -> Self { hash_to_g1(b).into_affine() }
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

    fn bytes_to_curve_unchecked<R: ReadBytesExt>(bytes: &mut R) -> Fallible<Self> {
        let mut g = G2Compressed::empty();
        bytes.read_exact(g.as_mut())?;
        Ok(g.into_affine_unchecked()?)
    }

    fn generate<T: Rng>(csprng: &mut T) -> Self { G2::random(csprng).into_affine() }

    fn generate_scalar<T: Rng>(csprng: &mut T) -> Self::Scalar { Fr::random(csprng) }

    fn hash_to_group(_b: &[u8]) -> Self {
        unimplemented!("hash_to_group_element for G2Affine of Bls12_381 is not implemented")
    }
}

impl Pairing for Bls12 {
    type BaseField = <Bls12 as Engine>::Fq;
    type G1 = <Bls12 as Engine>::G1;
    type G2 = <Bls12 as Engine>::G2;
    type ScalarField = Fr;
    type TargetField = <Bls12 as Engine>::Fqk;

    const SCALAR_LENGTH: usize = 32;

    fn pair(p: <Bls12 as Engine>::G1, q: <Bls12 as Engine>::G2) -> Self::TargetField {
        <Bls12 as Engine>::pairing(p.into_affine(), q.into_affine())
    }

    fn generate_scalar<T: Rng>(csprng: &mut T) -> Self::ScalarField { Fr::random(csprng) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_common::*;
    use std::io::Cursor;

    // For development only, delete later
    #[test]
    fn smoke_test_hash() {
        let mut rng = thread_rng();
        for _i in 0..10000 {
            let bytes = rng.gen::<[u8; 32]>();
            let _ = <Bls12 as Pairing>::G1::hash_to_group(&bytes);
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
