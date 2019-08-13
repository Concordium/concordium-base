// Authors:
// - bm@concordium.com
//

use crate::bls12_381_hashing::*;
use crate::curve_arithmetic::*;
use byteorder::{BigEndian, ReadBytesExt};
use pairing::{
    bls12_381::{
        Bls12, Fq, FqRepr, Fr, FrRepr, G1Affine, G1Compressed, G2Affine, G2Compressed, G1, G2,
    },
    CurveAffine, CurveProjective, EncodedPoint, Engine, PrimeField,
};
use rand::*;
use std::io::{Cursor, Read};

impl Curve for G2 {
    type Base = Fq;
    type Compressed = G2Compressed;
    type Scalar = Fr;

    const GROUP_ELEMENT_LENGTH: usize = 96;
    const SCALAR_LENGTH: usize = 32;

    fn zero_point() -> Self {
        G2::zero()
    }

    fn one_point() -> Self {
        G2::one()
    }

    fn inverse_point(&self) -> Self {
        let mut x = *self;
        x.negate();
        x
    }

    fn is_zero_point(&self) -> bool {
        self.is_zero()
    }

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

    fn compress(&self) -> Self::Compressed {
        self.into_affine().into_compressed()
    }

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

    fn scalar_to_bytes(e: &Self::Scalar) -> Box<[u8]> {
        let frpr = &e.into_repr();
        let mut bytes = [0u8; Self::SCALAR_LENGTH];
        let mut i = 0;
        for a in frpr.as_ref().iter().rev() {
            bytes[i..(i + 8)].copy_from_slice(&a.to_be_bytes());
            i += 8;
        }
        Box::new(bytes)
    }

    fn bytes_to_scalar(bytes: &mut Cursor<&[u8]>) -> Result<Self::Scalar, FieldDecodingError> {
        let mut frrepr: FrRepr = FrRepr([0u64; 4]);
        let mut i = true;
        for digit in frrepr.as_mut().iter_mut().rev() {
            *digit = bytes
                .read_u64::<BigEndian>()
                .map_err(|_| FieldDecodingError::NotFieldElement)?;
            if i {
                *digit &= !(1 << 63);
                i = false;
            }
        }
        match Fr::from_repr(frrepr) {
            Ok(fr) => Ok(fr),
            Err(_) => Err(FieldDecodingError::NotFieldElement),
        }
    }

    fn scalar_from_u64(n: u64) -> Result<Self::Scalar, FieldDecodingError> {
        match Fr::from_repr(FrRepr::from(n)) {
            Ok(sc) => Ok(sc),
            Err(_) => Err(FieldDecodingError::NotFieldElement),
        }
    }

    fn curve_to_bytes(&self) -> Box<[u8]> {
        let g = self.into_affine().into_compressed();
        let g_bytes = g.as_ref();
        let mut bytes = [0u8; Self::GROUP_ELEMENT_LENGTH];
        bytes.copy_from_slice(&g_bytes);
        Box::new(bytes)
    }

    fn bytes_to_curve(bytes: &mut Cursor<&[u8]>) -> Result<Self, CurveDecodingError> {
        let mut g = G2Compressed::empty();
        bytes
            .read_exact(g.as_mut())
            .map_err(|_| CurveDecodingError::NotOnCurve)?;
        match g.into_affine() {
            Err(_) => Err(CurveDecodingError::NotOnCurve),
            Ok(g_affine) => Ok(g_affine.into_projective()),
        }
    }

    fn bytes_to_curve_unchecked(bytes: &mut Cursor<&[u8]>) -> Result<Self, CurveDecodingError> {
        let mut g = G2Compressed::empty();
        bytes
            .read_exact(g.as_mut())
            .map_err(|_| CurveDecodingError::NotOnCurve)?;
        match g.into_affine_unchecked() {
            Err(_) => Err(CurveDecodingError::NotOnCurve),
            Ok(g_affine) => Ok(g_affine.into_projective()),
        }
    }

    fn generate<T: Rng>(csprng: &mut T) -> Self {
        G2::rand(csprng)
    }

    fn generate_scalar<T: Rng>(csprng: &mut T) -> Self::Scalar {
        Fr::rand(csprng)
    }

    fn hash_to_group_element(b: &[u8]) -> Self {
        unimplemented!("hashing to G2 of Bls12_381 is not implemented")
    }
}

impl Curve for G1 {
    type Base = Fq;
    type Compressed = G1Compressed;
    type Scalar = Fr;

    const GROUP_ELEMENT_LENGTH: usize = 48;
    const SCALAR_LENGTH: usize = 32;

    fn zero_point() -> Self {
        G1::zero()
    }

    fn one_point() -> Self {
        G1::one()
    }

    fn inverse_point(&self) -> Self {
        let mut x = *self;
        x.negate();
        x
    }

    fn is_zero_point(&self) -> bool {
        self.is_zero()
    }

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

    fn compress(&self) -> Self::Compressed {
        self.into_affine().into_compressed()
    }

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

    fn scalar_to_bytes(e: &Self::Scalar) -> Box<[u8]> {
        let frpr = &e.into_repr();
        let mut bytes = [0u8; Self::SCALAR_LENGTH];
        let mut i = 0;
        for a in frpr.as_ref().iter().rev() {
            bytes[i..(i + 8)].copy_from_slice(&a.to_be_bytes());
            i += 8;
        }
        Box::new(bytes)
    }

    fn bytes_to_scalar(bytes: &mut Cursor<&[u8]>) -> Result<Self::Scalar, FieldDecodingError> {
        let mut frrepr: FrRepr = FrRepr([0u64; 4]);
        let mut i = true;
        for digit in frrepr.as_mut().iter_mut().rev() {
            *digit = bytes
                .read_u64::<BigEndian>()
                .map_err(|_| FieldDecodingError::NotFieldElement)?;
            if i {
                *digit &= !(1 << 63);
                i = false;
            }
        }
        match Fr::from_repr(frrepr) {
            Ok(fr) => Ok(fr),
            Err(_) => Err(FieldDecodingError::NotFieldElement),
        }
    }

    fn scalar_from_u64(n: u64) -> Result<Self::Scalar, FieldDecodingError> {
        match Fr::from_repr(FrRepr::from(n)) {
            Ok(sc) => Ok(sc),

            Err(_) => Err(FieldDecodingError::NotFieldElement),
        }
    }

    fn curve_to_bytes(&self) -> Box<[u8]> {
        let g = self.into_affine().into_compressed();
        let g_bytes = g.as_ref();
        let mut bytes = [0u8; Self::GROUP_ELEMENT_LENGTH];
        bytes.copy_from_slice(&g_bytes);
        Box::new(bytes)
    }

    fn bytes_to_curve(bytes: &mut Cursor<&[u8]>) -> Result<Self, CurveDecodingError> {
        let mut g = G1Compressed::empty();
        bytes
            .read_exact(g.as_mut())
            .map_err(|_| CurveDecodingError::NotOnCurve)?;
        match g.into_affine() {
            Err(_) => Err(CurveDecodingError::NotOnCurve),
            Ok(g_affine) => Ok(g_affine.into_projective()),
        }
    }

    fn bytes_to_curve_unchecked(bytes: &mut Cursor<&[u8]>) -> Result<Self, CurveDecodingError> {
        let mut g = G1Compressed::empty();
        bytes
            .read_exact(g.as_mut())
            .map_err(|_| CurveDecodingError::NotOnCurve)?;
        match g.into_affine_unchecked() {
            Err(_) => Err(CurveDecodingError::NotOnCurve),
            Ok(g_affine) => Ok(g_affine.into_projective()),
        }
    }

    fn generate<T: Rng>(csprng: &mut T) -> Self {
        G1::rand(csprng)
    }

    fn generate_scalar<T: Rng>(csprng: &mut T) -> Self::Scalar {
        Fr::rand(csprng)
    }

    fn hash_to_group_element(bytes: &[u8]) -> Self {
        // WIP, see bls12_381_hashing.rs
        unimplemented!("hashing to G1 of Bls12_381 is not implemented");
    }
}

impl Curve for G1Affine {
    type Base = Fq;
    type Compressed = G1Compressed;
    type Scalar = Fr;

    const GROUP_ELEMENT_LENGTH: usize = 48;
    const SCALAR_LENGTH: usize = 32;

    fn zero_point() -> Self {
        G1Affine::zero()
    }

    fn one_point() -> Self {
        G1Affine::one()
    }

    fn inverse_point(&self) -> Self {
        let mut x = self.into_projective();
        x.negate();
        x.into_affine()
    }

    fn is_zero_point(&self) -> bool {
        self.is_zero()
    }

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

    fn compress(&self) -> Self::Compressed {
        self.into_compressed()
    }

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

    fn scalar_to_bytes(e: &Self::Scalar) -> Box<[u8]> {
        let frpr = &e.into_repr();
        let mut bytes = [0u8; Self::SCALAR_LENGTH];
        let mut i = 0;
        for a in frpr.as_ref().iter().rev() {
            bytes[i..(i + 8)].copy_from_slice(&a.to_be_bytes());
            i += 8;
        }
        Box::new(bytes)
    }

    fn bytes_to_scalar(bytes: &mut Cursor<&[u8]>) -> Result<Self::Scalar, FieldDecodingError> {
        let mut frrepr: FrRepr = FrRepr([0u64; 4]);
        let mut i = true;
        for digit in frrepr.as_mut().iter_mut().rev() {
            *digit = bytes
                .read_u64::<BigEndian>()
                .map_err(|_| FieldDecodingError::NotFieldElement)?;
            if i {
                *digit &= !(1 << 63);
                i = false;
            }
        }
        match Fr::from_repr(frrepr) {
            Ok(fr) => Ok(fr),
            Err(_) => Err(FieldDecodingError::NotFieldElement),
        }
    }

    fn scalar_from_u64(n: u64) -> Result<Self::Scalar, FieldDecodingError> {
        match Fr::from_repr(FrRepr::from(n)) {
            Ok(sc) => Ok(sc),
            Err(_) => Err(FieldDecodingError::NotFieldElement),
        }
    }

    fn curve_to_bytes(&self) -> Box<[u8]> {
        let g = self.into_compressed();
        let g_bytes = g.as_ref();
        let mut bytes = [0u8; Self::GROUP_ELEMENT_LENGTH];
        bytes.copy_from_slice(&g_bytes);
        Box::new(bytes)
    }

    fn bytes_to_curve(bytes: &mut Cursor<&[u8]>) -> Result<Self, CurveDecodingError> {
        let mut g = G1Compressed::empty();
        bytes
            .read_exact(g.as_mut())
            .map_err(|_| CurveDecodingError::NotOnCurve)?;
        match g.into_affine() {
            Err(_) => Err(CurveDecodingError::NotOnCurve),
            Ok(g_affine) => Ok(g_affine),
        }
    }

    fn bytes_to_curve_unchecked(bytes: &mut Cursor<&[u8]>) -> Result<Self, CurveDecodingError> {
        let mut g = G1Compressed::empty();
        bytes
            .read_exact(g.as_mut())
            .map_err(|_| CurveDecodingError::NotOnCurve)?;
        match g.into_affine_unchecked() {
            Err(_) => Err(CurveDecodingError::NotOnCurve),
            Ok(g_affine) => Ok(g_affine),
        }
    }

    fn generate<T: Rng>(csprng: &mut T) -> Self {
        G1::rand(csprng).into_affine()
    }

    fn generate_scalar<T: Rng>(csprng: &mut T) -> Self::Scalar {
        Fr::rand(csprng)
    }

    fn hash_to_group_element(b: &[u8]) -> Self {
        unimplemented!("hashing to G1Affine of Bls12_381 is not implemented")
    }
}

impl Curve for G2Affine {
    type Base = Fq;
    type Compressed = G2Compressed;
    type Scalar = Fr;

    const GROUP_ELEMENT_LENGTH: usize = 96;
    const SCALAR_LENGTH: usize = 32;

    fn zero_point() -> Self {
        G2Affine::zero()
    }

    fn one_point() -> Self {
        G2Affine::one()
    }

    fn inverse_point(&self) -> Self {
        let mut x = self.into_projective();
        x.negate();
        x.into_affine()
    }

    fn is_zero_point(&self) -> bool {
        self.is_zero()
    }

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

    fn compress(&self) -> Self::Compressed {
        self.into_compressed()
    }

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

    fn scalar_to_bytes(e: &Self::Scalar) -> Box<[u8]> {
        let frpr = &e.into_repr();
        let mut bytes = [0u8; Self::SCALAR_LENGTH];
        let mut i = 0;
        for a in frpr.as_ref().iter().rev() {
            bytes[i..(i + 8)].copy_from_slice(&a.to_be_bytes());
            i += 8;
        }
        Box::new(bytes)
    }

    fn bytes_to_scalar(bytes: &mut Cursor<&[u8]>) -> Result<Self::Scalar, FieldDecodingError> {
        let mut frrepr: FrRepr = FrRepr([0u64; 4]);
        let mut i = true;
        for digit in frrepr.as_mut().iter_mut().rev() {
            *digit = bytes
                .read_u64::<BigEndian>()
                .map_err(|_| FieldDecodingError::NotFieldElement)?;
            if i {
                *digit &= !(1 << 63);
                i = false;
            }
        }
        match Fr::from_repr(frrepr) {
            Ok(fr) => Ok(fr),
            Err(_) => Err(FieldDecodingError::NotFieldElement),
        }
    }

    fn scalar_from_u64(n: u64) -> Result<Self::Scalar, FieldDecodingError> {
        match Fr::from_repr(FrRepr::from(n)) {
            Ok(sc) => Ok(sc),
            Err(_) => Err(FieldDecodingError::NotFieldElement),
        }
    }

    fn curve_to_bytes(&self) -> Box<[u8]> {
        let g = self.into_compressed();
        let g_bytes = g.as_ref();
        let mut bytes = [0u8; Self::GROUP_ELEMENT_LENGTH];
        bytes.copy_from_slice(&g_bytes);
        Box::new(bytes)
    }

    fn bytes_to_curve(bytes: &mut Cursor<&[u8]>) -> Result<Self, CurveDecodingError> {
        let mut g = G2Compressed::empty();
        bytes
            .read_exact(g.as_mut())
            .map_err(|_| CurveDecodingError::NotOnCurve)?;
        match g.into_affine() {
            Err(_) => Err(CurveDecodingError::NotOnCurve),
            Ok(g_affine) => Ok(g_affine),
        }
    }

    fn bytes_to_curve_unchecked(bytes: &mut Cursor<&[u8]>) -> Result<Self, CurveDecodingError> {
        let mut g = G2Compressed::empty();
        bytes
            .read_exact(g.as_mut())
            .map_err(|_| CurveDecodingError::NotOnCurve)?;
        match g.into_affine_unchecked() {
            Err(_) => Err(CurveDecodingError::NotOnCurve),
            Ok(g_affine) => Ok(g_affine),
        }
    }

    fn generate<T: Rng>(csprng: &mut T) -> Self {
        G2::rand(csprng).into_affine()
    }

    fn generate_scalar<T: Rng>(csprng: &mut T) -> Self::Scalar {
        Fr::rand(csprng)
    }

    fn hash_to_group_element(b: &[u8]) -> Self {
        unimplemented!("hashing to G2Affine of Bls12_381 is not implemented")
    }
}

impl Pairing for Bls12 {
    type BaseField = <Bls12 as Engine>::Fq;
    type G_1 = <Bls12 as Engine>::G1;
    type G_2 = <Bls12 as Engine>::G2;
    type ScalarField = Fr;
    type TargetField = <Bls12 as Engine>::Fqk;

    const SCALAR_LENGTH: usize = 32;

    fn pair(p: <Bls12 as Engine>::G1, q: <Bls12 as Engine>::G2) -> Self::TargetField {
        <Bls12 as Engine>::pairing(p.into_affine(), q.into_affine())
    }

    fn scalar_to_bytes(e: &Self::ScalarField) -> Box<[u8]> {
        let frpr = &e.into_repr();
        let mut bytes = [0u8; Self::SCALAR_LENGTH];
        let mut i = 0;
        for a in frpr.as_ref().iter().rev() {
            bytes[i..(i + 8)].copy_from_slice(&a.to_be_bytes());
            i += 8;
        }
        Box::new(bytes)
    }

    fn generate_scalar<T: Rng>(csprng: &mut T) -> Self::ScalarField {
        Fr::rand(csprng)
    }

    fn bytes_to_scalar(bytes: &mut Cursor<&[u8]>) -> Result<Self::ScalarField, FieldDecodingError> {
        let mut frrepr: FrRepr = FrRepr([0u64; 4]);
        let mut i = true;
        for digit in frrepr.as_mut().iter_mut().rev() {
            *digit = bytes
                .read_u64::<BigEndian>()
                .map_err(|_| FieldDecodingError::NotFieldElement)?;
            if i {
                *digit &= !(1 << 63);
                i = false;
            }
        }
        match Fr::from_repr(frrepr) {
            Ok(fr) => Ok(fr),
            Err(_) => Err(FieldDecodingError::NotFieldElement),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! macro_test_scalar_byte_conversion {
        ($function_name:ident, $p:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                for _ in 0..1000 {
                    let scalar = <$p>::generate_scalar(&mut csprng);
                    let bytes = <$p>::scalar_to_bytes(&scalar);
                    let scalar_res = <$p>::bytes_to_scalar(&mut Cursor::new(&bytes));
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
                    let bytes = <$p>::curve_to_bytes(&curve);
                    let curve_res = <$p>::bytes_to_curve(&mut Cursor::new(&bytes));
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
                    let bytes = <$p>::curve_to_bytes(&curve);
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
