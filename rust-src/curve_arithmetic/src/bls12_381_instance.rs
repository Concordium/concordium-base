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
    CurveAffine, CurveProjective, EncodedPoint, Engine, Field, PrimeField,
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
        unimplemented!("hash_to_group_element for G2 of Bls12_381 is not implemented")
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
        let t: Fq = hash_bytes_to_fq(bytes);
        let mut t_pow2 = t;
        t_pow2.square();
        let mut t_pow4 = t_pow2;
        t_pow4.square();

        let mut t_pow4_minus_t_pow2_plus_one = t_pow4;
        t_pow4_minus_t_pow2_plus_one.sub_assign(&t_pow2);
        t_pow4_minus_t_pow2_plus_one.add_assign(&Fq::one());
        let b = Fq::from_repr(FqRepr(E11_B)).unwrap(); // this unwrap can't fail, E11_B is an element of the field
        let mut n = b;
        n.mul_assign(&t_pow4_minus_t_pow2_plus_one);

        let mut t_pow2_minus_t_pow4 = t_pow2;
        t_pow2_minus_t_pow4.sub_assign(&t_pow4);
        let a = Fq::from_repr(FqRepr(E11_A)).unwrap(); // this unwrap can't fail, E11_A is an element of the field
        let mut d = a;
        d.mul_assign(&t_pow2_minus_t_pow4);

        // if d, the denominator of X0(u), is 0 then we set the denominator to -a instead, since -b/a is square in Fq
        if d.is_zero() {
            d = a;
            d.negate();
        }

        let mut d_pow2 = d;
        d_pow2.square();
        let mut v = d_pow2;
        v.mul_assign(&d);
        let mut n_pow3 = n;
        n_pow3.square();
        n_pow3.mul_assign(&n);
        let mut a_mul_n_mul_d_pow2 = a;
        a_mul_n_mul_d_pow2.mul_assign(&n);
        a_mul_n_mul_d_pow2.mul_assign(&d_pow2);
        let mut b_mul_v = b;
        b_mul_v.mul_assign(&v);
        let mut u = n_pow3;
        u.add_assign(&a_mul_n_mul_d_pow2);
        u.add_assign(&b_mul_v);

        let mut v_pow3 = v;
        v_pow3.square();
        v_pow3.mul_assign(&v);
        let mut alpha_factor = u;
        alpha_factor.mul_assign(&v_pow3);
        alpha_factor = alpha_factor.pow(&P_MINUS_3_DIV_4);
        let mut alpha = u;
        alpha.mul_assign(&v);
        alpha.mul_assign(&alpha_factor);

        let mut alpha_pow2_mul_v_minus_u = alpha;
        alpha_pow2_mul_v_minus_u.square();
        alpha_pow2_mul_v_minus_u.mul_assign(&v);
        alpha_pow2_mul_v_minus_u.sub_assign(&u);

        // We use jacobian projective coordinates when computing SWU
        let mut x_jac: Fq;
        let mut y_jac: Fq;
        let z_jac: Fq = d;

        if alpha_pow2_mul_v_minus_u.is_zero() {
            x_jac = n;
            x_jac.mul_assign(&d);
            y_jac = alpha;
            y_jac.mul_assign(&v);
            match fq_sign(t) {
                Sign::Minus => y_jac.negate(),
                Sign::Plus => (),
            }
        } else {
            x_jac = t_pow2;
            x_jac.mul_assign(&n);
            x_jac.mul_assign(&d);
            x_jac.negate();
            y_jac = t_pow2;
            y_jac.mul_assign(&t);
            y_jac.mul_assign(&alpha);
            y_jac.mul_assign(&v);
        }

        let (_x, _y, _z) = iso_11(x_jac, y_jac, z_jac);
        //unimplemented!("hash_to_group_element for G1 of Bls12_381 is not implemented");
        Self::one_point()
    }
}

fn fq_sign(a: Fq) -> Sign {
    if a.into_repr() > FqRepr(P_MINUS_1_DIV_2) {
        Sign::Minus
    } else {
        Sign::Plus
    }
}

fn iso_11(x: Fq, y: Fq, z: Fq) -> (Fq, Fq, Fq) {
    // Compute Z^2i for i = 1,...,15
    let mut z_pow_2i: [Fq; 15] = [z; 15];
    z_pow_2i[0].square(); // Z^2
    z_pow_2i[1] = z_pow_2i[0];
    z_pow_2i[1].square(); // Z^4
    let mut z_ = z_pow_2i[1];
    z_.mul_assign(&z_pow_2i[1]);
    z_pow_2i[2] = z_; // Z^6
    z_pow_2i[3] = z_pow_2i[1];
    z_pow_2i[3].square(); // Z^8
    for i in 0..3 { // Z^10, Z^12, Z^14,
        z_ = z_pow_2i[3+i];
        z_.mul_assign(&z_pow_2i[0]);
        z_pow_2i[4+i] = z_;
    }
    z_pow_2i[7] = z_pow_2i[3];
    z_pow_2i[7].square(); // Z^16
    for i in 0..7 { // Z^18, Z^20, Z^22, Z^24, Z^26, Z^28, Z^30,
        z_ = z_pow_2i[7+i];
        z_.mul_assign(&z_pow_2i[0]);
        z_pow_2i[8+i] = z_;
    }

    macro_rules! horner {
        ($init:expr, $ks:expr, $var:expr) => {
            {
                for i in 0..($ks.len() - 1) {
                    $init.mul_assign(&$var);
                    let mut c = Fq::from_repr(FqRepr($ks[($ks.len() - 2)-i])).unwrap(); // unwrapping the Ki constants never fails
                    c.mul_assign(&z_pow_2i[i]);
                    $init.add_assign(&c);
                }
            }
        }
    }

    let mut x_num = Fq::from_repr(FqRepr(K1[11])).unwrap(); // unwrapping the Ki constants never fails
    horner!(x_num, K1, x);

    let mut x_den_ = Fq::from_repr(FqRepr(K2[10])).unwrap(); // unwrapping the Ki constants never fails
    horner!(x_den_, K2, x);
    let mut x_den = z;
    x_den.square();
    x_den.mul_assign(&x_den_);

    let mut y_num = Fq::from_repr(FqRepr(K3[15])).unwrap(); // unwrapping the Ki constants never fails
    horner!(y_num, K3, y);

    let mut y_den_ = Fq::from_repr(FqRepr(K4[15])).unwrap(); // unwrapping the Ki constants never fails
    horner!(y_den_, K4, y);
    let mut y_den = z;
    y_den.square();
    y_den.mul_assign(&z);
    y_den.mul_assign(&y_den_);

    let mut z_jac = x_den;
    z_jac.mul_assign(&y_den);
    let mut x_jac = x_num;
    x_jac.mul_assign(&y_den);
    x_jac.mul_assign(&z_jac);
    let mut z_jac_pow2 = z_jac;
    z_jac_pow2.square();
    let mut y_jac = y_num;
    y_jac.mul_assign(&x_den);
    y_jac.mul_assign(&z_jac_pow2);

    (x_jac, y_jac, z_jac)
}

enum Sign {
    Minus,
    Plus,
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
        unimplemented!("hash_to_group_element for G1Affine of Bls12_381 is not implemented")
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
        unimplemented!("hash_to_group_element for G2Affine of Bls12_381 is not implemented")
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
