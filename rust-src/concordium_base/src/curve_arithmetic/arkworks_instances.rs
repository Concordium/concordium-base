//! Wrapper types and blanket implementations serving as adapters from
//! `arkworks` field/curve traits.
use core::fmt;
use std::str::FromStr;

use crate::common::{Deserial, Serial, Serialize};

use super::{Curve, CurveDecodingError, Field, GenericMultiExp, PrimeField};
use anyhow::anyhow;
use ark_ec::hashing::HashToCurve;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// A wrapper type for `arkworks` field types.
#[derive(PartialOrd, Ord, PartialEq, Eq, Copy, Clone, fmt::Debug, derive_more::From)]
pub struct ArkField<F>(pub(crate) F);

/// Serialization is implemented by delegating the functionality to the wrapped
/// type.
impl<F: Serial> Serial for ArkField<F> {
    fn serial<B: crate::common::Buffer>(&self, out: &mut B) { self.0.serial(out) }
}

/// Deserialization is implemented by delegating the functionality to the
/// wrapped type.
impl<F: Deserial> Deserial for ArkField<F> {
    fn deserial<R: byteorder::ReadBytesExt>(source: &mut R) -> crate::common::ParseResult<Self> {
        let res = F::deserial(source)?;
        Ok(res.into())
    }
}

/// A blanket implementation of the `Field` trait using the functionality of
/// `ark_ff::Field`. This gives an implementation of our `Field` trait for
/// `ArkField<F>` for any `F` that implements `ark_ff::Field`.
impl<F: ark_ff::Field> Field for ArkField<F> {
    fn random<R: rand::prelude::RngCore + ?std::marker::Sized>(rng: &mut R) -> Self {
        F::rand(rng).into()
    }

    fn zero() -> Self { F::zero().into() }

    fn one() -> Self { F::one().into() }

    fn is_zero(&self) -> bool { F::is_zero(&self.0) }

    fn square(&mut self) { self.0.square_in_place(); }

    fn double(&mut self) { self.0.double_in_place(); }

    fn negate(&mut self) { self.0.neg_in_place(); }

    fn add_assign(&mut self, other: &Self) { self.0 += other.0 }

    fn sub_assign(&mut self, other: &Self) { self.0 -= other.0 }

    fn mul_assign(&mut self, other: &Self) { self.0 *= other.0 }

    fn inverse(&self) -> Option<Self> { self.0.inverse().map(|x| x.into()) }
}

impl<F: ark_ff::Field> ArkField<F> {
    pub fn into_ark(&self) -> &F { &self.0 }
}

/// A blanket implementation of the `PrimeField` trait using the functionality
/// of `ark_ff::PrimeField`. This gives an implementation of our `PrimeField`
/// trait for `ArkField<F>` for any `F` that implements `ark_ff::PrimeField`.
impl<F: ark_ff::PrimeField> PrimeField for ArkField<F> {
    const CAPACITY: u32 = Self::NUM_BITS - 1;
    const NUM_BITS: u32 = F::MODULUS_BIT_SIZE;

    fn into_repr(self) -> Vec<u64> { self.0.into_bigint().as_ref().to_vec() }

    fn from_repr(repr: &[u64]) -> Result<Self, super::CurveDecodingError> {
        let mut buffer = Vec::with_capacity(8 * repr.len());

        for u in repr {
            buffer.extend(u.to_le_bytes());
        }

        let big_int = num_bigint::BigUint::from_bytes_le(&buffer)
            .try_into()
            .map_err(|_| CurveDecodingError::NotInField(format!("{:?}", repr)))?;

        let res =
            F::from_bigint(big_int).ok_or(CurveDecodingError::NotInField(format!("{:?}", repr)))?;

        Ok(res.into())
    }
}

/// A wrapper type for `arkworks` group types.
#[derive(PartialEq, Eq, Copy, Clone, fmt::Debug, derive_more::From)]
pub struct ArkGroup<G>(pub(crate) G);

impl<G: ark_ec::CurveGroup> ArkGroup<G> {
    pub fn into_ark(&self) -> &G { &self.0 }
}

/// Serialization is implemented by delegating the functionality to the
/// compressed affine representation of `ark_ec:CurveGroup`.
impl<G: ark_ec::CurveGroup> Serial for ArkGroup<G> {
    fn serial<B: crate::common::Buffer>(&self, out: &mut B) {
        self.0
            .into_affine()
            .serialize_compressed(out)
            .expect("Serialzation expected to succeed");
    }
}

/// Deserialization is implemented by delegating the functionality to the
/// compressed affine representation of `ark_ec:CurveGroup`.
impl<G: ark_ec::CurveGroup> Deserial for ArkGroup<G> {
    fn deserial<R: byteorder::ReadBytesExt>(source: &mut R) -> crate::common::ParseResult<Self> {
        let res = G::Affine::deserialize_compressed(source)?;
        Ok(ArkGroup(res.into()))
    }
}

/// Curve configuration.
///
/// These parameters cannot be taken from the `arkworks` traits. Each `arkworks`
/// curve should come with an implementation of this configuration trait.
pub(crate) trait ArkCurveConfig<G: ark_ec::CurveGroup> {
    const SCALAR_LENGTH: usize;
    const GROUP_ELEMENT_LENGTH: usize;
    const DOMAIN_STRING: &'static str;
    type Hasher: ark_ec::hashing::HashToCurve<G>;
}

/// A blanket implementation of the `Curve` trait using the functionality of
/// `ark_ec::CurveGroup` and curve configuration `ArkCurveConfig`. This gives an
/// implementation of our `Curve` trait for `ArkGroup<F>` for any `F` that
/// implements `ark_ec::CurveGroup`, provided an instance of `ArkCurveConfig`
/// for that curve.
impl<G: ark_ec::CurveGroup + ArkCurveConfig<G>> Curve for ArkGroup<G>
where
    <G as ark_ec::Group>::ScalarField: Serialize,
{
    type MultiExpType = GenericMultiExp<Self>;
    type Scalar = ArkField<<G as ark_ec::Group>::ScalarField>;

    const GROUP_ELEMENT_LENGTH: usize = G::GROUP_ELEMENT_LENGTH;
    const SCALAR_LENGTH: usize = G::SCALAR_LENGTH;

    fn zero_point() -> Self { ArkGroup(G::zero()) }

    fn one_point() -> Self { ArkGroup(G::generator()) }

    fn is_zero_point(&self) -> bool { self.0.is_zero() }

    fn inverse_point(&self) -> Self { ArkGroup(-self.0) }

    fn double_point(&self) -> Self { ArkGroup(self.0.double()) }

    fn plus_point(&self, other: &Self) -> Self { ArkGroup(self.0 + other.0) }

    fn minus_point(&self, other: &Self) -> Self { ArkGroup(self.0 - other.0) }

    fn mul_by_scalar(&self, scalar: &Self::Scalar) -> Self { ArkGroup(self.0 * scalar.0) }

    fn bytes_to_curve_unchecked<R: byteorder::ReadBytesExt>(b: &mut R) -> anyhow::Result<Self> {
        // TODO: this is not the most efficient implementation, since there might be
        // some additional checks during deserialization. However, it seems
        // there are no unchecked methods available through traits.
        let res = G::Affine::deserialize_compressed(b).map_err(|e| anyhow!(e))?;
        Ok(ArkGroup(res.into()))
    }

    fn generate<R: rand::prelude::Rng>(rng: &mut R) -> Self { ArkGroup(G::rand(rng)) }

    fn generate_scalar<R: rand::prelude::Rng>(rng: &mut R) -> Self::Scalar {
        <G::ScalarField as ark_ff::UniformRand>::rand(rng).into()
    }

    fn scalar_from_u64(n: u64) -> Self::Scalar { ArkField(G::ScalarField::from(n)) }

    fn scalar_from_bytes<A: AsRef<[u8]>>(bs: A) -> Self::Scalar {
        // Traverse at most 4 8-byte chunks, for a total of 256 bits.
        // The top-most two bits in the last chunk are set to 0.
        let s = num::integer::div_ceil(Self::Scalar::CAPACITY, 8);
        let mut fr = Vec::with_capacity(s as usize);
        for chunk in bs.as_ref().chunks(8).take(s as usize) {
            let mut v = [0u8; 8];
            v[..chunk.len()].copy_from_slice(chunk);
            fr.push(u64::from_le_bytes(v));
        }
        // unset two topmost bits in the last read u64.
        *fr.last_mut().expect("Non empty vector expected") &= !(1u64 << 63 | 1u64 << 62);
        // fr[3] &= !(1u64 << 63 | 1u64 << 62);
        <Self::Scalar>::from_repr(&fr)
            .expect("The scalar with top two bits erased should be valid.")
    }

    fn hash_to_group(m: &[u8]) -> Self {
        let hasher = G::Hasher::new(G::DOMAIN_STRING.as_ref())
            .expect("Expected valid domain separation string");
        let res = G::Hasher::hash(&hasher, m).expect("Expected successful hashing to curve");
        ArkGroup(res.into())
    }
}

impl<F: FromStr> FromStr for ArkField<F> {
    type Err = F::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> { F::from_str(s).map(|x| x.into()) }
}