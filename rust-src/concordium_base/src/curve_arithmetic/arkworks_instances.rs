use core::fmt;
use std::{str::FromStr};

use crate::common::{Deserial, Serial};

use super::{Curve, CurveDecodingError, Field, GenericMultiExp, PrimeField};
use anyhow::anyhow;
use ark_ec::{hashing::HashToCurve, AffineRepr};

#[derive(PartialOrd, Ord, PartialEq, Eq, Copy, Clone, fmt::Debug)]
pub struct ArkField<F>(pub(crate) F);

impl<F> From<F> for ArkField<F> {
    fn from(value: F) -> Self { ArkField(value) }
}

impl<F: ark_ff::Field> Serial for ArkField<F> {
    fn serial<B: crate::common::Buffer>(&self, out: &mut B) {
        self.0
            .serialize_compressed(out)
            .expect("Serialzation expected to succeed")
    }
}

impl<F: ark_ff::Field> Deserial for ArkField<F> {
    fn deserial<R: byteorder::ReadBytesExt>(source: &mut R) -> crate::common::ParseResult<Self> {
        let res = F::deserialize_compressed(source)?;
        Ok(res.into())
    }
}

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

#[derive(PartialEq, Eq, Copy, Clone, fmt::Debug)]
pub struct ArkGroup<G>(pub(crate) G);

impl<G: ark_ec::CurveGroup> ArkGroup<G> {
    pub fn into_ark(&self) -> &G { &self.0 }
}

impl<G: ark_ec::CurveGroup> Serial for ArkGroup<G> {
    fn serial<B: crate::common::Buffer>(&self, out: &mut B) {
        self.0
            .serialize_compressed(out)
            .expect("Serialzation expected to succeed")
    }
}

impl<G: ark_ec::CurveGroup> Deserial for ArkGroup<G> {
    fn deserial<R: byteorder::ReadBytesExt>(source: &mut R) -> crate::common::ParseResult<Self> {
        let res = G::deserialize_compressed(source)?;
        Ok(ArkGroup(res))
    }
}

impl<G> From<G> for ArkGroup<G> {
    fn from(value: G) -> Self { ArkGroup(value) }
}

pub(crate) trait ArkCurveConfig<G: ark_ec::CurveGroup> {
    const SCALAR_LENGTH: usize;
    const GROUP_ELEMENT_LENGTH: usize;
    const DOMAIN_STRING: &'static str;
    type Hasher: ark_ec::hashing::HashToCurve<G>;
}

impl<G: ark_ec::CurveGroup + ArkCurveConfig<G>> Curve for ArkGroup<G> {
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
        // TODO: this implementation is not efficient.
        let mut buffer = Vec::new();
        b.read(&mut buffer)?;
        // In fact, `from_random_bytes` checks if the bytes correspond to a valid group
        // element. It seems like there is no unchecked methods exposed through
        // ark traits.
        let res = G::Affine::from_random_bytes(&buffer)
            .ok_or(anyhow!("Expected a valid group element"))?;
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
        println!("{:?}", Self::Scalar::NUM_BITS);
        println!("{:?}", Self::Scalar::CAPACITY);
        println!("{:?}", s);
        let mut fr = Vec::with_capacity(s as usize);
        for chunk in bs.as_ref().chunks(8).take(s as usize) {
            let mut v = [0u8; 8];
            v[..chunk.len()].copy_from_slice(chunk);
            println!("{:?}", v);
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
        let res = G::Hasher::hash(&hasher, &m).expect("Expected successful hashing to curve");
        ArkGroup(res.into())
    }
}

impl<F: FromStr> FromStr for ArkField<F> {
    type Err = F::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> { F::from_str(s).map(|x| x.into()) }
}
