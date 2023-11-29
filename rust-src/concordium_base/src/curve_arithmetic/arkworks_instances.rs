// use ark_ec::AffineCurve;
// use ark_ff::{FpParameters, FromBytes};
use core::fmt;

use ark_ff::BigInteger;

use crate::common::{Deserial, Serial};

use super::{Curve, CurveDecodingError, Field, GenericMultiExp, PrimeField};

#[derive(PartialEq, Eq, Copy, Clone, fmt::Debug)]
pub struct ArkField<F>(F);

impl<F> From<F> for ArkField<F> {
    fn from(value: F) -> Self { ArkField(value) }
}

impl<F: ark_ff::Field> Serial for ArkField<F> {
    fn serial<B: crate::common::Buffer>(&self, _out: &mut B) { todo!() }
}

impl<F: ark_ff::Field> Deserial for ArkField<F> {
    fn deserial<R: byteorder::ReadBytesExt>(_source: &mut R) -> crate::common::ParseResult<Self> {
        todo!()
    }
}

impl<F: fmt::Display> fmt::Display for ArkField<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <F as fmt::Display>::fmt(&self.0, f)
    }
}

impl<F: ark_ff::Field> Field for ArkField<F> {
    fn random<R: rand::prelude::RngCore + ?std::marker::Sized>(_rng: &mut R) -> Self { todo!() }

    fn zero() -> Self { F::zero().into() }

    fn one() -> Self { todo!() }

    fn is_zero(&self) -> bool { todo!() }

    fn square(&mut self) { todo!() }

    fn double(&mut self) { todo!() }

    fn negate(&mut self) { todo!() }

    fn add_assign(&mut self, _other: &Self) { todo!() }

    fn sub_assign(&mut self, _other: &Self) { todo!() }

    fn mul_assign(&mut self, _other: &Self) { todo!() }

    fn inverse(&self) -> Option<Self> { todo!() }
}

impl<F: ark_ff::PrimeField> PrimeField for ArkField<F> {
    const CAPACITY: u32 = Self::NUM_BITS - 1;
    const NUM_BITS: u32 = F::MODULUS_BIT_SIZE;

    fn into_repr(self) -> Vec<u64> {
        self.0.into_bigint().as_ref().to_vec()
        // self.0.into_repr().as_ref().to_vec()
    }

    fn from_repr(repr: &[u64]) -> Result<Self, super::CurveDecodingError> {
        // let mut buffer = Vec::new();
        // for u in repr {
        //     buffer.extend(u.to_le_bytes());
        // }
        // let big_int = F::BigInt::read(buffer.as_slice())
        //     .map_err(|_| CurveDecodingError::NotInField(format!("{:?}", repr)))?;
        // let res =
        //     F::from_repr(big_int).ok_or(CurveDecodingError::NotInField(format!("{:?}"
        // , repr)))?; Ok(ArkField(res))
        todo!()
    }
}

#[derive(PartialEq, Eq, Copy, Clone, fmt::Debug)]
pub struct ArkGroup<
    G: ark_ec::CurveGroup + Sized + Eq + Copy + Clone + Send + Sync + fmt::Debug + fmt::Display,
>(G);

impl<
        G: ark_ec::CurveGroup + Sized + Eq + Copy + Clone + Send + Sync + fmt::Debug + fmt::Display,
    > Serial for ArkGroup<G>
{
    fn serial<B: crate::common::Buffer>(&self, _out: &mut B) { todo!() }
}

impl<
        G: ark_ec::CurveGroup + Sized + Eq + Copy + Clone + Send + Sync + fmt::Debug + fmt::Display,
    > Deserial for ArkGroup<G>
{
    fn deserial<R: byteorder::ReadBytesExt>(_source: &mut R) -> crate::common::ParseResult<Self> {
        todo!()
    }
}

impl<
        G: ark_ec::CurveGroup + Sized + Eq + Copy + Clone + Send + Sync + fmt::Debug + fmt::Display,
    > From<G> for ArkGroup<G>
{
    fn from(value: G) -> Self { ArkGroup(value) }
}

pub(crate) trait ArkCurveConfig {
    const SCALAR_LENGTH: usize;
    const GROUP_ELEMENT_LENGTH: usize;
    const DOMAIN_STRING: String;
}

impl<G: ark_ec::CurveGroup + ark_ec::hashing::HashToCurve<G> + ArkCurveConfig> Curve
    for ArkGroup<G>
{
    type MultiExpType = GenericMultiExp<Self>;
    type Scalar = ArkField<G::ScalarField>;

    const GROUP_ELEMENT_LENGTH: usize = G::GROUP_ELEMENT_LENGTH;
    const SCALAR_LENGTH: usize = G::SCALAR_LENGTH;

    fn zero_point() -> Self { ArkGroup(G::zero()) }

    fn one_point() -> Self { ArkGroup(G::generator()) }

    fn is_zero_point(&self) -> bool { self.0.is_zero() }

    fn inverse_point(&self) -> Self { ArkGroup(-self.0) }

    fn double_point(&self) -> Self { ArkGroup(self.0.double()) }

    fn plus_point(&self, other: &Self) -> Self { ArkGroup(self.0 + other.0) }

    fn minus_point(&self, other: &Self) -> Self { ArkGroup(self.0 - other.0) }

    fn mul_by_scalar(&self, scalar: &Self::Scalar) -> Self {
        // ArkGroup(self.0.into_affine().mul(scalar.0))
        ArkGroup(self.0 * scalar.0)
    }

    fn bytes_to_curve_unchecked<R: byteorder::ReadBytesExt>(_b: &mut R) -> anyhow::Result<Self> {
        todo!()
    }

    fn generate<R: rand::prelude::Rng>(rng: &mut R) -> Self {
        todo!()
        // ArkGroup(G::rand(rng))
    }

    fn generate_scalar<R: rand::prelude::Rng>(rng: &mut R) -> Self::Scalar {
        //  ArkField(<G::ScalarField as ark_ff::UniformRand>::rand(rng))
        todo!()
    }

    fn scalar_from_u64(n: u64) -> Self::Scalar { ArkField(G::ScalarField::from(n)) }

    fn scalar_from_bytes<A: AsRef<[u8]>>(bs: A) -> Self::Scalar {
        let res = <G::ScalarField as ark_ff::Field>::from_random_bytes(bs.as_ref())
            .expect("Input bytes must be a valid scalar values");
        ArkField(res)
    }

    fn hash_to_group(m: &[u8]) -> Self {
        let hasher =
            G::new(G::DOMAIN_STRING.as_ref()).expect("Expected valid domain separation string");
        let res = <G as ark_ec::hashing::HashToCurve<_>>::hash(&hasher, &m)
            .expect("Expected successful hashing to curve");
        ArkGroup(res.into())
    }
}
