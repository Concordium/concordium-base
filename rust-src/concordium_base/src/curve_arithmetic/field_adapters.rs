//! Wrapper types and blanket implementations serving as adapters from
//! the `ff` crate `Field`.
use ff;
use rand::RngCore;

use crate::common::{Deserial, Serial};

use super::Field;

/// A wrapper type for `ff` field types.
#[derive(derive_more::From, Clone, Copy, Debug, PartialEq, Eq)]
pub struct FFField<F>(pub(crate) F);

/// Serialization is implemented by delegating the functionality to the wrapped
/// type.
impl<F: Serial> Serial for FFField<F> {
    fn serial<B: crate::common::Buffer>(&self, out: &mut B) { self.0.serial(out) }
}

/// Deserialization is implemented by delegating the functionality to the
/// wrapped type.
impl<F: Deserial> Deserial for FFField<F> {
    fn deserial<R: byteorder::ReadBytesExt>(source: &mut R) -> crate::common::ParseResult<Self> {
        let res = F::deserial(source)?;
        Ok(res.into())
    }
}

/// A blanket implementation of the `Field` trait using the functionality of
/// `ff::Field`. This gives an implementation of our `Field` trait for
/// `FFField<F>` for any `F` that implements `ff::Field`.
impl<F: ff::Field> Field for FFField<F> {
    fn random<R: RngCore + ?std::marker::Sized>(rng: &mut R) -> Self { F::random(rng).into() }

    fn zero() -> Self { F::ZERO.into() }

    fn one() -> Self { F::ONE.into() }

    fn is_zero(&self) -> bool { self.0.is_zero_vartime() }

    fn square(&mut self) { self.0 = self.0.square() }

    fn double(&mut self) { self.0 = self.0.double() }

    fn negate(&mut self) { self.0 = self.0.neg() }

    fn add_assign(&mut self, other: &Self) { self.0.add_assign(other.0) }

    fn sub_assign(&mut self, other: &Self) { self.0.sub_assign(other.0) }

    fn mul_assign(&mut self, other: &Self) { self.0.mul_assign(other.0) }

    fn inverse(&self) -> Option<Self> {
        let res: Option<_> = self.0.invert().into();
        res.map(|x: F| x.into())
    }
}
