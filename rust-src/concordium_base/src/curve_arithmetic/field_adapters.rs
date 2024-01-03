use ff;
use rand::RngCore;

use crate::common::{Deserial, Serial};

use super::Field;

#[derive(derive_more::From, Clone, Copy, Debug, PartialEq, Eq)]
pub struct FFField<F>(pub(crate) F);

impl<F: Serial> Serial for FFField<F> {
    fn serial<B: crate::common::Buffer>(&self, out: &mut B) { self.0.serial(out) }
}

impl<F: Deserial> Deserial for FFField<F> {
    fn deserial<R: byteorder::ReadBytesExt>(source: &mut R) -> crate::common::ParseResult<Self> {
        let res = F::deserial(source)?;
        Ok(res.into())
    }
}

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
