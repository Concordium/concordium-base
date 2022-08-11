//! PRF Key type

use crate::errors::{InternalError::DivisionByZero, *};
use crypto_common::*;
use curve_arithmetic::{Curve, Secret, Value};
use ff::Field;
use rand::*;
use std::rc::Rc;

/// A PRF key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, SerdeBase16Serialize)]
pub struct SecretKey<C: Curve>(Rc<Secret<C::Scalar>>);

/// This trait allows automatic conversion of &SecretKey<C> to &C::Scalar.
impl<C: Curve> std::ops::Deref for SecretKey<C> {
    type Target = C::Scalar;

    fn deref(&self) -> &C::Scalar { &self.0 }
}

impl<C: Curve> AsRef<C::Scalar> for SecretKey<C> {
    fn as_ref(&self) -> &C::Scalar { &self.0 }
}

impl<C: Curve> SecretKey<C> {
    pub fn new(secret: C::Scalar) -> Self { SecretKey(Rc::new(Secret::new(secret))) }

    /// Generate a non-zero SecretKey `SecretKey` from a `csprng`.
    pub fn generate_non_zero<T: Rng>(csprng: &mut T) -> SecretKey<C> {
        SecretKey::new(C::generate_non_zero_scalar(csprng))
    }

    /// View the SecretKey as a SecretKey in another group. This does not
    /// copy the secret SecretKey.
    #[inline]
    pub fn view<T: Curve<Scalar = C::Scalar>>(&self) -> SecretKey<T> { SecretKey(self.0.clone()) }

    /// View the SecretKey as a generic secret value. This does not
    /// copy the secret value.
    #[inline]
    pub fn to_value<T: Curve<Scalar = C::Scalar>>(&self) -> Value<T> {
        Value {
            value: self.0.clone(),
        }
    }

    /// Compute the exponent of the PRF function. This is an intermediate step
    /// in the computation of the PRF function, but it is sometimes necessary to
    /// know the exponent alone, and not just the result of the computation.
    /// If this function returns OK(_) then the [SecretKey::prf] would also
    /// return Ok, and vice-versa.
    pub fn prf_exponent(&self, n: u8) -> Result<C::Scalar, PrfError> {
        let mut x = C::scalar_from_u64(u64::from(n));
        x.add_assign(self);
        match x.inverse() {
            None => Err(PrfError(DivisionByZero)),
            Some(y) => Ok(y),
        }
    }

    /// Compute the PRF function given the base `g` and the counter.
    pub fn prf(&self, g: &C, n: u8) -> Result<C, PrfError> {
        let y = self.prf_exponent(n)?;
        Ok(g.mul_by_scalar(&y))
    }

    /// Generate a `SecretKey` from a `csprng`.
    pub fn generate<T>(csprng: &mut T) -> SecretKey<C>
    where
        T: Rng, {
        SecretKey::new(C::generate_scalar(csprng))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::G1;
    #[test]
    pub fn key_to_byte_conversion() {
        let mut csprng = thread_rng();
        for _ in 1..100 {
            let sk = SecretKey::<G1>::generate(&mut csprng);
            let res_sk2 = serialize_deserialize(&sk);
            assert!(res_sk2.is_ok());
            let sk2 = res_sk2.unwrap();
            assert_eq!(sk2, sk);
        }
    }
}
