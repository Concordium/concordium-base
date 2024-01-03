//! PRF Key type

use super::errors::{InternalError::DivisionByZero, *};
use crate::{
    common::*,
    curve_arithmetic::{Curve, Field, Secret, Value},
};
use rand::*;
use std::rc::Rc;

/// A PRF key.
#[derive(Clone, PartialEq, Eq, Serialize, SerdeBase16Serialize)]
pub struct SecretKey<C: Curve>(Rc<Secret<C::Scalar>>);

/// This trait allows automatic conversion of `&SecretKey<C>` to `&C::Scalar`.
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

impl<C: Curve> std::fmt::Display for SecretKey<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "<Dodis Yampolskiy SecretKey>")
    }
}

impl<C: Curve> std::fmt::Debug for SecretKey<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "<Dodis Yampolskiy SecretKey>")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SecretKeyFromStrError {
    #[error("Invalid secret key: {0}")]
    InvalidKey(#[from] anyhow::Error),
    #[error("Invalid hex string: {0}")]
    InvalidHex(#[from] hex::FromHexError),
}

impl<C: Curve> std::str::FromStr for SecretKey<C> {
    type Err = SecretKeyFromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = std::io::Cursor::new(hex::decode(s)?);
        let key = from_bytes(&mut bytes)?;
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve_arithmetic::arkworks_instances::ArkGroup;
    use ark_bls12_381::G1Projective;

    type SomeCurve = ArkGroup<G1Projective>;

    #[test]
    pub fn key_to_byte_conversion() {
        let mut csprng = thread_rng();
        for _ in 1..100 {
            let sk = SecretKey::<SomeCurve>::generate(&mut csprng);
            let res_sk2 = serialize_deserialize(&sk);
            assert!(res_sk2.is_ok());
            let sk2 = res_sk2.unwrap();
            assert_eq!(sk2, sk);
        }
    }
}
