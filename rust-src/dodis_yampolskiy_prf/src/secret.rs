//! PRF Key type

use crate::errors::{InternalError::DivisionByZero, *};
use crypto_common::*;
use curve_arithmetic::curve_arithmetic::Curve;

use ff::Field;
use rand::*;

/// A PRF  key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SecretKey<C: Curve>(pub C::Scalar);

impl<C: Curve> SecretKey<C> {
    pub fn prf_exponent(&self, n: u8) -> Result<C::Scalar, PrfError> {
        let x = C::scalar_from_u64(u64::from(n));
        let mut k = self.0;
        k.add_assign(&x);
        match k.inverse() {
            None => Err(PrfError(DivisionByZero)),
            Some(y) => Ok(y),
        }
    }

    pub fn prf(&self, g: &C, n: u8) -> Result<C, PrfError> {
        let y = self.prf_exponent(n)?;
        Ok(g.mul_by_scalar(&y))
    }

    /// Generate a `SecretKey` from a `csprng`.
    pub fn generate<T>(csprng: &mut T) -> SecretKey<C>
    where
        T: Rng, {
        SecretKey(C::generate_scalar(csprng))
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
