// -*- mode: rust; -*-
//
// Authors:
// - bm@concordium.com

//! PRF Key type

#[cfg(feature = "serde")]
use serde::de::Error as SerdeError;
#[cfg(feature = "serde")]
use serde::de::Visitor;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde::{Deserializer, Serializer};

use crate::errors::{
    InternalError::{DecodingError, DivisionByZero},
    *,
};
use curve_arithmetic::curve_arithmetic::Curve;
use pairing::Field;
use rand::*;

use std::io::Cursor;

/// A PRF  key.
#[derive(Debug, PartialEq, Eq)]
pub struct SecretKey<C: Curve>(pub C::Scalar);

impl<C: Curve> SecretKey<C> {
    #[inline]
    pub fn to_bytes(&self) -> Box<[u8]> { C::scalar_to_bytes(&self.0) }

    /// Construct a `SecretKey` from a slice of bytes.
    ///
    /// A `Result` whose okay value is an PRF key or whose error value
    /// is an `PRFError` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes(bytes: &mut Cursor<&[u8]>) -> Result<SecretKey<C>, PrfError> {
        match C::bytes_to_scalar(bytes) {
            Ok(scalar) => Ok(SecretKey(scalar)),
            Err(x) => Err(PrfError(DecodingError(x))),
        }
    }

    // NOTE: I have removed the negation since I don't think it is needed.
    // At least it does not appear in the white paper.
    // CHECK!
    pub fn prf_exponent(&self, n: u8) -> Result<C::Scalar, PrfError> {
        let res_x = C::scalar_from_u64(u64::from(n));
        if res_x.is_err() {
            let y = res_x.unwrap_err();
            return Err(PrfError(DecodingError(y)));
        }
        let x = res_x.unwrap();
        let k = self.0;
        let mut kx = k;
        // kx.add_assign(&k);
        kx.add_assign(&x);

        match kx.inverse() {
            None => Err(PrfError(DivisionByZero)),
            Some(y) => Ok(y)
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
            let r = sk.to_bytes();
            let res_sk2 = SecretKey::<G1>::from_bytes(&mut Cursor::new(&r));
            assert!(res_sk2.is_ok());
            let sk2 = res_sk2.unwrap();
            assert_eq!(sk2, sk);
        }
    }
}
