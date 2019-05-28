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

use crate::constants::*;
use crate::errors::InternalError::{DecodingError, DivisionByZero};
use crate::errors::*;
use pairing::bls12_381::{Fr, FrRepr, G1Affine};
use pairing::{CurveAffine, CurveProjective, Field, PrimeField};
use rand::*;

/// A PRF  key.
#[derive(Debug, PartialEq, Eq)]
pub struct SecretKey(pub(crate) Fr);

/*
/// Overwrite secret key material with null bytes when it goes out of scope.
impl Drop for SecretKey {
    fn drop(&mut self) {
        (self.0).into_repr().0.clear();
    }
}
*/

impl SecretKey {
    #[inline]
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        let frpr = &self.0.into_repr();
        let xs = frpr.as_ref(); //array of 64 bit integers (limbs) least significant first
        assert!(xs.len() * 8 <= SECRET_KEY_LENGTH);
        let mut bytes = [0u8; SECRET_KEY_LENGTH];
        let mut i = 0;
        for a in frpr.as_ref().iter().rev() {
            bytes[i..(i + 8)].copy_from_slice(&a.to_be_bytes());
            i += 8;
        }
        bytes
    }

    /// Construct a `SecretKey` from a slice of bytes.
    ///
    /// A `Result` whose okay value is an PRF key or whose error value
    /// is an `PRFError` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey, PrfError> {
        let mut frrepr: FrRepr = FrRepr([0u64; 4]);
        let mut tmp = [0u8; 8];
        let mut i = 0;
        for digit in frrepr.as_mut().iter_mut().rev() {
            tmp.copy_from_slice(&bytes[i..(i + 8)]);
            *digit = u64::from_be_bytes(tmp);
            i += 8;
        }
        match Fr::from_repr(frrepr) {
            Ok(fr) => Ok(SecretKey(fr)),
            Err(x) => Err(PrfError(DecodingError(x))),
        }
    }

    // TODO : Rename variable names more appropriately
    #[allow(clippy::many_single_char_names)]
    pub fn prf(&self, n: u8) -> Result<G1Affine, PrfError> {
        let res_x = Fr::from_repr(FrRepr::from(u64::from(n)));
        if res_x.is_err() {
            let y = res_x.unwrap_err();
            return Err(PrfError(DecodingError(y)));
        }
        let x = res_x.unwrap();
        let k = self.0;
        let mut kx = Fr::zero();
        kx.add_assign(&k);
        kx.add_assign(&x);

        match kx.inverse() {
            None => Err(PrfError(DivisionByZero)),
            Some(y) => Ok({
                let mut z = y;
                z.negate();
                G1Affine::one().mul(z).into_affine()
            }),
        }
    }

    /// Generate a `SecretKey` from a `csprng`.
    ///
    pub fn generate<T>(csprng: &mut T) -> SecretKey
    where
        T: Rng,
    {
        let mut fr = Fr::rand(csprng);
        while fr.into_repr() > MAX_SECRET_KEY {
            fr = Fr::rand(csprng) //try again
        }
        SecretKey(Fr::rand(csprng))
    }
}

#[cfg(feature = "serde")]
impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

#[cfg(feature = "serde")]
impl<'d> Deserialize<'d> for SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        struct SecretKeyVisitor;

        impl<'d> Visitor<'d> for SecretKeyVisitor {
            type Value = SecretKey;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                formatter.write_str("An PRF ecret key as 32 bytes.")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<SecretKey, E>
            where
                E: SerdeError,
            {
                SecretKey::from_bytes(bytes).or(Err(SerdeError::invalid_length(bytes.len(), &self)))
            }
        }
        deserializer.deserialize_bytes(SecretKeyVisitor)
    }
}

#[test]
pub fn test_bounds() {
    let mut m = Fr::from_repr(MAX_SECRET_KEY).unwrap();
    let l = Fr::from_repr(MAX_COUNT).unwrap();
    m.add_assign(&l);
    m.add_assign(&Fr::one());
    assert_eq!(m, Fr::zero());
}

#[test]
pub fn key_to_byte_conversion() {
    let mut csprng = thread_rng();
    for _ in 1..100 {
        let sk = SecretKey::generate(&mut csprng);
        let r = sk.to_bytes();
        let res_sk2 = SecretKey::from_bytes(&r);
        assert!(res_sk2.is_ok());
        let sk2 = res_sk2.unwrap();
        assert_eq!(sk2, sk);
    }
}
