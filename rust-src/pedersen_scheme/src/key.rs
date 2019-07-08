// -*- mode: rust; -*-
//
// Authors:
// - bm@concordium.com

//! Commitment key type

use crate::{
    commitment::*,
    errors::{InternalError::KeyValueLengthMismatch, *},
    value::*,
};
#[cfg(feature = "serde")]
use serde::de::Error as SerdeError;
#[cfg(feature = "serde")]
use serde::de::Visitor;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde::{Deserializer, Serializer};

use curve_arithmetic::{curve_arithmetic::*, serialization::*};

use failure::Error;
use rand::*;
use std::io::Cursor;

/// A commitment  key.
#[derive(Debug, PartialEq, Eq)]
pub struct CommitmentKey<C: Curve>(pub Vec<C>, pub C);

// impl Drop for SecretKey {
// fn drop(&mut self) {
// (self.0).into_repr().0.clear();
// }
// }

impl<C: Curve> CommitmentKey<C> {
    // turn commitment key into a byte aray
    #[inline]
    pub fn to_bytes(&self) -> Box<[u8]> {
        let gs = &self.0;
        let h = &self.1;
        let mut bytes: Vec<u8> = Vec::with_capacity((gs.len() + 1) * C::GROUP_ELEMENT_LENGTH);
        write_curve_elements(gs, &mut bytes);
        write_curve_element(h, &mut bytes);
        bytes.into_boxed_slice()
    }

    pub fn new(v: Vec<C>, r: C) -> Self { CommitmentKey(v, r) }

    /// Construct a commitmentkey from a slice of bytes.
    ///
    /// A `Result` whose okay value is an commitment key or whose error value
    /// is an `CommitmentError` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Result<CommitmentKey<C>, Error> {
        let mut group_buf = vec![0; C::GROUP_ELEMENT_LENGTH];
        let gs = read_curve_elements(cur, &mut group_buf)?;
        let h = read_curve(cur, &mut group_buf)?;
        Ok(CommitmentKey(gs, h))
    }

    pub fn commit<T>(&self, ss: &Value<C>, csprng: &mut T) -> (Commitment<C>, C::Scalar)
    where
        T: Rng, {
        let r = C::generate_scalar(csprng);
        (self.hide(ss, &r).unwrap(), r) // panicking is Ok here
    }

    fn hide(&self, ss: &Value<C>, r: &C::Scalar) -> Result<Commitment<C>, CommitmentError> {
        if self.0.len() != ss.0.len() {
            return Err(CommitmentError(KeyValueLengthMismatch));
        };
        let h = self.1;
        let hr = h.mul_by_scalar(r);
        let mut res = hr;
        for it in self.0.iter().zip(ss.0.iter()) {
            let (g, m) = it;
            let gm = g.mul_by_scalar(m);
            res = res.plus_point(&gm);
        }
        Ok(Commitment(res))
    }

    pub fn open(&self, ss: &Value<C>, r: &C::Scalar, c: &Commitment<C>) -> bool {
        match self.hide(ss, r) {
            Err(_) => false,
            Ok(x) => x == *c,
        }
    }

    /// Generate a `CommitmentKey` for `n` values from a `csprng`.
    pub fn generate<T>(n: usize, csprng: &mut T) -> CommitmentKey<C>
    where
        T: Rng, {
        let mut gs: Vec<C> = Vec::with_capacity(n);
        for _i in 0..n {
            gs.push(C::generate(csprng));
        }
        let h = C::generate(csprng);
        CommitmentKey(gs, h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::{G1Affine, G2Affine};

    macro_rules! macro_test_key_byte_conversion {
        ($function_name:ident, $curve_type:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                for i in 1..10 {
                    let sk = CommitmentKey::<$curve_type>::generate(i, &mut csprng);
                    let res_sk2 =
                        CommitmentKey::<$curve_type>::from_bytes(&mut Cursor::new(&sk.to_bytes()));
                    assert!(res_sk2.is_ok());
                    let sk2 = res_sk2.unwrap();
                    assert_eq!(sk2, sk);
                }
            }
        };
    }

    macro_test_key_byte_conversion!(key_byte_conversion_bls12_381_g1_affine, G1Affine);

    macro_test_key_byte_conversion!(key_byte_conversion_bls12_381_g2_affine, G2Affine);

    macro_rules! macro_test_commit_open {
        ($function_name:ident, $curve_type:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                for i in 1..10 {
                    let sk = CommitmentKey::<$curve_type>::generate(i, &mut csprng);
                    let ss = Value::<$curve_type>::generate(i, &mut csprng);
                    let (c, r) = sk.commit(&ss, &mut csprng);
                    assert!(sk.open(&ss, &r, &c));
                    let m = <$curve_type as Curve>::generate_scalar(&mut csprng);
                    assert!(!sk.open(&ss, &m, &c));
                    assert!(!sk.open(&ss, &r, &Commitment::<$curve_type>::generate(&mut csprng)));
                }
            }
        };
    }

    macro_test_commit_open!(commit_open_bls12_381_g1_affine, G1Affine);

    macro_test_commit_open!(commit_open_bls12_381_g2_affine, G2Affine);
}
