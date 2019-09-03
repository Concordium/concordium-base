// -*- mode: rust; -*-
//
// Authors:
// - bm@concordium.com

//! Commitment key type

use crate::{
    commitment::*,
    value::*,
    randomness::*,
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
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct CommitmentKey<C: Curve>(pub C, pub C);

// impl Drop for SecretKey {
// fn drop(&mut self) {
// (self.0).into_repr().0.clear();
// }
// }

impl<C: Curve> CommitmentKey<C> {
    // turn commitment key into a byte aray
    #[inline]
    pub fn to_bytes(&self) -> Box<[u8]> {
        let g = &self.0;
        let h = &self.1;
        let mut bytes: Vec<u8> = Vec::with_capacity( 2 * C::GROUP_ELEMENT_LENGTH);
        write_curve_element(g, &mut bytes);
        write_curve_element(h, &mut bytes);
        bytes.into_boxed_slice()
    }

    pub fn new(v: C, r: C) -> Self { CommitmentKey(v, r) }

    /// Construct a commitmentkey from a slice of bytes.
    ///
    /// A `Result` whose okay value is an commitment key or whose error value
    /// is an `CommitmentError` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Result<CommitmentKey<C>, Error> {
        let g = read_curve(cur)?;
        let h = read_curve(cur)?;
        Ok(CommitmentKey(g, h))
    }
    
     pub fn commit<T>(&self, s: &Value<C>, csprng: &mut T) -> (Commitment<C>, Randomness<C>)
      where
          T: Rng, {
          let r = Randomness::<C>::generate(csprng);
          (self.hide(s, &r), r) 
    }

    fn hide(&self, s: &Value<C>, r: &Randomness<C>) -> Commitment<C> {
        let h = self.1;
        let g = self.0;
        let m = s.0;
        let r_scalar = r.0;
        let hr = h.mul_by_scalar(&r_scalar);
        let gm = g.mul_by_scalar(&m);
        Commitment(hr.plus_point(&gm))
    }

    pub fn open(&self, s: &Value<C>, r: &Randomness<C>, c: &Commitment<C>) -> bool {
        self.hide(s,r) == *c
    }
    pub fn generate<T>(csprng: &mut T) -> CommitmentKey<C>
    where
        T: Rng, {
        let h = C::generate(csprng);
        let g = C::generate(csprng);
        CommitmentKey(g,h)
    }
    /*
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
    */
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::{G1Affine, G2Affine, G1, G2};

    macro_rules! macro_test_key_byte_conversion {
        ($function_name:ident, $curve_type:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                for _i in 1..100 {
                    let sk = CommitmentKey::<$curve_type>::generate(&mut csprng);
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
                for _i in 1..100 {
                    let sk = CommitmentKey::<$curve_type>::generate(&mut csprng);
                    let ss = Value::<$curve_type>::generate(&mut csprng);
                    let (c, r) = sk.commit(&ss, &mut csprng);
                    assert!(sk.open(&ss, &r, &c));
                    assert!(!sk.open(&ss, &r, &Commitment::<$curve_type>::generate(&mut csprng)));
                    assert!(!sk.open(&ss, &Randomness::<$curve_type>::generate(&mut csprng), &c));
                }
            }
        };
    }

    macro_test_commit_open!(commit_open_bls12_381_g1_affine, G1Affine);
    macro_test_commit_open!(commit_open_bls12_381_g1_projectitve, G1);

    macro_test_commit_open!(commit_open_bls12_381_g2_affine, G2Affine);
    macro_test_commit_open!(commit_open_bls12_381_g2_projective, G2);
}
