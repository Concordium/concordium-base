//! Commitment key type

use crate::{commitment::*, randomness::*, value::*};

use curve_arithmetic::curve_arithmetic::*;

use crypto_common::*;
use crypto_common_derive::*;
use rand::*;

/// A commitment  key.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, SerdeBase16Serialize)]
pub struct CommitmentKey<C: Curve>(pub C, pub C);

impl<C: Curve> CommitmentKey<C> {
    pub fn new(v: C, r: C) -> Self { CommitmentKey(v, r) }

    pub fn commit<T>(&self, s: &Value<C>, csprng: &mut T) -> (Commitment<C>, Randomness<C>)
    where
        T: Rng, {
        let r = Randomness::<C>::generate(csprng);
        (self.hide(s, &r), r)
    }

    pub fn hide(&self, s: &Value<C>, r: &Randomness<C>) -> Commitment<C> {
        let h = self.1;
        let g = self.0;
        let message = s.value;
        let r_scalar = r.randomness;
        let hr = h.mul_by_scalar(&r_scalar);
        let gm = g.mul_by_scalar(&message);
        Commitment(hr.plus_point(&gm))
    }

    pub fn open(&self, s: &Value<C>, r: &Randomness<C>, c: &Commitment<C>) -> bool {
        self.hide(s, r) == *c
    }

    pub fn generate<T>(csprng: &mut T) -> CommitmentKey<C>
    where
        T: Rng, {
        let h = C::generate(csprng);
        let g = C::generate(csprng);
        CommitmentKey(g, h)
    }
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
                    let res_sk2 = serialize_deserialize(&sk);
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
