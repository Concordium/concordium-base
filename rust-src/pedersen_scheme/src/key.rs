//! Commitment key type

use crate::{commitment::*, randomness::*};

use curve_arithmetic::*;

use crypto_common::*;
use crypto_common_derive::*;
use rand::*;

/// A commitment key is a pair of group elements that are used as a base to
/// raise the value and randomness, respectively.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, SerdeBase16Serialize)]
pub struct CommitmentKey<C: Curve> {
    /// Base to raise the value to when committing.
    pub g: C,
    /// Base to raise the randomness to when committing.
    pub h: C,
}

impl<C: Curve> CommitmentKey<C> {
    pub fn new(g: C, h: C) -> Self { CommitmentKey { g, h } }

    /// Commit to the given value using a freshly generated randomness, and
    /// return the randomness that was generated.
    pub fn commit<T, V: AsRef<C::Scalar>>(
        &self,
        s: &V,
        csprng: &mut T,
    ) -> (Commitment<C>, Randomness<C>)
    where
        T: Rng, {
        let r = Randomness::<C>::generate(csprng);
        (self.hide(s, &r), r)
    }

    /// The low-level worker function that actually does the commitment.
    /// The interface is not very type-safe, hence the availability of other
    /// functions.
    pub fn hide_worker(&self, value: &C::Scalar, randomness: &C::Scalar) -> Commitment<C> {
        let h = self.h;
        let g = self.g;
        let cmm = multiexp(&[g, h], &[*value, *randomness]);
        // let hr = h.mul_by_scalar(randomness);
        // let gm = g.mul_by_scalar(value);
        Commitment(cmm) // hr.plus_point(&gm))
    }

    #[inline(always)]
    /// Hide the value inside a commitment using the given randomness.
    pub fn hide<V: AsRef<C::Scalar>>(&self, s: &V, r: &Randomness<C>) -> Commitment<C> {
        self.hide_worker(s.as_ref(), r.as_ref())
    }

    /// Prove that the commitment `self` contains the given value and
    /// randomness.
    pub fn open(&self, s: &Value<C>, r: &Randomness<C>, c: &Commitment<C>) -> bool {
        self.hide(s, r) == *c
    }

    pub fn generate<T>(csprng: &mut T) -> CommitmentKey<C>
    where
        T: Rng, {
        let h = C::generate(csprng);
        let g = C::generate(csprng);
        CommitmentKey { g, h }
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
