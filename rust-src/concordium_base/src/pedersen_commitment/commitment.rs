// -*- mode: rust; -*-

//! Commitment type

use crypto_common::*;
use crypto_common_derive::*;
use curve_arithmetic::*;

use std::ops::Deref;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, SerdeBase16Serialize)]
/// A Commitment is a group element.
pub struct Commitment<C: Curve>(pub C);

impl<C: Curve> Commitment<C> {
    /// Combine two commitments. If the first is a commitment to v_1 with
    /// randomness r_1 and the second is a commitment to v_2 with randomness
    /// r_2, the resulting commitment is a commitment to v_1 + v_2 with
    /// randomness r_1 + r_2. NB: The commitments must be with the same
    /// commitment key, otherwise the above property does not hold.
    #[inline]
    pub fn combine(&self, other: &Commitment<C>) -> Commitment<C> {
        Commitment(self.0.plus_point(&other.0))
    }
}

/// This trait allows automatic conversion of &Commitment<C> to &C. In
/// particular this means that we can simply write `c.mul_by_scalar`, for
/// example.
impl<C: Curve> Deref for Commitment<C> {
    type Target = C;

    fn deref(&self) -> &C { &self.0 }
}

/// This trait allows automatic conversion of &Commitment<C> to &C. In
/// particular this means that we can simply write `c.mul_by_scalar`, for
/// example.
impl<C: Curve> std::borrow::Borrow<C> for Commitment<C> {
    fn borrow(&self) -> &C { &self.0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::{G1, G2};
    use rand::*;
    impl<C: Curve> Commitment<C> {
        pub fn generate<T: Rng>(csprng: &mut T) -> Commitment<C> { Commitment(C::generate(csprng)) }
    }

    macro_rules! macro_test_commitment_to_byte_conversion {
        ($function_name:ident, $curve_type:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                for _i in 0..20 {
                    let x = Commitment::<$curve_type>::generate(&mut csprng);
                    let y = serialize_deserialize(&x);
                    assert!(y.is_ok());
                    assert_eq!(x, y.unwrap());
                }
            }
        };
    }
    macro_test_commitment_to_byte_conversion!(commitment_to_byte_conversion_bls12_381_g1, G1);

    macro_test_commitment_to_byte_conversion!(commitment_to_byte_conversion_bls12_381_g2, G2);
}
