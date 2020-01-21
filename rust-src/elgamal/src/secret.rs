// -*- mode: rust; -*-

//! Elgamal secret key types
use crate::{cipher::*, message::*};
use rand::*;

use curve_arithmetic::Curve;
use crypto_common::*;

use ff::Field;

/// Elgamal secret key packed together with a chosen generator.
#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
pub struct SecretKey<C: Curve> {
    /// Generator of the group, not secret but convenient to have here.
    pub generator: C,
    /// Secret key.
    pub scalar: C::Scalar,
}

// THIS IS COMMENTED FOR NOW FOR COMPATIBILITY WITH BLS CURVE IMPLEMENTATION
// ONCE WE HAVE TAKEN OVER THE SOURCE OF THE CURVE THIS SHOULD BE IMPLEMENTED
// Overwrite secret key material with null bytes when it goes out of scope.
//
// impl Drop for SecretKey {
// fn drop(&mut self) {
// (self.0).into_repr().0.clear();
// }
// }

impl<C: Curve> SecretKey<C> {
    pub fn decrypt(&self, c: &Cipher<C>) -> Message<C> {
        let x = c.0; // k * g
        let kag = x.mul_by_scalar(&self.scalar); // k * a * g
        let y = c.1; // m + k * a * g
        let value = y.minus_point(&kag); // m
        Message { value }
    }

    pub fn decrypt_exponent(&self, c: &Cipher<C>) -> C::Scalar {
        let m = self.decrypt(c).value;
        let mut a = <C::Scalar as Field>::zero();
        let mut i = C::zero_point();
        let field_one = <C::Scalar as Field>::one();
        while m != i {
            i = i.plus_point(&self.generator);
            a.add_assign(&field_one);
        }
        a
    }

    pub fn decrypt_exponent_vec(&self, v: &[Cipher<C>]) -> Vec<C::Scalar> {
        v.iter().map(|y| self.decrypt_exponent(y)).collect()
    }

    /// Generate a `SecretKey` from a `csprng`.
    pub fn generate<T: Rng>(generator: &C, csprng: &mut T) -> Self {
        SecretKey {
            generator: *generator,
            scalar:    C::generate_scalar(csprng),
        }
    }

    /// Generate a `SecretKey` as well as a generator.
    pub fn generate_all<T: Rng>(csprng: &mut T) -> Self {
        let x = C::generate_non_zero_scalar(csprng);
        SecretKey {
            generator: C::one_point().mul_by_scalar(&x),
            scalar:    C::generate_scalar(csprng),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::{G1, G2};
    macro_rules! macro_test_secret_key_to_byte_conversion {
        ($function_name:ident, $curve_type:path) => {
            #[test]
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                for _i in 1..100 {
                    let sk: SecretKey<$curve_type> = SecretKey::generate_all(&mut csprng);
                    let res_sk2 = serialize_deserialize(&sk);
                    assert!(res_sk2.is_ok());
                    let sk2 = res_sk2.unwrap();
                    assert_eq!(sk2, sk);
                }
            }
        };
    }

    macro_test_secret_key_to_byte_conversion!(secret_key_to_byte_conversion_g1, G1);
    macro_test_secret_key_to_byte_conversion!(secret_key_to_byte_conversion_g2, G2);
}
