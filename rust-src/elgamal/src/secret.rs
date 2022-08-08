// -*- mode: rust; -*-

//! Elgamal secret key types
use crate::{cipher::*, message::*};
use anyhow::{bail, Result};
use crypto_common::*;
use curve_arithmetic::{Curve, Value};
use ff::Field;
use rand::*;
use std::collections::HashMap;

/// Elgamal secret key packed together with a chosen generator.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, SerdeBase16Serialize)]
pub struct SecretKey<C: Curve> {
    /// Generator of the group, not secret but convenient to have here.
    pub generator: C,
    /// Secret key.
    pub scalar:    C::Scalar,
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

pub type BabyStepGiantStepTable = HashMap<Vec<u8>, u64>;

#[derive(Eq, PartialEq, Debug)]
/// The table for the baby step giant step algorithm, with some auxiliary data.
pub struct BabyStepGiantStep<C: Curve> {
    /// Precomputed table of powers.
    table:         BabyStepGiantStepTable,
    /// Point base^{-m}
    inverse_point: C,
    /// Size of the table.
    m:             u64,
}

impl<C: Curve> Serial for BabyStepGiantStep<C> {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.put(&self.m);
        out.put(&self.inverse_point);
        for (k, v) in self.table.iter() {
            out.write_all(k).expect("Writing to buffer should succeed.");
            out.put(v)
        }
    }
}

impl<C: Curve> Deserial for BabyStepGiantStep<C> {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> Result<Self> {
        let m: u64 = source.get()?;
        let inverse_point = source.get()?;
        let mut table = HashMap::with_capacity(std::cmp::min(1 << 16, m as usize));
        for _ in 0..m {
            let mut k = vec![0; C::GROUP_ELEMENT_LENGTH];
            source.read_exact(&mut k)?;
            let v = source.get()?;
            if table.insert(k, v).is_some() {
                bail!("Duplicate element found during deserialization.")
            }
        }
        Ok(Self {
            table,
            inverse_point,
            m,
        })
    }
}

impl<C: Curve> BabyStepGiantStep<C> {
    /// Generate a new instance, precomputing the table.
    pub fn new(base: &C, m: u64) -> Self {
        let mut table = HashMap::with_capacity(m as usize);
        let mut base_j = C::zero_point();
        for j in 0..m {
            table.insert(to_bytes(&base_j), j);
            base_j = base_j.plus_point(base);
        }
        Self {
            table,
            m,
            inverse_point: base_j.inverse_point(),
        }
    }

    /// Compute the discrete log using the instance. This function's performance
    /// is linear in `l / m` where `l` is the value stored in the exponent of
    /// `v`, and `m` is the size of the table.
    ///
    /// The function will panic if `l` is not less than `u64::MAX`, although
    /// practically it will appear to loop well-before that value is reached.
    pub fn discrete_log(&self, v: &C) -> u64 {
        let mut y = *v;
        for i in 0..=u64::MAX {
            if let Some(j) = self.table.get(&to_bytes(&y)) {
                return i * self.m + j;
            }
            y = y.plus_point(&self.inverse_point);
        }
        unreachable!("It should not be feasible to do 2^64 group additions.")
    }

    /// Composition of `new` nad `discrete_log` methods for convenience.
    ///
    /// Less efficient than reusing the table.
    pub fn discrete_log_full(base: &C, m: u64, v: &C) -> u64 {
        BabyStepGiantStep::new(base, m).discrete_log(v)
    }
}

impl<C: Curve> SecretKey<C> {
    pub fn decrypt(&self, c: &Cipher<C>) -> Message<C> {
        let x = c.0; // k * g
        let kag = x.mul_by_scalar(&self.scalar); // k * a * g
        let y = c.1; // m + k * a * g
        let value = y.minus_point(&kag); // m
        Message { value }
    }

    pub fn decrypt_exponent_slow(&self, c: &Cipher<C>) -> Value<C> {
        let m = self.decrypt(c).value;
        let mut a = <C::Scalar as Field>::zero();
        let mut i = C::zero_point();
        let field_one = <C::Scalar as Field>::one();
        while m != i {
            i = i.plus_point(&self.generator);
            a.add_assign(&field_one);
        }
        Value::new(a)
    }

    /// Decrypt the value in the exponent. It is assumed the encrypted value can
    /// be represented in 64 bits, and are small enough. Otherwise this function
    /// will appear to not terminate.
    ///
    /// This function takes an auxiliary instance of BabyStepGiantStep to speed
    /// up decryption.
    pub fn decrypt_exponent(&self, c: &Cipher<C>, bsgs: &BabyStepGiantStep<C>) -> u64 {
        let dec = self.decrypt(c).value;
        bsgs.discrete_log(&dec)
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

    // Test serialiation of baby-step-giant-step since it is implemented manually.
    #[test]
    fn test_bsgs_serialize() {
        let mut csprng = thread_rng();
        let m = 1 << 16;
        for _ in 0..10 {
            let bsgs = BabyStepGiantStep::<G1>::new(&G1::generate(&mut csprng), m);
            let res = serialize_deserialize(&bsgs);
            assert!(
                res.is_ok(),
                "Failed to deserialize baby step giant step table."
            );
            assert_eq!(
                res.unwrap(),
                bsgs,
                "Deserialized table is different from original."
            );
        }
    }
}
