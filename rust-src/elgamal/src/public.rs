//! Elgamal  public keys.

use core::fmt::Debug;
use rand::*;

use crate::{cipher::*, message::*, secret::*};

use crypto_common::*;
use crypto_common_derive::*;
use curve_arithmetic::{multiexp, Curve, Value};

/// Elgamal public key .
#[derive(Copy, Clone, Eq, PartialEq, Serialize, SerdeBase16Serialize)]
pub struct PublicKey<C: Curve> {
    pub generator: C,
    pub key:       C,
}

impl<C: Curve> Debug for PublicKey<C> {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "PublicKey({:?}, {:?})", self.generator, self.key)
    }
}

impl<C: Curve> From<&SecretKey<C>> for PublicKey<C> {
    /// Derive this public key from its corresponding `SecretKey`.
    fn from(secret_key: &SecretKey<C>) -> PublicKey<C> {
        let generator: C = secret_key.generator;
        let key = generator.mul_by_scalar(&secret_key.scalar);
        PublicKey { generator, key }
    }
}

impl<C: Curve> PublicKey<C> {
    /// Encrypt and returned the randomness used. NB: Randomness must be kept
    /// private.
    pub fn encrypt_rand<T>(&self, csprng: &mut T, m: &Message<C>) -> (Cipher<C>, Randomness<C>)
    where
        T: Rng, {
        let k = Randomness::generate(csprng);
        let g = self.generator.mul_by_scalar(&k.randomness);
        // FIXME: Could use multiexponentiation when we are calling from
        // encrypt_exponent_rand.
        let s = self.key.mul_by_scalar(&k.randomness).plus_point(&m.value);
        (Cipher(g, s), k)
    }

    #[inline]
    /// Wrapper around `encrypt_rand` that forgets the randomness.
    pub fn encrypt<T>(&self, csprng: &mut T, m: &Message<C>) -> Cipher<C>
    where
        T: Rng, {
        self.encrypt_rand(csprng, m).0
    }

    pub fn hide(&self, k: &C::Scalar, message: &Message<C>) -> Cipher<C> {
        let t = self.generator.mul_by_scalar(k);
        let s = self.key.mul_by_scalar(k).plus_point(&message.value);
        Cipher(t, s)
    }

    /// Encrypt a value in the exponent, using the generator of the public key
    /// as the base.
    #[inline]
    pub fn encrypt_exponent_rand<T>(
        &self,
        csprng: &mut T,
        e: &Value<C>,
    ) -> (Cipher<C>, Randomness<C>)
    where
        T: Rng, {
        self.encrypt_exponent_rand_given_generator(e, &self.generator, csprng)
    }

    /// Encrypt the value "in the exponent", using the supplied generator as the
    /// base. Return the randomness used in encryption.
    ///
    /// Takes a generator h as an argument and encrypts h^e.
    pub fn encrypt_exponent_rand_given_generator<T>(
        &self,
        e: &Value<C>,
        h: &C,
        csprng: &mut T,
    ) -> (Cipher<C>, Randomness<C>)
    where
        T: Rng, {
        let randomness = C::generate_scalar(csprng);
        let g = self.generator.mul_by_scalar(&randomness);
        let s = multiexp(&[self.key, *h], &[randomness, *e.as_ref()]);
        let randomness = Randomness::new(randomness);
        (Cipher(g, s), randomness)
    }

    /// Wrapper around `encrypt_exponent_rand` that forgets the randomness.
    pub fn encrypt_exponent<T>(&self, csprng: &mut T, e: &Value<C>) -> Cipher<C>
    where
        T: Rng, {
        self.encrypt_exponent_rand(csprng, e).0
    }

    /// Wrapper around `encrypt_exponent_rand_given_generator` that forgets the
    /// randomness.
    pub fn encrypt_exponent_given_generator<T>(
        &self,
        e: &Value<C>,
        h: &C,
        csprng: &mut T,
    ) -> Cipher<C>
    where
        T: Rng, {
        self.encrypt_exponent_rand_given_generator(e, h, csprng).0
    }

    /// Variant of `encrypt_exponent_vec_given_generator` using generator of the
    /// public key as the base.
    pub fn encrypt_exponent_vec<'a, T, I>(
        &self,
        es: I,
        csprng: &mut T,
    ) -> Vec<(Cipher<C>, Randomness<C>)>
    where
        T: Rng,
        I: IntoIterator<Item = &'a Value<C>>, {
        self.encrypt_exponent_vec_given_generator(es, &self.generator, csprng)
    }

    /// Encrypt a sequence of values in the exponent, and return the list of
    /// encryptions.
    ///
    /// The generator `h` that serves the base of encryption in the exponent is
    /// given.
    pub fn encrypt_exponent_vec_given_generator<'a, T, I>(
        &self,
        es: I,
        h: &C,
        csprng: &mut T,
    ) -> Vec<(Cipher<C>, Randomness<C>)>
    where
        T: Rng,
        I: IntoIterator<Item = &'a Value<C>>, {
        let f = move |x: &Value<C>| -> (Cipher<C>, Randomness<C>) {
            self.encrypt_exponent_rand_given_generator(x, h, csprng)
        };
        es.into_iter().map(f).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::{G1, G2};

    macro_rules! macro_test_key_to_byte_conversion {
        ($function_name:ident, $curve_type:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                for _i in 1..100 {
                    let sk: SecretKey<$curve_type> = SecretKey::generate_all(&mut csprng);
                    let pk = PublicKey::from(&sk);
                    let res_pk2 = serialize_deserialize(&pk);
                    assert!(res_pk2.is_ok());
                    let pk2 = res_pk2.unwrap();
                    assert_eq!(pk2, pk);
                }
            }
        };
    }

    macro_test_key_to_byte_conversion!(key_to_byte_conversion_g1, G1);
    macro_test_key_to_byte_conversion!(key_to_byte_conversion_g2, G2);
}
