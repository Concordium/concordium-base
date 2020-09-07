//! Elgamal cipher  types

use crypto_common::*;
use crypto_common_derive::*;
use curve_arithmetic::*;

use rand::*;
use std::ops::Deref;

use std::rc::Rc;

#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, SerdeBase16Serialize)]
/// Encrypted message.
pub struct Cipher<C: Curve>(pub C, pub C);

/// Randomness which was used to encrypt a message.
#[derive(Debug, PartialEq, Eq, Clone, Serialize)]
#[repr(transparent)]
pub struct Randomness<C: Curve> {
    pub randomness: Rc<Secret<C::Scalar>>,
}

impl<C: Curve> AsRef<C::Scalar> for Randomness<C> {
    fn as_ref(&self) -> &C::Scalar { &self.randomness }
}

/// This trait allows automatic conversion of &Randomness<C> to &C::Scalar.
impl<C: Curve> Deref for Randomness<C> {
    type Target = C::Scalar;

    fn deref(&self) -> &C::Scalar { &self.randomness }
}

impl<C: Curve> Randomness<C> {
    pub fn new(v: C::Scalar) -> Self {
        Randomness {
            randomness: Rc::new(Secret::new(v)),
        }
    }

    pub fn to_value(&self) -> Value<C> {
        Value {
            value: self.randomness.clone(),
        }
    }

    /// Generate a non-zero randomness. Used in encryption.
    pub fn generate<T>(csprng: &mut T) -> Self
    where
        T: Rng, {
        Randomness::new(C::generate_non_zero_scalar(csprng))
    }
}

impl<C: Curve> Cipher<C> {
    /// Construct a cipher from a slice of bytes.
    /// only use if you know that the bytes are an encoding fo a cipher
    /// A `Result` whose okay value is a cipher key or whose error value
    /// is an `ElgamalError` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes_unchecked<R: ReadBytesExt>(bytes: &mut R) -> Fallible<Cipher<C>> {
        let g = C::bytes_to_curve_unchecked(bytes)?;
        let h = C::bytes_to_curve_unchecked(bytes)?;
        Ok(Cipher(g, h))
    }

    /// Generate a random cipher.
    pub fn generate<T>(csprng: &mut T) -> Self
    where
        T: Rng, {
        Cipher(C::generate(csprng), C::generate(csprng))
    }

    /// Combine two ciphers together by adding the individual components.
    ///
    /// This does not check that both ciphers were produced with the same public
    /// key, that is the responsibility of the caller. In case ciphers were
    /// produced with different public keys, their combination is still
    /// mathematically valid, however it does not have meaning.
    pub fn combine(&self, other: &Self) -> Self {
        Self(self.0.plus_point(&other.0), self.1.plus_point(&other.1))
    }

    /// Scale the ciphertext by the given scalar. If the input is encryption of
    /// `m`, then the result is the encryption of `m^e`, where `e` is the given
    /// exponent.
    pub fn scale(&self, e: &C::Scalar) -> Self {
        Self(self.0.mul_by_scalar(e), self.1.mul_by_scalar(e))
    }

    /// Same as `scale`, but provided for convenience.
    pub fn scale_u64(&self, e: u64) -> Self { self.scale(&C::scalar_from_u64(e)) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::{G1, G2};

    macro_rules! macro_test_cipher_to_byte_conversion {
        ($function_name:ident, $curve_type:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                for _i in 1..100 {
                    let c: Cipher<$curve_type> = Cipher::generate(&mut csprng);
                    let s = serialize_deserialize(&c);
                    assert!(s.is_ok());
                    assert_eq!(c, s.unwrap());
                }
            }
        };
    }

    macro_test_cipher_to_byte_conversion!(key_to_cipher_conversion_g1, G1);
    macro_test_cipher_to_byte_conversion!(key_to_cipher_conversion_g2, G2);
}
