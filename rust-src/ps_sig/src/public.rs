// -*- mode: rust; -*-

//! A known message

use rand::*;
#[cfg(feature = "serde")]
use serde::de::Error as SerdeError;
#[cfg(feature = "serde")]
use serde::de::Visitor;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde::{Deserializer, Serializer};

use crate::{known_message::*, signature::*};
use curve_arithmetic::curve_arithmetic::*;
use failure::Error;
use std::io::Cursor;

use crate::secret::*;

use curve_arithmetic::serialization::*;

/// PS public key. The documentation of the fields
/// assumes the secret key is $(x, y_1, ..., y_n)$ (see specification).
#[derive(Debug, Clone)]
pub struct PublicKey<C: Pairing> {
    /// Generator of G_1
    pub g: C::G_1,
    /// Generator of G_2
    pub g_tilda: C::G_2,
    /// Generator $g_1$ raised to the powers $y_i$
    pub ys: Vec<C::G_1>,
    /// Generator $g_2$ raised to the powers $y_i$
    pub y_tildas: Vec<C::G_2>,
    /// Generator $g_2$ raised to the power $x$.
    pub x_tilda: C::G_2,
}

impl<C: Pairing> PartialEq for PublicKey<C> {
    fn eq(&self, other: &Self) -> bool {
        self.g == other.g
            && self.g_tilda == other.g_tilda
            && self.ys == other.ys
            && self.y_tildas == other.y_tildas
            && self.x_tilda == other.x_tilda
    }
}

impl<C: Pairing> Eq for PublicKey<C> {}

#[allow(clippy::len_without_is_empty)]
impl<C: Pairing> PublicKey<C> {
    // turn message vector into a byte aray
    #[inline]
    pub fn to_bytes(&self) -> Box<[u8]> {
        let gen1 = &self.g;
        let gen2 = &self.g_tilda;
        let vs = &self.ys;
        let us = &self.y_tildas;
        let s = &self.x_tilda;
        let mut bytes: Vec<u8> = Vec::with_capacity(
            4 + 4
                + (vs.len() + 1) * C::G_1::GROUP_ELEMENT_LENGTH
                + (us.len() + 2) * C::G_2::GROUP_ELEMENT_LENGTH,
        );
        write_curve_element::<C::G_1>(gen1, &mut bytes);
        write_curve_element::<C::G_2>(gen2, &mut bytes);
        write_curve_elements::<C::G_1>(vs, &mut bytes);
        write_curve_elements::<C::G_2>(us, &mut bytes);
        write_curve_element::<C::G_2>(s, &mut bytes);
        bytes.into_boxed_slice()
    }

    /// Return the number of commitments that can be signed with this key.
    pub fn len(&self) -> usize { self.ys.len() }

    /// Construct a message vec from a slice of bytes.
    ///
    /// A `Result` whose okay value is a message vec  or whose error value
    /// is an `Error` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes(bytes: &mut Cursor<&[u8]>) -> Result<PublicKey<C>, Error> {
        let g = read_curve::<C::G_1>(bytes)?;
        let g_tilda = read_curve::<C::G_2>(bytes)?;
        let ys = read_curve_elements::<C::G_1>(bytes)?;
        let y_tildas = read_curve_elements::<C::G_2>(bytes)?;
        let x_tilda = read_curve::<C::G_2>(bytes)?;
        Ok(PublicKey {
            g,
            g_tilda,
            ys,
            y_tildas,
            x_tilda,
        })
    }

    pub fn verify(&self, sig: &Signature<C>, message: &KnownMessage<C>) -> bool {
        let ys = &self.y_tildas;
        let x = self.x_tilda;
        let ms = &message.0;
        if ms.len() > ys.len() {
            return false;
        }
        let h = ys
            .iter()
            .zip(ms.iter())
            .fold(C::G_2::zero_point(), |acc, (y, m)| {
                let ym = y.mul_by_scalar(&m);
                acc.plus_point(&ym)
            });
        let hx = h.plus_point(&x);
        let p1 = C::pair(sig.0, hx);
        let p2 = C::pair(sig.1, self.g_tilda);
        p1 == p2
    }

    /// Generate a public key  from a `csprng`.
    pub fn arbitrary<T>(n: usize, csprng: &mut T) -> PublicKey<C>
    where
        T: Rng, {
        let mut ys: Vec<C::G_1> = Vec::with_capacity(n);
        for _i in 0..n {
            ys.push(C::G_1::generate(csprng));
        }

        let mut y_tildas: Vec<C::G_2> = Vec::with_capacity(n);
        for _i in 0..n {
            y_tildas.push(C::G_2::generate(csprng));
        }

        PublicKey {
            g: C::G_1::one_point(),
            g_tilda: C::G_2::one_point(),
            ys,
            y_tildas,
            x_tilda: C::G_2::generate(csprng),
        }
    }
}

impl<'a, C: Pairing> From<&'a SecretKey<C>> for PublicKey<C> {
    /// Derive this public key from its corresponding `SecretKey`.
    fn from(sk: &SecretKey<C>) -> PublicKey<C> {
        let ys = sk.ys.iter().map(|r| sk.g.mul_by_scalar(&r)).collect();
        let y_tildas = sk.ys.iter().map(|r| sk.g_tilda.mul_by_scalar(&r)).collect();
        let x_tilda = sk.g_tilda.mul_by_scalar(&sk.x);
        PublicKey {
            g: sk.g,
            g_tilda: sk.g_tilda,
            ys,
            y_tildas,
            x_tilda,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::Bls12;

    macro_rules! macro_test_public_key_to_byte_conversion {
        ($function_name:ident, $pairing_type:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                for i in 1..20 {
                    let val = PublicKey::<$pairing_type>::arbitrary(i, &mut csprng);
                    let res_val2 =
                        PublicKey::<$pairing_type>::from_bytes(&mut Cursor::new(&*val.to_bytes()));
                    assert!(res_val2.is_ok());
                    let val2 = res_val2.unwrap();
                    assert_eq!(val2, val);
                }
            }
        };
    }

    macro_test_public_key_to_byte_conversion!(public_key_to_byte_conversion_bls12_381, Bls12);

    macro_rules! macro_test_sign_verify_pass {
        ($function_name:ident, $pairing_type:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                for i in 1..20 {
                    let sk = SecretKey::<$pairing_type>::generate(i, &mut csprng);
                    let pk = PublicKey::from(&sk);
                    let message = KnownMessage::<$pairing_type>::generate(i, &mut csprng);
                    let sig = sk.sign_known_message(&message, &mut csprng);
                    assert!(sig.is_ok());
                    assert!(&pk.verify(&sig.unwrap(), &message));
                }
            }
        };
    }
    macro_test_sign_verify_pass!(sign_verify_pass_bls12_381, Bls12);

    macro_rules! macro_test_sign_verify_different_message {
        ($function_name:ident, $pairing_type:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                for i in 1..20 {
                    let sk = SecretKey::<$pairing_type>::generate(i, &mut csprng);
                    let pk = PublicKey::from(&sk);
                    let message = KnownMessage::<$pairing_type>::generate(i, &mut csprng);
                    let different_message = KnownMessage::<$pairing_type>::generate(i, &mut csprng);
                    let sig = sk.sign_known_message(&message, &mut csprng);
                    assert!(sig.is_ok());
                    assert!(!&pk.verify(&sig.unwrap(), &different_message));
                }
            }
        };
    }

    macro_test_sign_verify_different_message!(sign_verify_different_message_bls12_381, Bls12);

    macro_rules! macro_test_sign_verify_different_sig {
        ($function_name:ident, $pairing_type:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                for i in 1..20 {
                    let sk = SecretKey::<$pairing_type>::generate(i, &mut csprng);
                    let pk = PublicKey::from(&sk);
                    let message = KnownMessage::<$pairing_type>::generate(i, &mut csprng);
                    let different_message = KnownMessage::<$pairing_type>::generate(i, &mut csprng);
                    let sig = sk.sign_known_message(&message, &mut csprng);
                    let different_sig = sk.sign_known_message(&different_message, &mut csprng);
                    assert!(sig.is_ok());
                    assert!(different_sig.is_ok());
                    assert!(!&pk.verify(&different_sig.unwrap(), &message));
                }
            }
        };
    }

    macro_test_sign_verify_different_sig!(sign_verify_different_sig_bls12_381, Bls12);
}
