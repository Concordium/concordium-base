// -*- mode: rust; -*-

//! A known message

use rand::*;

use crate::{known_message::*, signature::*};
use crypto_common::*;
use crypto_common_derive::*;
use curve_arithmetic::*;

use crate::secret::*;

/// PS public key. The documentation of the fields
/// assumes the secret key is $(x, y_1, ..., y_n)$ (see specification).
#[derive(Debug, Clone, Serialize, SerdeBase16Serialize)]
pub struct PublicKey<C: Pairing> {
    /// Generator of G1
    pub g:        C::G1,
    /// Generator of G2
    pub g_tilda:  C::G2,
    /// Generator $g_1$ raised to the powers $y_i$
    #[size_length = 4]
    pub ys:       Vec<C::G1>,
    /// Generator $g_2$ raised to the powers $y_i$
    #[size_length = 4]
    pub y_tildas: Vec<C::G2>,
    /// Generator $g_2$ raised to the power $x$.
    pub x_tilda:  C::G2,
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
    /// Return the number of commitments that can be signed with this key.
    pub fn len(&self) -> usize { self.ys.len() }

    pub fn verify(&self, sig: &Signature<C>, message: &KnownMessage<C>) -> bool {
        let ys = &self.y_tildas;
        let x = self.x_tilda;
        let ms = &message.0;
        if sig.0.is_zero_point() || ms.len() > ys.len() {
            return false;
        }
        let h = ys
            .iter()
            .zip(ms.iter())
            .fold(C::G2::zero_point(), |acc, (y, m)| {
                let ym = y.mul_by_scalar(m);
                acc.plus_point(&ym)
            });
        let hx = h.plus_point(&x);
        C::check_pairing_eq(&sig.0, &hx, &sig.1, &self.g_tilda)
    }

    /// Generate a public key  from a `csprng`.
    pub fn arbitrary<T>(n: usize, csprng: &mut T) -> PublicKey<C>
    where
        T: Rng, {
        let mut ys: Vec<C::G1> = Vec::with_capacity(n);
        for _i in 0..n {
            ys.push(C::G1::generate(csprng));
        }

        let mut y_tildas: Vec<C::G2> = Vec::with_capacity(n);
        for _i in 0..n {
            y_tildas.push(C::G2::generate(csprng));
        }

        PublicKey {
            g: C::G1::one_point(),
            g_tilda: C::G2::one_point(),
            ys,
            y_tildas,
            x_tilda: C::G2::generate(csprng),
        }
    }
}

impl<C: Pairing> From<&SecretKey<C>> for PublicKey<C> {
    /// Derive this public key from its corresponding `SecretKey`.
    fn from(sk: &SecretKey<C>) -> PublicKey<C> {
        let ys = sk.ys.iter().map(|r| sk.g.mul_by_scalar(r)).collect();
        let y_tildas = sk.ys.iter().map(|r| sk.g_tilda.mul_by_scalar(r)).collect();
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
                    let res_val2 = serialize_deserialize(&val);
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

    macro_rules! macro_test_sign_verify_dummy_sig {
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
                    let dummy = Signature(
                        <$pairing_type as Pairing>::G1::zero_point(),
                        <$pairing_type as Pairing>::G1::zero_point(),
                    );
                    assert!(!&pk.verify(&dummy, &message));
                }
            }
        };
    }

    macro_test_sign_verify_dummy_sig!(sign_verify_dummy_sig_bls12_381, Bls12);
}
