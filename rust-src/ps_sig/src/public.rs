// -*- mode: rust; -*-
//
// Authors:
// - bm@concordium.com

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

use crate::errors::{
    InternalError::{CurveDecodingError, PublicKeyLengthError},
    *,
};

use crate::{known_message::*, signature::*};
use curve_arithmetic::curve_arithmetic::*;

use crate::secret::*;

/// A message
#[derive(Debug)]
pub struct PublicKey<C: Pairing>(
    pub Vec<C::G_1>,
    pub Vec<C::G_2>,
    pub C::G_2,
);

impl<C: Pairing> PartialEq for PublicKey<C> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0 && self.1 == other.1 && self.2 == other.2
    }
}

impl<C: Pairing> Eq for PublicKey<C> {}

impl<C: Pairing> PublicKey<C> {
    // turn message vector into a byte aray
    #[inline]
    pub fn to_bytes(&self) -> Box<[u8]> {
        let vs = &self.0;
        let us = &self.1;
        let s = &self.2;
        let mut bytes: Vec<u8> = Vec::with_capacity(
            vs.len() * C::G_1::GROUP_ELEMENT_LENGTH + (us.len() + 1) * C::G_2::GROUP_ELEMENT_LENGTH,
        );
        for v in vs.iter() {
            bytes.extend_from_slice(&*C::G_1::curve_to_bytes(&v));
        }
        for u in us.iter() {
            bytes.extend_from_slice(&*C::G_2::curve_to_bytes(&u));
        }
        bytes.extend_from_slice(&*C::G_2::curve_to_bytes(s));
        bytes.into_boxed_slice()
    }

    /// Construct a message vec from a slice of bytes.
    ///
    /// A `Result` whose okay value is a message vec  or whose error value
    /// is an `SignatureError` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey<C>, SignatureError> {
        let l = bytes.len();
        if l < (C::G_2::GROUP_ELEMENT_LENGTH * 2 + C::G_1::GROUP_ELEMENT_LENGTH)
            || (l - C::G_2::GROUP_ELEMENT_LENGTH)
                % (C::G_1::GROUP_ELEMENT_LENGTH + C::G_2::GROUP_ELEMENT_LENGTH)
                != 0
        {
            return Err(SignatureError(PublicKeyLengthError));
        }
        let vlen = (l - C::G_2::GROUP_ELEMENT_LENGTH)
            / (C::G_1::GROUP_ELEMENT_LENGTH + C::G_2::GROUP_ELEMENT_LENGTH);
        let mut vs: Vec<C::G_1> = Vec::with_capacity(vlen);
        for i in 0..vlen {
            let j = i * C::G_1::GROUP_ELEMENT_LENGTH;
            let k = j + C::G_1::GROUP_ELEMENT_LENGTH;
            match C::G_1::bytes_to_curve(&bytes[j..k]) {
                Err(_) => return Err(SignatureError(CurveDecodingError)),
                Ok(fr) => vs.push(fr),
            }
        }

        let index = vlen * C::G_1::GROUP_ELEMENT_LENGTH;
        let mut us: Vec<C::G_2> = Vec::with_capacity(vlen);

        for i in 0..vlen {
            let j = i * C::G_2::GROUP_ELEMENT_LENGTH + index;
            let k = j + C::G_2::GROUP_ELEMENT_LENGTH;
            match C::G_2::bytes_to_curve(&bytes[j..k]) {
                Err(_) => return Err(SignatureError(CurveDecodingError)),
                Ok(fr) => us.push(fr),
            }
        }

        match C::G_2::bytes_to_curve(&bytes[(l - C::G_2::GROUP_ELEMENT_LENGTH)..]) {
            Err(_) => Err(SignatureError(CurveDecodingError)),
            Ok(fr) => Ok(PublicKey(vs, us, fr)),
        }
    }

    pub fn verify(&self, sig: &Signature<C>, message: &KnownMessage<C>) -> bool {
        let ys = &self.1;
        let x = self.2;
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
        let p2 = C::pair(sig.1, C::G_2::one_point());
        p1 == p2
    }

    /// Generate a public key  from a `csprng`.
    pub fn arbitrary<T>(n: usize, csprng: &mut T) -> PublicKey<C>
    where
        T: Rng, {
        let mut vs: Vec<C::G_1> = Vec::with_capacity(n);
        for _i in 0..n {
            vs.push(C::G_1::generate(csprng));
        }

        let mut us: Vec<C::G_2> = Vec::with_capacity(n);
        for _i in 0..n {
            us.push(C::G_2::generate(csprng));
        }

        PublicKey(vs, us, C::G_2::generate(csprng))
    }
}

impl<'a, C: Pairing> From<&'a SecretKey<C>> for PublicKey<C> {
    /// Derive this public key from its corresponding `SecretKey`.
    fn from(sk: &SecretKey<C>) -> PublicKey<C> {
        let (vs, x) = (&sk.0, &sk.1);
        let rs = vs
            .iter()
            .map(|r| C::G_1::one_point().mul_by_scalar(&r))
            .collect();
        let ts = vs
            .iter()
            .map(|r| C::G_2::one_point().mul_by_scalar(&r))
            .collect();
        let h = C::G_2::one_point().mul_by_scalar(&x);
        PublicKey(rs, ts, h)
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
                    let res_val2 = PublicKey::<$pairing_type>::from_bytes(&*val.to_bytes());
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
