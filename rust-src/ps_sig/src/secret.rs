// -*- mode: rust; -*-

//! A secret key

use crate::{
    errors::{InternalError::SecretKeyLengthError, *},
    known_message::*,
    signature::*,
    unknown_message::*,
};
use crypto_common::*;
use curve_arithmetic::*;

use ff::Field;

use rand::*;

/// A secret key
#[derive(Debug, Serialize)]
pub struct SecretKey<C: Pairing> {
    /// Generator of the first pairing group. Not secret, but needed for various
    /// operations.
    pub g:       C::G1,
    /// Generator of the second pairing group. Not secret, but needed for
    /// various operations.
    pub g_tilda: C::G2,
    #[size_length = 4]
    pub ys:      Vec<C::ScalarField>,
    pub x:       C::ScalarField,
}

impl<C: Pairing> PartialEq for SecretKey<C> {
    fn eq(&self, other: &Self) -> bool { self.ys == other.ys && self.x == other.x }
}

impl<C: Pairing> Eq for SecretKey<C> {}

impl<C: Pairing> SecretKey<C> {
    /// Generate a secret key from a `csprng`. NB: This fixes the generators to
    /// be those defined by the library.
    pub fn generate<T>(n: usize, csprng: &mut T) -> SecretKey<C>
    where
        T: Rng, {
        let mut ys: Vec<C::ScalarField> = Vec::with_capacity(n);
        for _i in 0..n {
            ys.push(C::generate_scalar(csprng));
        }

        SecretKey {
            g: C::G1::one_point(),
            g_tilda: C::G2::one_point(),
            ys,
            x: C::generate_scalar(csprng),
        }
    }

    pub fn sign_known_message<T>(
        &self,
        message: &KnownMessage<C>,
        csprng: &mut T,
    ) -> Result<Signature<C>, SignatureError>
    where
        T: Rng, {
        let ys = &self.ys;
        let ms = &message.0;
        if ms.len() > ys.len() {
            return Err(SignatureError(SecretKeyLengthError));
        }

        let mut z =
            ms.iter()
                .zip(ys.iter())
                .fold(<C::ScalarField as Field>::zero(), |mut acc, (m, y)| {
                    let mut r = *m;
                    r.mul_assign(y);
                    acc.add_assign(&r);
                    acc
                });
        z.add_assign(&self.x);
        let h = self.g.mul_by_scalar(&C::generate_scalar(csprng));

        Ok(Signature(h, h.mul_by_scalar(&z)))
    }

    // FIXME: Should this not require also a AggregateDLog proof that the user knows
    // the values being commited to?
    pub fn sign_unknown_message<T>(
        &self,
        message: &UnknownMessage<C>,
        csprng: &mut T,
    ) -> Signature<C>
    where
        T: Rng, {
        let sk = self.g.mul_by_scalar(&self.x);
        let r = C::generate_non_zero_scalar(csprng);
        let a = self.g.mul_by_scalar(&r);
        let xmr = sk.plus_point(message).mul_by_scalar(&r);
        Signature(a, xmr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::Bls12;

    macro_rules! macro_test_secret_key_to_byte_conversion {
        ($function_name:ident, $pairing_type:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                for i in 0..20 {
                    let val = SecretKey::<$pairing_type>::generate(i, &mut csprng);
                    let res_val2 = serialize_deserialize(&val);
                    assert!(res_val2.is_ok());
                    let val2 = res_val2.unwrap();
                    assert_eq!(val2, val);
                }
            }
        };
    }

    macro_test_secret_key_to_byte_conversion!(secret_key_to_byte_conversion_bls12_381, Bls12);
}
