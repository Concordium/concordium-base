//! A known message

use rand::*;

use crypto_common::*;
use curve_arithmetic::*;

/// A message to sign. The PS scheme allows signing both a known message, where
/// the message is a vector of values to be signed, and also an unknown message,
/// which is a single value constructed in a special way.
#[derive(Debug, Serialize)]
pub struct KnownMessage<C: Pairing>(#[size_length = 4] pub Vec<C::ScalarField>);

impl<C: Pairing> PartialEq for KnownMessage<C> {
    fn eq(&self, other: &Self) -> bool { self.0 == other.0 }
}

impl<C: Pairing> Eq for KnownMessage<C> {}

impl<C: Pairing> KnownMessage<C> {
    /// Generate a valid `Message` from a `csprng`.
    pub fn generate<T>(n: usize, csprng: &mut T) -> KnownMessage<C>
    where
        T: Rng, {
        let mut vs: Vec<C::ScalarField> = Vec::with_capacity(n);
        for _i in 0..n {
            vs.push(C::generate_scalar(csprng));
        }

        KnownMessage(vs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::Bls12;

    macro_rules! macro_test_message_to_byte_conversion {
        ($function_name:ident, $pairing_type:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                for i in 1..20 {
                    let val = KnownMessage::<$pairing_type>::generate(i, &mut csprng);
                    let res_val2 = serialize_deserialize(&val);
                    assert!(res_val2.is_ok());
                    let val2 = res_val2.unwrap();
                    assert_eq!(val2, val);
                }
            }
        };
    }
    macro_test_message_to_byte_conversion!(message_to_byte_conversion_bls12_381, Bls12);
}
