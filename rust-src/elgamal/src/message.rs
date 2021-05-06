//! Elgamal message  types

use rand::*;

use crypto_common::*;
use crypto_common_derive::*;
use curve_arithmetic::Curve;

#[derive(Debug, PartialEq, Eq, Serialize, SerdeBase16Serialize)]
#[repr(transparent)]
pub struct Message<C: Curve> {
    pub value: C,
}

impl<C: Curve> Message<C> {
    // generate random message (for testing)
    pub fn generate<T>(csprng: &mut T) -> Self
    where
        T: Rng,
    {
        Message {
            value: C::generate(csprng),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::{G1, G2};

    macro_rules! macro_test_message_to_byte_conversion {
        ($function_name:ident, $curve_type:path) => {
            #[test]
            pub fn $function_name() {
                let mut csprng = thread_rng();
                for _i in 1..100 {
                    let m: Message<$curve_type> = Message::generate(&mut csprng);
                    let s = serialize_deserialize(&m);
                    assert!(s.is_ok());
                    assert_eq!(m, s.unwrap());
                }
            }
        };
    }
    macro_test_message_to_byte_conversion!(message_to_byte_conversion_g1, G1);
    macro_test_message_to_byte_conversion!(message_to_byte_conversion_g2, G2);
}
