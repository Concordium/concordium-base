//! Elgamal message  types

use rand::*;

use crypto_common::*;
use crypto_common_derive::*;
use curve_arithmetic::Curve;

#[derive(Debug, PartialEq, Eq, Serialize, SerdeBase16Serialize)]
#[repr(transparent)]
/// Message to be encrypted. This is a simple wrapper around a group element,
/// but we use it for added type safety.
pub struct Message<C: Curve> {
    pub value: C,
}

impl<C: Curve> Message<C> {
    // generate random message (for testing)
    pub fn generate<T>(csprng: &mut T) -> Self
    where
        T: Rng, {
        Message {
            value: C::generate(csprng),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::{G1, G2};

    fn test_message_serialization_helper<C: Curve>() {
        let mut csprng = thread_rng();
        for _i in 1..100 {
            let m: Message<C> = Message::generate(&mut csprng);
            let s = serialize_deserialize(&m);
            assert!(s.is_ok());
            assert_eq!(m, s.unwrap());
        }
    }

    #[test]
    pub fn message_to_byte_conversion_g1() { test_message_serialization_helper::<G1>(); }
    #[test]
    pub fn message_to_byte_conversion_g2() { test_message_serialization_helper::<G2>(); }
}
