//! Elgamal message  types

use rand::*;

use crate::{common::*, curve_arithmetic::Curve};

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
    use ark_bls12_381::{G1Projective, G2Projective};

    use crate::curve_arithmetic::arkworks_instances::ArkGroup;

    use super::*;

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
    pub fn message_to_byte_conversion_g1() {
        test_message_serialization_helper::<ArkGroup<G1Projective>>();
    }
    #[test]
    pub fn message_to_byte_conversion_g2() {
        test_message_serialization_helper::<ArkGroup<G2Projective>>();
    }
}
