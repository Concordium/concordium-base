// -*- mode: rust; -*-
//
// Authors:
// - bm@concordium.com

//! Elgamal message  types

#[cfg(feature = "serde")]
use serde::de::Error as SerdeError;
#[cfg(feature = "serde")]
use serde::de::Visitor;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde::{Deserializer, Serializer};
#[cfg(feature = "serde")]
use std::marker::PhantomData;

use crate::errors::*;

use rand::*;

use curve_arithmetic::Curve;

use std::io::Cursor;

#[derive(Debug, PartialEq, Eq)]
pub struct Message<C: Curve>(pub C);

impl<C: Curve> Message<C> {
    // generate random message (for testing)
    pub fn generate<T>(csprng: &mut T) -> Self
    where
        T: Rng, {
        Message(C::generate(csprng))
    }

    /// Convert this message to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> Box<[u8]> { self.0.curve_to_bytes() }

    /// Construct a message from a slice of bytes.
    ///
    /// A `Result` whose okay value is a message key or whose error value
    /// is an `ElgamalError` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes(bytes: &mut Cursor<&[u8]>) -> Result<Self, ElgamalError> {
        let g = C::bytes_to_curve(bytes)?;
        Ok(Message(g))
    }
}

#[cfg(feature = "serde")]
impl<C: Curve> Serialize for Message<C> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer, {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

#[cfg(feature = "serde")]
impl<'d, C: Curve> Deserialize<'d> for Message<C> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>, {
        struct MessageVisitor<C: Curve>(PhantomData<C>);

        impl<'d, C: Curve> Visitor<'d> for MessageVisitor<C> {
            type Value = Message<C>;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                formatter.write_str("An Elgamal message key as a 48-bytes")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Message<C>, E>
            where
                E: SerdeError, {
                Message::from_bytes(bytes).or(Err(SerdeError::invalid_length(bytes.len(), &self)))
            }
        }
        deserializer.deserialize_bytes(MessageVisitor(PhantomData))
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
                    let s = Message::from_bytes(&mut Cursor::new(&m.to_bytes()));
                    assert!(s.is_ok());
                    assert_eq!(m, s.unwrap());
                }
            }
        };
    }
    macro_test_message_to_byte_conversion!(message_to_byte_conversion_g1, G1);
    macro_test_message_to_byte_conversion!(message_to_byte_conversion_g2, G2);
}
