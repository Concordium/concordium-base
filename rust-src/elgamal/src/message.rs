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

use pairing::{
    bls12_381::{G1Compressed, G1},
    CurveAffine, CurveProjective, EncodedPoint,
};
use rand::*;

use crate::{
    constants::*,
    errors::{InternalError::*, *},
};

#[derive(Debug, PartialEq, Eq)]
pub struct Message(pub(crate) G1);

impl Message {
    // generate random message (for testing)
    pub fn generate<T>(csprng: &mut T) -> Message
    where
        T: Rng, {
        Message(G1::rand(csprng))
    }

    /// Convert this message to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; MESSAGE_LENGTH] {
        let mut ar = [0u8; MESSAGE_LENGTH];
        ar.copy_from_slice(self.0.into_affine().into_compressed().as_ref());
        ar
    }

    /// Construct a message from a slice of bytes.
    ///
    /// A `Result` whose okay value is a message key or whose error value
    /// is an `ElgamalError` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Message, ElgamalError> {
        if bytes.len() != MESSAGE_LENGTH {
            return Err(ElgamalError(MessageLengthError));
        }
        let mut g = G1Compressed::empty();
        g.as_mut().copy_from_slice(&bytes);
        match g.into_affine() {
            Err(x) => Err(ElgamalError(GDecodingError(x))),
            Ok(g_affine) => Ok(Message(G1::from(g_affine))),
        }
    }
}

#[cfg(feature = "serde")]
impl Serialize for Message {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer, {
        serializer.serialize_bytes(&self.to_bytes())
    }
}

#[cfg(feature = "serde")]
impl<'d> Deserialize<'d> for Message {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>, {
        struct MessageVisitor;

        impl<'d> Visitor<'d> for MessageVisitor {
            type Value = Message;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                formatter.write_str("An Elgamal message key as a 48-bytes")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Message, E>
            where
                E: SerdeError, {
                Message::from_bytes(bytes).or(Err(SerdeError::invalid_length(bytes.len(), &self)))
            }
        }
        deserializer.deserialize_bytes(MessageVisitor)
    }
}

#[test]
pub fn message_to_byte_conversion() {
    let mut csprng = thread_rng();
    for _i in 1..100 {
        let m = Message::generate(&mut csprng);
        let s = Message::from_bytes(&m.to_bytes());
        assert!(s.is_ok());
        assert_eq!(m, s.unwrap());
    }
}
