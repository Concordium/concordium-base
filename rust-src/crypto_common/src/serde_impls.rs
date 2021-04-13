use crate::*;
use serde::{de, de::Visitor, Deserializer};
use std::convert::TryInto;

// A workaround since dalek does not implement proper serde instances.
#[derive(SerdeSerialize, SerdeDeserialize)]
pub struct KeyPairDef {
    #[serde(
        rename = "signKey",
        serialize_with = "base16_encode",
        deserialize_with = "base16_decode"
    )]
    pub secret: ed25519_dalek::SecretKey,
    #[serde(
        rename = "verifyKey",
        serialize_with = "base16_encode",
        deserialize_with = "base16_decode"
    )]
    pub public: ed25519_dalek::PublicKey,
}

impl KeyPairDef {
    pub fn generate<R: rand::CryptoRng + rand::Rng>(rng: &mut R) -> Self {
        Self::from(ed25519_dalek::Keypair::generate(rng))
    }
}

impl From<ed25519_dalek::Keypair> for KeyPairDef {
    fn from(kp: ed25519_dalek::Keypair) -> Self {
        Self {
            secret: kp.secret,
            public: kp.public,
        }
    }
}

impl From<KeyPairDef> for ed25519_dalek::Keypair {
    fn from(kp: KeyPairDef) -> ed25519_dalek::Keypair {
        ed25519_dalek::Keypair {
            secret: kp.secret,
            public: kp.public,
        }
    }
}

/// A manual implementation of the Serde deserializer to support
/// reading both from strings and from integers.
impl<'de> SerdeDeserialize<'de> for types::KeyIndex {
    fn deserialize<D: Deserializer<'de>>(des: D) -> Result<Self, D::Error> {
        // expect a u8, but also handle string
        des.deserialize_any(KeyIndexVisitor)
    }
}

struct KeyIndexVisitor;

impl<'de> Visitor<'de> for KeyIndexVisitor {
    type Value = types::KeyIndex;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "Either a string or a u8.")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        let x = v.parse().map_err(de::Error::custom)?;
        Ok(types::KeyIndex(x))
    }

    fn visit_u64<E: de::Error>(self, x: u64) -> Result<Self::Value, E> {
        if let Ok(x) = x.try_into() {
            Ok(types::KeyIndex(x))
        } else {
            Err(de::Error::custom("Key index value out of range."))
        }
    }
}
