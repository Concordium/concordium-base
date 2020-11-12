use crate::*;

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
