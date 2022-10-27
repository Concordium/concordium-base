//! Common types needed in concordium.

use crate::{
    deserial_string, serial_string, Buffer, Deserial, Get, ParseResult, SerdeDeserialize,
    SerdeSerialize, Serial,
};
use byteorder::{BigEndian, ReadBytesExt};
pub use concordium_contracts_common::{AccountAddress, Address, Amount, ACCOUNT_ADDRESS_SIZE};
use concordium_contracts_common::{
    ContractAddress, ContractName, OwnedContractName, OwnedReceiveName, ReceiveName,
};
use crypto_common_derive::Serialize;
use derive_more::{Display, From, FromStr, Into};
use std::{collections::BTreeMap, num::ParseIntError, str::FromStr};
/// Index of an account key that is to be used.
#[derive(
    Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Serialize, Display, From, Into,
)]
#[repr(transparent)]
#[derive(SerdeSerialize)]
#[serde(transparent)]
pub struct KeyIndex(pub u8);

#[derive(
    SerdeSerialize,
    SerdeDeserialize,
    Serialize,
    Copy,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Debug,
    FromStr,
    Display,
    From,
    Into,
)]
#[serde(transparent)]
/// Index of the credential that is to be used.
pub struct CredentialIndex {
    pub index: u8,
}

impl Serial for Amount {
    fn serial<B: crate::Buffer>(&self, out: &mut B) { self.micro_ccd().serial(out) }
}

impl Deserial for Amount {
    fn deserial<R: byteorder::ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let micro_ccd = source.get()?;
        Ok(Amount::from_micro_ccd(micro_ccd))
    }
}

impl Serial for Address {
    fn serial<B: Buffer>(&self, out: &mut B) {
        match self {
            Address::Account(acc) => {
                0u8.serial(out);
                acc.serial(out)
            }
            Address::Contract(ca) => {
                1u8.serial(out);
                ca.serial(out)
            }
        }
    }
}

impl Deserial for Address {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        match u8::deserial(source)? {
            0u8 => Ok(Self::Account(source.get()?)),
            1u8 => Ok(Self::Contract(source.get()?)),
            _ => anyhow::bail!("Unsupported address type."),
        }
    }
}

impl Serial for AccountAddress {
    #[inline]
    fn serial<B: Buffer>(&self, x: &mut B) {
        x.write_all(&self.0)
            .expect("Writing to buffer should succeed.")
    }
}

impl Deserial for AccountAddress {
    #[inline]
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let mut buf = [0u8; ACCOUNT_ADDRESS_SIZE];
        source.read_exact(&mut buf)?;
        Ok(AccountAddress(buf))
    }
}

impl Serial for ContractAddress {
    #[inline]
    fn serial<B: Buffer>(&self, x: &mut B) {
        x.write_u64::<BigEndian>(self.index)
            .expect("Writing to buffer should succeed.");
        x.write_u64::<BigEndian>(self.subindex)
            .expect("Writing to buffer should succeed.");
    }
}

impl Deserial for ContractAddress {
    #[inline]
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let index = source.read_u64::<BigEndian>()?;
        let subindex = source.read_u64::<BigEndian>()?;
        Ok(ContractAddress::new(index, subindex))
    }
}

impl Serial for ReceiveName<'_> {
    #[inline]
    fn serial<B: Buffer>(&self, out: &mut B) {
        let string = self.get_chain_name();
        (string.len() as u16).serial(out);
        serial_string(string, out)
    }
}

impl Serial for OwnedReceiveName {
    #[inline]
    fn serial<B: Buffer>(&self, x: &mut B) { self.as_receive_name().serial(x) }
}

impl Deserial for OwnedReceiveName {
    #[inline]
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let len: u16 = source.get()?;
        let name = deserial_string(source, len.into())?;
        Ok(OwnedReceiveName::new(name)?)
    }
}

impl Serial for ContractName<'_> {
    #[inline]
    fn serial<B: Buffer>(&self, out: &mut B) {
        let string = self.get_chain_name();
        (string.len() as u16).serial(out);
        serial_string(string, out)
    }
}

impl Serial for OwnedContractName {
    #[inline]
    fn serial<B: Buffer>(&self, x: &mut B) { self.as_contract_name().serial(x) }
}

impl Deserial for OwnedContractName {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let len: u16 = source.get()?;
        let name = deserial_string(source, len.into())?;
        Ok(OwnedContractName::new(name)?)
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
/// A single signature. Using the same binary and JSON serialization as the
/// Haskell counterpart. In particular this means encoding the length as 2
/// bytes, and thus the largest size is 65535 bytes.
pub struct Signature {
    pub sig: Vec<u8>,
}

impl Serial for Signature {
    fn serial<B: Buffer>(&self, out: &mut B) {
        (self.sig.len() as u16).serial(out);
        out.write_all(&self.sig)
            .expect("Writing to buffer should succeed.");
    }
}

impl Deserial for Signature {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let len: u16 = source.get()?;
        // allocating is safe because len is a u16
        let mut sig = vec![0; len as usize];
        source.read_exact(&mut sig)?;
        Ok(Signature { sig })
    }
}

impl SerdeSerialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer, {
        serializer.serialize_str(&hex::encode(&self.sig))
    }
}

impl<'de> SerdeDeserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>, {
        let s = String::deserialize(deserializer)?;
        let sig = hex::decode(s).map_err(|e| serde::de::Error::custom(format!("{}", e)))?;
        if sig.len() <= 65535 {
            Ok(Signature { sig })
        } else {
            Err(serde::de::Error::custom("Signature length out of bounds."))
        }
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] { &self.sig }
}

/// Transaction signature structure, to match the one on the Haskell side.
#[derive(SerdeDeserialize, SerdeSerialize, Clone, PartialEq, Eq, Debug)]
#[serde(transparent)]
pub struct TransactionSignature {
    pub signatures: BTreeMap<CredentialIndex, BTreeMap<KeyIndex, Signature>>,
}

impl TransactionSignature {
    /// The total number of signatures.
    pub fn num_signatures(&self) -> u32 {
        // Since there are at most 256 credential indices, and at most 256 key indices
        // using `as` is safe.
        let x: usize = self.signatures.values().map(|sigs| sigs.len()).sum();
        x as u32
    }
}

impl Serial for TransactionSignature {
    fn serial<B: Buffer>(&self, out: &mut B) {
        let l = self.signatures.len() as u8;
        l.serial(out);
        for (idx, map) in self.signatures.iter() {
            idx.serial(out);
            (map.len() as u8).serial(out);
            crate::serial_map_no_length(map, out);
        }
    }
}

impl Deserial for TransactionSignature {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let num_creds: u8 = source.get()?;
        anyhow::ensure!(num_creds > 0, "Number of signatures must not be 0.");
        let mut out = BTreeMap::new();
        let mut last = None;
        for _ in 0..num_creds {
            let idx = source.get()?;
            anyhow::ensure!(
                last < Some(idx),
                "Credential indices must be strictly increasing."
            );
            last = Some(idx);
            let inner_len: u8 = source.get()?;
            anyhow::ensure!(
                inner_len > 0,
                "Each credential must have at least one signature."
            );
            let inner_map = crate::deserial_map_no_length(source, inner_len.into())?;
            out.insert(idx, inner_map);
        }
        Ok(TransactionSignature { signatures: out })
    }
}

/// Datatype used to indicate transaction expiry.
#[derive(
    SerdeDeserialize, SerdeSerialize, PartialEq, Eq, Debug, Serialize, Clone, Copy, PartialOrd, Ord,
)]
#[serde(transparent)]
pub struct TransactionTime {
    /// Seconds since the unix epoch.
    pub seconds: u64,
}

impl TransactionTime {
    pub fn from_seconds(seconds: u64) -> Self { Self { seconds } }
}

impl From<u64> for TransactionTime {
    fn from(seconds: u64) -> Self { Self { seconds } }
}

impl FromStr for TransactionTime {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let seconds = u64::from_str(s)?;
        Ok(Self { seconds })
    }
}

/// Datatype used to indicate a timestamp in milliseconds.
#[derive(
    SerdeDeserialize, SerdeSerialize, PartialEq, Eq, Debug, Serialize, Clone, Copy, PartialOrd, Ord,
)]
#[serde(transparent)]
pub struct Timestamp {
    /// Milliseconds since the unix epoch.
    pub millis: u64,
}

impl From<u64> for Timestamp {
    fn from(millis: u64) -> Self { Self { millis } }
}

impl FromStr for Timestamp {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let millis = u64::from_str(s)?;
        Ok(Self { millis })
    }
}

/// A ed25519 keypair. This is available in the `ed25519::dalek` crate, but the
/// JSON serialization there is not compatible with what we use, so we redefine
/// it there.
#[derive(Debug, SerdeSerialize, SerdeDeserialize)]
pub struct KeyPair {
    #[serde(
        rename = "signKey",
        serialize_with = "crate::serialize::base16_encode",
        deserialize_with = "crate::serialize::base16_decode"
    )]
    pub secret: ed25519_dalek::SecretKey,
    #[serde(
        rename = "verifyKey",
        serialize_with = "crate::serialize::base16_encode",
        deserialize_with = "crate::serialize::base16_decode"
    )]
    pub public: ed25519_dalek::PublicKey,
}

impl KeyPair {
    pub fn generate<R: rand::CryptoRng + rand::Rng>(rng: &mut R) -> Self {
        Self::from(ed25519_dalek::Keypair::generate(rng))
    }
}

impl From<ed25519_dalek::Keypair> for KeyPair {
    fn from(kp: ed25519_dalek::Keypair) -> Self {
        Self {
            secret: kp.secret,
            public: kp.public,
        }
    }
}

impl KeyPair {
    /// Sign the given message with the keypair.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        let expanded = ed25519_dalek::ExpandedSecretKey::from(&self.secret);
        let sig = expanded.sign(msg, &self.public);
        Signature {
            sig: sig.to_bytes().to_vec(),
        }
    }
}

impl From<KeyPair> for ed25519_dalek::Keypair {
    fn from(kp: KeyPair) -> ed25519_dalek::Keypair {
        ed25519_dalek::Keypair {
            secret: kp.secret,
            public: kp.public,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{
        distributions::{Distribution, Uniform},
        Rng,
    };

    #[test]
    fn transaction_signature_serialization() {
        let mut rng = rand::thread_rng();
        for _ in 0..100 {
            let num_creds = rng.gen_range(1, 30);
            let mut signatures = BTreeMap::new();
            for _ in 0..num_creds {
                let num_keys = rng.gen_range(1, 20);
                let mut cred_sigs = BTreeMap::new();
                for _ in 0..num_keys {
                    let num_elems = rng.gen_range(0, 200);
                    let sig = Signature {
                        sig: Uniform::new_inclusive(0, 255u8)
                            .sample_iter(rng)
                            .take(num_elems)
                            .collect(),
                    };
                    cred_sigs.insert(KeyIndex(rng.gen()), sig);
                }
                signatures.insert(CredentialIndex { index: rng.gen() }, cred_sigs);
            }
            let signatures = TransactionSignature { signatures };
            let js = serde_json::to_string(&signatures).expect("Serialization should succeed.");
            match serde_json::from_str::<TransactionSignature>(&js) {
                Ok(s) => assert_eq!(s, signatures, "Deserialized incorrect value."),
                Err(e) => panic!("{}", e),
            }

            let binary_result = crate::serialize_deserialize(&signatures)
                .expect("Binary signature serialization is not invertible.");
            assert_eq!(
                binary_result, signatures,
                "Binary signature parses incorrectly."
            );
        }
    }

    #[test]
    fn amount_json_serialization() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let amount = Amount::from_micro_ccd(rng.gen::<u64>());
            let s = serde_json::to_string(&amount).expect("Could not serialize");
            assert_eq!(
                amount,
                serde_json::from_str(&s).unwrap(),
                "Could not deserialize amount."
            );
        }

        let amount = Amount::from_micro_ccd(12345);
        let s = serde_json::to_string(&amount).expect("Could not serialize");
        assert_eq!(s, r#""12345""#, "Could not deserialize amount.");

        assert!(
            serde_json::from_str::<Amount>(r#""""#).is_err(),
            "Parsed empty string, but should not."
        );
        assert!(
            serde_json::from_str::<Amount>(r#""12f""#).is_err(),
            "Parsed string with corrupt data at end, but should not."
        );
        assert!(
            serde_json::from_str::<Amount>(r#""12345612312315415123123""#).is_err(),
            "Parsed overflowing amount, but should not."
        );
    }
}
