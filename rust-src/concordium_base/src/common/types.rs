//! Common types needed in concordium.

use super::{
    deserial_string, serial_string, Buffer, Deserial, Get, ParseResult, SerdeDeserialize,
    SerdeSerialize, Serial,
};
use crate::common::Serialize;
use byteorder::{BigEndian, ReadBytesExt};
use concordium_contracts_common::{
    self as concordium_std, ContractAddress, ContractName, OwnedContractName, OwnedParameter,
    OwnedReceiveName, Parameter, ReceiveName,
};
pub use concordium_contracts_common::{AccountAddress, Address, Amount, ACCOUNT_ADDRESS_SIZE};
use derive_more::{Display, From, FromStr, Into};
use ed25519_dalek::Signer;
use std::{collections::BTreeMap, num::ParseIntError, str::FromStr};
/// Index of an account key that is to be used.
#[derive(
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Clone,
    Copy,
    Hash,
    Serialize,
    Display,
    From,
    Into,
    concordium_std::Serialize,
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
    concordium_std::Serialize,
)]
#[serde(transparent)]
/// Index of the credential that is to be used.
pub struct CredentialIndex {
    pub index: u8,
}

impl Serial for Amount {
    fn serial<B: super::Buffer>(&self, out: &mut B) { self.micro_ccd().serial(out) }
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

impl Serial for Parameter<'_> {
    fn serial<B: Buffer>(&self, out: &mut B) {
        let bytes = self.as_ref();
        (bytes.len() as u16).serial(out);
        out.write_all(bytes)
            .expect("Writing to buffer should succeed.")
    }
}

impl Serial for OwnedParameter {
    #[inline]
    fn serial<B: Buffer>(&self, out: &mut B) { self.as_parameter().serial(out) }
}

impl Deserial for OwnedParameter {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        // Since `MAX_PARAMETER_LEN == u16::MAX`, we don't need to check it explicitly.
        // The constant exists in concordium_contracts_common::constants.
        let len: u16 = source.get()?;
        let mut bytes = vec![0u8; len.into()]; // Safe to preallocate since len fits `u16`.
        source.read_exact(&mut bytes)?;
        Ok(OwnedParameter::new_unchecked(bytes))
    }
}

/// A ratio between two `u64` integers.
///
/// It should be safe to assume the denominator is not zero and that numerator
/// and denominator are coprime.
///
/// This type is introduced (over using `num::rational::Ratio<u64>`) to add the
/// above requirements and to provide implementations for `serde::Serialize` and
/// `serde::Deserialize`.
#[derive(Debug, SerdeDeserialize, SerdeSerialize, Serial, Clone, Copy)]
#[serde(try_from = "rust_decimal::Decimal", into = "rust_decimal::Decimal")]
pub struct Ratio {
    numerator:   u64,
    denominator: u64,
}

/// Error during creating a new ratio.
#[derive(Debug, Clone, thiserror::Error)]
pub enum NewRatioError {
    #[error("Denominator cannot be 0.")]
    ZeroDenominator,
    #[error("Numerator and denominator must be coprime.")]
    NotCoprime,
}

impl Ratio {
    /// Construct a new ratio. Returns an error if denominator is non-zero or
    /// numerator and denominator are not coprime.
    pub fn new(numerator: u64, denominator: u64) -> Result<Self, NewRatioError> {
        if denominator == 0 {
            return Err(NewRatioError::ZeroDenominator);
        }
        if num::Integer::gcd(&numerator, &denominator) != 1 {
            return Err(NewRatioError::NotCoprime);
        }
        Ok(Self {
            numerator,
            denominator,
        })
    }

    /// Construct a new ratio without checking anything.
    ///
    /// It is up to the caller to ensure the denominator is not zero and that
    /// numerator and denominator are coprime.
    pub fn new_unchecked(numerator: u64, denominator: u64) -> Self {
        Self {
            numerator,
            denominator,
        }
    }

    /// Get the numerator of the ratio.
    pub fn numerator(&self) -> u64 { self.numerator }

    /// Get the denominator of the ratio.
    pub fn denominator(&self) -> u64 { self.denominator }
}

impl Deserial for Ratio {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let numerator: u64 = source.get()?;
        let denominator: u64 = source.get()?;
        Ok(Self::new(numerator, denominator)?)
    }
}

impl From<Ratio> for rust_decimal::Decimal {
    fn from(ratio: Ratio) -> rust_decimal::Decimal {
        rust_decimal::Decimal::from(ratio.numerator)
            / rust_decimal::Decimal::from(ratio.denominator)
    }
}

/// Error from converting a decimal to a [`Ratio`].
#[derive(Debug, Clone, thiserror::Error)]
#[error("Unrepresentable number.")]
pub struct RatioFromDecimalError;

impl TryFrom<rust_decimal::Decimal> for Ratio {
    type Error = RatioFromDecimalError;

    fn try_from(mut value: rust_decimal::Decimal) -> Result<Self, Self::Error> {
        value.normalize_assign();
        let mantissa = value.mantissa();
        let scale = value.scale();
        let denominator = 10u64.checked_pow(scale).ok_or(RatioFromDecimalError)?;
        let numerator: u64 = mantissa.try_into().map_err(|_| RatioFromDecimalError)?;
        let g = num::Integer::gcd(&numerator, &denominator);
        let numerator = numerator / g;
        let denominator = denominator / g;
        Ok(Self {
            numerator,
            denominator,
        })
    }
}

impl From<Ratio> for num::rational::Ratio<u64> {
    fn from(ratio: Ratio) -> Self { Self::new_raw(ratio.numerator, ratio.denominator) }
}

#[derive(Clone, PartialEq, Eq, Debug)]
/// A single signature. Using the same binary and JSON serialization as the
/// Haskell counterpart. In particular this means encoding the length as 2
/// bytes, and thus the largest size is 65535 bytes.
pub struct Signature {
    pub sig: Vec<u8>,
}

impl From<ed25519_dalek::Signature> for Signature {
    fn from(value: ed25519_dalek::Signature) -> Self {
        Self {
            sig: value.to_vec(),
        }
    }
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
#[derive(SerdeDeserialize, SerdeSerialize, Clone, PartialEq, Eq, Debug, derive_more::AsRef)]
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
            super::serial_map_no_length(map, out);
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
            let inner_map = super::deserial_map_no_length(source, inner_len.into())?;
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
    /// Construct a timestamp from seconds since the unix epoch.
    pub fn from_seconds(seconds: u64) -> Self { Self { seconds } }

    /// Construct a timestamp that is the given amount of seconds in the future.
    pub fn seconds_after(seconds: u32) -> Self {
        Self::from_seconds(chrono::offset::Utc::now().timestamp() as u64 + u64::from(seconds))
    }

    /// Construct a timestamp that is the given amount of minutes in the future.
    pub fn minutes_after(minutes: u32) -> Self { Self::seconds_after(minutes * 60) }

    /// Construct a timestamp that is the given amount of hours in the future.
    pub fn hours_after(hours: u32) -> Self { Self::minutes_after(hours * 60) }
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

impl Timestamp {
    pub fn now() -> Self { (chrono::Utc::now().timestamp_millis() as u64).into() }
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

/// A ed25519 keypair. This is available in the `ed25519_dalek` crate, but the
/// JSON serialization there is not compatible with what we use, so we redefine
/// it there.
#[derive(
    Debug,
    SerdeSerialize,
    SerdeDeserialize,
    derive_more::AsRef,
    derive_more::From,
    derive_more::Into,
    Clone,
)]
#[serde(try_from = "key_pair_json::KeyPair", into = "key_pair_json::KeyPair")]
pub struct KeyPair {
    inner: ed25519_dalek::SigningKey,
}

impl KeyPair {
    pub fn public(&self) -> ed25519_dalek::VerifyingKey {
        self.inner.verifying_key()
    }
}

mod key_pair_json {
    #[derive(Debug, super::SerdeSerialize, super::SerdeDeserialize)]
    pub struct KeyPair {
        #[serde(
            rename = "signKey",
            serialize_with = "crate::common::base16_encode_array",
            deserialize_with = "crate::common::base16_decode_array"
        )]
        pub secret: ed25519_dalek::SecretKey,
        #[serde(
            rename = "verifyKey",
            serialize_with = "crate::common::base16_encode",
            deserialize_with = "crate::common::base16_decode"
        )]
        pub public: ed25519_dalek::VerifyingKey,
    }

    impl TryFrom<KeyPair> for super::KeyPair {
        type Error = ed25519_dalek::SignatureError;

        fn try_from(value: KeyPair) -> Result<Self, Self::Error> {
            let inner = ed25519_dalek::SigningKey::from_bytes(&value.secret);
            if inner.verifying_key() != value.public {
                Err(Self::Error::from_source("Public/secret key mismatch."))
            } else {
                Ok(Self { inner })
            }
        }
    }

    impl From<super::KeyPair> for KeyPair {
        fn from(value: super::KeyPair) -> Self {
            Self {
                secret: value.inner.to_bytes(),
                public: value.inner.verifying_key(),
            }
        }
    }
}

impl KeyPair {
    pub fn generate<R: rand::CryptoRng + rand::Rng>(rng: &mut R) -> Self {
        Self::from(ed25519_dalek::SigningKey::generate(rng))
    }
}

impl KeyPair {
    /// Sign the given message with the keypair.
    pub fn sign(&self, msg: &[u8]) -> ed25519_dalek::Signature { self.inner.sign(msg) }
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
            let num_creds = rng.gen_range(1..30);
            let mut signatures = BTreeMap::new();
            for _ in 0..num_creds {
                let num_keys = rng.gen_range(1..20);
                let mut cred_sigs = BTreeMap::new();
                for _ in 0..num_keys {
                    let num_elems = rng.gen_range(0..200);
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

            let binary_result = crate::common::serialize_deserialize(&signatures)
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
