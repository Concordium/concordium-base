//! Common types needed in concordium.

use crate::{
    serial_string, Buffer, Deserial, Get, ParseResult, SerdeDeserialize, SerdeSerialize, Serial,
};
use byteorder::ReadBytesExt;
use crypto_common_derive::Serialize;
use derive_more::{Display, From, FromStr, Into};
use std::{collections::BTreeMap, num::ParseIntError, ops::Add, str::FromStr};
use thiserror::*;

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

pub struct UrlText {
    pub url: String,
}

pub const MAX_URL_SIZE: usize = 2048; // Needs to be same as maxUrlTextLength in Types.hs in haskell-src

impl Serial for UrlText {
    fn serial<B: Buffer>(&self, out: &mut B) {
        (self.url.len() as u16).serial(out);
        serial_string(&self.url, out)
    }
}

impl<'de> SerdeDeserialize<'de> for UrlText {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>, {
        let url = String::deserialize(deserializer)?;
        if url.len() <= MAX_URL_SIZE {
            Ok(UrlText { url })
        } else {
            Err(serde::de::Error::custom("Url length out of bounds."))
        }
    }
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
pub enum OpenStatus {
    #[serde(rename = "openForAll")]
    OpenForAll,
    #[serde(rename = "closedForNew")]
    ClosedForNew,
    #[serde(rename = "closedForAll")]
    ClosedForAll,
}

impl Serial for OpenStatus {
    fn serial<B: Buffer>(&self, out: &mut B) {
        match *self {
            OpenStatus::OpenForAll => out.write_u8(0),
            OpenStatus::ClosedForNew => out.write_u8(1),
            OpenStatus::ClosedForAll => out.write_u8(2),
        }
        .expect("Writing to a buffer should not fail.");
    }
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum DelegationTarget {
    #[serde(rename = "delegateToLPool")]
    DelegateToLPool,
    #[serde(rename = "delegateToBaker")]
    DelegateToBaker {
        #[serde(rename = "targetBaker")]
        target_baker: u64,
    },
}

impl Serial for DelegationTarget {
    fn serial<B: Buffer>(&self, out: &mut B) {
        match *self {
            DelegationTarget::DelegateToLPool => out
                .write_u8(0)
                .expect("Writing to a buffer should not fail."),
            DelegationTarget::DelegateToBaker { target_baker } => {
                out.write_u8(1)
                    .expect("Writing to a buffer should not fail.");
                target_baker.serial(out)
            }
        }
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
/// An amount of GTU. The lowest expressible amount is 1microGTU. The string
/// representation of this type uses a decimal separator with at most 6
/// decimals.
pub struct Amount {
    pub microgtu: u64,
}

impl From<Amount> for u64 {
    fn from(x: Amount) -> Self { x.microgtu }
}

impl From<u64> for Amount {
    fn from(microgtu: u64) -> Self { Amount { microgtu } }
}

impl Serial for Amount {
    fn serial<B: crate::Buffer>(&self, out: &mut B) { self.microgtu.serial(out) }
}

impl Deserial for Amount {
    fn deserial<R: byteorder::ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let microgtu = source.get()?;
        Ok(Amount { microgtu })
    }
}

/// Add two amounts together, checking for overflow.
impl Add for Amount {
    type Output = Option<Amount>;

    fn add(self, rhs: Self) -> Self::Output {
        let microgtu = self.microgtu.checked_add(rhs.microgtu)?;
        Some(Amount { microgtu })
    }
}

/// Add an amount to an optional amount, propagating `None`.
impl Add<Option<Amount>> for Amount {
    type Output = Option<Amount>;

    fn add(self, rhs: Option<Amount>) -> Self::Output {
        let rhs = rhs?;
        let microgtu = self.microgtu.checked_add(rhs.microgtu)?;
        Some(Amount { microgtu })
    }
}

/// Errors that can occur during parsing of an [Amount] from a string.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum AmountParseError {
    #[error("Amount overflow.")]
    Overflow,
    #[error("Expected dot.")]
    ExpectedDot,
    #[error("Expected digit.")]
    ExpectedDigit,
    #[error("Expected more input.")]
    ExpectedMore,
    #[error("Expected digit or dot.")]
    ExpectedDigitOrDot,
    #[error("Amounts can have at most six decimals.")]
    AtMostSixDecimals,
}

/// Parse from string in GTU units. The input string must be of the form
/// `n[.m]` where `n` and `m` are both digits. The notation `[.m]` indicates
/// that that part is optional.
///
/// - if `n` starts with 0 then it must be 0l
/// - `m` can have at most 6 digits, and must have at least 1
/// - both `n` and `m` must be non-negative.
impl std::str::FromStr for Amount {
    type Err = AmountParseError;

    fn from_str(v: &str) -> Result<Self, Self::Err> {
        let mut microgtu: u64 = 0;
        let mut after_dot = 0;
        let mut state = 0;
        for c in v.chars() {
            match state {
                0 => {
                    // looking at the first character.
                    if let Some(d) = c.to_digit(10) {
                        if d == 0 {
                            state = 1;
                        } else {
                            microgtu = u64::from(d);
                            state = 2;
                        }
                    } else {
                        return Err(AmountParseError::ExpectedDigit);
                    }
                }
                1 => {
                    // we want to be looking at a dot now (unless we reached the end, in which case
                    // this is not reachable anyhow)
                    if c != '.' {
                        return Err(AmountParseError::ExpectedDot);
                    } else {
                        state = 3;
                    }
                }
                2 => {
                    // we are reading a normal number until we hit the dot.
                    if let Some(d) = c.to_digit(10) {
                        microgtu = microgtu.checked_mul(10).ok_or(AmountParseError::Overflow)?;
                        microgtu = microgtu
                            .checked_add(u64::from(d))
                            .ok_or(AmountParseError::Overflow)?;
                    } else if c == '.' {
                        state = 3;
                    } else {
                        return Err(AmountParseError::ExpectedDigitOrDot);
                    }
                }
                3 => {
                    // we're reading after the dot.
                    if after_dot >= 6 {
                        return Err(AmountParseError::AtMostSixDecimals);
                    }
                    if let Some(d) = c.to_digit(10) {
                        microgtu = microgtu.checked_mul(10).ok_or(AmountParseError::Overflow)?;
                        microgtu = microgtu
                            .checked_add(u64::from(d))
                            .ok_or(AmountParseError::Overflow)?;
                        after_dot += 1;
                    } else {
                        return Err(AmountParseError::ExpectedDigit);
                    }
                }
                _ => unreachable!(),
            }
        }
        if state == 0 || state >= 3 && after_dot == 0 {
            return Err(AmountParseError::ExpectedMore);
        }
        for _ in 0..6 - after_dot {
            microgtu = microgtu.checked_mul(10).ok_or(AmountParseError::Overflow)?;
        }
        Ok(Amount { microgtu })
    }
}

impl std::fmt::Display for Amount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let high = self.microgtu / 1_000_000;
        let low = self.microgtu % 1_000_000;
        if low == 0 {
            write!(f, "{}", high)
        } else {
            write!(f, "{}.{:06}", high, low)
        }
    }
}

/// JSON instance serializes and deserializes in microgtu units.
impl SerdeSerialize for Amount {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.microgtu.to_string())
    }
}

impl<'de> SerdeDeserialize<'de> for Amount {
    fn deserialize<D: serde::de::Deserializer<'de>>(des: D) -> Result<Self, D::Error> {
        let s = String::deserialize(des)?;
        let microgtu = s
            .parse::<u64>()
            .map_err(|e| serde::de::Error::custom(format!("{}", e)))?;
        Ok(Amount { microgtu })
    }
}

#[derive(Debug, Clone)]
pub struct Memo {
    pub memo: Vec<u8>,
}

pub const MAX_MEMO_SIZE: usize = 256; // Needs to be same as maxMemoSize in Types.hs in haskell-src

impl Serial for Memo {
    fn serial<B: Buffer>(&self, out: &mut B) {
        (self.memo.len() as u16).serial(out);
        out.write_all(&self.memo)
            .expect("Writing to buffer should succeed.");
    }
}

impl Deserial for Memo {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let len: u16 = source.get()?;
        anyhow::ensure!(
            len as usize <= MAX_MEMO_SIZE,
            "Memo size of {} is too big. Maximum size is {}.",
            len,
            MAX_MEMO_SIZE
        );
        let mut memo = vec![0; len as usize];
        source.read_exact(&mut memo)?;
        Ok(Memo { memo })
    }
}

impl SerdeSerialize for Memo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer, {
        serializer.serialize_str(&hex::encode(&self.memo))
    }
}

impl<'de> SerdeDeserialize<'de> for Memo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>, {
        let s = String::deserialize(deserializer)?;
        let memo = hex::decode(s).map_err(|e| serde::de::Error::custom(format!("{}", e)))?;
        if memo.len() <= MAX_MEMO_SIZE {
            Ok(Memo { memo })
        } else {
            Err(serde::de::Error::custom("Memo length out of bounds."))
        }
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
                Err(e) => assert!(false, "{}", e),
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
    // test amount serialization is correct
    fn amount_serialization() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let microgtu = Amount::from(rng.gen::<u64>());
            let s = microgtu.to_string();
            let parsed = s.parse::<Amount>();
            assert_eq!(
                Ok(microgtu),
                parsed,
                "Parsed amount differs from expected amount."
            );
        }

        assert_eq!(
            "0.".parse::<Amount>(),
            Err(AmountParseError::ExpectedMore),
            "There must be at least one digit after dot."
        );
        assert_eq!(
            "0.1234567".parse::<Amount>(),
            Err(AmountParseError::AtMostSixDecimals),
            "There can be at most 6 digits after dot."
        );
        assert_eq!(
            "0.000000000".parse::<Amount>(),
            Err(AmountParseError::AtMostSixDecimals),
            "There can be at most 6 digits after dot."
        );
        assert_eq!(
            "00.1234".parse::<Amount>(),
            Err(AmountParseError::ExpectedDot),
            "There can be at most one leading 0."
        );
        assert_eq!(
            "01.1234".parse::<Amount>(),
            Err(AmountParseError::ExpectedDot),
            "Leading zero must be followed by a dot."
        );
        assert_eq!(
            "0.1234".parse::<Amount>(),
            Ok(Amount::from(123400u64)),
            "Leading zero is OK."
        );
        assert_eq!(
            "0.0".parse::<Amount>(),
            Ok(Amount::from(0)),
            "Leading zero and zero after dot is OK."
        );
        assert_eq!(
            ".0".parse::<Amount>(),
            Err(AmountParseError::ExpectedDigit),
            "There should be at least one digit before a dot."
        );
        assert_eq!(
            "13".parse::<Amount>(),
            Ok(Amount::from(13000000)),
            "No dot is needed."
        );
        assert_eq!(
            "".parse::<Amount>(),
            Err(AmountParseError::ExpectedMore),
            "Empty string is not a valid amount."
        );
    }

    #[test]
    fn amount_json_serialization() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let amount = Amount::from(rng.gen::<u64>());
            let s = serde_json::to_string(&amount).expect("Could not serialize");
            assert_eq!(
                amount,
                serde_json::from_str(&s).unwrap(),
                "Could not deserialize amount."
            );
        }

        let amount = Amount::from(12345);
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
