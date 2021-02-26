//! Common types needed in concordium.

//! FIXME: This should be moved into a concordium-common at some point when that
//! is moved to the bottom of the dependency hierarchy.

use crate::{
    deserial_vector_no_length, serial_vector_no_length, Buffer, Deserial, Get, SerdeDeserialize,
    SerdeSerialize, Serial,
};
use byteorder::ReadBytesExt;
use crypto_common_derive::Serialize;
use failure::Fallible;
use std::{collections::BTreeMap, ops::Add};

/// Index of an account key that is to be used.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Serialize)]
#[repr(transparent)]
#[derive(SerdeSerialize, SerdeDeserialize)]
#[serde(transparent)]
pub struct KeyIndex(pub u8);

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
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
    fn deserial<R: byteorder::ReadBytesExt>(source: &mut R) -> failure::Fallible<Self> {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AmountParseError {
    Overflow,
    ExpectedDot,
    ExpectedDigit,
    ExpectedMore,
    ExpectedDigitOrDot,
    AtMostSixDecimals,
}

impl std::fmt::Display for AmountParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use AmountParseError::*;
        match self {
            Overflow => write!(f, "Amount overflow."),
            ExpectedDot => write!(f, "Expected dot."),
            ExpectedDigit => write!(f, "Expected digit."),
            ExpectedMore => write!(f, "Expected more input."),
            ExpectedDigitOrDot => write!(f, "Expected digit or dot."),
            AtMostSixDecimals => write!(f, "Amounts can have at most six decimals."),
        }
    }
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

#[derive(Serialize, PartialEq, Eq, Debug)]
/// A single signature. Using the same binary and JSON serialization as the
/// Haskell counterpart. In particular this means encoding the length as 2
/// bytes, and thus the largest size is 65535 bytes.
pub struct Signature {
    #[size_length = 2]
    pub sig: Vec<u8>,
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

/// Transaction signature structure, to match the one on the Haskell side.
#[derive(SerdeDeserialize, SerdeSerialize, PartialEq, Eq, Debug)]
#[serde(transparent)]
pub struct TransactionSignature {
    pub signatures: BTreeMap<KeyIndex, BTreeMap<KeyIndex, Signature>>,
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
                signatures.insert(KeyIndex(rng.gen()), cred_sigs);
            }
            let signatures = TransactionSignature { signatures };
            let js = serde_json::to_string(&signatures).expect("Serialization should succeed.");
            println!("{}", js);
            match serde_json::from_str::<TransactionSignature>(&js) {
                Ok(s) => assert_eq!(s, signatures, "Deserialized incorrect value."),
                Err(e) => assert!(false, "{}", e),
            }
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
