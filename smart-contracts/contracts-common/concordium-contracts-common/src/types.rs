use crate as concordium_std;
pub use crate::hashes::ModuleReference;
use crate::{constants, to_bytes, Serial};
#[cfg(all(not(feature = "std"), feature = "concordium-quickcheck"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;
#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, string::String, string::ToString, vec::Vec};
#[cfg(feature = "fuzz")]
use arbitrary::Arbitrary;
use cmp::Ordering;
use concordium_contracts_common_derive::SchemaType;
#[cfg(not(feature = "std"))]
use core::{cmp, convert, fmt, hash, iter, ops, str};
use core::{marker::PhantomData, str::FromStr};
use hash::Hash;
#[cfg(feature = "concordium-quickcheck")]
use quickcheck::Gen;
#[cfg(feature = "derive-serde")]
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
#[cfg(feature = "derive-serde")]
pub use serde_impl::*;
#[cfg(feature = "std")]
use std::collections::BTreeMap;
#[cfg(feature = "std")]
use std::{cmp, convert, fmt, hash, iter, ops, str};

/// Reexport of the `HashMap` from `hashbrown` with the default hasher set to
/// the `fnv` hash function.
pub type HashMap<K, V, S = fnv::FnvBuildHasher> = hashbrown::HashMap<K, V, S>;

/// Reexport of the `HashSet` from `hashbrown` with the default hasher set to
/// the `fnv` hash function.
pub type HashSet<K, S = fnv::FnvBuildHasher> = hashbrown::HashSet<K, S>;

/// Contract address index. A contract address consists of an index and a
/// subindex. This type is for the index.
pub type ContractIndex = u64;

/// Contract address subindex. A contract address consists of an index and a
/// subindex. This type is for the subindex.
pub type ContractSubIndex = u64;

/// Size of an account address when serialized in binary.
/// NB: This is different from the Base58 representation.
pub const ACCOUNT_ADDRESS_SIZE: usize = 32;

const CANONICAL_ACCOUNT_ADDRESS_SIZE: usize = 29;

/// The type of amounts on the chain.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
pub struct Amount {
    pub micro_ccd: u64,
}

#[cfg(feature = "concordium-quickcheck")]
impl quickcheck::Arbitrary for Amount {
    fn arbitrary(g: &mut Gen) -> Amount {
        Amount::from_micro_ccd(quickcheck::Arbitrary::arbitrary(g))
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        Box::new(quickcheck::Arbitrary::shrink(&self.micro_ccd).map(Amount::from_micro_ccd))
    }
}

#[cfg(feature = "derive-serde")]
impl SerdeSerialize for Amount {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.micro_ccd.to_string())
    }
}

#[cfg(feature = "derive-serde")]
impl<'de> SerdeDeserialize<'de> for Amount {
    fn deserialize<D: serde::de::Deserializer<'de>>(des: D) -> Result<Self, D::Error> {
        let s = String::deserialize(des)?;
        let micro_ccd = s.parse::<u64>().map_err(|e| serde::de::Error::custom(format!("{}", e)))?;
        Ok(Amount {
            micro_ccd,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// An error indicating why parsing of an amount failed.
/// Since amount parsing is typically a user-facing activity
/// this is fairly precise, so we can notify the user why we failed, and what
/// they can do to fix it.
pub enum AmountParseError {
    Overflow,
    ExpectedDot,
    ExpectedDigit,
    ExpectedMore,
    ExpectedDigitOrDot,
    AtMostSixDecimals,
}

impl fmt::Display for AmountParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

#[cfg(feature = "std")]
impl std::error::Error for AmountParseError {}

/// Parse from string in CCD units. The input string must be of the form
/// `n[.m]` where `n` and `m` are both digits. The notation `[.m]` indicates
/// that that part is optional.
///
/// - if `n` starts with 0 then it must be 0l
/// - `m` can have at most 6 digits, and must have at least 1
/// - both `n` and `m` must be non-negative.
impl str::FromStr for Amount {
    type Err = AmountParseError;

    fn from_str(v: &str) -> Result<Self, Self::Err> {
        let mut micro_ccd: u64 = 0;
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
                            micro_ccd = u64::from(d);
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
                        micro_ccd = micro_ccd.checked_mul(10).ok_or(AmountParseError::Overflow)?;
                        micro_ccd = micro_ccd
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
                        micro_ccd = micro_ccd.checked_mul(10).ok_or(AmountParseError::Overflow)?;
                        micro_ccd = micro_ccd
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
            micro_ccd = micro_ccd.checked_mul(10).ok_or(AmountParseError::Overflow)?;
        }
        Ok(Amount {
            micro_ccd,
        })
    }
}

impl Amount {
    /// Create amount from a number of microCCD
    #[inline(always)]
    pub const fn from_micro_ccd(micro_ccd: u64) -> Amount {
        Amount {
            micro_ccd,
        }
    }

    /// Get the amount in microCCD
    #[inline(always)]
    pub const fn micro_ccd(&self) -> u64 { self.micro_ccd }

    /// Create amount from a number of CCD
    #[inline(always)]
    pub const fn from_ccd(ccd: u64) -> Amount {
        Amount {
            micro_ccd: ccd * 1_000_000,
        }
    }

    /// Create zero amount
    #[inline(always)]
    pub const fn zero() -> Amount {
        Amount {
            micro_ccd: 0,
        }
    }

    /// Add a number of micro CCD to an amount
    #[inline(always)]
    pub fn add_micro_ccd(self, micro_ccd: u64) -> Amount {
        Amount {
            micro_ccd: self.micro_ccd + micro_ccd,
        }
    }

    /// Checked addition. Adds another amount and returns None if overflow
    /// occurred.
    #[inline(always)]
    pub fn checked_add(self, other: Amount) -> Option<Amount> {
        self.micro_ccd.checked_add(other.micro_ccd).map(Amount::from_micro_ccd)
    }

    /// Checked subtraction. Subtracts another amount and returns None if
    /// underflow occurred.
    #[inline(always)]
    pub fn checked_sub(self, other: Amount) -> Option<Amount> {
        self.micro_ccd.checked_sub(other.micro_ccd).map(Amount::from_micro_ccd)
    }

    /// Add a number of CCD to an amount
    #[inline(always)]
    pub fn add_ccd(self, ccd: u64) -> Amount {
        Amount {
            micro_ccd: self.micro_ccd + ccd * 1_000_000,
        }
    }

    /// Subtract a number of micro CCD to an amount
    #[inline(always)]
    pub fn subtract_micro_ccd(self, micro_ccd: u64) -> Amount {
        Amount {
            micro_ccd: self.micro_ccd - micro_ccd,
        }
    }

    /// Subtract a number of CCD to an amount
    #[inline(always)]
    pub fn subtract_ccd(self, ccd: u64) -> Amount {
        Amount {
            micro_ccd: self.micro_ccd - ccd * 1_000_000,
        }
    }

    /// Calculates the quotient and remainder of integer division
    #[inline(always)]
    pub fn quotient_remainder(self, denominator: u64) -> (Amount, Amount) {
        let div = Amount {
            micro_ccd: self.micro_ccd / denominator,
        };
        let rem = self % denominator;
        (div, rem)
    }
}

impl ops::Mul<u64> for Amount {
    type Output = Self;

    #[inline(always)]
    fn mul(self, other: u64) -> Self::Output {
        Amount {
            micro_ccd: self.micro_ccd * other,
        }
    }
}

impl ops::Mul<Amount> for u64 {
    type Output = Amount;

    #[inline(always)]
    fn mul(self, other: Amount) -> Self::Output {
        Amount {
            micro_ccd: self * other.micro_ccd,
        }
    }
}

impl ops::Add<Amount> for Amount {
    type Output = Self;

    #[inline(always)]
    fn add(self, other: Amount) -> Self::Output {
        Amount {
            micro_ccd: self.micro_ccd + other.micro_ccd,
        }
    }
}

impl ops::Sub<Amount> for Amount {
    type Output = Self;

    #[inline(always)]
    fn sub(self, other: Amount) -> Self::Output {
        Amount {
            micro_ccd: self.micro_ccd - other.micro_ccd,
        }
    }
}

impl ops::Rem<u64> for Amount {
    type Output = Self;

    #[inline(always)]
    fn rem(self, other: u64) -> Self::Output {
        Amount {
            micro_ccd: self.micro_ccd % other,
        }
    }
}

impl iter::Sum for Amount {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Amount::from_micro_ccd(0), ops::Add::add)
    }
}

impl ops::AddAssign for Amount {
    #[inline(always)]
    fn add_assign(&mut self, other: Amount) { *self = *self + other; }
}

impl ops::SubAssign for Amount {
    #[inline(always)]
    fn sub_assign(&mut self, other: Amount) { *self = *self - other; }
}

impl ops::MulAssign<u64> for Amount {
    #[inline(always)]
    fn mul_assign(&mut self, other: u64) { *self = *self * other; }
}

impl ops::RemAssign<u64> for Amount {
    #[inline(always)]
    fn rem_assign(&mut self, other: u64) { *self = *self % other; }
}

/// The current public balances of an account.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AccountBalance {
    /// The total balance of the account. Note that part of this balance might
    /// be staked and/or locked in scheduled transfers.
    pub total:  Amount,
    /// The current staked amount of the account. This amount is used for
    /// staking.
    pub staked: Amount,
    /// The current amount locked in releases that resulted from transfers with
    /// schedule. A locked amount can still be used for staking.
    pub locked: Amount,
}

impl AccountBalance {
    /// Construct a new account balance, ensuring that both the staked amount
    /// and the locked amount is smaller than or equal to the total balance.
    pub fn new(total: Amount, staked: Amount, locked: Amount) -> Option<Self> {
        if total < staked || total < locked {
            None
        } else {
            Some(Self {
                total,
                staked,
                locked,
            })
        }
    }

    /// The current available balance of the account. This is the amount
    /// an account currently has available for transferring and is not
    /// staked or locked in releases by scheduled transfers.
    pub fn available(&self) -> Amount { self.total - cmp::max(self.locked, self.staked) }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
/// A marker type used to define the [`AccountThreshold`]. This is used only
/// at the type-level and there are no values of the type.
pub enum AccountKind {}

/// The minimum number of credentials that need to sign any transaction coming
/// from an associated account.
pub type AccountThreshold = NonZeroThresholdU8<AccountKind>;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
/// A marker type used to define the [`SignatureThreshold`]. This is used only
/// at the type-level and there are no values of the type.
pub enum SignatureKind {}

/// The minimum number of signatures on a credential that need to sign any
/// transaction coming from an associated account.
///
/// Accounts on Concordium consist of one or more credentials, and
/// each credential has one or more public keys, and its own threshold for how
/// many of those credential's keys need to sign any valid message.
///
/// See [`AccountThreshold`] for the threshold of how many credentials need to
/// sign a valid message.
pub type SignatureThreshold = NonZeroThresholdU8<SignatureKind>;

#[repr(transparent)]
#[cfg_attr(feature = "derive-serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "derive-serde",
    serde(
        bound(serialize = "Kind: Sized", deserialize = "Kind: Sized"),
        try_from = "u8",
        into = "u8"
    )
)]
#[derive(Debug)]
/// A type representing a `u8` threshold, typically used for signatures.
/// Serialization for this type ensures that the threshold is never 0.
///
/// This type has a phantom type marker so that thresholds of different types
/// can be distinguished. The intended use is that a new empty type is defined
/// to serve as marker, and then a type alias. See [`AccountThreshold`] for an
/// example.
pub struct NonZeroThresholdU8<Kind> {
    pub(crate) threshold: u8,
    pub(crate) kind:      PhantomData<Kind>,
}

#[derive(Debug)]
#[cfg_attr(feature = "derive-serde", derive(thiserror::Error))]
#[cfg_attr(feature = "derive-serde", error("Signature threshold cannot be 0."))]
/// An error type that indicates that a 0 attempted to be used as a signature
/// threshold.
pub struct ZeroSignatureThreshold;

/// Public key for Ed25519. Must be 32 bytes long.
#[derive(Copy, Clone, Debug, PartialEq, PartialOrd, Eq, Ord, crate::Deserial, crate::Serial)]
#[cfg_attr(
    feature = "derive-serde",
    derive(SerdeSerialize, SerdeDeserialize),
    serde(into = "String", try_from = "String")
)]
#[repr(transparent)]
pub struct PublicKeyEd25519(pub [u8; 32]);

impl From<PublicKeyEd25519> for String {
    fn from(pk: PublicKeyEd25519) -> String { pk.to_string() }
}

#[cfg(feature = "derive-serde")]
impl TryFrom<String> for PublicKeyEd25519 {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, ParseError> { Self::from_str(s.as_str()) }
}

impl fmt::Display for PublicKeyEd25519 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl FromStr for PublicKeyEd25519 {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 64 {
            return Err(ParseError {});
        }

        let mut public_key: [u8; 32] = [0u8; 32];
        for (i, place) in public_key.iter_mut().enumerate() {
            *place = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| ParseError {})?;
        }

        Ok(PublicKeyEd25519(public_key))
    }
}

/// Public key for ECDSA over Secp256k1. Must be 33 bytes long.
#[derive(Copy, Clone, Debug, PartialEq, PartialOrd, Eq, Ord, crate::Deserial, crate::Serial)]
#[repr(transparent)]
pub struct PublicKeyEcdsaSecp256k1(pub [u8; 33]);

impl fmt::Display for PublicKeyEcdsaSecp256k1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl FromStr for PublicKeyEcdsaSecp256k1 {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 66 {
            return Err(ParseError {});
        }

        let mut public_key: [u8; 33] = [0u8; 33];
        for (i, place) in public_key.iter_mut().enumerate() {
            *place = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| ParseError {})?;
        }

        Ok(PublicKeyEcdsaSecp256k1(public_key))
    }
}

/// Signature for a Ed25519 message. Must be 64 bytes long.
#[derive(Copy, Clone, Debug, PartialEq, PartialOrd, Eq, Ord, crate::Deserial, crate::Serial)]
#[cfg_attr(
    feature = "derive-serde",
    derive(SerdeSerialize, SerdeDeserialize),
    serde(into = "String", try_from = "String")
)]
#[repr(transparent)]
pub struct SignatureEd25519(pub [u8; 64]);

impl From<SignatureEd25519> for String {
    fn from(sig: SignatureEd25519) -> String { sig.to_string() }
}

#[cfg(feature = "derive-serde")]
impl TryFrom<String> for SignatureEd25519 {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, ParseError> { Self::from_str(s.as_str()) }
}

impl fmt::Display for SignatureEd25519 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl FromStr for SignatureEd25519 {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 128 {
            return Err(ParseError {});
        }

        let mut signature: [u8; 64] = [0u8; 64];
        for (i, place) in signature.iter_mut().enumerate() {
            *place = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| ParseError {})?;
        }

        Ok(SignatureEd25519(signature))
    }
}

/// Signature for a ECDSA (over Secp256k1) message. Must be 64 bytes longs
/// (serialized in compressed format).
#[derive(Copy, Clone, Debug, PartialEq, PartialOrd, Eq, Ord, crate::Deserial, crate::Serial)]
#[cfg_attr(
    feature = "derive-serde",
    derive(SerdeSerialize, SerdeDeserialize),
    serde(into = "String", try_from = "String")
)]
#[repr(transparent)]
pub struct SignatureEcdsaSecp256k1(pub [u8; 64]);

impl From<SignatureEcdsaSecp256k1> for String {
    fn from(sig: SignatureEcdsaSecp256k1) -> String { sig.to_string() }
}

#[cfg(feature = "derive-serde")]
impl TryFrom<String> for SignatureEcdsaSecp256k1 {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, ParseError> { Self::from_str(s.as_str()) }
}

impl fmt::Display for SignatureEcdsaSecp256k1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl FromStr for SignatureEcdsaSecp256k1 {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 128 {
            return Err(ParseError {});
        }

        let mut signature: [u8; 64] = [0u8; 64];
        for (i, place) in signature.iter_mut().enumerate() {
            *place = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| ParseError {})?;
        }

        Ok(SignatureEcdsaSecp256k1(signature))
    }
}

#[cfg(feature = "concordium-quickcheck")]
/// Arbitrary public keys.
/// Note that this is a simple generator that might produce an array of bytes
/// that is not a valid public key.
impl quickcheck::Arbitrary for PublicKeyEd25519 {
    fn arbitrary(g: &mut quickcheck::Gen) -> Self {
        let lower: u128 = quickcheck::Arbitrary::arbitrary(g);
        let upper: u128 = quickcheck::Arbitrary::arbitrary(g);
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&lower.to_le_bytes());
        out[16..].copy_from_slice(&upper.to_le_bytes());
        PublicKeyEd25519(out)
    }
}

pub(crate) type KeyIndex = u8;

#[derive(crate::Serialize, Debug, SchemaType, PartialEq, Eq)]
/// A public indexed by the signature scheme. Currently only a
/// single scheme is supported, `ed25519`.
pub enum PublicKey {
    Ed25519(PublicKeyEd25519),
}

#[derive(crate::Serialize, Debug, SchemaType, PartialEq, Eq)]
pub struct CredentialPublicKeys {
    #[concordium(size_length = 1)]
    pub keys:      BTreeMap<KeyIndex, PublicKey>,
    pub threshold: SignatureThreshold,
}

#[derive(crate::Serialize, Debug, SchemaType, PartialEq, Eq)]
/// Public keys of an account, together with the thresholds.
pub struct AccountPublicKeys {
    #[concordium(size_length = 1)]
    pub keys:      BTreeMap<CredentialIndex, CredentialPublicKeys>,
    pub threshold: AccountThreshold,
}

pub(crate) type CredentialIndex = u8;

#[derive(crate::Serialize, Debug, SchemaType, PartialEq, Eq)]
#[cfg_attr(
    feature = "derive-serde",
    derive(serde::Deserialize, serde::Serialize),
    serde(tag = "signatureScheme", content = "signature")
)]
#[non_exhaustive]
/// A cryptographic signature indexed by the signature scheme. Currently only a
/// single scheme is supported, `ed25519`.
pub enum Signature {
    Ed25519(SignatureEd25519),
}

#[derive(crate::Serialize, Debug, SchemaType, PartialEq, Eq)]
#[cfg_attr(feature = "derive-serde", derive(serde::Deserialize, serde::Serialize))]
#[concordium(transparent)]
/// Account signatures. This is an analogue of transaction signatures that are
/// part of transactions that get sent to the chain.
///
/// It should be thought of as a nested map, indexed on the outer layer by
/// credential indexes, and the inner map maps key indices to [`Signature`]s.
pub struct AccountSignatures {
    #[concordium(size_length = 1)]
    pub sigs: BTreeMap<CredentialIndex, CredentialSignatures>,
}

#[derive(crate::Serialize, Debug, SchemaType, PartialEq, Eq)]
#[cfg_attr(feature = "derive-serde", derive(serde::Deserialize, serde::Serialize))]
#[concordium(transparent)]
pub struct CredentialSignatures {
    #[concordium(size_length = 1)]
    pub sigs: BTreeMap<KeyIndex, Signature>,
}

/// Timestamp represented as milliseconds since unix epoch.
///
/// Timestamps from before January 1st 1970 at 00:00 are not supported.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
pub struct Timestamp {
    /// Milliseconds since unix epoch.
    pub millis: u64,
}

impl From<u64> for Timestamp {
    fn from(millis: u64) -> Self {
        Self {
            millis,
        }
    }
}

#[cfg(feature = "concordium-quickcheck")]
impl quickcheck::Arbitrary for Timestamp {
    fn arbitrary(g: &mut Gen) -> Timestamp {
        Timestamp::from_timestamp_millis(quickcheck::Arbitrary::arbitrary(g))
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        Box::new(quickcheck::Arbitrary::shrink(&self.millis).map(Timestamp::from_timestamp_millis))
    }
}

impl Timestamp {
    /// Construct a timestamp corresponding to the current date and time.
    #[cfg(feature = "derive-serde")]
    pub fn now() -> Self { (chrono::Utc::now().timestamp_millis() as u64).into() }

    /// Construct timestamp from milliseconds since unix epoch.
    #[inline(always)]
    pub const fn from_timestamp_millis(millis: u64) -> Self {
        Self {
            millis,
        }
    }

    /// Milliseconds since the UNIX epoch.
    #[inline(always)]
    pub const fn timestamp_millis(&self) -> u64 { self.millis }

    /// Add duration to the timestamp. Returns `None` if the resulting timestamp
    /// is not representable, i.e., too far in the future.
    #[inline(always)]
    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        self.millis.checked_add(duration.milliseconds).map(Self::from_timestamp_millis)
    }

    /// Subtract duration from the timestamp. Returns `None` instead of
    /// overflowing if the resulting timestamp would be before the Unix
    /// epoch.
    #[inline(always)]
    pub fn checked_sub(self, duration: Duration) -> Option<Self> {
        self.millis.checked_sub(duration.milliseconds).map(Self::from_timestamp_millis)
    }

    /// Compute the duration between the self and another timestamp.
    /// The duration is always positive, and is the difference between
    /// the the more recent timestamp and the one further in the past.
    #[inline(always)]
    pub fn duration_between(self, other: Timestamp) -> Duration {
        let millis = if self >= other {
            self.millis - other.millis
        } else {
            other.millis - self.millis
        };
        Duration::from_millis(millis)
    }

    /// Compute duration since a given timestamp. Returns `None` if given time
    /// is in the future compared to self.
    #[inline(always)]
    pub fn duration_since(self, before: Timestamp) -> Option<Duration> {
        self.millis.checked_sub(before.millis).map(Duration::from_millis)
    }
}

#[cfg(feature = "derive-serde")]
#[derive(Debug, thiserror::Error)]
#[error("The timestamp is too far in the future.")]
pub struct TimestampOverflow;

#[cfg(feature = "derive-serde")]
impl TryFrom<Timestamp> for chrono::DateTime<chrono::Utc> {
    type Error = TimestampOverflow;

    fn try_from(value: Timestamp) -> Result<Self, Self::Error> {
        use chrono::TimeZone;
        if let Some(utc) = chrono::Utc
            .timestamp_millis_opt(value.millis.try_into().map_err(|_| TimestampOverflow)?)
            .single()
        {
            Ok(utc)
        } else {
            // according to the documentation of `timestamp_millis_opt` this case only
            // happens on overflow.
            Err(TimestampOverflow)
        }
    }
}

#[cfg(feature = "derive-serde")]
/// Note that this is a lossy conversion from a datetime to a [`Timestamp`].
/// Any precision above milliseconds is lost.
impl TryFrom<chrono::DateTime<chrono::Utc>> for Timestamp {
    type Error = core::num::TryFromIntError;

    fn try_from(value: chrono::DateTime<chrono::Utc>) -> Result<Self, Self::Error> {
        let millis = value.timestamp_millis().try_into()?;
        Ok(Self {
            millis,
        })
    }
}

#[cfg(feature = "derive-serde")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseTimestampError {
    ParseError(chrono::format::ParseError),
    BeforeUnixEpoch,
}

#[cfg(feature = "derive-serde")]
impl fmt::Display for ParseTimestampError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ParseTimestampError::*;
        match self {
            ParseError(err) => err.fmt(f),
            BeforeUnixEpoch => write!(f, "Timestamp is before January 1st 1970 00:00."),
        }
    }
}

#[cfg(feature = "derive-serde")]
impl std::error::Error for ParseTimestampError {}

#[cfg(feature = "derive-serde")]
/// The FromStr parses a string representing either an [`u64`] of milliseconds
/// or the time according to RFC3339.
impl str::FromStr for Timestamp {
    type Err = ParseTimestampError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let try_parse_u64 = s.parse::<u64>().map(Timestamp::from_timestamp_millis);

        if let Ok(parsed_u64) = try_parse_u64 {
            return Ok(parsed_u64);
        }

        let datetime =
            chrono::DateTime::parse_from_rfc3339(s).map_err(ParseTimestampError::ParseError)?;
        let millis = datetime
            .timestamp_millis()
            .try_into()
            .map_err(|_| ParseTimestampError::BeforeUnixEpoch)?;
        Ok(Timestamp::from_timestamp_millis(millis))
    }
}

#[cfg(feature = "derive-serde")]
/// This display implementation attempts to format the timestamp as per
/// the RFC3339 standard, using the UTC time zone.
/// If parsing the timestamp into a [`chrono::DateTime<Utc>`] fails, it
/// simply returns the timestamp in milliseconds as a string.
impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use chrono::offset::TimeZone;
        let time = self.timestamp_millis() as i64;
        let date = match chrono::Utc.timestamp_millis_opt(time).single() {
            Some(date_parsed) => date_parsed.to_rfc3339(),
            None => self.timestamp_millis().to_string(),
        };
        write!(f, "{}", date)
    }
}

#[cfg(feature = "derive-serde")]
/// The JSON serialization serialized the string obtained by using the Display
/// implementation of the Timestamp.
impl SerdeSerialize for Timestamp {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.to_string())
    }
}

#[cfg(feature = "derive-serde")]
/// Deserialize from a string via the RFC3339 format.
impl<'de> SerdeDeserialize<'de> for Timestamp {
    fn deserialize<D: serde::de::Deserializer<'de>>(des: D) -> Result<Self, D::Error> {
        let s = String::deserialize(des)?;
        let t = str::FromStr::from_str(&s).map_err(serde::de::Error::custom)?;
        Ok(t)
    }
}

/// Duration of time in milliseconds.
///
/// Negative durations are not allowed.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Duration {
    pub(crate) milliseconds: u64,
}

impl Duration {
    /// Construct duration from milliseconds.
    #[inline(always)]
    pub const fn from_millis(milliseconds: u64) -> Self {
        Self {
            milliseconds,
        }
    }

    /// Construct duration from seconds.
    #[inline(always)]
    pub const fn from_seconds(seconds: u64) -> Self { Self::from_millis(seconds * 1000) }

    /// Construct duration from minutes.
    #[inline(always)]
    pub const fn from_minutes(minutes: u64) -> Self { Self::from_millis(minutes * 1000 * 60) }

    /// Construct duration from hours.
    #[inline(always)]
    pub const fn from_hours(hours: u64) -> Self { Self::from_millis(hours * 1000 * 60 * 60) }

    /// Construct duration from days.
    #[inline(always)]
    pub const fn from_days(days: u64) -> Self { Self::from_millis(days * 1000 * 60 * 60 * 24) }

    /// Get number of milliseconds in the duration.
    #[inline(always)]
    pub fn millis(&self) -> u64 { self.milliseconds }

    /// Get number of seconds in the duration.
    #[inline(always)]
    pub fn seconds(&self) -> u64 { self.milliseconds / 1000 }

    /// Get number of minutes in the duration.
    #[inline(always)]
    pub fn minutes(&self) -> u64 { self.milliseconds / (1000 * 60) }

    /// Get number of hours in the duration.
    #[inline(always)]
    pub fn hours(&self) -> u64 { self.milliseconds / (1000 * 60 * 60) }

    /// Get number of days in the duration.
    #[inline(always)]
    pub fn days(&self) -> u64 { self.milliseconds / (1000 * 60 * 60 * 24) }

    /// Add duration. Returns `None` instead of overflowing.
    #[inline(always)]
    pub fn checked_add(self, other: Duration) -> Option<Self> {
        self.milliseconds.checked_add(other.milliseconds).map(Self::from_millis)
    }

    /// Subtract duration. Returns `None` instead of overflowing.
    #[inline(always)]
    pub fn checked_sub(self, other: Duration) -> Option<Self> {
        self.milliseconds.checked_sub(other.milliseconds).map(Self::from_millis)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseDurationError {
    MissingUnit,
    FailedParsingNumber,
    InvalidUnit(String),
}

impl fmt::Display for ParseDurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ParseDurationError::*;
        match self {
            MissingUnit => write!(f, "Missing unit on duration measure."),
            FailedParsingNumber => write!(f, "Failed parsing number"),
            InvalidUnit(s) => write!(f, "Unknown unit \"{}\".", s),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseDurationError {}

/// Parse a string containing a list of duration measures separated by
/// whitespaces. A measure is a number followed by the unit (no whitespace
/// between is allowed). Every measure is accumulated into a duration. The
/// string is allowed to contain any number of measures with the same unit in no
/// particular order.
///
/// The supported units are:
/// - `ms` for milliseconds
/// - `s` for seconds
/// - `m` for minutes
/// - `h` for hours
/// - `d` for days
///
/// # Example
/// The duration of 10 days, 1 hour, 2minutes and 7 seconds is:
/// ```text
/// "10d 1h 2m 3s 4s"
/// ```
impl str::FromStr for Duration {
    type Err = ParseDurationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use ParseDurationError::*;
        let mut duration = 0;
        for measure in s.split_whitespace() {
            let split_index = measure.find(|c: char| !c.is_ascii_digit()).ok_or(MissingUnit)?;
            let (n, unit) = measure.split_at(split_index);

            let n: u64 = n.parse().map_err(|_| FailedParsingNumber)?;
            let unit: u64 = match unit {
                "ms" => 1,
                "s" => 1000,
                "m" => 1000 * 60,
                "h" => 1000 * 60 * 60,
                "d" => 1000 * 60 * 60 * 24,
                other => return Err(InvalidUnit(String::from(other))),
            };
            duration += n * unit;
        }
        Ok(Duration::from_millis(duration))
    }
}

impl fmt::Display for Duration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let days = self.days();
        let hours = Duration::from_millis(self.millis() % (1000 * 60 * 60 * 24)).hours();
        let minutes = Duration::from_millis(self.millis() % (1000 * 60 * 60)).minutes();
        let seconds = Duration::from_millis(self.millis() % (1000 * 60)).seconds();
        let milliseconds = Duration::from_millis(self.millis() % 1000).millis();
        write!(formatter, "{}d {}h {}m {}s {}ms", days, hours, minutes, seconds, milliseconds)
    }
}

#[cfg(feature = "derive-serde")]
/// The JSON serialization serialized the string obtained by using the Display
/// implementation of the Duration.
impl SerdeSerialize for Duration {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.to_string())
    }
}

#[cfg(feature = "derive-serde")]
/// Deserialize using `from_str` implementation of [`Duration`].
impl<'de> SerdeDeserialize<'de> for Duration {
    fn deserialize<D: serde::de::Deserializer<'de>>(des: D) -> Result<Self, D::Error> {
        let s = String::deserialize(des)?;
        let t = str::FromStr::from_str(&s).map_err(serde::de::Error::custom)?;
        Ok(t)
    }
}

/// Canonical address of an account, as raw bytes.
/// The canonical address is the first 29 bytes of the account address, uniquely
/// identifying accounts. The last 3 bytes is reserved as an account alias, to
/// be used for example by exchanges to uniquely identify graceful clients
#[derive(Eq, PartialEq, Copy, Clone, PartialOrd, Ord, Debug, Hash)]
#[repr(transparent)]
pub struct CanonicalAccountAddress(pub [u8; CANONICAL_ACCOUNT_ADDRESS_SIZE]);

/// Address of an account, as raw bytes.
#[derive(Eq, PartialEq, Copy, Clone, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
pub struct AccountAddress(pub [u8; ACCOUNT_ADDRESS_SIZE]);

#[cfg(feature = "concordium-quickcheck")]
impl quickcheck::Arbitrary for AccountAddress {
    fn arbitrary(g: &mut Gen) -> AccountAddress {
        AccountAddress([0u8; ACCOUNT_ADDRESS_SIZE].map(|_| quickcheck::Arbitrary::arbitrary(g)))
    }
}

impl convert::AsRef<[u8; 32]> for AccountAddress {
    fn as_ref(&self) -> &[u8; 32] { &self.0 }
}

impl convert::AsRef<[u8]> for AccountAddress {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

impl convert::AsMut<[u8; 32]> for AccountAddress {
    fn as_mut(&mut self) -> &mut [u8; 32] { &mut self.0 }
}

impl AccountAddress {
    /// Get the canonical address representing the unique first 29 bytes of the
    /// account address. This is the unique account address part and is
    /// independent of the individual aliases.
    pub fn get_canonical_address(&self) -> CanonicalAccountAddress {
        CanonicalAccountAddress(
            self.0[..CANONICAL_ACCOUNT_ADDRESS_SIZE]
                .try_into()
                .expect("Slice with incorrect length"),
        )
    }

    /// Check whether `self` is an alias of `other`. Two addresses are aliases
    /// if they identify the same account. This is defined to be when the
    /// addresses agree on the first 29 bytes.
    pub fn is_alias(&self, other: &AccountAddress) -> bool {
        self.0[..CANONICAL_ACCOUNT_ADDRESS_SIZE] == other.0[..CANONICAL_ACCOUNT_ADDRESS_SIZE]
    }

    /// Get the `n-th` alias of an address. There are 2^24 possible aliases.
    /// If the counter is `>= 2^24` then this function will return [`None`].
    pub const fn get_alias(&self, counter: u32) -> Option<Self> {
        if counter < (1 << 24) {
            Some(self.get_alias_unchecked(counter))
        } else {
            None
        }
    }

    /// Get the `n-th` alias of an address. There are 2^24 possible aliases.
    /// If the counter is `>= 2^24` then this function will have unintended
    /// behaviour, since it will wrap around. Meaning that counter values
    /// 2^24 and 0 will give the same alias.
    pub const fn get_alias_unchecked(&self, counter: u32) -> Self {
        let mut data = self.0;
        let counter_bytes = counter.to_le_bytes();

        data[29] = counter_bytes[2];
        data[30] = counter_bytes[1];
        data[31] = counter_bytes[0];

        Self(data)
    }
}

/// Address of a contract.
#[derive(Eq, PartialEq, Copy, Clone, Debug, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "derive-serde", derive(SerdeSerialize, SerdeDeserialize))]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
pub struct ContractAddress {
    pub index:    ContractIndex,
    pub subindex: ContractSubIndex,
}

impl ContractAddress {
    /// Construct a new contract address from index and subindex.
    pub const fn new(index: ContractIndex, subindex: ContractSubIndex) -> Self {
        Self {
            index,
            subindex,
        }
    }
}

#[cfg(feature = "concordium-quickcheck")]
impl quickcheck::Arbitrary for ContractAddress {
    fn arbitrary(g: &mut Gen) -> ContractAddress {
        ContractAddress {
            index:    quickcheck::Arbitrary::arbitrary(g),
            subindex: quickcheck::Arbitrary::arbitrary(g),
        }
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        let index = self.index;
        let subindex = self.subindex;
        let iter = index.shrink().flat_map(move |i| {
            subindex.shrink().map(move |si| ContractAddress {
                index:    i,
                subindex: si,
            })
        });
        Box::new(iter)
    }
}

/// Either an address of an account, or contract.
#[cfg_attr(
    feature = "derive-serde",
    derive(SerdeSerialize, SerdeDeserialize),
    serde(tag = "type", content = "address")
)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[derive(Eq, Copy, Clone, Debug)]
pub enum Address {
    #[cfg_attr(feature = "derive-serde", serde(rename = "AddressAccount"))]
    Account(AccountAddress),
    #[cfg_attr(feature = "derive-serde", serde(rename = "AddressContract"))]
    Contract(ContractAddress),
}

#[cfg(feature = "concordium-quickcheck")]
impl quickcheck::Arbitrary for Address {
    fn arbitrary(g: &mut Gen) -> Address {
        //Randomly pick account or contract address.
        if quickcheck::Arbitrary::arbitrary(g) {
            Address::Account(quickcheck::Arbitrary::arbitrary(g))
        } else {
            Address::Contract(quickcheck::Arbitrary::arbitrary(g))
        }
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        // Note that shrinking an address does not change its type: account addresses
        // remain account addresses, the same for contract addresses.
        match self {
            Address::Account(a) => Box::new(quickcheck::Arbitrary::shrink(a).map(Address::Account)),
            Address::Contract(a) => {
                Box::new(quickcheck::Arbitrary::shrink(a).map(Address::Contract))
            }
        }
    }
}

impl From<AccountAddress> for Address {
    fn from(address: AccountAddress) -> Address { Address::Account(address) }
}

impl From<ContractAddress> for Address {
    fn from(address: ContractAddress) -> Address { Address::Contract(address) }
}

// This trait is implemented manually to produce fewer bytes in the generated
// WASM.
impl PartialEq for Address {
    fn eq(&self, other: &Address) -> bool {
        match (self, other) {
            (Address::Account(s), Address::Account(o)) => s == o,
            (Address::Contract(s), Address::Contract(o)) => s == o,
            _ => false,
        }
    }
}

// This trait is implemented manually to produce fewer bytes in the generated
// WASM.
impl Hash for Address {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        match self {
            Address::Account(address) => {
                0u8.hash(state);
                address.hash(state);
            }
            Address::Contract(address) => {
                1u8.hash(state);
                address.hash(state);
            }
        }
    }
}

// This trait is implemented manually to produce fewer bytes in the generated
// WASM.
impl PartialOrd for Address {
    fn partial_cmp(&self, other: &Address) -> Option<Ordering> { Some(self.cmp(other)) }
}

// This trait is implemented manually to produce fewer bytes in the generated
// WASM.
impl Ord for Address {
    fn cmp(&self, other: &Address) -> Ordering {
        match (self, other) {
            (Address::Account(s), Address::Account(o)) => s.cmp(o),
            (Address::Contract(s), Address::Contract(o)) => s.cmp(o),
            (Address::Account(_), _) => Ordering::Less,
            _ => Ordering::Greater,
        }
    }
}

/// A contract name. Expected format: "init_<contract_name>".
#[derive(Eq, PartialEq, Copy, Clone, Debug, Hash)]
pub struct ContractName<'a>(&'a str);

impl<'a> fmt::Display for ContractName<'a> {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { self.0.fmt(f) }
}

impl<'a> PartialEq<str> for ContractName<'a> {
    fn eq(&self, other: &str) -> bool { self.0 == other }
}

impl<'a> PartialEq<&'a str> for ContractName<'a> {
    fn eq(&self, other: &&'a str) -> bool { self.0 == *other }
}

impl<'a> ContractName<'a> {
    /// Create a new ContractName and check the format. Expected format:
    /// "init_<contract_name>".
    #[inline(always)]
    pub fn new(name: &'a str) -> Result<Self, NewContractNameError> {
        ContractName::is_valid_contract_name(name)?;
        Ok(ContractName(name))
    }

    /// Create a new ContractName without checking the format. Expected format:
    /// "init_<contract_name>". If this precondition is not satisfied then
    /// the behaviour of any methods on this type is unspecified, and may
    /// include panics.
    #[inline(always)]
    pub const fn new_unchecked(name: &'a str) -> Self { ContractName(name) }

    /// Get contract name used on chain: "init_<contract_name>".
    #[inline(always)]
    pub const fn get_chain_name(self) -> &'a str { self.0 }

    /// Convert a [`ContractName`] to its owned counterpart. This is an
    /// expensive operation that requires memory allocation.
    pub fn to_owned(&self) -> OwnedContractName { OwnedContractName(self.0.to_owned()) }

    /// Extract the contract name by removing the "init_" prefix.
    #[inline(always)]
    pub fn contract_name(self) -> &'a str { self.get_chain_name().strip_prefix("init_").unwrap() }

    /// Check whether the given string is a valid contract initialization
    /// function name. This is the case if and only if
    /// - the string is no more than [constants::MAX_FUNC_NAME_SIZE][m] bytes
    /// - the string starts with `init_`
    /// - the string __does not__ contain a `.`
    /// - all characters are ascii alphanumeric or punctuation characters.
    ///
    /// [m]: ./constants/constant.MAX_FUNC_NAME_SIZE.html
    pub fn is_valid_contract_name(name: &str) -> Result<(), NewContractNameError> {
        if !name.starts_with("init_") {
            return Err(NewContractNameError::MissingInitPrefix);
        }
        if name.len() > constants::MAX_FUNC_NAME_SIZE {
            return Err(NewContractNameError::TooLong);
        }
        if name.contains('.') {
            return Err(NewContractNameError::ContainsDot);
        }
        if !name.chars().all(|c| c.is_ascii_alphanumeric() || c.is_ascii_punctuation()) {
            return Err(NewContractNameError::InvalidCharacters);
        }
        Ok(())
    }
}

impl<'a> From<ContractName<'a>> for &'a str {
    fn from(n: ContractName<'a>) -> Self { n.0 }
}

/// A contract name (owned version). Expected format: "init_<contract_name>".
#[derive(Eq, PartialEq, Debug, Hash, Clone, PartialOrd, Ord)]
#[cfg_attr(
    feature = "derive-serde",
    derive(SerdeSerialize, SerdeDeserialize),
    serde(into = "String", try_from = "String")
)]
pub struct OwnedContractName(String);

impl fmt::Display for OwnedContractName {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { self.0.fmt(f) }
}

impl PartialEq<str> for OwnedContractName {
    fn eq(&self, other: &str) -> bool { self.0 == other }
}

impl<'a> PartialEq<&'a str> for OwnedContractName {
    fn eq(&self, other: &&'a str) -> bool { self.0 == *other }
}

impl OwnedContractName {
    /// Create a new OwnedContractName and check the format. Expected format:
    /// "init_<contract_name>".
    #[inline(always)]
    pub fn new(name: String) -> Result<Self, NewContractNameError> {
        ContractName::is_valid_contract_name(&name)?;
        Ok(OwnedContractName(name))
    }

    /// Create a new OwnedContractName without checking the format. Expected
    /// format: "init_<contract_name>".
    #[inline(always)]
    pub const fn new_unchecked(name: String) -> Self { OwnedContractName(name) }

    /// Convert to [`ContractName`] by reference.
    #[inline(always)]
    pub fn as_contract_name(&self) -> ContractName { ContractName(self.0.as_str()) }
}

impl From<OwnedContractName> for String {
    fn from(n: OwnedContractName) -> Self { n.0 }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NewContractNameError {
    MissingInitPrefix,
    TooLong,
    ContainsDot,
    InvalidCharacters,
}

impl fmt::Display for NewContractNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use NewContractNameError::*;
        match self {
            MissingInitPrefix => write!(f, "Contract names have the format 'init_<contract_name>'"),
            TooLong => {
                write!(f, "Contract names have a max length of {}", constants::MAX_FUNC_NAME_SIZE)
            }
            ContainsDot => write!(f, "Contract names cannot contain a '.'"),
            InvalidCharacters => write!(
                f,
                "Contract names can only contain ascii alphanumeric or punctuation characters"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NewContractNameError {}

impl convert::TryFrom<String> for OwnedContractName {
    type Error = NewContractNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> { OwnedContractName::new(value) }
}

/// A receive name. Expected format: "<contract_name>.<func_name>".
#[derive(Eq, PartialEq, Copy, Clone, Debug, Hash)]
#[repr(transparent)]
pub struct ReceiveName<'a>(&'a str);

impl<'a> fmt::Display for ReceiveName<'a> {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { self.0.fmt(f) }
}

impl<'a> PartialEq<str> for ReceiveName<'a> {
    fn eq(&self, other: &str) -> bool { self.0 == other }
}

impl<'a> PartialEq<&'a str> for ReceiveName<'a> {
    fn eq(&self, other: &&'a str) -> bool { self.0 == *other }
}

impl<'a> ReceiveName<'a> {
    /// Create a new ReceiveName and check the format. Expected format:
    /// "<contract_name>.<func_name>".
    pub fn new(name: &'a str) -> Result<Self, NewReceiveNameError> {
        ReceiveName::is_valid_receive_name(name)?;
        Ok(ReceiveName(name))
    }

    /// Create a new ReceiveName without checking the format. Expected format:
    /// "<contract_name>.<func_name>".
    #[inline(always)]
    pub const fn new_unchecked(name: &'a str) -> Self { ReceiveName(name) }

    /// Get receive name used on chain: "<contract_name>.<func_name>".
    pub const fn get_chain_name(self) -> &'a str { self.0 }

    /// Convert a [`ReceiveName`] to its owned counterpart. This is an expensive
    /// operation that requires memory allocation.
    pub fn to_owned(self) -> OwnedReceiveName { OwnedReceiveName(self.0.to_string()) }

    /// Extract the contract name by splitting at the first dot.
    pub fn contract_name(self) -> &'a str { self.get_name_parts().0 }

    /// Extract the entrypoint name by splitting at the first dot.
    pub fn entrypoint_name(self) -> EntrypointName<'a> { EntrypointName(self.get_name_parts().1) }

    /// Extract (contract_name, func_name) by splitting at the first dot.
    fn get_name_parts(self) -> (&'a str, &'a str) {
        let mut splitter = self.get_chain_name().splitn(2, '.');
        let contract = splitter.next().unwrap_or("");
        let func = splitter.next().unwrap_or("");
        (contract, func)
    }

    /// Check whether the given string is a valid contract receive function
    /// name. This is the case if and only if
    /// - the string is no more than [constants::MAX_FUNC_NAME_SIZE][m] bytes
    /// - the string __contains__ a `.`
    /// - all characters are ascii alphanumeric or punctuation characters.
    ///
    /// [m]: ./constants/constant.MAX_FUNC_NAME_SIZE.html
    pub fn is_valid_receive_name(name: &str) -> Result<(), NewReceiveNameError> {
        if !name.contains('.') {
            return Err(NewReceiveNameError::MissingDotSeparator);
        }
        if name.len() > constants::MAX_FUNC_NAME_SIZE {
            return Err(NewReceiveNameError::TooLong);
        }
        if !name.chars().all(|c| c.is_ascii_alphanumeric() || c.is_ascii_punctuation()) {
            return Err(NewReceiveNameError::InvalidCharacters);
        }
        Ok(())
    }
}

/// A receive name (owned version). Expected format:
/// "<contract_name>.<func_name>". Most methods are available only on the
/// [`ReceiveName`] type, the intention is to access those via the
/// [`as_receive_name`](OwnedReceiveName::as_receive_name) method.
#[derive(Eq, PartialEq, Debug, Clone, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "derive-serde", derive(SerdeSerialize, SerdeDeserialize))]
#[cfg_attr(feature = "derive-serde", serde(try_from = "String"))]
pub struct OwnedReceiveName(String);

impl PartialEq<str> for OwnedReceiveName {
    fn eq(&self, other: &str) -> bool { self.0 == other }
}

impl<'a> PartialEq<&'a str> for OwnedReceiveName {
    fn eq(&self, other: &&'a str) -> bool { self.0 == *other }
}

impl fmt::Display for OwnedReceiveName {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { self.0.fmt(f) }
}

impl convert::TryFrom<String> for OwnedReceiveName {
    type Error = NewReceiveNameError;

    #[inline(always)]
    fn try_from(value: String) -> Result<Self, Self::Error> { OwnedReceiveName::new(value) }
}

impl str::FromStr for OwnedReceiveName {
    type Err = NewReceiveNameError;

    #[inline(always)]
    fn from_str(s: &str) -> Result<Self, Self::Err> { OwnedReceiveName::new(s.to_string()) }
}

impl OwnedReceiveName {
    /// Create a new OwnedReceiveName and check the format. Expected format:
    /// "<contract_name>.<func_name>".
    pub fn new(name: String) -> Result<Self, NewReceiveNameError> {
        ReceiveName::is_valid_receive_name(&name)?;
        Ok(OwnedReceiveName(name))
    }

    /// Construct a receive name from contract and entrypoint names.
    pub fn construct(
        contract: ContractName,
        entrypoint: EntrypointName,
    ) -> Result<Self, NewReceiveNameError> {
        let mut rm = contract.contract_name().to_string();
        rm.push('.');
        rm.push_str(entrypoint.0);
        Self::new(rm)
    }

    /// Construct a receive name from contract and entrypoint names, assuming
    /// that the resulting name is valid.
    pub fn construct_unchecked(contract: ContractName, entrypoint: EntrypointName) -> Self {
        let mut rm = contract.contract_name().to_string();
        rm.push('.');
        rm.push_str(entrypoint.0);
        Self::new_unchecked(rm)
    }

    /// Create a new OwnedReceiveName without checking the format. Expected
    /// format: "<contract_name>.<func_name>".
    #[inline(always)]
    pub const fn new_unchecked(name: String) -> Self { OwnedReceiveName(name) }

    /// Convert to [`ReceiveName`]. See [`ReceiveName`] for additional methods
    /// available on the type.
    #[inline(always)]
    pub fn as_receive_name(&self) -> ReceiveName { ReceiveName(self.0.as_str()) }
}

/// An entrypoint name (borrowed version). Expected format:
/// "<func_name>" where the name of the function consists solely of ASCII
/// alphanumeric or punctuation characters.
#[derive(Eq, PartialEq, Ord, PartialOrd, Debug, Clone, Copy, Hash)]
#[cfg_attr(feature = "derive-serde", derive(SerdeSerialize))]
#[cfg_attr(feature = "derive-serde", serde(transparent))]
#[repr(transparent)]
pub struct EntrypointName<'a>(pub(crate) &'a str);

impl<'a> EntrypointName<'a> {
    /// Size of the name in bytes.
    pub fn size(&self) -> u32 { self.0.as_bytes().len() as u32 }

    /// Create a new name and check the format. See [is_valid_entrypoint_name]
    /// for the expected format.
    pub fn new(name: &'a str) -> Result<Self, NewReceiveNameError> {
        is_valid_entrypoint_name(name)?;
        Ok(Self(name))
    }

    /// Convert a [`EntrypointName`] to its owned counterpart. This is an
    /// expensive operation that requires memory allocation.
    pub fn to_owned(&self) -> OwnedEntrypointName { OwnedEntrypointName(self.0.to_owned()) }

    /// Create a new name. **This does not check the format and is therefore
    /// unsafe.** It is provided for convenience since sometimes it is
    /// statically clear that the format is satisfied.
    #[inline(always)]
    pub const fn new_unchecked(name: &'a str) -> Self { Self(name) }
}

impl<'a> fmt::Display for EntrypointName<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(self.0) }
}

impl<'a> From<EntrypointName<'a>> for &'a str {
    fn from(en: EntrypointName<'a>) -> Self { en.0 }
}

impl<'a> From<EntrypointName<'a>> for OwnedEntrypointName {
    fn from(epn: EntrypointName<'a>) -> Self { Self(String::from(epn.0)) }
}

impl<'a> PartialEq<str> for EntrypointName<'a> {
    fn eq(&self, other: &str) -> bool { self.0 == other }
}

impl<'a> PartialEq<&'a str> for EntrypointName<'a> {
    fn eq(&self, other: &&'a str) -> bool { self.0 == *other }
}

/// An entrypoint name (owned version). Expected format:
/// "<func_name>". Most methods on this type are available via the
/// [`as_entrypoint_name`](OwnedEntrypointName::as_entrypoint_name) and the
/// methods on the [`EntrypointName`] type.
#[derive(Eq, PartialEq, Ord, PartialOrd, Debug, Clone, Hash)]
#[cfg_attr(feature = "derive-serde", derive(SerdeSerialize, SerdeDeserialize))]
#[cfg_attr(feature = "derive-serde", serde(into = "String", try_from = "String"))]
pub struct OwnedEntrypointName(pub(crate) String);

impl fmt::Display for OwnedEntrypointName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { self.as_entrypoint_name().fmt(f) }
}

impl From<OwnedEntrypointName> for String {
    fn from(oen: OwnedEntrypointName) -> Self { oen.0 }
}

impl convert::TryFrom<String> for OwnedEntrypointName {
    type Error = NewReceiveNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> { OwnedEntrypointName::new(value) }
}

impl PartialEq<str> for OwnedEntrypointName {
    fn eq(&self, other: &str) -> bool { self.0 == other }
}

impl<'a> PartialEq<&'a str> for OwnedEntrypointName {
    fn eq(&self, other: &&'a str) -> bool { self.0 == *other }
}

impl OwnedEntrypointName {
    /// Create a new name and check the format. See [is_valid_entrypoint_name]
    /// for the expected format.
    pub fn new(name: String) -> Result<Self, NewReceiveNameError> {
        is_valid_entrypoint_name(&name)?;
        Ok(Self(name))
    }

    /// Create a new name. **This does not check the format and is therefore
    /// unsafe.** It is provided for convenience since sometimes it is
    /// statically clear that the format is satisfied.
    #[inline(always)]
    pub const fn new_unchecked(name: String) -> Self { Self(name) }

    /// Convert to an [`EntrypointName`] by reference.
    #[inline(always)]
    pub fn as_entrypoint_name(&self) -> EntrypointName { EntrypointName(self.0.as_str()) }
}

/// Parameter to the init function or entrypoint.
#[repr(transparent)]
#[derive(Eq, PartialEq, Clone, Copy, Hash, Default)]
pub struct Parameter<'a>(pub(crate) &'a [u8]);

impl<'a> fmt::Debug for Parameter<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            self.0.fmt(f)
        } else {
            for b in self.0 {
                f.write_fmt(format_args!("{:02x}", b))?
            }
            Ok(())
        }
    }
}

impl<'a> AsRef<[u8]> for Parameter<'a> {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] { self.0 }
}

impl<'a> convert::TryFrom<&'a [u8]> for Parameter<'a> {
    type Error = ExceedsParameterSize;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let actual = bytes.len();
        if actual <= constants::MAX_PARAMETER_LEN {
            Ok(Self(bytes))
        } else {
            Err(ExceedsParameterSize {
                actual,
                max: constants::MAX_PARAMETER_LEN,
            })
        }
    }
}

impl<'a> From<Parameter<'a>> for &'a [u8] {
    fn from(p: Parameter<'a>) -> Self { p.0 }
}

/// Display the entire parameter in hex.
impl fmt::Display for Parameter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0.iter() {
            f.write_fmt(format_args!("{:02x}", b))?
        }
        Ok(())
    }
}

impl<'a> Parameter<'a> {
    /// Construct a parameter from a slice of bytes without checking that it
    /// fits the size limit. The caller is assumed to ensure this via
    /// external means.
    #[inline]
    pub const fn new_unchecked(bytes: &'a [u8]) -> Self { Self(bytes) }

    /// Construct an empty parameter.
    #[inline]
    pub const fn empty() -> Self { Self(&[]) }
}

/// Parameter to the init function or entrypoint. Owned version.
#[repr(transparent)]
#[derive(Eq, PartialEq, Clone, Hash, Default)]
#[cfg_attr(feature = "derive-serde", derive(SerdeSerialize, SerdeDeserialize))]
pub struct OwnedParameter(
    #[cfg_attr(feature = "derive-serde", serde(with = "serde_impl::byte_array_hex"))]
    pub(crate)  Vec<u8>,
);

// Output as a hex string.
impl fmt::Debug for OwnedParameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            self.0.fmt(f)
        } else {
            for b in &self.0 {
                f.write_fmt(format_args!("{:02x}", b))?
            }
            Ok(())
        }
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "derive-serde", derive(thiserror::Error))]
#[cfg_attr(
    feature = "derive-serde",
    error("The byte array of size {actual} is too large to fit into parameter size limit {max}.")
)]
pub struct ExceedsParameterSize {
    pub actual: usize,
    pub max:    usize,
}

impl AsRef<[u8]> for OwnedParameter {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] { self.0.as_ref() }
}

impl convert::TryFrom<Vec<u8>> for OwnedParameter {
    type Error = ExceedsParameterSize;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let actual = bytes.len();
        if actual <= constants::MAX_PARAMETER_LEN {
            Ok(Self(bytes))
        } else {
            Err(ExceedsParameterSize {
                actual,
                max: constants::MAX_PARAMETER_LEN,
            })
        }
    }
}

impl From<OwnedParameter> for Vec<u8> {
    fn from(op: OwnedParameter) -> Self { op.0 }
}

/// Display the entire parameter in hex.
impl fmt::Display for OwnedParameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            f.write_fmt(format_args!("{:02x}", b))?
        }
        Ok(())
    }
}

impl OwnedParameter {
    /// Get [`Self`] as the borrowed variant [`Parameter`].
    pub fn as_parameter(&self) -> Parameter { Parameter(self.0.as_ref()) }

    /// Construct an [`Self`]` by serializing the input using its
    /// `Serial` instance.
    ///
    /// Returns an error if the serialized parameter exceeds
    /// [`MAX_PARAMETER_LEN`][constants::MAX_PARAMETER_LEN].
    pub fn from_serial<D: Serial>(data: &D) -> Result<Self, ExceedsParameterSize> {
        let bytes = to_bytes(data);
        if bytes.len() > constants::MAX_PARAMETER_LEN {
            return Err(ExceedsParameterSize {
                actual: bytes.len(),
                max:    constants::MAX_PARAMETER_LEN,
            });
        }
        Ok(Self(bytes))
    }

    /// Construct a parameter from a vector of bytes without checking that it
    /// fits the size limit. The caller is assumed to ensure this via
    /// external means.
    #[inline]
    pub const fn new_unchecked(bytes: Vec<u8>) -> Self { Self(bytes) }

    /// Construct an empty parameter.
    #[inline]
    pub const fn empty() -> Self { Self(Vec::new()) }
}

/// Check whether the given string is a valid contract entrypoint name.
/// This is the case if and only if
/// - the string is less than [constants::MAX_FUNC_NAME_SIZE][m] bytes
/// - all characters are ascii alphanumeric or punctuation characters.
///
/// [m]: ./constants/constant.MAX_FUNC_NAME_SIZE.html
pub fn is_valid_entrypoint_name(name: &str) -> Result<(), NewReceiveNameError> {
    if name.as_bytes().len() >= constants::MAX_FUNC_NAME_SIZE {
        return Err(NewReceiveNameError::TooLong);
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c.is_ascii_punctuation()) {
        return Err(NewReceiveNameError::InvalidCharacters);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NewReceiveNameError {
    MissingDotSeparator,
    TooLong,
    InvalidCharacters,
}

impl fmt::Display for NewReceiveNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use NewReceiveNameError::*;
        match self {
            MissingDotSeparator => {
                f.write_str("Receive names have the format '<contract_name>.<func_name>'.")
            }
            TooLong => {
                write!(f, "Receive names have a max length of {}", constants::MAX_FUNC_NAME_SIZE)
            }
            InvalidCharacters => write!(
                f,
                "Receive names can only contain ascii alphanumeric or punctuation characters"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NewReceiveNameError {}

/// Time at the beginning of the current slot, in miliseconds since unix epoch.
pub type SlotTime = Timestamp;

/// An exchange rate between two quantities. This is never 0, and the exchange
/// rate should also never be infinite.
#[cfg_attr(
    feature = "derive-serde",
    derive(SerdeSerialize, SerdeDeserialize),
    serde(try_from = "serde_impl::ExchangeRateJSON")
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExchangeRate {
    numerator:   u64,
    denominator: u64,
}

impl ExchangeRate {
    /// Attempt to construct an exchange rate from a numerator and denominator.
    /// The numerator and denominator must both be non-zero, and they have to be
    /// in reduced form.
    #[cfg(feature = "derive-serde")]
    pub fn new(numerator: u64, denominator: u64) -> Option<Self> {
        if numerator != 0 && denominator != 0 && num_integer::gcd(numerator, denominator) == 1 {
            Some(Self {
                numerator,
                denominator,
            })
        } else {
            None
        }
    }

    /// Construct an unchecked exchange rate from a numerator and denominator.
    /// The numerator and denominator must both be non-zero, and they have to be
    /// in reduced form.
    pub const fn new_unchecked(numerator: u64, denominator: u64) -> Self {
        Self {
            numerator,
            denominator,
        }
    }

    /// Get the numerator. This is never 0.
    pub const fn numerator(&self) -> u64 { self.numerator }

    /// Get the denominator. This is never 0.
    pub const fn denominator(&self) -> u64 { self.denominator }
}

/// The euro/NRG and microCCD/euro exchange rates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExchangeRates {
    /// Euro per NRG exchange rate.
    pub euro_per_energy:    ExchangeRate,
    /// Micro CCD per Euro exchange rate.
    pub micro_ccd_per_euro: ExchangeRate,
}

impl ExchangeRates {
    /// Convert Euro cent to CCD using the current exchange rate.
    /// This will round down to the nearest micro CCD.
    pub fn convert_euro_cent_to_amount(&self, euro_cent: u64) -> Amount {
        let numerator: u128 = self.micro_ccd_per_euro.numerator().into();
        let denominator: u128 = self.micro_ccd_per_euro.denominator().into();
        let euro_cent: u128 = euro_cent.into();
        let result = numerator * euro_cent / (denominator * 100);
        Amount::from_micro_ccd(result as u64)
    }

    /// Convert CCD to Euro cent using the current exchange rate.
    /// This will round down to the nearest Euro cent.
    pub fn convert_amount_to_euro_cent(&self, amount: Amount) -> u64 {
        let numerator: u128 = self.micro_ccd_per_euro.numerator().into();
        let denominator: u128 = self.micro_ccd_per_euro.denominator().into();
        let micro_ccd: u128 = amount.micro_ccd().into();
        let result = micro_ccd * 100 * denominator / numerator;
        result as u64
    }
}

/// Chain metadata accessible to both receive and init methods.
#[cfg_attr(
    feature = "derive-serde",
    derive(SerdeSerialize, SerdeDeserialize),
    serde(rename_all = "camelCase")
)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[derive(Debug, Clone)]
/// Information about the chain available to smart contracts.
pub struct ChainMetadata {
    /// The objective (i.e., the entire network agrees on it) time of the block
    /// in whose context the smart contract is being executed.
    pub slot_time: SlotTime,
}

#[cfg(feature = "concordium-quickcheck")]
impl quickcheck::Arbitrary for ChainMetadata {
    fn arbitrary(g: &mut Gen) -> ChainMetadata {
        ChainMetadata {
            slot_time: quickcheck::Arbitrary::arbitrary(g),
        }
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        Box::new(quickcheck::Arbitrary::shrink(&self.slot_time).map(|slot_time| ChainMetadata {
            slot_time,
        }))
    }
}

/// Add offset tracking inside a data structure.
#[derive(Debug)]
pub struct Cursor<T> {
    pub offset: usize,
    pub data:   T,
}

/// Adapter to chain together two readers.
#[derive(Debug)]
pub struct Chain<T, U> {
    pub(crate) first:      T,
    pub(crate) second:     U,
    pub(crate) done_first: bool,
}

impl<T, U> Chain<T, U> {
    /// Construct a reader by chaining to readers together.
    pub const fn new(first: T, second: U) -> Self {
        Self {
            first,
            second,
            done_first: false,
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NewAttributeValueError {}

/// Errors that can occur when constructing a new [`AttributeValue`].
#[derive(Debug, PartialEq, Eq)]
pub enum NewAttributeValueError {
    TooLong(usize),
}

impl fmt::Display for NewAttributeValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NewAttributeValueError::TooLong(size) => write!(
                f,
                "Attribute values have a max length of 31. The slice given had length {}.",
                size
            ),
        }
    }
}

/// Tag of an attribute. See the module [attributes](./attributes/index.html)
/// for the currently supported attributes.
#[repr(transparent)]
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[derive(Clone, Copy, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct AttributeTag(pub u8);

#[cfg(feature = "concordium-quickcheck")]
impl quickcheck::Arbitrary for AttributeTag {
    // We choose not to constrain the generated attributes to those currently
    // defined in `concordium-base/rust-src/id/src/types.rs`. The protocol
    // supports more attributes and it is reasonable to generate all values
    // supported by the protocol to ensure that the tested code is robust with
    // respect to future additions.
    fn arbitrary(g: &mut Gen) -> AttributeTag { AttributeTag(quickcheck::Arbitrary::arbitrary(g)) }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        Box::new(quickcheck::Arbitrary::shrink(&self.0).map(AttributeTag))
    }
}

/// An attribute value.
/// The meaning of the bytes is dependent on the type of the attribute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct AttributeValue {
    pub(crate) inner: [u8; 32],
}

#[cfg(feature = "fuzz")]
impl arbitrary::Arbitrary<'_> for AttributeValue {
    fn arbitrary(u: &mut arbitrary::Unstructured) -> arbitrary::Result<Self> {
        let size = u.int_in_range(0..=31)?;
        let mut inner: [u8; 32] = [0u8; 32];
        inner[0] = size;
        u.fill_buffer(&mut inner[1..=usize::from(size)])?;
        Ok(AttributeValue {
            inner,
        })
    }
}

impl AttributeValue {
    /// Create a new [`Self`] from a slice of bytes. The slice must have a
    /// length of *at most 31 bytes*.
    pub fn new(data: &[u8]) -> Result<Self, NewAttributeValueError> {
        if data.len() > 31 {
            return Err(NewAttributeValueError::TooLong(data.len()));
        }
        let mut inner = [0u8; 32];
        inner[1..=data.len()].copy_from_slice(data);
        inner[0] = data.len() as u8;
        Ok(Self {
            inner,
        })
    }

    #[doc(hidden)]
    /// Create a new [`Self`] from a byte array. The first byte *must* tell
    /// the length of the attribute in the array.
    pub unsafe fn new_unchecked(inner: [u8; 32]) -> Self {
        Self {
            inner,
        }
    }

    /// Get the length of the attribute value.
    pub fn len(&self) -> usize { self.inner[0].into() }

    /// Whether the attribute value has zero length.
    pub fn is_empty(&self) -> bool { self.len() == 0 }
}

#[cfg(feature = "concordium-quickcheck")]
fn gen_sized_vec<A: quickcheck::Arbitrary>(g: &mut Gen, size: usize) -> Vec<A> {
    (0..size).map(|_| quickcheck::Arbitrary::arbitrary(g)).collect()
}

#[cfg(feature = "concordium-quickcheck")]
impl quickcheck::Arbitrary for AttributeValue {
    fn arbitrary(g: &mut Gen) -> AttributeValue {
        let size = gen_range_u8(g, 0..32);
        let mut inner: [u8; 32] = [0u8; 32];
        let random_data = gen_sized_vec(g, size as usize);
        inner[1..=size as usize].copy_from_slice(&random_data);
        inner[0] = size;
        AttributeValue {
            inner,
        }
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        let size = self.inner[0];
        let data: &[u8] = &self.inner[1..=size as usize];
        let vs = data.to_vec().shrink();
        Box::new(vs.map(|v| {
            let mut inner = [0u8; 32];
            inner[1..=v.len()].copy_from_slice(&v);
            inner[0] = v.len() as u8;
            AttributeValue {
                inner,
            }
        }))
    }
}

impl AsRef<[u8]> for AttributeValue {
    fn as_ref(&self) -> &[u8] { &self.inner[1..=usize::from(self.inner[0])] }
}

impl convert::TryFrom<&[u8]> for AttributeValue {
    type Error = NewAttributeValueError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> { Self::new(value) }
}

/// Apply the given macro to each of the elements in the list
/// For example, `repeat_macro!(println, "foo", "bar")` is equivalent to
/// `println!("foo"); println!("bar").
macro_rules! repeat_macro {
    ($f:ident, $n:expr) => ($f!($n););
    ($f:ident, $n:expr, $($ns:expr),*) => {
        $f!($n);
        repeat_macro!($f, $($ns),*);
    };
}

/// Generate a [`From`] implementation from a bytearray of size `n` to an
/// [`AttributeValue`] (also generates one for a referenced array). `n` *must*
/// be between 0 and 31, both inclusive, otherwise the resulting code will
/// panic.
///
/// The implementation for references of byte arrays are need to ease the use of
/// literals. Specifically, it allows you to write `b"abc".into()` instead of
/// `(*b"abc").into()`.
macro_rules! from_bytearray_to_attribute_value {
    ($n:expr) => {
        impl From<[u8; $n]> for AttributeValue {
            fn from(data: [u8; $n]) -> Self { AttributeValue::new(&data[..]).unwrap() }
        }

        impl From<&[u8; $n]> for AttributeValue {
            fn from(data: &[u8; $n]) -> Self { AttributeValue::new(&data[..]).unwrap() }
        }
    };
}

repeat_macro!(
    from_bytearray_to_attribute_value,
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    16,
    17,
    18,
    19,
    20,
    21,
    22,
    23,
    24,
    25,
    26,
    27,
    28,
    29,
    30,
    31
);

/// A policy with a vector of attributes, fully allocated and owned.
/// This is in contrast to a policy which is lazily read from a read source.
/// The latter is useful for efficiency, this type is more useful for testing
/// since the values are easier to construct.
pub type OwnedPolicy = Policy<Vec<(AttributeTag, AttributeValue)>>;

impl OwnedPolicy {
    /// Serialize the policy for consumption by smart contract execution engine.
    ///
    /// This entails the following serialization scheme:
    /// - `1`:             u16           specifying a single policy.
    /// - `len`:           u16           length of the inner payload
    /// - `inner payload`: `len` bytes   the serialized `OwnedPolicy`
    #[doc(hidden)]
    pub fn serial_for_smart_contract<W: crate::traits::Write>(
        &self,
        out: &mut W,
    ) -> Result<(), W::Err> {
        // Serialize to an inner vector.
        let inner = to_bytes(self);
        // Specify that there is only one policy.
        out.write_u16(1)?;
        // Write length of the inner.
        (inner.len() as u16).serial(out)?;
        // Write the inner buffer.
        out.write_all(&inner)?;
        Ok(())
    }
}

/// Index of the identity provider on the chain.
/// An identity provider with the given index will not be replaced,
/// so this is a stable identifier.
pub type IdentityProvider = u32;

/// Policy on the credential of the account.
///
/// This is one of the key features of the Concordium blockchain. Each account
/// on the chain is backed by an identity. The policy is verified and signed by
/// the identity provider before an account can be created on the chain.
///
/// The type is parameterized by the choice of `Attributes`. These are either
/// borrowed or owned, in the form of an iterator over key-value pairs or a
/// vector of such. This flexibility is needed so that attributes can be
/// accessed efficiently, as well as constructed conveniently for testing.
#[cfg_attr(feature = "fuzz", derive(Arbitrary))]
#[derive(Debug, Clone)]
pub struct Policy<Attributes> {
    /// Identity of the identity provider who signed the identity object that
    /// this policy is derived from.
    pub identity_provider: IdentityProvider,
    /// Timestamp at the beginning of the month when the identity object backing
    /// this policy was created. This timestamp has very coarse granularity
    /// in order for the identity provider to not be able to link identities
    /// they have created with accounts that users created on the chain.
    /// as a timestamp (which has millisecond granularity) in order to make it
    /// easier to compare with, e.g., `slot_time`.
    pub created_at:        Timestamp,
    /// Beginning of the month where the identity is __no longer valid__.
    pub valid_to:          Timestamp,
    /// List of attributes, in ascending order of the tag.
    pub items:             Attributes,
}

/// Generate a vector of random key-value pairs with no duplication
/// The length of the resulting vector is <= `size`
#[cfg(feature = "concordium-quickcheck")]
fn gen_no_dup_kv_vec<A: quickcheck::Arbitrary + Ord, B: quickcheck::Arbitrary>(
    g: &mut Gen,
    size: usize,
) -> Vec<(A, B)> {
    let mut m: BTreeMap<A, B> = BTreeMap::new();
    for _ in 0..size {
        let k = A::arbitrary(g);
        let v = B::arbitrary(g);
        m.insert(k, v);
    }
    m.into_iter().collect()
}

/// Generate a random `u64` value in the given range by shifting a random `u64`
/// value using the `%` operator. The reason for doing it this way is that the
/// range generation method is not exposed by QuickCheck's `Gen`.
#[cfg(feature = "concordium-quickcheck")]
fn gen_range_u64(g: &mut Gen, range: core::ops::Range<u64>) -> u64 {
    let i: u64 = quickcheck::Arbitrary::arbitrary(g);
    i % (range.end - range.start) + range.start
}

/// Generate a random `u8` value in the given range by shifting a random `u8`
/// value using the `%` operator. The reason for doing it this way is that the
/// range generation method is not exposed by QuickCheck's `Gen`.
#[cfg(feature = "concordium-quickcheck")]
fn gen_range_u8(g: &mut Gen, range: core::ops::Range<u8>) -> u8 {
    let i: u8 = quickcheck::Arbitrary::arbitrary(g);
    i % (range.end - range.start) + range.start
}

/// Check that the creation date `created_at` is less then or equal to the
/// validity date `valid_to`.
#[cfg(feature = "concordium-quickcheck")]
fn valid_owned_policy(op: &OwnedPolicy) -> bool {
    let OwnedPolicy {
        created_at,
        valid_to,
        ..
    } = op;
    created_at <= valid_to
}

#[cfg(feature = "concordium-quickcheck")]
impl quickcheck::Arbitrary for OwnedPolicy {
    fn arbitrary(g: &mut Gen) -> OwnedPolicy {
        let size: u8 = quickcheck::Arbitrary::arbitrary(g);
        let created_at: Timestamp = quickcheck::Arbitrary::arbitrary(g);
        // generate `created_at` date so it's <= `valid_to`
        let valid_to_millis = gen_range_u64(g, created_at.timestamp_millis()..u64::MAX);
        OwnedPolicy {
            identity_provider: quickcheck::Arbitrary::arbitrary(g),
            created_at,
            valid_to: Timestamp::from_timestamp_millis(valid_to_millis),
            items: gen_no_dup_kv_vec(g, size as usize),
        }
    }

    fn shrink(&self) -> Box<dyn Iterator<Item = Self>> {
        let identity_provider = self.identity_provider;
        let created_at = self.created_at;
        let valid_to = self.valid_to;
        let items = self.items.clone();
        let iter = identity_provider
            .shrink()
            .flat_map(move |ip| {
                let items = items.clone();
                created_at.shrink().flat_map(move |ca| {
                    let items = items.clone();
                    valid_to.shrink().flat_map(move |vt| {
                        items.shrink().map(move |it| OwnedPolicy {
                            identity_provider: ip,
                            created_at:        ca,
                            valid_to:          vt,
                            items:             it,
                        })
                    })
                })
            })
            .filter(valid_owned_policy);
        Box::new(iter)
    }
}

/// This implementation of deserialize is only useful when used
/// to deserialize JSON. Other formats could be implemented in the future.
#[cfg(feature = "derive-serde")]
impl<'de> SerdeDeserialize<'de> for OwnedPolicy {
    fn deserialize<D>(deserializer: D) -> Result<OwnedPolicy, D::Error>
    where
        D: serde::Deserializer<'de>, {
        deserializer.deserialize_map(policy_json::OwnedPolicyVisitor)
    }
}

#[cfg(feature = "derive-serde")]
mod policy_json {
    use super::*;
    use convert::{TryFrom, TryInto};

    pub(crate) struct OwnedPolicyVisitor;

    impl<'de> serde::de::Visitor<'de> for OwnedPolicyVisitor {
        type Value = OwnedPolicy;

        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> Result<Self::Value, A::Error> {
            let mut idp = None;
            let mut ca = None;
            let mut vt = None;
            let mut items = Vec::new();

            let parse_date = |s: &str| {
                if !s.chars().all(|c| c.is_numeric() && c.is_ascii()) || s.len() != 6 {
                    return Err(serde::de::Error::custom("Incorrect YYYYMM format."));
                }
                let (s_year, s_month) = s.split_at(4);
                let year =
                    s_year.parse::<u16>().map_err(|_| serde::de::Error::custom("Invalid year."))?;
                let month = s_month
                    .parse::<u8>()
                    .map_err(|_| serde::de::Error::custom("Invalid month."))?;
                if month > 12 {
                    return Err(serde::de::Error::custom("Month out of range."));
                }
                if year < 1000 {
                    return Err(serde::de::Error::custom("Year out of range."));
                }
                let dt =
                    chrono::naive::NaiveDate::from_ymd_opt(i32::from(year), u32::from(month), 1)
                        .ok_or_else(|| serde::de::Error::custom("Invalid year or month."))?
                        .and_hms_opt(0, 0, 0)
                        .ok_or_else(|| {
                            serde::de::Error::custom("Could not convert YearMonth to a date.")
                        })?;
                let timestamp: u64 = dt.and_utc().timestamp_millis().try_into().map_err(|_| {
                    serde::de::Error::custom("Times before 1970 are not supported.")
                })?;
                Ok(timestamp)
            };

            while let Some((k, v)) = map.next_entry::<String, serde_json::Value>()? {
                match k.as_str() {
                    "identityProvider" => {
                        idp = Some(serde_json::from_value(v).map_err(|_| {
                            serde::de::Error::custom("Unsupported identity provider value.")
                        })?)
                    }
                    "createdAt" => {
                        if let Some(s) = v.as_str() {
                            ca = Some(parse_date(s)?);
                        } else {
                            return Err(serde::de::Error::custom("Unsupported creation format."));
                        }
                    }
                    "validTo" => {
                        if let Some(s) = v.as_str() {
                            vt = Some(parse_date(s)?);
                        } else {
                            return Err(serde::de::Error::custom("Unsupported valid to format."));
                        }
                    }
                    s => {
                        if let Ok(tag) = AttributeTag::try_from(s) {
                            match v {
                                serde_json::Value::String(value_string)
                                    if value_string.as_bytes().len() <= 31 =>
                                {
                                    let value =
                                        AttributeValue::new(&value_string.into_bytes()).unwrap(); // Safe as we know the length is valid.
                                    items.push((tag, value))
                                }
                                _ => {
                                    return Err(serde::de::Error::custom(
                                        "Invalid attribute value. Attributes must be at most 31 \
                                         characters in utf8 encoding.",
                                    ))
                                }
                            }
                        } // ignore this value otherwise.
                    }
                }
            }
            let identity_provider =
                idp.ok_or_else(|| serde::de::Error::custom("Missing field 'identityProvider'"))?;
            let created_at =
                ca.ok_or_else(|| serde::de::Error::custom("Missing field 'createdAt'"))?;
            let valid_to = vt.ok_or_else(|| serde::de::Error::custom("Missing field 'validTo'"))?;
            Ok(Policy {
                identity_provider,
                created_at: Timestamp::from_timestamp_millis(created_at),
                valid_to: Timestamp::from_timestamp_millis(valid_to),
                items,
            })
        }

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("an object representing a policy.")
        }
    }
}

/// Currently defined attributes possible in a policy.
pub mod attributes {
    // NB: These names and values must match the rest of the Concordium ecosystem.
    use super::{convert, AttributeTag};
    pub const FIRST_NAME: AttributeTag = AttributeTag(0u8);
    pub const LAST_NAME: AttributeTag = AttributeTag(1u8);
    pub const SEX: AttributeTag = AttributeTag(2u8);
    pub const DOB: AttributeTag = AttributeTag(3u8);
    pub const COUNTRY_OF_RESIDENCE: AttributeTag = AttributeTag(4u8);
    pub const NATIONALITY: AttributeTag = AttributeTag(5u8);
    pub const ID_DOC_TYPE: AttributeTag = AttributeTag(6u8);
    pub const ID_DOC_NUMBER: AttributeTag = AttributeTag(7u8);
    pub const ID_DOC_ISSUER: AttributeTag = AttributeTag(8u8);
    pub const ID_DOC_ISSUED_AT: AttributeTag = AttributeTag(9u8);
    pub const ID_DOC_EXPIRES_AT: AttributeTag = AttributeTag(10u8);
    pub const NATIONAL_ID_NO: AttributeTag = AttributeTag(11u8);
    pub const TAX_ID_NO: AttributeTag = AttributeTag(12u8);

    // NB: These names must match the rest of the Concordium ecosystem.
    impl<'a> convert::TryFrom<&'a str> for AttributeTag {
        type Error = super::ParseError;

        fn try_from(v: &'a str) -> Result<Self, Self::Error> {
            match v {
                "firstName" => Ok(FIRST_NAME),
                "lastName" => Ok(LAST_NAME),
                "sex" => Ok(SEX),
                "dob" => Ok(DOB),
                "countryOfResidence" => Ok(COUNTRY_OF_RESIDENCE),
                "nationality" => Ok(NATIONALITY),
                "idDocType" => Ok(ID_DOC_TYPE),
                "idDocNo" => Ok(ID_DOC_NUMBER),
                "idDocIssuer" => Ok(ID_DOC_ISSUER),
                "idDocIssuedAt" => Ok(ID_DOC_ISSUED_AT),
                "idDocExpiresAt" => Ok(ID_DOC_EXPIRES_AT),
                "nationalIdNo" => Ok(NATIONAL_ID_NO),
                "taxIdNo" => Ok(TAX_ID_NO),
                _ => Err(super::ParseError {}),
            }
        }
    }
}

/// Zero-sized type to represent an error when reading bytes and deserializing.
///
/// When using custom error types in your smart contract, it is convenient to
/// implement the trait `From<ParseError>` for you custom error type, to allow
/// using the `?` operator when deserializing bytes, such as the contract state
/// or parameters.
///
/// ```ignore
/// # use concordium_std::*;
/// enum MyCustomReceiveError {
///     Parsing
/// }
///
/// impl From<ParseError> for MyCustomReceiveError {
///     fn from(_: ParseError) -> Self { MyCustomReceiveError::Parsing }
/// }
///
/// #[receive(contract = "mycontract", name="some_receive_name", mutable)]
/// fn contract_receive<S: HasStateApi>(
///     ctx: &impl HasReceiveContext,
///     host: &mut impl HasHost<State, StateApiType = S>,
/// ) -> Result<A, MyCustomReceiveError> {
///     // ...
///     let msg: MyParameterType = ctx.parameter_cursor().get()?;
///     // ...
/// }
/// ```
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ParseError {}

/// A type alias used to indicate that the value is a result
/// of parsing from binary via the `Serial` instance.
pub type ParseResult<A> = Result<A, ParseError>;

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("Parsing failed") }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
#[cfg_attr(feature = "derive-serde", derive(SerdeSerialize, SerdeDeserialize))]
#[cfg_attr(feature = "derive-serde", serde(try_from = "u8", into = "u8"))]
/// Version of the module. This determines the chain API that the module can
/// access.
pub enum WasmVersion {
    /// The initial smart contracts version. This has a simple state API that
    /// has very limited capacity. `V0` contracts also use message-passing as
    /// the interaction method.
    V0 = 0u8,
    /// `V1` contracts were introduced with protocol version 4. In comparison to
    /// `V0` contracts they use synchronous calls as the interaction method,
    /// and they have access to a more fine-grained state API allowing for
    /// unlimited (apart from NRG costs) state size.
    V1,
}

impl fmt::Display for WasmVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WasmVersion::V0 => f.write_str("V0"),
            WasmVersion::V1 => f.write_str("V1"),
        }
    }
}

/// V0 is the default version of smart contracts.
impl Default for WasmVersion {
    fn default() -> Self { Self::V0 }
}

impl convert::From<WasmVersion> for u8 {
    fn from(x: WasmVersion) -> Self { x as u8 }
}

#[cfg(feature = "derive-serde")]
mod serde_impl {
    use super::*;
    use serde::{de, de::Visitor, Deserializer, Serializer};
    use std::{fmt, num};

    #[derive(Debug, thiserror::Error)]
    #[error("Unsupported version: {unexpected_string}. Only 'V0' and 'V1' are supported.")]
    pub struct WasmVersionParseError {
        pub unexpected_string: String,
    }

    impl str::FromStr for WasmVersion {
        type Err = WasmVersionParseError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            match s {
                "V0" | "v0" => Ok(WasmVersion::V0),
                "V1" | "v1" => Ok(WasmVersion::V1),
                unexpected_string => Err(WasmVersionParseError {
                    unexpected_string: unexpected_string.to_string(),
                }),
            }
        }
    }

    #[derive(Debug, thiserror::Error)]
    #[error(
        "Unsupported version: {unexpected_version}. Only versions 0 and 1 of smart contracts are \
         supported."
    )]
    pub struct U8WasmVersionConvertError {
        pub unexpected_version: u8,
    }

    impl TryFrom<u8> for WasmVersion {
        type Error = U8WasmVersionConvertError;

        fn try_from(value: u8) -> Result<Self, Self::Error> {
            match value {
                0 => Ok(Self::V0),
                1 => Ok(Self::V1),
                unexpected_version => Err(U8WasmVersionConvertError {
                    unexpected_version,
                }),
            }
        }
    }

    /// An error that may occur when converting from a string to an exchange
    /// rate.
    #[derive(Debug, thiserror::Error)]
    pub enum ExchangeRateConversionError {
        #[error("Could not convert from decimal: {0}")]
        FromDecimal(#[from] rust_decimal::Error),
        #[error("Exchange rate must be strictly positive.")]
        NotStrictlyPositive,
        #[error(
            "Exchange rate is not representable, either it is too large or has too many digits."
        )]
        Unrepresentable,
    }

    impl str::FromStr for ExchangeRate {
        type Err = ExchangeRateConversionError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let mut decimal = rust_decimal::Decimal::from_str_exact(s)?;
            decimal.normalize_assign();
            if decimal.is_zero() || decimal.is_sign_negative() {
                return Err(ExchangeRateConversionError::NotStrictlyPositive);
            }
            let mantissa = decimal.mantissa();
            let scale = decimal.scale();
            let denominator: u64 =
                10u64.checked_pow(scale).ok_or(ExchangeRateConversionError::Unrepresentable)?;
            let numerator: u64 =
                mantissa.try_into().map_err(|_| ExchangeRateConversionError::Unrepresentable)?;
            let g = num_integer::gcd(numerator, denominator);
            Ok(ExchangeRate {
                numerator:   numerator / g,
                denominator: denominator / g,
            })
        }
    }

    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    pub enum ExchangeRateJSON {
        String(String),
        Num(f64),
        Object {
            numerator:   u64,
            denominator: u64,
        },
    }

    impl convert::TryFrom<ExchangeRateJSON> for ExchangeRate {
        type Error = ExchangeRateConversionError;

        fn try_from(value: ExchangeRateJSON) -> Result<Self, Self::Error> {
            match value {
                ExchangeRateJSON::String(value) => value.parse(),
                ExchangeRateJSON::Num(v) => v.to_string().parse(),
                ExchangeRateJSON::Object {
                    numerator,
                    denominator,
                } => {
                    let g = num_integer::gcd(numerator, denominator);
                    Ok(ExchangeRate {
                        numerator:   numerator / g,
                        denominator: denominator / g,
                    })
                }
            }
        }
    }

    /// Error type for when parsing an account address.
    #[derive(Debug, thiserror::Error)]
    pub enum AccountAddressParseError {
        /// Failed parsing the Base58Check encoding.
        #[error("Invalid Base58Check encoding: {0}")]
        InvalidBase58Check(#[from] bs58::decode::Error),
        /// The decoded bytes are not of length [`ACCOUNT_ADDRESS_SIZE`].
        #[error("Invalid number of bytes, expected {ACCOUNT_ADDRESS_SIZE}, but got {0}.")]
        InvalidByteLength(usize),
    }

    /// Parse from string assuming base58check encoding.
    impl str::FromStr for AccountAddress {
        type Err = AccountAddressParseError;

        fn from_str(v: &str) -> Result<Self, Self::Err> {
            // The buffer must be large enough to contain the 32 bytes for the address, 4
            // bytes for a checksum and 1 byte for the version.
            let mut buf = [0u8; ACCOUNT_ADDRESS_SIZE + 4 + 1];
            let len = bs58::decode(v).with_check(Some(1)).onto(&mut buf)?;
            // Prepends 1 byte for the version
            if len != 1 + ACCOUNT_ADDRESS_SIZE {
                return Err(AccountAddressParseError::InvalidByteLength(len));
            }
            // Copy out the 32 bytes for the account address. Ignoring 1 byte prepended
            // for the version and the 4 bytes appended for the checksum.
            let mut address_bytes = [0u8; ACCOUNT_ADDRESS_SIZE];
            address_bytes.copy_from_slice(&buf[1..1 + ACCOUNT_ADDRESS_SIZE]);
            Ok(AccountAddress(address_bytes))
        }
    }

    impl TryFrom<&[u8]> for AccountAddress {
        type Error = AccountAddressParseError;

        fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
            if slice.len() == ACCOUNT_ADDRESS_SIZE {
                let mut array = [0u8; ACCOUNT_ADDRESS_SIZE];
                array.copy_from_slice(slice);
                Ok(AccountAddress(array))
            } else {
                Err(AccountAddressParseError::InvalidByteLength(slice.len()))
            }
        }
    }

    impl fmt::Display for AccountAddress {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", bs58::encode(&self.0).with_check_version(1).into_string())
        }
    }

    impl SerdeSerialize for AccountAddress {
        fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
            let b58_str = self.to_string();
            ser.serialize_str(&b58_str)
        }
    }

    impl<'de> SerdeDeserialize<'de> for AccountAddress {
        fn deserialize<D: Deserializer<'de>>(des: D) -> Result<Self, D::Error> {
            des.deserialize_str(Base58Visitor)
        }
    }

    /// Helper for [de]serializing a byte array as an hex string.
    pub(super) mod byte_array_hex {
        use super::*;

        /// Serialize (via Serde)
        pub fn serialize<S: serde::Serializer>(dt: &[u8], ser: S) -> Result<S::Ok, S::Error> {
            ser.serialize_str(hex::encode(dt).as_str())
        }

        /// Deserialize (via Serde)
        pub fn deserialize<'de, D: serde::Deserializer<'de>>(des: D) -> Result<Vec<u8>, D::Error> {
            struct HexVisitor;
            impl<'de> serde::de::Visitor<'de> for HexVisitor {
                type Value = Vec<u8>;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    write!(formatter, "A hex string.")
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error, {
                    let r = hex::decode(v).map_err(serde::de::Error::custom)?;
                    Ok(r)
                }
            }
            des.deserialize_str(HexVisitor)
        }
    }

    /// Error that can occur when parsing a [`ContractAddress`] from a string.
    #[derive(Debug, thiserror::Error)]
    pub enum ContractAddressParseError {
        #[error("A contract address must start with '<'")]
        MissingStartBracket,
        #[error("A contract address must end with '>'")]
        MissingEndBracket,
        #[error("Failed to parse the index integer: {0}")]
        ParseIndexIntError(num::ParseIntError),
        #[error("Failed to parse the subindex integer: {0}")]
        ParseSubIndexIntError(num::ParseIntError),
        #[error("Missing comma separater between index and subindex")]
        NoComma,
    }

    /// Parse a [`ContractAddress`] from a string of the format
    /// "<index,subindex>" where index and subindex are [`ContractIndex`]
    /// and [`ContractSubIndex`], respectively.
    impl str::FromStr for ContractAddress {
        type Err = ContractAddressParseError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            if !s.starts_with('<') {
                return Err(ContractAddressParseError::MissingStartBracket);
            }
            if !s.ends_with('>') {
                return Err(ContractAddressParseError::MissingEndBracket);
            }
            let trimmed = &s[1..s.len() - 1];
            let (index, sub_index) =
                trimmed.split_once(',').ok_or(ContractAddressParseError::NoComma)?;
            let index =
                u64::from_str(index).map_err(ContractAddressParseError::ParseIndexIntError)?;
            let sub_index = u64::from_str(sub_index)
                .map_err(ContractAddressParseError::ParseSubIndexIntError)?;
            Ok(ContractAddress::new(index, sub_index))
        }
    }

    impl fmt::Display for ContractAddress {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "<{},{}>", self.index, self.subindex)
        }
    }

    /// Error that can occur when parsing an [`Address`] from a string.
    #[derive(Debug, thiserror::Error)]
    pub enum AddressParseError {
        #[error("Failed parsing a contract address: {0}")]
        ContractAddressError(#[from] ContractAddressParseError),
        #[error("Failed parsing an account address: {0}")]
        AccountAddressError(#[from] AccountAddressParseError),
    }

    /// Parse a string into an [`Address`], by first trying to parse the string
    /// as a contract address string. If this fails, because of missing
    /// bracket, it will try parsing it as an account address string.
    impl str::FromStr for Address {
        type Err = AddressParseError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let contract_result = ContractAddress::from_str(s);
            let address = match contract_result {
                Ok(contract) => contract.into(),
                Err(ContractAddressParseError::MissingStartBracket) => {
                    AccountAddress::from_str(s)?.into()
                }
                Err(err) => return Err(err.into()),
            };
            Ok(address)
        }
    }

    /// Display the [`Address`] using contract notation <index,subindex> for
    /// contract addresses and display for account addresses.
    impl fmt::Display for Address {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
            match self {
                Address::Account(a) => a.fmt(f),
                Address::Contract(c) => c.fmt(f),
            }
        }
    }

    impl fmt::Display for Amount {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let q = self.micro_ccd / 1_000_000;
            let r = self.micro_ccd % 1_000_000;
            if r == 0 {
                write!(f, "{}.0", q)
            } else {
                write!(f, "{}.{:06}", q, r)
            }
        }
    }

    struct Base58Visitor;

    impl<'de> Visitor<'de> for Base58Visitor {
        type Value = AccountAddress;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "A base58 string, version 1.")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            v.parse::<AccountAddress>().map_err(|_| de::Error::custom("Wrong Base58 version."))
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;
        use rand::Rng;

        #[test]
        fn test_account_address_to_string_parse_is_id() {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            let mut address_bytes = [0u8; 32];

            for _ in 0..1000 {
                rng.fill(&mut address_bytes);
                let address = AccountAddress(address_bytes);
                let parsed: AccountAddress =
                    address.to_string().parse().expect("Failed to parse address string.");
                assert_eq!(
                    parsed, address,
                    "Parsed account address differs from the expected address."
                );
            }
        }

        #[test]
        // test amount serialization is correct
        fn amount_serialization() {
            let mut rng = rand::thread_rng();
            for _ in 0..1000 {
                let micro_ccd = Amount::from_micro_ccd(rng.gen::<u64>());
                let s = micro_ccd.to_string();
                let parsed = s.parse::<Amount>();
                assert_eq!(Ok(micro_ccd), parsed, "Parsed amount differs from expected amount.");
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
                Ok(Amount::from_micro_ccd(123400u64)),
                "Leading zero is OK."
            );
            assert_eq!(
                "0.0".parse::<Amount>(),
                Ok(Amount::from_micro_ccd(0)),
                "Leading zero and zero after dot is OK."
            );
            assert_eq!(
                ".0".parse::<Amount>(),
                Err(AmountParseError::ExpectedDigit),
                "There should be at least one digit before a dot."
            );
            assert_eq!(
                "13".parse::<Amount>(),
                Ok(Amount::from_micro_ccd(13000000)),
                "No dot is needed."
            );
            assert_eq!(
                "".parse::<Amount>(),
                Err(AmountParseError::ExpectedMore),
                "Empty string is not a valid amount."
            );
        }

        #[test]
        fn test_exchange_rate_json() {
            let data = ExchangeRate {
                numerator:   1,
                denominator: 100,
            };
            assert_eq!(
                data,
                serde_json::from_str("{\"numerator\": 1, \"denominator\": 100}").unwrap(),
                "Exchange rate: case 1"
            );
            assert_eq!(
                data,
                serde_json::from_value(serde_json::from_str("0.01").unwrap()).unwrap(),
                "Exchange rate: case 2"
            );
            let data2 = ExchangeRate {
                numerator:   10,
                denominator: 1,
            };
            assert_eq!(data2, serde_json::from_str("10").unwrap(), "Exchange rate: case 3");
            let data3 = ExchangeRate {
                numerator:   17,
                denominator: 39,
            };
            assert_eq!(
                data3,
                serde_json::from_str(&serde_json::to_string(&data3).unwrap()).unwrap(),
                "Exchange rate: case 4"
            );
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;

    #[test]
    #[cfg(feature = "derive-serde")]
    fn test_json_serialization_and_deserialization_of_signature_ed25519() {
        let hex_string = "FC87CE9497CBD9DDDFB6CED31914D4FB93DD158EEFE7AF927AB31BB47178E61A33BEA52568475C161EC5B7A5E86B9F5F0274274192665D83197C4CE9A24C7C06";

        let signature = SignatureEd25519::from_str(&hex_string.to_string()).unwrap();

        // Serialize to JSON
        let serialized = serde_json::to_value(&signature).unwrap();

        // Deserialize from JSON
        let deserialized: SignatureEd25519 = serde_json::from_value(serialized).unwrap();

        assert_eq!(
            signature, deserialized,
            "Serializing and then deserializing should return the original value."
        );
    }

    #[test]
    #[cfg(feature = "derive-serde")]
    fn test_json_serialization_and_deserialization_of_signature_ecdsa_secp256k1() {
        let hex_string = "FC87CE9497CBD9DDDFB6CED31914D4FB93DD158EEFE7AF927AB31BB47178E61A33BEA52568475C161EC5B7A5E86B9F5F0274274192665D83197C4CE9A24C7C06";

        let signature = SignatureEcdsaSecp256k1::from_str(&hex_string.to_string()).unwrap();

        // Serialize to JSON
        let serialized = serde_json::to_value(&signature).unwrap();

        // Deserialize from JSON
        let deserialized: SignatureEcdsaSecp256k1 = serde_json::from_value(serialized).unwrap();

        assert_eq!(
            signature, deserialized,
            "Serializing and then deserializing should return the original value."
        );
    }

    #[test]
    #[cfg(feature = "derive-serde")]
    fn test_json_serialization_and_deserialization_of_signature() {
        let hex_string = "FC87CE9497CBD9DDDFB6CED31914D4FB93DD158EEFE7AF927AB31BB47178E61A33BEA52568475C161EC5B7A5E86B9F5F0274274192665D83197C4CE9A24C7C06";

        let signature =
            Signature::Ed25519(SignatureEd25519::from_str(&hex_string.to_string()).unwrap());

        // Serialize to JSON
        let serialized = serde_json::to_value(&signature).unwrap();

        // Deserialize from JSON
        let deserialized: Signature = serde_json::from_value(serialized).unwrap();

        assert_eq!(
            signature, deserialized,
            "Serializing and then deserializing should return the original value."
        );
    }

    #[test]
    #[cfg(feature = "derive-serde")]
    fn test_json_serialization_and_deserialization_of_credential_signature() {
        let hex_string = "FC87CE9497CBD9DDDFB6CED31914D4FB93DD158EEFE7AF927AB31BB47178E61A33BEA52568475C161EC5B7A5E86B9F5F0274274192665D83197C4CE9A24C7C06";

        let signature =
            Signature::Ed25519(SignatureEd25519::from_str(&hex_string.to_string()).unwrap());

        let mut sig_map = BTreeMap::new();
        sig_map.insert(0u8, signature);

        let credential_signature = CredentialSignatures {
            sigs: sig_map,
        };

        // Serialize to JSON
        let serialized = serde_json::to_value(&credential_signature).unwrap();

        // Deserialize from JSON
        let deserialized = serde_json::from_value(serialized).unwrap();

        assert_eq!(
            credential_signature, deserialized,
            "Serializing and then deserializing should return the original value."
        );
    }

    #[test]
    #[cfg(feature = "derive-serde")]
    fn test_json_serialization_and_deserialization_of_account_signature() {
        let hex_string = "FC87CE9497CBD9DDDFB6CED31914D4FB93DD158EEFE7AF927AB31BB47178E61A33BEA52568475C161EC5B7A5E86B9F5F0274274192665D83197C4CE9A24C7C06";

        let signature =
            Signature::Ed25519(SignatureEd25519::from_str(&hex_string.to_string()).unwrap());

        let mut sig_map = BTreeMap::new();
        sig_map.insert(0u8, signature);

        let credential_signature = CredentialSignatures {
            sigs: sig_map,
        };

        let mut sig_map_outer = BTreeMap::new();
        sig_map_outer.insert(0u8, credential_signature);

        let account_signature = AccountSignatures {
            sigs: sig_map_outer,
        };

        // Serialize to JSON
        let serialized = serde_json::to_value(&account_signature).unwrap();

        // Deserialize from JSON
        let deserialized = serde_json::from_value(serialized).unwrap();

        assert_eq!(
            account_signature, deserialized,
            "Serializing and then deserializing should return the original value."
        );
    }

    #[test]
    #[cfg(feature = "derive-serde")]
    fn test_given_millis_far_in_future_when_string_to_timestamp_then_map() {
        let millis = 100000001683508889u64;
        if let Ok(timestamp) = Timestamp::from_str(&millis.to_string()) {
            assert_eq!(timestamp.millis, millis);
        } else {
            assert!(false)
        };
    }

    #[test]
    #[cfg(feature = "derive-serde")]
    fn test_given_rfc3339_format_when_string_to_timestamp_then_map() {
        let datetime = "1970-01-01T00:00:00.042+00:00";
        if let Ok(timestamp) = Timestamp::from_str(datetime) {
            assert_eq!(timestamp.millis, 42);
        } else {
            assert!(false)
        };
    }

    #[test]
    #[cfg(feature = "derive-serde")]
    fn test_given_millis_far_in_future_when_timestamp_to_string_then_map_to_integer() {
        let timestamp = Timestamp::from_timestamp_millis(100000001683508889u64);
        assert_eq!(timestamp.to_string(), "100000001683508889");
    }

    #[test]
    #[cfg(feature = "derive-serde")]
    fn test_given_millis_not_far_in_future_when_timestamp_to_string_then_map_to_rfc3339_format() {
        let timestamp = Timestamp::from_timestamp_millis(42u64);
        assert_eq!(timestamp.to_string(), "1970-01-01T00:00:00.042+00:00");
    }

    #[test]
    fn test_duration_from_string_simple() {
        let duration = Duration::from_str("12d 1h 39s 3m 2h").unwrap();
        assert_eq!(
            duration.millis(),
            1000 * 60 * 60 * 24 * 12 // 12d
                + 1000 * 60 * 60     // 1h
                + 1000 * 39          // 39s
                + 1000 * 60 * 3      // 3m
                + 1000 * 60 * 60 * 2 // 2h
        )
    }

    #[test]
    fn test_valid_new_contract_name() {
        let contract_name = ContractName::new("init_contract");
        assert!(contract_name.is_ok());
        let contract_name = ContractName::new("init_01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234");
        assert!(contract_name.is_ok());
        let contract_name = ContractName::new("init_");
        assert!(contract_name.is_ok());
        let contract_name = ContractName::new(
            "init_!\"#$%&'()*+,-/0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\\
             ]^_`abcdefghijklmnopqrstuvwxyz{|}~",
        );
        assert!(contract_name.is_ok());
    }

    #[test]
    fn test_invalid_new_contract_name_missing_prefix() {
        let contract_name = ContractName::new("no_init_prefix");
        assert_eq!(contract_name, Err(NewContractNameError::MissingInitPrefix));
        let contract_name = ContractName::new("init");
        assert_eq!(contract_name, Err(NewContractNameError::MissingInitPrefix))
    }

    #[test]
    fn test_invalid_new_contract_name_too_long() {
        // Is too long when the prefix is included.
        let long_name = format!("init_{}", "c".repeat(constants::MAX_FUNC_NAME_SIZE));
        let contract_name = ContractName::new(long_name.as_str());
        assert_eq!(contract_name, Err(NewContractNameError::TooLong));
        // One character too long.
        let long_name = "init_012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345";
        let contract_name = ContractName::new(long_name);
        assert_eq!(contract_name, Err(NewContractNameError::TooLong))
    }

    #[test]
    fn test_getters_for_contract_name() {
        let expected_chain_name = "init_contract";
        let contract_name = ContractName::new(expected_chain_name).unwrap();
        assert_eq!(contract_name.get_chain_name(), expected_chain_name);
    }

    #[test]
    fn test_valid_new_owned_contract_name() {
        let contract_name = OwnedContractName::new("init_contract".to_string());
        assert!(contract_name.is_ok());
        let contract_name = OwnedContractName::new("init_01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234".to_string());
        assert!(contract_name.is_ok());
        let contract_name = OwnedContractName::new("init_".to_string());
        assert!(contract_name.is_ok());
        let contract_name = OwnedContractName::new(
            "init_!\"#$%&'()*+,-/0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\\
             ]^_`abcdefghijklmnopqrstuvwxyz{|}~"
                .to_string(),
        );
        assert!(contract_name.is_ok())
    }

    #[test]
    fn test_invalid_new_owned_contract_name_missing_prefix() {
        let contract_name = OwnedContractName::new("no_init_prefix".to_string());
        assert_eq!(contract_name, Err(NewContractNameError::MissingInitPrefix));
        let contract_name = OwnedContractName::new("init".to_string());
        assert_eq!(contract_name, Err(NewContractNameError::MissingInitPrefix))
    }

    #[test]
    fn test_invalid_new_owned_contract_name_too_long() {
        // Is too long when the prefix is included.
        let long_name = format!("init_{}", "c".repeat(constants::MAX_FUNC_NAME_SIZE));
        let contract_name = OwnedContractName::new(long_name);
        assert_eq!(contract_name, Err(NewContractNameError::TooLong));
        // One character too long.
        // One character too long.
        let long_name = "init_012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345";
        let contract_name = OwnedContractName::new(long_name.to_string());
        assert_eq!(contract_name, Err(NewContractNameError::TooLong))
    }

    #[test]
    fn test_getters_for_owned_contract_name() {
        let contract_name = ContractName::new("init_contract").unwrap();
        assert_eq!(contract_name.get_chain_name(), "init_contract");
        assert_eq!(contract_name.contract_name(), "contract");
    }

    #[test]
    fn test_valid_new_receive_name() {
        let receive_name = ReceiveName::new("contract.receive");
        assert!(receive_name.is_ok());
        let receive_name = ReceiveName::new(".012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678");
        assert!(receive_name.is_ok());
        let receive_name = ReceiveName::new(".");
        assert!(receive_name.is_ok());
        let receive_name = ReceiveName::new(
            "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\\
             ]^_`abcdefghijklmnopqrstuvwxyz{|}~",
        );
        assert!(receive_name.is_ok())
    }

    #[test]
    fn test_invalid_new_receive_name_missing_dot() {
        let receive_name = ReceiveName::new("no_dot_separator");
        assert_eq!(receive_name, Err(NewReceiveNameError::MissingDotSeparator))
    }

    #[test]
    fn test_invalid_new_receive_name_too_long() {
        let long_str = "c".repeat(constants::MAX_FUNC_NAME_SIZE);
        let long_name = format!("{}.{}", long_str, long_str);
        let contract_name = ReceiveName::new(long_name.as_str());
        assert_eq!(contract_name, Err(NewReceiveNameError::TooLong))
    }

    #[test]
    fn test_invalid_new_receive_name_one_too_long() {
        let long_name = ".0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789";
        let contract_name = ReceiveName::new(long_name);
        assert_eq!(contract_name, Err(NewReceiveNameError::TooLong))
    }

    #[test]
    fn test_invalid_new_receive_name_invalid_character() {
        let contract_name = ReceiveName::new("contract. receive");
        assert_eq!(contract_name, Err(NewReceiveNameError::InvalidCharacters))
    }

    #[test]
    fn test_getters_for_receive_name() {
        let expected_chain_name = "contract.receive";
        let receive_name = ReceiveName::new(expected_chain_name).unwrap();
        assert_eq!(receive_name.get_chain_name(), expected_chain_name);
    }

    #[test]
    fn test_valid_new_owned_receive_name() {
        let receive_name = OwnedReceiveName::new("contract.receive".to_string());
        assert!(receive_name.is_ok());
        let receive_name = OwnedReceiveName::new(".012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678".to_string());
        assert!(receive_name.is_ok());
        let receive_name = OwnedReceiveName::new(".".to_string());
        assert!(receive_name.is_ok());
        let receive_name = OwnedReceiveName::new(
            "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\\
             ]^_`abcdefghijklmnopqrstuvwxyz{|}~"
                .to_string(),
        );
        assert!(receive_name.is_ok())
    }

    #[test]
    fn test_invalid_new_owned_receive_name_missing_dot() {
        let receive_name = OwnedReceiveName::new("no_dot_separator".to_string());
        assert_eq!(receive_name, Err(NewReceiveNameError::MissingDotSeparator))
    }

    #[test]
    fn test_invalid_new_owned_receive_name_too_long() {
        let long_str = "c".repeat(constants::MAX_FUNC_NAME_SIZE);
        let long_name = format!("{}.{}", long_str, long_str);
        let contract_name = OwnedReceiveName::new(long_name);
        assert_eq!(contract_name, Err(NewReceiveNameError::TooLong))
    }

    #[test]
    fn test_invalid_new_owned_receive_name_one_too_long() {
        let long_name = ".0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789";
        let contract_name = OwnedReceiveName::new(long_name.to_string());
        assert_eq!(contract_name, Err(NewReceiveNameError::TooLong))
    }

    #[test]
    fn test_invalid_new_owned_receive_name_invalid_character() {
        let contract_name = OwnedReceiveName::new("contract. receive".to_string());
        assert_eq!(contract_name, Err(NewReceiveNameError::InvalidCharacters))
    }

    #[test]
    fn test_getters_for_owned_receive_name() {
        let receive_name = OwnedReceiveName::new("contract.receive".to_string()).unwrap();
        assert_eq!(receive_name.as_receive_name().get_chain_name(), "contract.receive");
        assert_eq!(receive_name.as_receive_name().contract_name(), "contract");
        assert_eq!(
            receive_name.as_receive_name().entrypoint_name(),
            EntrypointName::new_unchecked("receive")
        );
    }

    #[test]
    fn test_valid_new_entrypoint_name() {
        let entrypoint_name = EntrypointName::new("entrypoint");
        assert!(entrypoint_name.is_ok());
        let entrypoint_name = EntrypointName::new("012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678");
        assert!(entrypoint_name.is_ok());
        let entrypoint_name = EntrypointName::new("");
        assert!(entrypoint_name.is_ok());
        let entrypoint_name = EntrypointName::new(
            "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\\
             ]^_`abcdefghijklmnopqrstuvwxyz{|}~",
        );
        assert!(entrypoint_name.is_ok())
    }

    #[test]
    fn test_invalid_new_entrypoint_name_too_long() {
        let long_name = "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789";
        let entrypoint_name = EntrypointName::new(long_name);
        assert_eq!(entrypoint_name, Err(NewReceiveNameError::TooLong))
    }

    #[test]
    fn test_invalid_new_entrypoint_name_invalid_character() {
        let entrypoint_name = EntrypointName::new("entry point");
        assert_eq!(entrypoint_name, Err(NewReceiveNameError::InvalidCharacters))
    }

    #[test]
    fn test_valid_owned_entrypoint_name() {
        let entrypoint_name = OwnedEntrypointName::new("entrypoint".to_string());
        assert!(entrypoint_name.is_ok());
        let entrypoint_name = OwnedEntrypointName::new("012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678".to_string());
        assert!(entrypoint_name.is_ok());
        let entrypoint_name = OwnedEntrypointName::new("".to_string());
        assert!(entrypoint_name.is_ok());
        let entrypoint_name = OwnedEntrypointName::new(
            "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\\
             ]^_`abcdefghijklmnopqrstuvwxyz{|}~"
                .to_string(),
        );
        assert!(entrypoint_name.is_ok())
    }

    #[test]
    fn test_invalid_owned_entrypoint_name_too_long() {
        let long_name = "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789";
        let entrypoint_name = OwnedEntrypointName::new(long_name.to_string());
        assert_eq!(entrypoint_name, Err(NewReceiveNameError::TooLong))
    }

    #[test]
    fn test_invalid_owned_entrypoint_name_invalid_character() {
        let entrypoint_name = OwnedEntrypointName::new("entry point".to_string());
        assert_eq!(entrypoint_name, Err(NewReceiveNameError::InvalidCharacters))
    }

    #[test]
    fn test_attribute_value_valid_length() {
        let data = [0u8; 1];
        let res = AttributeValue::new(&data[..]);
        assert!(res.is_ok());
    }

    #[test]
    fn test_attribute_value_max_length() {
        let data = [0u8; 31];
        let res = AttributeValue::new(&data[..]);
        assert!(res.is_ok());
    }

    #[test]
    fn test_attribute_value_invalid_length() {
        let data = [0u8; 35];
        let res = AttributeValue::new(&data[..]);
        assert_eq!(res, Err(NewAttributeValueError::TooLong(35)));
    }
}
