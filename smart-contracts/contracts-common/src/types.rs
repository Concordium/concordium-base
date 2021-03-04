#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};
#[cfg(not(feature = "std"))]
use core::{convert, fmt, iter, ops, str};
#[cfg(feature = "std")]
use std::{convert, fmt, iter, ops, str};

/// Size of an account address when serialized in binary.
/// NB: This is different from the Base58 representation.
pub const ACCOUNT_ADDRESS_SIZE: usize = 32;

#[cfg(feature = "derive-serde")]
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};

/// The type of amounts on the chain
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Amount {
    pub micro_gtu: u64,
}

#[cfg(feature = "derive-serde")]
impl SerdeSerialize for Amount {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.micro_gtu.to_string())
    }
}

#[cfg(feature = "derive-serde")]
impl<'de> SerdeDeserialize<'de> for Amount {
    fn deserialize<D: serde::de::Deserializer<'de>>(des: D) -> Result<Self, D::Error> {
        let s = String::deserialize(des)?;
        let micro_gtu = s.parse::<u64>().map_err(|e| serde::de::Error::custom(format!("{}", e)))?;
        Ok(Amount {
            micro_gtu,
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

/// Parse from string in GTU units. The input string must be of the form
/// `n[.m]` where `n` and `m` are both digits. The notation `[.m]` indicates
/// that that part is optional.
///
/// - if `n` starts with 0 then it must be 0l
/// - `m` can have at most 6 digits, and must have at least 1
/// - both `n` and `m` must be non-negative.
impl str::FromStr for Amount {
    type Err = AmountParseError;

    fn from_str(v: &str) -> Result<Self, Self::Err> {
        let mut micro_gtu: u64 = 0;
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
                            micro_gtu = u64::from(d);
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
                        micro_gtu = micro_gtu.checked_mul(10).ok_or(AmountParseError::Overflow)?;
                        micro_gtu = micro_gtu
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
                        micro_gtu = micro_gtu.checked_mul(10).ok_or(AmountParseError::Overflow)?;
                        micro_gtu = micro_gtu
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
            micro_gtu = micro_gtu.checked_mul(10).ok_or(AmountParseError::Overflow)?;
        }
        Ok(Amount {
            micro_gtu,
        })
    }
}

impl Amount {
    /// Create amount from a number of microGTU
    #[inline(always)]
    pub fn from_micro_gtu(micro_gtu: u64) -> Amount {
        Amount {
            micro_gtu,
        }
    }

    /// Create amount from a number of GTU
    #[inline(always)]
    pub fn from_gtu(gtu: u64) -> Amount {
        Amount {
            micro_gtu: gtu * 1000000,
        }
    }

    /// Create zero amount
    #[inline(always)]
    pub fn zero() -> Amount {
        Amount {
            micro_gtu: 0,
        }
    }

    /// Add a number of micro GTU to an amount
    #[inline(always)]
    pub fn add_micro_gtu(self, micro_gtu: u64) -> Amount {
        Amount {
            micro_gtu: self.micro_gtu + micro_gtu,
        }
    }

    /// Checked addition. Adds another amount and return None if overflow
    /// occurred
    #[inline(always)]
    pub fn checked_add(self, other: Amount) -> Option<Amount> {
        self.micro_gtu.checked_add(other.micro_gtu).map(Amount::from_micro_gtu)
    }

    /// Add a number of GTU to an amount
    #[inline(always)]
    pub fn add_gtu(self, gtu: u64) -> Amount {
        Amount {
            micro_gtu: self.micro_gtu + gtu * 1000000,
        }
    }

    /// Subtract a number of micro GTU to an amount
    #[inline(always)]
    pub fn subtract_micro_gtu(self, micro_gtu: u64) -> Amount {
        Amount {
            micro_gtu: self.micro_gtu - micro_gtu,
        }
    }

    /// Subtract a number of GTU to an amount
    #[inline(always)]
    pub fn subtract_gtu(self, gtu: u64) -> Amount {
        Amount {
            micro_gtu: self.micro_gtu - gtu * 1000000,
        }
    }

    /// Calculates the quotient and remainder of integer division
    #[inline(always)]
    pub fn quotient_remainder(self, denominator: u64) -> (Amount, Amount) {
        let div = Amount {
            micro_gtu: self.micro_gtu / denominator,
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
            micro_gtu: self.micro_gtu * other,
        }
    }
}

impl ops::Mul<Amount> for u64 {
    type Output = Amount;

    #[inline(always)]
    fn mul(self, other: Amount) -> Self::Output {
        Amount {
            micro_gtu: self * other.micro_gtu,
        }
    }
}

impl ops::Add<Amount> for Amount {
    type Output = Self;

    #[inline(always)]
    fn add(self, other: Amount) -> Self::Output {
        Amount {
            micro_gtu: self.micro_gtu + other.micro_gtu,
        }
    }
}

impl ops::Sub<Amount> for Amount {
    type Output = Self;

    #[inline(always)]
    fn sub(self, other: Amount) -> Self::Output {
        Amount {
            micro_gtu: self.micro_gtu - other.micro_gtu,
        }
    }
}

impl ops::Rem<u64> for Amount {
    type Output = Self;

    #[inline(always)]
    fn rem(self, other: u64) -> Self::Output {
        Amount {
            micro_gtu: self.micro_gtu % other,
        }
    }
}

impl iter::Sum for Amount {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Amount::from_micro_gtu(0), ops::Add::add)
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

/// Timestamp represented as milliseconds since unix epoch.
///
/// Timestamps from before January 1st 1970 at 00:00 are not supported.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp {
    /// Milliseconds since unix epoch.
    pub(crate) milliseconds: u64,
}

impl Timestamp {
    /// Construct timestamp from milliseconds since unix epoch.
    #[inline(always)]
    pub fn from_timestamp_millis(milliseconds: u64) -> Self {
        Self {
            milliseconds,
        }
    }

    /// Milliseconds since the UNIX epoch.
    #[inline(always)]
    pub fn timestamp_millis(&self) -> u64 { self.milliseconds }

    /// Add duration to the timestamp. Returns `None` if the resulting timestamp
    /// is not representable, i.e., too far in the future.
    #[inline(always)]
    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        self.milliseconds.checked_add(duration.milliseconds).map(Self::from_timestamp_millis)
    }

    /// Subtract duration from the timestamp. Returns `None` instead of
    /// overflowing if the resulting timestamp would be before the Unix
    /// epoch.
    #[inline(always)]
    pub fn checked_sub(self, duration: Duration) -> Option<Self> {
        self.milliseconds.checked_sub(duration.milliseconds).map(Self::from_timestamp_millis)
    }

    /// Compute the duration between the self and another timestamp.
    /// The duration is always positive, and is the difference between
    /// the the more recent timestamp and the one further in the past.
    #[inline(always)]
    pub fn duration_between(self, other: Timestamp) -> Duration {
        let millis = if self >= other {
            self.milliseconds - other.milliseconds
        } else {
            other.milliseconds - self.milliseconds
        };
        Duration::from_millis(millis)
    }

    /// Compute duration since a given timestamp. Returns `None` if given time
    /// is in the future compared to self.
    #[inline(always)]
    pub fn duration_since(self, before: Timestamp) -> Option<Duration> {
        self.milliseconds.checked_sub(before.milliseconds).map(Duration::from_millis)
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
/// The FromStr parses the time according to RFC3339.
impl str::FromStr for Timestamp {
    type Err = ParseTimestampError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use convert::TryInto;
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
/// The display implementation displays the timestamp according to RFC3339
/// format in the UTC time zone.
impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use chrono::offset::TimeZone;
        let time = self.timestamp_millis() as i64;
        let date = chrono::Utc.timestamp_millis(time);
        write!(f, "{}", date.to_rfc3339())
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
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Duration {
    pub(crate) milliseconds: u64,
}

impl Duration {
    /// Construct duration from milliseconds.
    #[inline(always)]
    pub fn from_millis(milliseconds: u64) -> Self {
        Self {
            milliseconds,
        }
    }

    /// Construct duration from seconds.
    #[inline(always)]
    pub fn from_seconds(seconds: u64) -> Self { Self::from_millis(seconds * 1000) }

    /// Construct duration from minutes.
    #[inline(always)]
    pub fn from_minutes(minutes: u64) -> Self { Self::from_millis(minutes * 1000 * 60) }

    /// Construct duration from hours.
    #[inline(always)]
    pub fn from_hours(hours: u64) -> Self { Self::from_millis(hours * 1000 * 60 * 60) }

    /// Construct duration from days.
    #[inline(always)]
    pub fn from_days(days: u64) -> Self { Self::from_millis(days * 1000 * 60 * 60 * 24) }

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
/// ```ignore
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

/// Address of an account, as raw bytes.
#[derive(Eq, PartialEq, Copy, Clone, PartialOrd, Ord, Debug)]
pub struct AccountAddress(pub [u8; ACCOUNT_ADDRESS_SIZE]);

impl convert::AsRef<[u8; 32]> for AccountAddress {
    fn as_ref(&self) -> &[u8; 32] { &self.0 }
}

impl convert::AsRef<[u8]> for AccountAddress {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

/// Address of a contract.
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
#[cfg_attr(feature = "derive-serde", derive(SerdeSerialize, SerdeDeserialize))]
pub struct ContractAddress {
    pub index:    u64,
    pub subindex: u64,
}

/// Either an address of an account, or contract.
#[cfg_attr(
    feature = "derive-serde",
    derive(SerdeSerialize, SerdeDeserialize),
    serde(tag = "type", content = "address", rename_all = "lowercase")
)]
#[derive(PartialEq, Eq, Copy, Clone)]
pub enum Address {
    Account(AccountAddress),
    Contract(ContractAddress),
}

/// A contract name. Expected format: "init_<contract_name>".
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub struct ContractName<'a>(&'a str);

impl<'a> ContractName<'a> {
    /// Create a new ContractName. Expected format: "init_<contract_name>".
    #[inline(always)]
    pub fn new(name: &'a str) -> Self { ContractName(name) }

    /// Get contract name used on chain: "init_<contract_name>".
    #[inline(always)]
    pub fn get_chain_name(&self) -> &str { self.0 }
}

/// A contract name (owned version). Expected format: "init_<contract_name>".
#[derive(Eq, PartialEq, Debug)]
pub struct OwnedContractName(String);

impl OwnedContractName {
    /// Create a new OwnedContractName. Expected format: "init_<contract_name>".
    #[inline(always)]
    pub fn new(name: String) -> Self { OwnedContractName(name) }

    /// Get contract name used on chain: "init_<contract_name>".
    #[inline(always)]
    pub fn get_chain_name(&self) -> &String { &self.0 }

    /// Try to extract the contract name by removing the "init_" prefix.
    #[inline(always)]
    pub fn contract_name(&self) -> Option<&str> { self.get_chain_name().strip_prefix("init_") }

    /// Convert to ContractName by reference.
    #[inline(always)]
    pub fn as_ref(&self) -> ContractName { ContractName(self.get_chain_name().as_str()) }
}

/// A receive name. Expected format: "<contract_name>.<func_name>".
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub struct ReceiveName<'a>(&'a str);

impl<'a> ReceiveName<'a> {
    /// Create a new ReceiveName. Expected format:
    /// "<contract_name>.<func_name>".
    pub fn new(name: &'a str) -> Self { ReceiveName(name) }

    /// Get receive name used on chain: "<contract_name>.<func_name>".
    pub fn get_chain_name(&self) -> &str { self.0 }
}

/// A receive name (owned version). Expected format:
/// "<contract_name>.<func_name>".
#[derive(Eq, PartialEq, Debug)]
pub struct OwnedReceiveName(String);

impl OwnedReceiveName {
    /// Create a new OwnedReceiveName. Expected format:
    /// "<contract_name>.<func_name>".
    pub fn new(name: String) -> Self { OwnedReceiveName(name) }

    /// Get receive name used on chain: "<contract_name>.<func_name>".
    pub fn get_chain_name(&self) -> &String { &self.0 }

    /// Try to extract the contract name by splitting at the first dot.
    pub fn contract_name(&self) -> Option<&str> { self.get_name_parts().map(|parts| parts.0) }

    /// Try to extract the func name by splitting at the first dot.
    pub fn func_name(&self) -> Option<&str> { self.get_name_parts().map(|parts| parts.1) }

    /// Try to extract (contract_name, func_name) by splitting at the first dot.
    fn get_name_parts(&self) -> Option<(&str, &str)> {
        let mut splitter = self.get_chain_name().splitn(2, '.');
        let contract = splitter.next()?;
        let func = splitter.next()?;
        Some((contract, func))
    }

    /// Convert to ReceiveName by reference.
    pub fn as_ref(&self) -> ReceiveName { ReceiveName(self.0.as_str()) }
}

/// Genesis block has slot number 0, and otherwise it is always the case that a
/// parent of a block has a slot number strictly less than the block itself.
/// However in contrast to `BlockHeight`, slot numbers are not strictly
/// sequential, there will be gaps.
pub type SlotNumber = u64;

/// Height of the block. Height of the genesis block is 0, and otherwise it is
/// always the case that a block has height one more than its parent.
pub type BlockHeight = u64;

/// Finalized height. In the context of chain metadata this is the height of the
/// block which is explicitly recorded as the last finalized block in the block
/// under consideration.
pub type FinalizedHeight = u64;

/// Time at the beginning of the current slot, in miliseconds since unix epoch.
pub type SlotTime = Timestamp;

/// Chain metadata accessible to both receive and init methods.
#[cfg_attr(
    feature = "derive-serde",
    derive(SerdeSerialize, SerdeDeserialize),
    serde(rename_all = "camelCase")
)]
pub struct ChainMetadata {
    pub slot_time: SlotTime,
}

/// Add offset tracking inside a data structure.
pub struct Cursor<T> {
    pub offset: usize,
    pub data:   T,
}

/// Tag of an attribute. See the module [attributes](./attributes/index.html)
/// for the currently supported attributes.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct AttributeTag(pub u8);

/// A borrowed attribute value. The slice will have at most 31 bytes.
/// The meaning of the bytes is dependent on the type of the attribute.
pub type AttributeValue<'a> = &'a [u8];

/// An owned counterpart of `AttributeValue`, more convenient for testing.
pub type OwnedAttributeValue = Vec<u8>;

/// A policy with a vector of attributes, fully allocated and owned.
/// This is in contrast to a policy which is lazily read from a read source.
/// The latter is useful for efficiency, this type is more useful for testing
/// since the values are easier to construct.
pub type OwnedPolicy = Policy<Vec<(AttributeTag, OwnedAttributeValue)>>;

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
    pub created_at: Timestamp,
    /// Beginning of the month where the identity is __no longer valid__.
    pub valid_to: Timestamp,
    /// List of attributes, in ascending order of the tag.
    pub items: Attributes,
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
                let dt = chrono::naive::NaiveDate::from_ymd(i32::from(year), u32::from(month), 1)
                    .and_hms(0, 0, 0);
                let timestamp: u64 = dt.timestamp_millis().try_into().map_err(|_| {
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
                                    items.push((tag, value_string.into_bytes()))
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
/// enum MyCustomReceiveError {
///     Parsing
/// }
///
/// impl From<ParseError> for MyCustomReceiveError {
///     fn from(_: ParseError) -> Self { MyCustomReceiveError::ParseParams }
/// }
///
/// #[receive(contract = "mycontract", name="some_receive_name")]
/// fn contract_receive<R: HasReceiveContext<()>, L: HasLogger, A: HasActions>(
///     ctx: &R,
///     receive_amount: Amount,
///     logger: &mut L,
///     state: &mut State,
/// ) -> Result<A, MyCustomReceiveError> {
///     ...
///     let msg: MyParameterType = ctx.parameter_cursor().get()?;
///     ...
/// }
/// ```
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ParseError {}

/// A type alias used to indicate that the value is a result
/// of parsing from binary via the `Serial` instance.
pub type ParseResult<A> = Result<A, ParseError>;

#[cfg(feature = "derive-serde")]
mod serde_impl {
    // FIXME: This is duplicated from crypto/id/types.
    use super::*;
    use base58check::*;
    use serde::{de, de::Visitor, Deserializer, Serializer};
    use std::fmt;

    // Parse from string assuming base58 check encoding.
    impl str::FromStr for AccountAddress {
        type Err = ();

        fn from_str(v: &str) -> Result<Self, Self::Err> {
            let (version, body) = v.from_base58check().map_err(|_| ())?;
            if version == 1 && body.len() == ACCOUNT_ADDRESS_SIZE {
                let mut buf = [0u8; ACCOUNT_ADDRESS_SIZE];
                buf.copy_from_slice(&body);
                Ok(AccountAddress(buf))
            } else {
                Err(())
            }
        }
    }

    impl fmt::Display for AccountAddress {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0.to_base58check(1))
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

    impl fmt::Display for ContractAddress {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "<{},{}>", self.index, self.subindex)
        }
    }

    impl fmt::Display for Amount {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let q = self.micro_gtu / 1000000;
            let r = self.micro_gtu % 1000000;
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
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;

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
}
