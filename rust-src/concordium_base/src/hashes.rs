//! Different types of hashes based on SHA256.

use crate::constants::*;
use crypto_common::{Deserial, SerdeDeserialize, SerdeSerialize, Serial};
use std::{
    convert::{TryFrom, TryInto},
    fmt,
    marker::PhantomData,
    ops::Deref,
    str::FromStr,
};
use thiserror::Error;

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, SerdeSerialize)]
#[serde(into = "String")]
/// A general wrapper around Sha256 hash. This is used to add type safety to
/// a hash that is used in different context. The underlying value is always the
/// same, but the phantom type variable makes it impossible to mistakenly misuse
/// the hashes.
pub struct HashBytes<Purpose> {
    pub(crate) bytes: [u8; SHA256 as usize],
    #[serde(skip)] // use default when deserializing
    _phantom:         PhantomData<Purpose>,
}

impl<Purpose> Clone for HashBytes<Purpose> {
    fn clone(&self) -> Self {
        Self {
            bytes:    self.bytes,
            _phantom: Default::default(),
        }
    }
}

impl<Purpose> Serial for HashBytes<Purpose> {
    fn serial<B: crypto_common::Buffer>(&self, out: &mut B) {
        out.write_all(&self.bytes)
            .expect("Writing to buffer always succeeds.");
    }
}

impl<Purpose> Deserial for HashBytes<Purpose> {
    fn deserial<R: crypto_common::ReadBytesExt>(
        source: &mut R,
    ) -> crypto_common::ParseResult<Self> {
        let mut bytes = [0u8; SHA256 as usize];
        source.read_exact(&mut bytes)?;
        Ok(HashBytes {
            bytes,
            _phantom: Default::default(),
        })
    }
}

#[doc(hidden)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
/// Used as a phantom type to indicate a hash is a block hash.
pub enum BlockMarker {}

#[doc(hidden)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
/// Used as a phantom type to indicate a hash is a transaction hash.
pub enum TransactionMarker {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
/// Used as a phantom type to indicate a hash is a transaction sign hash, i.e.,
/// the hash that is signed.
pub enum TransactionSignMarker {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
/// Used as a phantom type to indicate a hash is an update sign hash, i.e.,
/// the hash that is signed to make an update instruction.
pub enum UpdateSignMarker {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
/// Used as a phantom type to indicate a hash is a block state hash.
pub enum StateMarker {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
/// Used as a phantom type to indicate a hash is a hash with no specific
/// meaning.
pub enum PureHashMarker {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
/// Used as a phantom type to indicate a hash is a hash is a leadership election
/// nonce.
pub enum ElectionNonceMarker {}

/// The leadership election nonce is an unpredictable value updated once an
/// epoch to make sure that bakers cannot predict too far in the future when
/// they will win blocks.
pub type LeadershipElectionNonce = HashBytes<ElectionNonceMarker>;
/// Hash of a block.
pub type BlockHash = HashBytes<BlockMarker>;
/// Hash of a transaction.
pub type TransactionHash = HashBytes<TransactionMarker>;
/// Hash that is signed by the account holder's keys to make a transaction
/// signature.
pub type TransactionSignHash = HashBytes<TransactionSignMarker>;
/// Hash that is signed by the governance keys to make an update instruction
/// signature.
pub type UpdateSignHash = HashBytes<UpdateSignMarker>;
/// Hash of the block state that is included in a block.
pub type StateHash = HashBytes<StateMarker>;

/// A Sha256 with no specific meaning.
pub type Hash = HashBytes<PureHashMarker>;

#[derive(Debug, Error)]
/// Possible errors when converting from a string to any kind of hash.
/// String representation of hashes is as base 16.
pub enum HashFromStrError {
    #[error("Not a valid hex string: {0}")]
    HexDecodeError(#[from] hex::FromHexError),
    #[error("Incorrect length, found {found}, expected 32.")]
    IncorrectLength {
        // length that was found
        found: usize,
    },
}

impl<Purpose> HashBytes<Purpose> {
    /// Construct HashBytes from a slice.
    pub fn new(bytes: [u8; SHA256 as usize]) -> Self {
        Self {
            bytes,
            _phantom: Default::default(),
        }
    }
}

impl<Purpose> From<[u8; 32]> for HashBytes<Purpose> {
    fn from(array: [u8; 32]) -> Self { Self::new(array) }
}

impl<Purpose> Deref for HashBytes<Purpose> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target { &self.bytes }
}

impl<Purpose> AsRef<[u8]> for HashBytes<Purpose> {
    fn as_ref(&self) -> &[u8] { self }
}

impl<Purpose> FromStr for HashBytes<Purpose> {
    type Err = HashFromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex_decoded = hex::decode(s)?;
        let found = hex_decoded.len();
        let bytes = hex_decoded
            .try_into()
            .map_err(|_| HashFromStrError::IncorrectLength { found })?;
        Ok(HashBytes::new(bytes))
    }
}

impl<Purpose> TryFrom<&str> for HashBytes<Purpose> {
    type Error = HashFromStrError;

    fn try_from(value: &str) -> Result<Self, Self::Error> { Self::from_str(value) }
}

#[derive(Error, Debug)]
#[error("Slice has incompatible length with a hash.")]
pub struct IncorrectLength;

impl<Purpose> TryFrom<&[u8]> for HashBytes<Purpose> {
    type Error = IncorrectLength;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; SHA256 as usize] = value.try_into().map_err(|_| IncorrectLength)?;
        Ok(bytes.into())
    }
}

// NB: Using try_from = &str does not work correctly for HashBytes
// SerdeDeserialize instance due to ownership issues for the JSON format. Hence
// we implement this manually. The issue is that a &'a str cannot be
// deserialized from a String for arbitrary 'a, and this is needed when
// parsing with serde_json::from_value via &'a str.
impl<'de, Purpose> SerdeDeserialize<'de> for HashBytes<Purpose> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>, {
        struct HashBytesVisitor<Purpose> {
            _phantom: PhantomData<Purpose>,
        }

        impl<'de, Purpose> serde::de::Visitor<'de> for HashBytesVisitor<Purpose> {
            type Value = HashBytes<Purpose>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "A hex string.")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                HashBytes::try_from(v).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(HashBytesVisitor {
            _phantom: Default::default(),
        })
    }
}

impl<Purpose> From<HashBytes<Purpose>> for String {
    fn from(x: HashBytes<Purpose>) -> String { x.to_string() }
}

// a short, 8-character beginning of the SHA
impl<Purpose> fmt::Debug for HashBytes<Purpose> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.iter().take(4) {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

// the full SHA256 in hex
impl<Purpose> fmt::Display for HashBytes<Purpose> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.iter() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}
