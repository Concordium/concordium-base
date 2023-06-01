//! Different types of hashes based on SHA256.

use crate::constants::SHA256;
#[cfg(all(feature = "derive-serde", not(feature = "std")))]
use core::str::FromStr;
#[cfg(not(feature = "std"))]
use core::{
    convert::{TryFrom, TryInto},
    fmt, hash,
    marker::PhantomData,
    ops::Deref,
};
#[cfg(feature = "derive-serde")]
use serde;
#[cfg(all(feature = "derive-serde", feature = "std"))]
use std::str::FromStr;
#[cfg(feature = "std")]
use std::{
    convert::{TryFrom, TryInto},
    fmt, hash,
    marker::PhantomData,
    ops::Deref,
};

#[derive(Ord, PartialOrd, Copy)]
#[cfg_attr(feature = "derive-serde", derive(serde::Serialize))]
#[cfg_attr(feature = "derive-serde", serde(into = "String"))]
#[repr(transparent)]
/// A general wrapper around Sha256 hash. This is used to add type safety to
/// a hash that is used in different context. The underlying value is always the
/// same, but the phantom type variable makes it impossible to mistakenly misuse
/// the hashes.
pub struct HashBytes<Purpose> {
    pub bytes: [u8; SHA256],
    #[cfg_attr(feature = "derive-serde", serde(skip))] // use default when deserializing
    _phantom: PhantomData<Purpose>,
}

impl<Purpose> PartialEq for HashBytes<Purpose> {
    fn eq(&self, other: &Self) -> bool { self.bytes == other.bytes }
}

impl<Purpose> Eq for HashBytes<Purpose> {}

impl<Purpose> hash::Hash for HashBytes<Purpose> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) { self.bytes.hash(state); }
}

impl<Purpose> Clone for HashBytes<Purpose> {
    fn clone(&self) -> Self {
        Self {
            bytes:    self.bytes,
            _phantom: Default::default(),
        }
    }
}

impl<Purpose> crate::Serial for HashBytes<Purpose> {
    fn serial<W: crate::Write>(&self, out: &mut W) -> Result<(), W::Err> {
        out.write_all(self.as_ref())
    }
}

impl<Purpose> crate::Deserial for HashBytes<Purpose> {
    fn deserial<R: crate::Read>(source: &mut R) -> crate::ParseResult<Self> {
        let bytes: [u8; 32] = <[u8; 32]>::deserial(source)?;
        Ok(bytes.into())
    }
}

#[doc(hidden)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
/// Used as a phantom type to indicate a hash is a block hash.
pub enum ModuleReferenceMarker {}

/// A reference to a smart contract module deployed on the chain.
pub type ModuleReference = HashBytes<ModuleReferenceMarker>;

#[cfg(feature = "derive-serde")]
#[derive(Debug, thiserror::Error)]
/// Possible errors when converting from a string to any kind of hash.
/// String representation of hashes is as base 16.
pub enum HashFromStrError {
    #[cfg_attr(feature = "derive-serde", error("Not a valid hex string: {0}"))]
    HexDecodeError(#[from] hex::FromHexError),
    #[cfg_attr(feature = "derive-serde", error("Incorrect length, found {found}, expected 32."))]
    IncorrectLength {
        // length that was found
        found: usize,
    },
}

impl<Purpose> HashBytes<Purpose> {
    /// Construct [`HashBytes`] from a slice.
    pub fn new(bytes: [u8; SHA256]) -> Self {
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

#[cfg(feature = "derive-serde")]
impl<Purpose> FromStr for HashBytes<Purpose> {
    type Err = HashFromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex_decoded = hex::decode(s)?;
        let found = hex_decoded.len();
        let bytes = hex_decoded.try_into().map_err(|_| HashFromStrError::IncorrectLength {
            found,
        })?;
        Ok(HashBytes::new(bytes))
    }
}

#[cfg(feature = "derive-serde")]
impl<Purpose> TryFrom<&str> for HashBytes<Purpose> {
    type Error = HashFromStrError;

    fn try_from(value: &str) -> Result<Self, Self::Error> { Self::from_str(value) }
}

#[derive(Debug)]
#[cfg_attr(feature = "derive-serde", derive(thiserror::Error))]
#[cfg_attr(feature = "derive-serde", error("Slice has incompatible length with a hash."))]
pub struct IncorrectLength;

impl<Purpose> TryFrom<&[u8]> for HashBytes<Purpose> {
    type Error = IncorrectLength;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; SHA256] = value.try_into().map_err(|_| IncorrectLength)?;
        Ok(bytes.into())
    }
}

// NB: Using try_from = &str does not work correctly for HashBytes
// serde::Deserialize instance due to ownership issues for the JSON format.
// Hence we implement this manually. The issue is that a &'a str cannot be
// deserialized from a String for arbitrary 'a, and this is needed when
// parsing with serde_json::from_value via &'a str.
#[cfg(feature = "derive-serde")]
impl<'de, Purpose> serde::Deserialize<'de> for HashBytes<Purpose> {
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

#[cfg(feature = "derive-serde")]
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
