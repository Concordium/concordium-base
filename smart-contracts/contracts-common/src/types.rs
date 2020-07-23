#[cfg(not(feature = "std"))]
use core::convert;
#[cfg(feature = "std")]
use std::convert;

pub const ACCOUNT_ADDRESS_SIZE: usize = 32;

#[cfg(feature = "derive-serde")]
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};

/// The type of amounts on the chain.
pub type Amount = u64;

/// Address of an account, as raw bytes.
#[derive(Eq, PartialEq, Copy, Clone, PartialOrd, Ord)]
pub struct AccountAddress(pub [u8; ACCOUNT_ADDRESS_SIZE]);

impl convert::AsRef<[u8; 32]> for AccountAddress {
    fn as_ref(&self) -> &[u8; 32] { &self.0 }
}

impl convert::AsRef<[u8]> for AccountAddress {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

/// Address of a contract.
#[derive(Eq, PartialEq, Copy, Clone)]
#[cfg_attr(feature = "derive-serde", derive(SerdeSerialize, SerdeDeserialize))]
pub struct ContractAddress {
    pub index:    u64,
    pub subindex: u64,
}

/// Chain context accessible to the init methods.
///
/// TODO: We could optimize this to be initialized lazily
#[cfg_attr(
    feature = "derive-serde",
    derive(SerdeSerialize, SerdeDeserialize),
    serde(rename = "camelCase")
)]
pub struct InitContext {
    pub(crate) metadata:    ChainMetadata,
    pub(crate) init_origin: AccountAddress,
}

/// Either an address of an account, or contract.
#[cfg_attr(
    feature = "derive-serde",
    derive(SerdeSerialize, SerdeDeserialize),
    serde(tag = "type", content = "address")
)]
#[derive(PartialEq, Eq)]
pub enum Address {
    Account(AccountAddress),
    Contract(ContractAddress),
}

/// Chain context accessible to the receive methods.
///
/// TODO: We could optimize this to be initialized lazily.
#[cfg_attr(
    feature = "derive-serde",
    derive(SerdeSerialize, SerdeDeserialize),
    serde(rename = "camelCase")
)]
pub struct ReceiveContext {
    pub(crate) metadata:     ChainMetadata,
    pub(crate) invoker:      AccountAddress,
    pub(crate) self_address: ContractAddress,
    pub self_balance:        Amount,
    pub(crate) sender:       Address,
    pub(crate) owner:        AccountAddress,
}

/// Chain metadata accessible to both receive and init methods.
#[cfg_attr(
    feature = "derive-serde",
    derive(SerdeSerialize, SerdeDeserialize),
    serde(rename = "camelCase")
)]
pub struct ChainMetadata {
    pub(crate) slot_number:      u64,
    pub(crate) block_height:     u64,
    pub(crate) finalized_height: u64,
    pub(crate) slot_time:        u64,
}

/// Add offset tracking inside a data structure.
pub struct Cursor<T> {
    pub offset: usize,
    pub data:   T,
}

#[cfg(feature = "derive-serde")]
mod serde_impl {
    // FIXME: This is duplicated from crypto/id/types.
    use super::*;
    use base58check::*;
    use serde::{de, de::Visitor, Deserializer, Serializer};
    use std::fmt;

    // Parse from string assuming base58 check encoding.
    impl std::str::FromStr for AccountAddress {
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

    impl SerdeSerialize for AccountAddress {
        fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
            let b58_str = self.0.to_base58check(1);
            ser.serialize_str(&b58_str)
        }
    }

    impl<'de> SerdeDeserialize<'de> for AccountAddress {
        fn deserialize<D: Deserializer<'de>>(des: D) -> Result<Self, D::Error> {
            des.deserialize_str(Base58Visitor)
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
