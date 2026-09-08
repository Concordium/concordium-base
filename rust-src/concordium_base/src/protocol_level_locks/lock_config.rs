use super::LockConfigSimpleV0;
use crate::common::cbor::{
    self, value, CborDecoder, CborDeserialize, CborEncoder, CborSerializationError,
    CborSerializationResult, CborSerialize, DataItemHeader,
};
use crate::protocol_level_tokens::{CborHolderAccount, RawCbor};
use concordium_base_derive::{CborDeserialize, CborSerialize};
use std::collections::HashMap;

/// Accounts that can receive funds controlled by a lock.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum LockRecipients {
    /// Any eligible account can receive funds from this lock.
    Any,
    /// Only the listed accounts can receive funds from this lock.
    Limited(Vec<CborHolderAccount>),
}

impl CborSerialize for LockRecipients {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> Result<(), C::WriteError> {
        match self {
            Self::Any => encoder.encode_text("any"),
            Self::Limited(accounts) => accounts.serialize(encoder),
        }
    }
}

impl CborDeserialize for LockRecipients {
    fn deserialize<C: CborDecoder>(mut decoder: C) -> CborSerializationResult<Self>
    where
        Self: Sized,
    {
        match decoder.peek_data_item_header()? {
            DataItemHeader::Text(_) => {
                let value = String::deserialize(decoder)?;
                if value == "any" {
                    Ok(Self::Any)
                } else {
                    Err(CborSerializationError::invalid_data(format_args!(
                        "unsupported lock recipients text value {value:?}"
                    )))
                }
            }
            DataItemHeader::Array(_) => Ok(Self::Limited(Vec::deserialize(decoder)?)),
            header => Err(CborSerializationError::invalid_data(format_args!(
                "lock recipients must be text \"any\" or an array of account addresses, was {header:?}"
            ))),
        }
    }
}

/// User-facing metadata attached to a lock at creation time.
#[derive(Debug, Clone, PartialEq, CborSerialize, CborDeserialize, Default)]
pub struct LockMetadata {
    /// Optional user-facing lock name.
    pub name: Option<String>,
    /// Optional user-facing lock description.
    pub description: Option<String>,
    /// Additional text-keyed CBOR fields preserved for future extensibility and
    /// user-defined metadata.
    #[cbor(other)]
    pub additional: HashMap<String, value::Value>,
}

impl LockMetadata {
    /// Decode typed lock metadata from raw CBOR bytes.
    ///
    /// # Arguments
    ///
    /// * `raw_cbor` - Raw bytes expected to contain a CBOR-encoded lock metadata map.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not valid CBOR for [`LockMetadata`].
    ///
    /// # Example
    ///
    /// ```
    /// use concordium_base::common::cbor;
    /// use concordium_base::protocol_level_locks::LockMetadata;
    /// use concordium_base::protocol_level_tokens::RawCbor;
    ///
    /// let raw = RawCbor::from(cbor::cbor_encode(&LockMetadata::default()));
    /// let metadata = LockMetadata::decode_raw_cbor(&raw)?;
    /// # Ok::<(), concordium_base::common::cbor::CborSerializationError>(())
    /// ```
    pub fn decode_raw_cbor(raw_cbor: &RawCbor) -> CborSerializationResult<Self> {
        cbor::cbor_decode(raw_cbor.as_ref())
    }

    /// Encode typed lock metadata to raw CBOR bytes.
    ///
    /// # Example
    ///
    /// ```
    /// use concordium_base::protocol_level_locks::LockMetadata;
    ///
    /// let raw = LockMetadata::default().encode_raw_cbor();
    /// assert!(!raw.as_ref().is_empty());
    /// ```
    pub fn encode_raw_cbor(&self) -> RawCbor {
        RawCbor::from(cbor::cbor_encode(self))
    }
}

/// Top-level lock configuration.
///
/// Each variant represents a different lock type.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
#[cbor(map)]
pub enum LockConfig {
    /// SimpleV0 lock controller configuration.
    SimpleV0(LockConfigSimpleV0),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol_level_tokens::test_fixtures::ADDRESS;
    use crate::{
        common::{cbor, types::TransactionTime},
        protocol_level_locks::{LockControllerSimpleV0Grant, LockRecipients},
        protocol_level_tokens::CborHolderAccount,
    };

    #[test]
    fn simple_v0_is_a_tagged_complete_configuration() {
        let config = LockConfig::SimpleV0(LockConfigSimpleV0 {
            recipients: LockRecipients::Limited(vec![CborHolderAccount::from(ADDRESS)]),
            expiry: TransactionTime::from_seconds(1),
            grants: vec![LockControllerSimpleV0Grant {
                account: CborHolderAccount::from(ADDRESS),
                roles: vec![],
            }],
            tokens: vec!["CCD".parse().unwrap()],
            keep_alive: false,
            memo: None,
            metadata: None,
        });
        let bytes = cbor::cbor_encode(&config);
        assert_eq!(cbor::cbor_decode::<LockConfig>(&bytes).unwrap(), config);
        assert_eq!(
            &bytes[0..10],
            &[0xa1, 0x68, b's', b'i', b'm', b'p', b'l', b'e', b'V', b'0']
        );
    }
}
