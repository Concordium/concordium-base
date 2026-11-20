use crate::{
    common::{
        cbor::{
            CborDecoder, CborDeserialize, CborEncoder, CborSerializationError,
            CborSerializationResult, CborSerialize,
        },
        types::TransactionTime,
    },
    protocol_level_locks::LockRecipients,
    protocol_level_tokens::{CborHolderAccount, RawCbor, TokenId},
};
use concordium_base_derive::{CborDeserialize, CborSerialize};

/// Explicit creation capabilities; holders receive `fund` implicitly.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum LockCreateCapability {
    /// Authorizes releasing locked funds to their owner.
    Release,
    /// Authorizes sending locked funds, subject to token policies.
    Send,
    /// Authorizes cancelling the lock before expiry.
    Cancel,
}

impl CborSerialize for LockCreateCapability {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> Result<(), C::WriteError> {
        encoder.encode_text(match self {
            Self::Release => "release",
            Self::Send => "send",
            Self::Cancel => "cancel",
        })
    }
}

impl CborDeserialize for LockCreateCapability {
    fn deserialize<C: CborDecoder>(decoder: C) -> CborSerializationResult<Self> {
        match String::deserialize(decoder)?.as_str() {
            "release" => Ok(Self::Release),
            "send" => Ok(Self::Send),
            "cancel" => Ok(Self::Cancel),
            other => Err(CborSerializationError::invalid_data(format_args!(
                "unsupported lock creation capability {other:?}"
            ))),
        }
    }
}

/// Explicit role assignment; decoding requires at least one capability.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize)]
pub struct LockCreateRole {
    /// Account receiving the capabilities.
    pub account: CborHolderAccount,
    /// Nonempty explicit capabilities, excluding `fund`.
    pub roles: Vec<LockCreateCapability>,
}

impl CborDeserialize for LockCreateRole {
    fn deserialize<C: CborDecoder>(decoder: C) -> CborSerializationResult<Self> {
        #[derive(CborDeserialize)]
        struct Wire {
            account: CborHolderAccount,
            roles: Vec<LockCreateCapability>,
        }
        let wire = Wire::deserialize(decoder)?;
        if wire.roles.is_empty() {
            return Err(CborSerializationError::invalid_data(
                "lock creation role capabilities must be nonempty",
            ));
        }
        Ok(Self {
            account: wire.account,
            roles: wire.roles,
        })
    }
}

/// Simple lock creation input; decoding requires nonempty holders and tokens.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize)]
pub struct LockCreateConfigSimpleV0 {
    /// Accounts permitted to receive locked funds.
    pub recipients: LockRecipients,
    /// Nonempty accounts permitted to hold and fund locked tokens.
    pub holders: Vec<CborHolderAccount>,
    /// Expiry time of the lock.
    pub expiry: TransactionTime,
    /// Explicit role assignments; this list may be empty.
    pub roles: Vec<LockCreateRole>,
    /// Nonempty token identifiers permitted in the lock.
    pub tokens: Vec<TokenId>,
    /// Opaque metadata bytes, not checked for nested CBOR validity.
    pub metadata: Option<RawCbor>,
}

impl CborDeserialize for LockCreateConfigSimpleV0 {
    fn deserialize<C: CborDecoder>(decoder: C) -> CborSerializationResult<Self> {
        #[derive(CborDeserialize)]
        struct Wire {
            recipients: LockRecipients,
            holders: Vec<CborHolderAccount>,
            expiry: TransactionTime,
            roles: Vec<LockCreateRole>,
            tokens: Vec<TokenId>,
            metadata: Option<RawCbor>,
        }
        let wire = Wire::deserialize(decoder)?;
        if wire.holders.is_empty() || wire.tokens.is_empty() {
            return Err(CborSerializationError::invalid_data(
                "lock creation holders and tokens must be nonempty",
            ));
        }
        Ok(Self {
            recipients: wire.recipients,
            holders: wire.holders,
            expiry: wire.expiry,
            roles: wire.roles,
            tokens: wire.tokens,
            metadata: wire.metadata,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::cbor;

    #[test]
    fn creation_capabilities_match_fixtures_and_exclude_fund() {
        for (capability, fixture) in [
            (LockCreateCapability::Release, "6772656c65617365"),
            (LockCreateCapability::Send, "6473656e64"),
            (LockCreateCapability::Cancel, "6663616e63656c"),
        ] {
            assert_eq!(hex::encode(cbor::cbor_encode(&capability)), fixture);
            assert_eq!(
                cbor::cbor_decode::<LockCreateCapability>(hex::decode(fixture).unwrap()).unwrap(),
                capability
            );
        }
        for unsupported in ["fund", "recipient", "unknown"] {
            assert!(
                cbor::cbor_decode::<LockCreateCapability>(cbor::cbor_encode(unsupported)).is_err()
            );
        }
    }
}
