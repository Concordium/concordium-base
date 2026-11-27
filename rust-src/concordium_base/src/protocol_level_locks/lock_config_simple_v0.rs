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
pub enum SimpleLockConfigCapability {
    /// Authorizes releasing locked funds to their owner.
    Release,
    /// Authorizes sending locked funds, subject to token policies.
    Send,
    /// Authorizes cancelling the lock before expiry.
    Cancel,
}

impl CborSerialize for SimpleLockConfigCapability {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> Result<(), C::WriteError> {
        encoder.encode_text(match self {
            Self::Release => "release",
            Self::Send => "send",
            Self::Cancel => "cancel",
        })
    }
}

impl CborDeserialize for SimpleLockConfigCapability {
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

/// Explicit role assignment.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
pub struct SimpleLockConfigRoles {
    /// Account receiving the capabilities.
    pub account: CborHolderAccount,
    /// Explicit capabilities, excluding `fund`.
    pub roles: Vec<SimpleLockConfigCapability>,
}

/// Simple lock creation input; the node rejects empty holders, tokens, or role capabilities
/// after charging creation energy.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
pub struct SimpleLockConfigV0 {
    /// Accounts permitted to receive locked funds.
    pub recipients: LockRecipients,
    /// Accounts permitted to hold and fund locked tokens.
    pub holders: Vec<CborHolderAccount>,
    /// Expiry time of the lock.
    pub expiry: TransactionTime,
    /// Explicit role assignments; this list may be empty.
    pub roles: Vec<SimpleLockConfigRoles>,
    /// Token identifiers permitted in the lock.
    pub tokens: Vec<TokenId>,
    /// Opaque metadata bytes, not checked for nested CBOR validity.
    pub metadata: Option<RawCbor>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::cbor;

    #[test]
    fn creation_capabilities_match_fixtures_and_exclude_fund() {
        for (capability, fixture) in [
            (SimpleLockConfigCapability::Release, "6772656c65617365"),
            (SimpleLockConfigCapability::Send, "6473656e64"),
            (SimpleLockConfigCapability::Cancel, "6663616e63656c"),
        ] {
            assert_eq!(hex::encode(cbor::cbor_encode(&capability)), fixture);
            assert_eq!(
                cbor::cbor_decode::<SimpleLockConfigCapability>(hex::decode(fixture).unwrap())
                    .unwrap(),
                capability
            );
        }
        for unsupported in ["fund", "recipient", "unknown"] {
            assert!(
                cbor::cbor_decode::<SimpleLockConfigCapability>(cbor::cbor_encode(unsupported))
                    .is_err()
            );
        }
    }
}
