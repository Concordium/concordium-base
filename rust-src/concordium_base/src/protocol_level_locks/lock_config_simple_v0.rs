use crate::common::cbor::{
    CborDecoder, CborDeserialize, CborEncoder, CborSerializationError, CborSerializationResult,
    CborSerialize,
};
use crate::{
    common::types::TransactionTime,
    protocol_level_locks::LockRecipients,
    protocol_level_tokens::{CborHolderAccount, CborMemo, RawCbor, TokenId},
};
use concordium_base_derive::{CborDeserialize, CborSerialize, Serialize};

/// Capability that can be granted to an account for a SimpleV0 lock
/// controller.
///
/// Each capability authorizes the grantee to perform the corresponding lock
/// operation.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize)]
pub enum LockControllerSimpleV0Capability {
    /// Authorizes funding the lock with a permitted token.
    Fund,
    /// Authorizes returning funds from the lock.
    Return,
    /// Authorizes sending funds from the lock to a recipient. This is subject to individual token
    /// policies such as pausation and allow/deny lists.
    Send,
    /// Authorizes cancelling the lock.
    Cancel,
}

impl LockControllerSimpleV0Capability {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Fund => "fund",
            Self::Return => "return",
            Self::Send => "send",
            Self::Cancel => "cancel",
        }
    }

    fn from_str(s: &str) -> Result<Self, CborSerializationError> {
        match s {
            "fund" => Ok(Self::Fund),
            "return" => Ok(Self::Return),
            "send" => Ok(Self::Send),
            "cancel" => Ok(Self::Cancel),
            other => Err(CborSerializationError::invalid_data(format_args!(
                "unknown LockControllerSimpleV0Capability: \"{}\"",
                other
            ))),
        }
    }
}

impl CborSerialize for LockControllerSimpleV0Capability {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> Result<(), C::WriteError> {
        encoder.encode_text(self.as_str())
    }
}

impl CborDeserialize for LockControllerSimpleV0Capability {
    fn deserialize<C: CborDecoder>(decoder: C) -> CborSerializationResult<Self>
    where
        Self: Sized,
    {
        let text_bytes = decoder.decode_text()?;
        let text = std::str::from_utf8(&text_bytes).map_err(|_| {
            CborSerializationError::invalid_data(format_args!(
                "LockControllerSimpleV0Capability text is not valid UTF-8"
            ))
        })?;
        Self::from_str(text)
    }
}

/// A grant of capabilities to a specific account for a SimpleV0 lock
/// controller.
///
/// Each grant assigns one or more [`LockControllerSimpleV0Capability`] roles
/// to the given account, authorizing it to perform the corresponding lock
/// operations.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
pub struct LockControllerSimpleV0Grant {
    /// The account receiving the grant.
    pub account: CborHolderAccount,
    /// The capabilities granted to the account.
    pub roles: Vec<LockControllerSimpleV0Capability>,
}

/// Configuration for a SimpleV0 lock controller.
///
/// Contains the list of capability grants, which tokens are affected,
/// a keep-alive flag, and an optional memo.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
pub struct LockConfigSimpleV0 {
    /// Accounts that can receive funds from this lock.
    pub recipients: LockRecipients,
    /// Expiry time of the lock.
    pub expiry: TransactionTime,
    /// Capability grants to accounts.
    pub grants: Vec<LockControllerSimpleV0Grant>,
    /// Tokens affected by this lock controller.
    pub tokens: Vec<TokenId>,
    /// Whether the lock should be kept alive after all funds are
    /// returned. Interpreted as `false` when omitted from the serialization.
    #[cbor(default = false)]
    pub keep_alive: bool,
    /// Optional memo attached to the lock.
    pub memo: Option<CborMemo>,
    /// Optional opaque CBOR-encoded user-facing metadata.
    pub metadata: Option<RawCbor>,
}
