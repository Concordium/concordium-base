use crate::transactions::Memo;

use super::{cbor::RawCbor, TokenAmount, TokenHolder, TokenId};

/// Details provided by the token module in the event of rejecting a
/// transaction.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenModuleRejectReason {
    /// The unique symbol of the token, which produced this event.
    pub token_id:   TokenId,
    /// The type of event produced.
    pub event_type: TokenModuleCborTypeDiscriminator,
    /// The details of the event produced, in the raw byte encoded form.
    pub details:    Option<RawCbor>,
}

/// An event produced from the effect of a token transaction.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenEvent {
    /// The unique symbol of the token, which produced this event.
    pub token_id: TokenId,
    /// The type of the event.
    pub event:    TokenEventDetails,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
/// The type of the token event.
pub enum TokenEventDetails {
    /// An event emitted by the token module.
    Module(TokenModuleEvent),
    /// An event emitted when a transfer of tokens is performed.
    Transfer(TokenTransferEvent),
    /// An event emitted when the token supply is updated by minting tokens to a
    /// token holder.
    Mint(TokenSupplyUpdateEvent),
    /// An event emitted when the token supply is updated by burning tokens from
    /// the balance of a token holder.
    Burn(TokenSupplyUpdateEvent),
}

/// Event produced from the effect of a token transaction.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenModuleEvent {
    /// The type of event produced.
    pub event_type: TokenModuleCborTypeDiscriminator,
    /// The details of the event produced, in the raw byte encoded form.
    pub details:    RawCbor,
}

/// Maximum number of bytes allowed for an encoding of a token module event type
/// and token module reject reason type.
const TYPE_MAX_BYTE_LEN: usize = 255;
    /// An optional memo field that can be used to attach a message to the token
    /// transfer.
    pub memo:   Option<Memo>,
}

/// An event emitted when the token supply is updated, i.e. by minting/burning
/// tokens to/from the balance of the `target`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenSupplyUpdateEvent {
    /// The token holder the balance update is performed on.
    pub target: TokenHolder,
    /// The balance difference to be applied to the target.
    pub amount: TokenAmount,

/// String representing the type of token module event or token module reject
/// reason type.
///
/// Limited to 255 bytes in length and must be valid UTF-8.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
#[repr(transparent)]
pub struct TokenModuleCborTypeDiscriminator {
    value: String,
}

/// Error from converting a string into a [`TokenModuleCborTypeDiscriminator`].
#[derive(Debug, thiserror::Error)]
#[error(
    "Byte encoding of TokenModuleTypeDiscriminator must be within {TYPE_MAX_BYTE_LEN} bytes, \
     instead got {actual_size}"
)]
pub struct TypeFromStringError {
    /// The byte size of the provided string.
    actual_size: usize,
}

impl AsRef<str> for TokenModuleCborTypeDiscriminator {
    fn as_ref(&self) -> &str { self.value.as_str() }
}

impl std::str::FromStr for TokenModuleCborTypeDiscriminator {
    type Err = TypeFromStringError;

    fn from_str(s: &str) -> Result<Self, Self::Err> { s.to_owned().try_into() }
}

impl TryFrom<String> for TokenModuleCborTypeDiscriminator {
    type Error = TypeFromStringError;

    fn try_from(event_type: String) -> Result<Self, Self::Error> {
        let byte_len = event_type.as_bytes().len();
        if byte_len > TYPE_MAX_BYTE_LEN {
            Err(TypeFromStringError {
                actual_size: byte_len,
            })
        } else {
            Ok(Self { value: event_type })
        }
    }
}

impl From<TokenModuleCborTypeDiscriminator> for String {
    fn from(event_type: TokenModuleCborTypeDiscriminator) -> Self { event_type.value }
}
