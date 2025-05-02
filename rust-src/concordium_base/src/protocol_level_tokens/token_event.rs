use super::{cbor::RawCbor, TokenId};

/// Event produced from the effect of a token holder transaction.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenHolderEvent {
    /// The unique symbol of the token, which produced this event.
    pub token_id:   TokenId,
    /// The type of event produced.
    pub event_type: TokenEventType,
    /// The details of the event produced, in the raw byte encoded form.
    pub details:    RawCbor,
}

/// Event produced from the effect of a token governance transaction.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenGovernanceEvent {
    /// The unique symbol of the token, which produced this event.
    pub token_id:   TokenId,
    /// The type of event produced.
    pub event_type: TokenEventType,
    /// The details of the event produced, in the raw byte encoded form.
    pub details:    RawCbor,
}

/// Maximum number of bytes allowed for an encoding of a token event type.
const TOKEN_EVENT_TYPE_MAX_BYTE_LEN: usize = 255;

/// String representing the type of token event produced.
///
/// Limited to 255 bytes in length and must be valid UTF-8.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
#[repr(transparent)]
pub struct TokenEventType {
    value: String,
}

/// Error from converting a string into a [`TokenEventType`].
#[derive(Debug, thiserror::Error)]
#[error(
    "Byte encoding of TokenEventType must be within {TOKEN_EVENT_TYPE_MAX_BYTE_LEN} bytes, \
     instead got {actual_size}"
)]
pub struct TokenEventTypeFromStringError {
    /// The byte size of the provided string.
    actual_size: usize,
}

impl AsRef<str> for TokenEventType {
    fn as_ref(&self) -> &str { self.value.as_str() }
}

impl std::str::FromStr for TokenEventType {
    type Err = TokenEventTypeFromStringError;

    fn from_str(s: &str) -> Result<Self, Self::Err> { s.to_owned().try_into() }
}

impl TryFrom<String> for TokenEventType {
    type Error = TokenEventTypeFromStringError;

    fn try_from(event_type: String) -> Result<Self, Self::Error> {
        let byte_len = event_type.as_bytes().len();
        if byte_len > TOKEN_EVENT_TYPE_MAX_BYTE_LEN {
            Err(TokenEventTypeFromStringError {
                actual_size: byte_len,
            })
        } else {
            Ok(Self { value: event_type })
        }
    }
}

impl From<TokenEventType> for String {
    fn from(event_type: TokenEventType) -> Self { event_type.value }
}
