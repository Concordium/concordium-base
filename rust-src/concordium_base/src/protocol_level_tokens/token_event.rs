use super::{CborHolderAccount, RawCbor, TokenAmount};
use crate::common::cbor;
use crate::common::cbor::CborSerializationResult;
use crate::transactions::Memo;
use concordium_base_derive::{CborDeserialize, CborSerialize};
use concordium_contracts_common::AccountAddress;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

/// Token module event parsed from type and CBOR
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum TokenModuleEventType {
    /// An account was added to the allow list of a protocol level token ([`AddAllowListEvent`])
    AddAllowList,
    /// An account was removed from the allow list of a protocol level token ([`RemoveAllowListEvent`])
    RemoveAllowList,
    /// An account was added to the deny list of a protocol level token ([`AddDenyListEvent`])
    AddDenyList,
    /// An account was removed from the deny list of a protocol level token ([`RemoveDenyListEvent`])
    RemoveDenyList,
    /// Execution of certain operations on a protocol level token was
    /// paused ([`PauseEvent`])
    Pause,
    /// Execution of certain operations on a protocol level token was
    /// unpaused ([`UnpauseEvent`])
    Unpause,
}

/// Unknown token module reject reason
#[derive(Debug, thiserror::Error)]
#[error("Unknown token module reject reason type: {0}")]
pub struct UnknownTokenModuleEventTypeError(String);

impl TokenModuleEventType {
    /// String identifier for the token module event
    const fn as_str(&self) -> &'static str {
        match self {
            TokenModuleEventType::AddAllowList => "addAllowList",
            TokenModuleEventType::RemoveAllowList => "removeAllowList",
            TokenModuleEventType::AddDenyList => "addDenyList",
            TokenModuleEventType::RemoveDenyList => "removeDenyList",
            TokenModuleEventType::Pause => "pause",
            TokenModuleEventType::Unpause => "unpause",
        }
    }

    /// Convert to the "dynamic" representation of the token module event
    pub fn to_type_discriminator(&self) -> TokenModuleCborTypeDiscriminator {
        TokenModuleCborTypeDiscriminator::from_str(self.as_str()).expect("static length")
    }

    /// Convert from "dynamic" representation of the reject reason type to static
    pub fn try_from_type_discriminator(
        type_discriminator: &TokenModuleCborTypeDiscriminator,
    ) -> Result<Self, UnknownTokenModuleEventTypeError> {
        Ok(match type_discriminator.as_ref() {
            "addAllowList" => TokenModuleEventType::AddAllowList,
            "removeAllowList" => TokenModuleEventType::RemoveAllowList,
            "addDenyList" => TokenModuleEventType::AddDenyList,
            "removeDenyList" => TokenModuleEventType::RemoveDenyList,
            "pause" => TokenModuleEventType::Pause,
            "unpause" => TokenModuleEventType::Unpause,
            _ => {
                return Err(UnknownTokenModuleEventTypeError(
                    type_discriminator.to_string(),
                ))
            }
        })
    }
}

/// Token module event parsed from type and CBOR
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TokenModuleEventEnum {
    /// An account was added to the allow list of a protocol level token
    AddAllowList(AddAllowListEvent),
    /// An account was removed from the allow list of a protocol level token
    RemoveAllowList(RemoveAllowListEvent),
    /// An account was added to the deny list of a protocol level token
    AddDenyList(AddDenyListEvent),
    /// An account was removed from the deny list of a protocol level token
    RemoveDenyList(RemoveDenyListEvent),
    /// Execution of certain operations on a protocol level token was
    /// paused
    Pause(PauseEvent),
    /// Execution of certain operations on a protocol level token was
    /// unpaused
    Unpause(UnpauseEvent),
}

impl TokenModuleEventEnum {
    /// Token module event type
    pub fn event_type(&self) -> TokenModuleEventType {
        match self {
            TokenModuleEventEnum::AddAllowList(_) => TokenModuleEventType::AddAllowList,
            TokenModuleEventEnum::RemoveAllowList(_) => TokenModuleEventType::RemoveAllowList,
            TokenModuleEventEnum::AddDenyList(_) => TokenModuleEventType::AddDenyList,
            TokenModuleEventEnum::RemoveDenyList(_) => TokenModuleEventType::RemoveDenyList,
            TokenModuleEventEnum::Pause(_) => TokenModuleEventType::Pause,
            TokenModuleEventEnum::Unpause(_) => TokenModuleEventType::Unpause,
        }
    }

    /// Encode event as CBOR. Returns the event type and its CBOR encoding.
    pub fn encode_event(&self) -> (TokenModuleEventType, RawCbor) {
        match self {
            TokenModuleEventEnum::AddAllowList(event) => (
                TokenModuleEventType::AddAllowList,
                RawCbor::from(cbor::cbor_encode(event)),
            ),
            TokenModuleEventEnum::RemoveAllowList(event) => (
                TokenModuleEventType::RemoveAllowList,
                RawCbor::from(cbor::cbor_encode(event)),
            ),
            TokenModuleEventEnum::AddDenyList(event) => (
                TokenModuleEventType::AddDenyList,
                RawCbor::from(cbor::cbor_encode(event)),
            ),
            TokenModuleEventEnum::RemoveDenyList(event) => (
                TokenModuleEventType::RemoveDenyList,
                RawCbor::from(cbor::cbor_encode(event)),
            ),
            TokenModuleEventEnum::Pause(event) => (
                TokenModuleEventType::Pause,
                RawCbor::from(cbor::cbor_encode(event)),
            ),
            TokenModuleEventEnum::Unpause(event) => (
                TokenModuleEventType::Unpause,
                RawCbor::from(cbor::cbor_encode(event)),
            ),
        }
    }

    /// Decode event from CBOR encoding
    pub fn decode_event(
        event_type: TokenModuleEventType,
        cbor: &RawCbor,
    ) -> CborSerializationResult<Self> {
        Ok(match event_type {
            TokenModuleEventType::AddAllowList => {
                TokenModuleEventEnum::AddAllowList(cbor::cbor_decode(cbor)?)
            }
            TokenModuleEventType::RemoveAllowList => {
                TokenModuleEventEnum::RemoveAllowList(cbor::cbor_decode(cbor)?)
            }
            TokenModuleEventType::AddDenyList => {
                TokenModuleEventEnum::AddDenyList(cbor::cbor_decode(cbor)?)
            }
            TokenModuleEventType::RemoveDenyList => {
                TokenModuleEventEnum::RemoveDenyList(cbor::cbor_decode(cbor)?)
            }
            TokenModuleEventType::Pause => TokenModuleEventEnum::Pause(cbor::cbor_decode(cbor)?),
            TokenModuleEventType::Unpause => {
                TokenModuleEventEnum::Unpause(cbor::cbor_decode(cbor)?)
            }
        })
    }
}

pub type AddAllowListEvent = TokenListUpdateEventDetails;
pub type RemoveAllowListEvent = TokenListUpdateEventDetails;
pub type AddDenyListEvent = TokenListUpdateEventDetails;
pub type RemoveDenyListEvent = TokenListUpdateEventDetails;
pub type PauseEvent = TokenPauseEventDetails;
pub type UnpauseEvent = TokenPauseEventDetails;

/// Details of an event updating the allow or deny list of a protocol level
/// token
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    serde::Serialize,
    serde::Deserialize,
    CborSerialize,
    CborDeserialize,
)]
#[serde(rename_all = "camelCase")]
pub struct TokenListUpdateEventDetails {
    /// The account that was added or removed from an allow or deny list
    pub target: CborHolderAccount,
}

/// An event emitted when the token is paused or unpaused.
#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    CborSerialize,
    CborDeserialize,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub struct TokenPauseEventDetails {}

/// An entity that can hold PLTs (protocol level tokens).
/// The type is used in the `TokenTransfer`, `TokenMint`, and `TokenBurn`
/// events. Currently, this can only be a Concordium account address.
/// The type can be extended to e.g. support smart contracts in the future.
/// This type shouldn't be confused with the `CborHolderAccount` type that in
/// contrast is used in the transaction payload, in reject reasons, and in the
/// `TokenModuleEvent`.
#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
pub enum TokenHolder {
    Account { address: AccountAddress },
}

/// An event emitted when a transfer of tokens from `from` to `to` is performed.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenTransferEvent {
    /// The token holder from which the tokens are transferred.
    pub from: TokenHolder,
    /// The token holder to which the tokens are transferred.
    pub to: TokenHolder,
    /// The amount of tokens transferred.
    pub amount: TokenAmount,
    /// An optional memo field that can be used to attach a message to the token
    /// transfer.
    pub memo: Option<Memo>,
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
}

/// Maximum number of bytes allowed for an encoding of a token module event type
/// and token module reject reason type.
const TYPE_MAX_BYTE_LEN: usize = 255;

/// String representing the type of token module event or token module reject
/// reason type.
///
/// Limited to 255 bytes in length and must be valid UTF-8.
#[derive(Debug, Clone, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize)]
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
    fn as_ref(&self) -> &str {
        self.value.as_str()
    }
}

impl Display for TokenModuleCborTypeDiscriminator {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.value)
    }
}

impl std::str::FromStr for TokenModuleCborTypeDiscriminator {
    type Err = TypeFromStringError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.to_owned().try_into()
    }
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
    fn from(event_type: TokenModuleCborTypeDiscriminator) -> Self {
        event_type.value
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        common::cbor,
        protocol_level_tokens::{token_holder, CborHolderAccount},
    };

    #[test]
    fn test_decode_add_allow_list_event_cbor() {
        let event = TokenListUpdateEventDetails {
            target: CborHolderAccount {
                address: token_holder::test_fixtures::ADDRESS,
                coin_info: None,
            },
        };
        let cbor = cbor::cbor_encode(&event);
        assert_eq!(hex::encode(&cbor), "a166746172676574d99d73a10358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");

        let event_decoded: TokenListUpdateEventDetails = cbor::cbor_decode(cbor).unwrap();
        assert_eq!(event_decoded, event);
    }

    #[test]
    fn test_decode_remove_allow_list_event_cbor() {
        let event = TokenListUpdateEventDetails {
            target: CborHolderAccount {
                address: token_holder::test_fixtures::ADDRESS,
                coin_info: None,
            },
        };
        let cbor = cbor::cbor_encode(&event);
        assert_eq!(hex::encode(&cbor), "a166746172676574d99d73a10358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");

        let event_decoded: TokenListUpdateEventDetails = cbor::cbor_decode(cbor).unwrap();
        assert_eq!(event_decoded, event);
    }

    #[test]
    fn test_decode_add_deny_list_event_cbor() {
        let event = TokenListUpdateEventDetails {
            target: CborHolderAccount {
                address: token_holder::test_fixtures::ADDRESS,
                coin_info: None,
            },
        };
        let cbor = cbor::cbor_encode(&event);
        assert_eq!(hex::encode(&cbor), "a166746172676574d99d73a10358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");

        let event_decoded: TokenListUpdateEventDetails = cbor::cbor_decode(cbor).unwrap();
        assert_eq!(event_decoded, event);
    }

    #[test]
    fn test_decode_remove_deny_list_event_cbor() {
        let event = TokenListUpdateEventDetails {
            target: CborHolderAccount {
                address: token_holder::test_fixtures::ADDRESS,
                coin_info: None,
            },
        };
        let cbor = cbor::cbor_encode(&event);
        assert_eq!(hex::encode(&cbor), "a166746172676574d99d73a10358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");

        let event_decoded: TokenListUpdateEventDetails = cbor::cbor_decode(cbor).unwrap();
        assert_eq!(event_decoded, event);
    }

    #[test]
    fn test_decode_pause_event_cbor() {
        let event = TokenPauseEventDetails {};
        let cbor = cbor::cbor_encode(&event);
        assert_eq!(hex::encode(&cbor), "a0");

        let event_decoded: TokenPauseEventDetails = cbor::cbor_decode(cbor).unwrap();
        assert_eq!(event_decoded, event);
    }

    #[test]
    fn test_decode_unpause_event_cbor() {
        let event = TokenPauseEventDetails {};
        let cbor = cbor::cbor_encode(&event);
        assert_eq!(hex::encode(&cbor), "a0");

        let event_decoded: TokenPauseEventDetails = cbor::cbor_decode(cbor).unwrap();
        assert_eq!(event_decoded, event);
    }
}
