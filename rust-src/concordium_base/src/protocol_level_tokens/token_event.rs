use crate::{
    common::cbor::{self, CborSerializationResult},
    transactions::Memo,
};
use concordium_base_derive::{CborDeserialize, CborSerialize};
use concordium_contracts_common::AccountAddress;

use super::{cbor::RawCbor, CborTokenHolder, TokenAmount, TokenId};

/// An event produced from the effect of a token transaction.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenEvent {
    /// The unique symbol of the token, which produced this event.
    pub token_id: TokenId,
    /// The type of the event.
    pub event:    TokenEventDetails,
}

/// The type of the token event.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
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
    #[serde(rename = "type")]
    pub event_type: TokenModuleCborTypeDiscriminator,
    /// The details of the event produced, in the raw byte encoded form.
    pub details:    RawCbor,
}

impl TokenModuleEvent {
    /// Decode token module event from CBOR
    pub fn decode_token_module_event(&self) -> CborSerializationResult<TokenModuleEventType> {
        use TokenModuleEventType::*;

        Ok(match self.event_type.as_ref() {
            "addAllowList" => AddAllowList(cbor::cbor_decode(self.details.as_ref())?),
            "removeAllowList" => RemoveAllowList(cbor::cbor_decode(self.details.as_ref())?),
            "addDenyList" => AddDenyList(cbor::cbor_decode(self.details.as_ref())?),
            "removeDenyList" => RemoveDenyList(cbor::cbor_decode(self.details.as_ref())?),
            "pause" => Pause(cbor::cbor_decode(self.details.as_ref())?),
            "unpause" => Unpause(cbor::cbor_decode(self.details.as_ref())?),
            _ => Unknow,
        })
    }
}

/// Token module event parsed from type and CBOR
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TokenModuleEventType {
    /// An account was added to the allow list of a protocol level token
    AddAllowList(TokenListUpdateEventDetails),
    /// An account was removed from the allow list of a protocol level token
    RemoveAllowList(TokenListUpdateEventDetails),
    /// An account was added to the deny list of a protocol level token
    AddDenyList(TokenListUpdateEventDetails),
    /// An account was removed from the deny list of a protocol level token
    RemoveDenyList(TokenListUpdateEventDetails),
    /// Execution of certain operations on a protocol level token was
    /// paused
    Pause(TokenPauseEventDetails),
    /// Execution of certain operations on a protocol level token was
    /// unpaused
    Unpause(TokenPauseEventDetails),
    /// Unknow token module event type. If new events types are added that are
    /// unknown to this enum, they will be decoded to this variant.
    Unknow,
}

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
    pub target: CborTokenHolder,
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
/// This type shouldn't be confused with the `CborTokenHolder` type that in
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
    pub from:   TokenHolder,
    /// The token holder to which the tokens are transferred.
    pub to:     TokenHolder,
    /// The amount of tokens transferred.
    pub amount: TokenAmount,
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
}

/// Maximum number of bytes allowed for an encoding of a token module event type
/// and token module reject reason type.
const TYPE_MAX_BYTE_LEN: usize = 255;

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

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        common::cbor,
        protocol_level_tokens::{token_holder, CborHolderAccount},
    };

    #[test]
    fn test_decode_add_allow_list_event_cbor() {
        let variant = TokenListUpdateEventDetails {
            target: CborTokenHolder::Account(CborHolderAccount {
                address:   token_holder::test_fixtures::ADDRESS,
                coin_info: None,
            }),
        };
        let cbor = cbor::cbor_encode(&variant).unwrap();
        assert_eq!(hex::encode(&cbor), "a166746172676574d99d73a10358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let module_event = TokenModuleEvent {
            event_type: "addAllowList".to_string().try_into().unwrap(),
            details:    cbor.into(),
        };

        let module_event_type = module_event.decode_token_module_event().unwrap();
        assert_eq!(
            module_event_type,
            TokenModuleEventType::AddAllowList(variant)
        );
    }

    #[test]
    fn test_decode_remove_allow_list_event_cbor() {
        let variant = TokenListUpdateEventDetails {
            target: CborTokenHolder::Account(CborHolderAccount {
                address:   token_holder::test_fixtures::ADDRESS,
                coin_info: None,
            }),
        };
        let cbor = cbor::cbor_encode(&variant).unwrap();
        assert_eq!(hex::encode(&cbor), "a166746172676574d99d73a10358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let module_event = TokenModuleEvent {
            event_type: "removeAllowList".to_string().try_into().unwrap(),
            details:    cbor.into(),
        };

        let module_event_type = module_event.decode_token_module_event().unwrap();
        assert_eq!(
            module_event_type,
            TokenModuleEventType::RemoveAllowList(variant)
        );
    }

    #[test]
    fn test_decode_add_deny_list_event_cbor() {
        let variant = TokenListUpdateEventDetails {
            target: CborTokenHolder::Account(CborHolderAccount {
                address:   token_holder::test_fixtures::ADDRESS,
                coin_info: None,
            }),
        };
        let cbor = cbor::cbor_encode(&variant).unwrap();
        assert_eq!(hex::encode(&cbor), "a166746172676574d99d73a10358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let module_event = TokenModuleEvent {
            event_type: "addDenyList".to_string().try_into().unwrap(),
            details:    cbor.into(),
        };

        let module_event_type = module_event.decode_token_module_event().unwrap();
        assert_eq!(
            module_event_type,
            TokenModuleEventType::AddDenyList(variant)
        );
    }

    #[test]
    fn test_decode_remove_deny_list_event_cbor() {
        let variant = TokenListUpdateEventDetails {
            target: CborTokenHolder::Account(CborHolderAccount {
                address:   token_holder::test_fixtures::ADDRESS,
                coin_info: None,
            }),
        };
        let cbor = cbor::cbor_encode(&variant).unwrap();
        assert_eq!(hex::encode(&cbor), "a166746172676574d99d73a10358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let module_event = TokenModuleEvent {
            event_type: "removeDenyList".to_string().try_into().unwrap(),
            details:    cbor.into(),
        };

        let module_event_type = module_event.decode_token_module_event().unwrap();
        assert_eq!(
            module_event_type,
            TokenModuleEventType::RemoveDenyList(variant)
        );
    }

    #[test]
    fn test_decode_pause_event_cbor() {
        let variant = TokenPauseEventDetails {};
        let cbor = cbor::cbor_encode(&variant).unwrap();
        assert_eq!(hex::encode(&cbor), "a0");
        let module_event = TokenModuleEvent {
            event_type: "pause".to_string().try_into().unwrap(),
            details:    cbor.into(),
        };

        let module_event_type = module_event.decode_token_module_event().unwrap();
        assert_eq!(module_event_type, TokenModuleEventType::Pause(variant));
    }

    #[test]
    fn test_decode_unpause_event_cbor() {
        let variant = TokenPauseEventDetails {};
        let cbor = cbor::cbor_encode(&variant).unwrap();
        assert_eq!(hex::encode(&cbor), "a0");
        let module_event = TokenModuleEvent {
            event_type: "unpause".to_string().try_into().unwrap(),
            details:    cbor.into(),
        };

        let module_event_type = module_event.decode_token_module_event().unwrap();
        assert_eq!(module_event_type, TokenModuleEventType::Unpause(variant));
    }
}
