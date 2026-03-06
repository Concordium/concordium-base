use super::{CborHolderAccount, RawCbor, TokenAmount};
use crate::common;
use crate::common::cbor::CborSerializationResult;
use crate::common::{cbor, Buffer, Deserial, Get, ParseResult, SerdeDeserialize, Serial};
use crate::protocol_level_tokens::TokenAdminRole;
use crate::transactions::Memo;
use concordium_base_derive::{CborDeserialize, CborSerialize};
use concordium_contracts_common::AccountAddress;
use serde::de::Error;
use serde::Deserializer;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

/// Token module event type
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
    // Assign admin roles to an Account for a protocol level token.
    AssignAdminRoles,
    // Revoke admin roles from an Account for a protocol level token.
    RevokeAdminRoles,
}

/// Unknown token module event
#[derive(Debug, thiserror::Error)]
#[error("Unknown token module event type: {0}")]
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
            TokenModuleEventType::AssignAdminRoles => "assignAdminRoles",
            TokenModuleEventType::RevokeAdminRoles => "revokeAdminRoles",
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
            "assignAdminRoles" => TokenModuleEventType::AssignAdminRoles,
            "revokeAdminRoles" => TokenModuleEventType::RevokeAdminRoles,
            _ => {
                return Err(UnknownTokenModuleEventTypeError(
                    type_discriminator.to_string(),
                ))
            }
        })
    }
}

/// Token module event parsed from type and CBOR
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "serde_deprecated", serde(rename_all = "camelCase"))]
pub enum TokenModuleEvent {
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
    /// Assign admin roles to an Account for a protocol level token
    AssignAdminRoles(AssignAdminRolesEvent),
    /// Revoke admin roles to an Account for a protocol level token
    RevokeAdminRoles(RevokeAdminRolesEvent),
}

impl TokenModuleEvent {
    /// Token module event type
    pub fn event_type(&self) -> TokenModuleEventType {
        match self {
            TokenModuleEvent::AddAllowList(_) => TokenModuleEventType::AddAllowList,
            TokenModuleEvent::RemoveAllowList(_) => TokenModuleEventType::RemoveAllowList,
            TokenModuleEvent::AddDenyList(_) => TokenModuleEventType::AddDenyList,
            TokenModuleEvent::RemoveDenyList(_) => TokenModuleEventType::RemoveDenyList,
            TokenModuleEvent::Pause(_) => TokenModuleEventType::Pause,
            TokenModuleEvent::Unpause(_) => TokenModuleEventType::Unpause,
            TokenModuleEvent::AssignAdminRoles(_) => TokenModuleEventType::AssignAdminRoles,
            TokenModuleEvent::RevokeAdminRoles(_) => TokenModuleEventType::RevokeAdminRoles,
        }
    }

    /// Encode event as CBOR. Returns the event type and its CBOR encoding.
    pub fn encode_event(&self) -> (TokenModuleEventType, RawCbor) {
        match self {
            TokenModuleEvent::AddAllowList(event) => (
                TokenModuleEventType::AddAllowList,
                RawCbor::from(cbor::cbor_encode(event)),
            ),
            TokenModuleEvent::RemoveAllowList(event) => (
                TokenModuleEventType::RemoveAllowList,
                RawCbor::from(cbor::cbor_encode(event)),
            ),
            TokenModuleEvent::AddDenyList(event) => (
                TokenModuleEventType::AddDenyList,
                RawCbor::from(cbor::cbor_encode(event)),
            ),
            TokenModuleEvent::RemoveDenyList(event) => (
                TokenModuleEventType::RemoveDenyList,
                RawCbor::from(cbor::cbor_encode(event)),
            ),
            TokenModuleEvent::Pause(event) => (
                TokenModuleEventType::Pause,
                RawCbor::from(cbor::cbor_encode(event)),
            ),
            TokenModuleEvent::Unpause(event) => (
                TokenModuleEventType::Unpause,
                RawCbor::from(cbor::cbor_encode(event)),
            ),
            TokenModuleEvent::AssignAdminRoles(event) => (
                TokenModuleEventType::AssignAdminRoles,
                RawCbor::from(cbor::cbor_encode(event)),
            ),
            TokenModuleEvent::RevokeAdminRoles(event) => (
                TokenModuleEventType::RevokeAdminRoles,
                RawCbor::from(cbor::cbor_encode(event)),
            ),
        }
    }

    /// Decode event from CBOR encoding assuming type given by `event_type`.
    pub fn decode_event(
        event_type: TokenModuleEventType,
        cbor: &RawCbor,
    ) -> CborSerializationResult<Self> {
        Ok(match event_type {
            TokenModuleEventType::AddAllowList => {
                TokenModuleEvent::AddAllowList(cbor::cbor_decode(cbor)?)
            }
            TokenModuleEventType::RemoveAllowList => {
                TokenModuleEvent::RemoveAllowList(cbor::cbor_decode(cbor)?)
            }
            TokenModuleEventType::AddDenyList => {
                TokenModuleEvent::AddDenyList(cbor::cbor_decode(cbor)?)
            }
            TokenModuleEventType::RemoveDenyList => {
                TokenModuleEvent::RemoveDenyList(cbor::cbor_decode(cbor)?)
            }
            TokenModuleEventType::Pause => TokenModuleEvent::Pause(cbor::cbor_decode(cbor)?),
            TokenModuleEventType::Unpause => TokenModuleEvent::Unpause(cbor::cbor_decode(cbor)?),
            TokenModuleEventType::AssignAdminRoles => {
                TokenModuleEvent::AssignAdminRoles(cbor::cbor_decode(cbor)?)
            }
            TokenModuleEventType::RevokeAdminRoles => {
                TokenModuleEvent::RevokeAdminRoles(cbor::cbor_decode(cbor)?)
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
pub type AssignAdminRolesEvent = TokenUpdateAdminRolesEventDetails;
pub type RevokeAdminRolesEvent = TokenUpdateAdminRolesEventDetails;

/// Details of an event updating the allow or deny list of a protocol level
/// token
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "serde_deprecated", serde(rename_all = "camelCase"))]
pub struct TokenListUpdateEventDetails {
    /// The account that was added or removed from an allow or deny list
    pub target: CborHolderAccount,
}

/// An event emitted when the token is paused or unpaused.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "serde_deprecated", serde(rename_all = "camelCase"))]
pub struct TokenPauseEventDetails {}

/// An event emmitted when there are updates made to admin roles
/// that are assigned or revoked from an Account for a protocol level token.
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
pub struct TokenUpdateAdminRolesEventDetails {
    // The admin roles to update.
    pub roles: Vec<TokenAdminRole>,
    // The account to update admin for.
    pub account: CborHolderAccount,
}

/// An entity that can hold PLTs (protocol level tokens).
/// The type is used in the `TokenTransfer`, `TokenMint`, and `TokenBurn`
/// events. Currently, this can only be a Concordium account address.
/// The type can be extended to e.g. support smart contracts in the future.
/// This type shouldn't be confused with the `CborHolderAccount` type that in
/// contrast is used in the transaction payload, in reject reasons, and in the
/// `TokenModuleEvent`.
#[derive(Debug, Eq, PartialEq, Clone)]
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "serde_deprecated", serde(tag = "type"))]
#[cfg_attr(feature = "serde_deprecated", serde(rename_all = "camelCase"))]
pub enum TokenHolder {
    Account { address: AccountAddress },
}

/// An event emitted when a transfer of tokens from `from` to `to` is performed.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "serde_deprecated", serde(rename_all = "camelCase"))]
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
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "serde_deprecated", serde(rename_all = "camelCase"))]
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
#[derive(Debug, Clone, Eq, PartialEq, Hash, serde::Serialize)]
#[serde(try_from = "String", into = "String")]
#[repr(transparent)]
pub struct TokenModuleCborTypeDiscriminator {
    value: String,
}

impl<'de> SerdeDeserialize<'de> for TokenModuleCborTypeDiscriminator {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let string = String::deserialize(deserializer)?;

        Self::try_from(string).map_err(D::Error::custom)
    }
}

/// Serial implementation matching the serialization of `TokenEventType`
/// in the Haskell module `Concordium.Types.Tokens`.
impl Serial for TokenModuleCborTypeDiscriminator {
    fn serial<B: Buffer>(&self, out: &mut B) {
        // length is always less or equal to TYPE_MAX_BYTE_LEN which fits into a u8
        let len = u8::try_from(self.value.len())
            .expect("Invariant violation for byte length of TokenModuleCborTypeDiscriminator");
        len.serial(out);
        common::serial_string(&self.value, out);
    }
}

/// Deserial implementation matching the serialization of `TokenEventType`
/// in the Haskell module `Concordium.Types.Tokens`.
impl Deserial for TokenModuleCborTypeDiscriminator {
    fn deserial<R: byteorder::ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let len: u8 = source.get()?;
        let value = common::deserial_string(source, len as usize)?;
        Ok(Self::try_from(value)?)
    }
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
        let byte_len = event_type.len();
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
        common,
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

    /// Test decoding a role event operation for assigning or revoking a single role.
    #[test]
    fn test_decode_assign_mint_admin_roles_event_cbor() {
        let event = TokenUpdateAdminRolesEventDetails {
            account: CborHolderAccount {
                address: token_holder::test_fixtures::ADDRESS,
                coin_info: None,
            },
            roles: vec![TokenAdminRole::Mint],
        };

        let cbor = cbor::cbor_encode(&event);
        assert_eq!(hex::encode(&cbor), "a265726f6c657381646d696e74676163636f756e74d99d73a10358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");

        let event_decoded: TokenUpdateAdminRolesEventDetails = cbor::cbor_decode(cbor).unwrap();
        assert_eq!(event_decoded, event);
    }

    /// Test Decoding all roles event details for assigning or revoking roles.
    #[test]
    fn test_decode_all_admin_roles_event_cbor() {
        let event = TokenUpdateAdminRolesEventDetails {
            account: CborHolderAccount {
                address: token_holder::test_fixtures::ADDRESS,
                coin_info: None,
            },
            roles: vec![
                TokenAdminRole::UpdateAdminRoles,
                TokenAdminRole::Mint,
                TokenAdminRole::Burn,
                TokenAdminRole::UpdateAllowList,
                TokenAdminRole::UpdateDenyList,
                TokenAdminRole::Pause,
                TokenAdminRole::UpdateMetadata,
            ],
        };

        let cbor = cbor::cbor_encode(&event);
        assert_eq!(hex::encode(&cbor), "a265726f6c6573877075706461746541646d696e526f6c6573646d696e74646275726e6f757064617465416c6c6f774c6973746e75706461746544656e794c6973746570617573656e7570646174654d65746164617461676163636f756e74d99d73a10358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");

        let event_decoded: TokenUpdateAdminRolesEventDetails = cbor::cbor_decode(cbor).unwrap();
        assert_eq!(event_decoded, event);
    }

    /// Test `TryFrom<String> for TokenModuleCborTypeDiscriminator`
    #[test]
    fn test_token_module_cbor_type_discriminator_try_from_string() {
        // test simple discriminator
        let discr =
            TokenModuleCborTypeDiscriminator::try_from("discr1".to_string()).expect("simple");
        assert_eq!(discr.as_ref(), "discr1");

        // test max length discriminator
        let discr = TokenModuleCborTypeDiscriminator::from_str("a".repeat(255).as_str())
            .expect("max length");
        assert_eq!(discr.as_ref(), "a".repeat(255));

        // test discriminator above max length
        let err = TokenModuleCborTypeDiscriminator::try_from("a".repeat(256))
            .expect_err("above max length");
        assert!(
            err.to_string().contains("must be within 255 bytes"),
            "err: {}",
            err
        );
    }

    /// Test `FromStr for TokenModuleCborTypeDiscriminator`
    #[test]
    fn test_token_module_cbor_type_discriminator_from_str() {
        // test simple discriminator
        let discr = TokenModuleCborTypeDiscriminator::from_str("discr1").expect("simple");
        assert_eq!(discr.as_ref(), "discr1");

        // test discriminator above max length
        let err = TokenModuleCborTypeDiscriminator::from_str("a".repeat(256).as_str())
            .expect_err("above max length");
        assert!(
            err.to_string().contains("must be within 255 bytes"),
            "err: {}",
            err
        );
    }

    /// Test binary serialization of [`TokenModuleCborTypeDiscriminator`]
    #[test]
    fn test_token_module_cbor_type_discriminator_serialize() {
        let discr: TokenModuleCborTypeDiscriminator = "discr1".parse().unwrap();
        let bytes = common::to_bytes(&discr);
        assert_eq!(hex::encode(&bytes), "06646973637231");
        let discr_deserialized: TokenModuleCborTypeDiscriminator =
            common::from_bytes(&mut bytes.as_slice()).unwrap();
        assert_eq!(discr_deserialized, discr);
    }

    /// Test JSON serialization of [`TokenModuleCborTypeDiscriminator`]
    #[test]
    fn test_token_module_cbor_type_discriminator_json_serialize() {
        // test simple discriminator
        let discr: TokenModuleCborTypeDiscriminator = "discr1".parse().unwrap();
        let json = serde_json::to_string(&discr).expect("serialize");
        assert_eq!(json, r#""discr1""#);
        let discr_deserialized: TokenModuleCborTypeDiscriminator =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(discr_deserialized, discr);

        // test discriminator above max length
        let json = format!("\"{}\"", "a".repeat(256));
        let err = serde_json::from_str::<TokenModuleCborTypeDiscriminator>(&json)
            .expect_err("deserialize");
        assert!(
            err.to_string().contains("must be within 255 bytes"),
            "err: {}",
            err
        );
    }
}
