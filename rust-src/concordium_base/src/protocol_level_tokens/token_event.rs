use concordium_contracts_common::AccountAddress;
use super::{cbor::RawCbor, TokenAmount, TokenId};

/// Event produced from the effect of a token holder transaction.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenHolderEvent {
    /// The unique symbol of the token, which produced this event.
    pub token_id: TokenId,
    /// The type of event produced.
    pub event_type: TokenEventType,
    /// The details of the event produced, in the raw byte encoded form.
    pub details: RawCbor,
}

/// Event produced from the effect of a token governance transaction.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenGovernanceEvent {
    /// The unique symbol of the token, which produced this event.
    pub token_id: TokenId,
    /// The type of event produced.
    pub event_type: TokenEventType,
    /// The details of the event produced, in the raw byte encoded form.
    pub details: RawCbor,
}

/// Details provided by the token module in the event of rejecting a
/// transaction.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenModuleRejectReason {
    /// The unique symbol of the token, which produced this event.
    pub token_id: TokenId,
    /// The type of the reject reason.
    pub reason_type: TokenModuleRejectReasonTypeString,
    /// (Optional) CBOR-encoded details.
    pub details: Option<RawCbor>,
}

impl TokenModuleRejectReason {
    pub fn to_reject_reason_type(&self) -> TokenModuleRejectReasonType {
        todo!()
    }
}

/// Token module reject reason parsed from type and CBOR if possible
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TokenModuleRejectReasonType {
    AddressNotFound(AddressNotFoundRejectReason),
    TokenBalanceInsufficient(TokenBalanceInsufficientRejectReason),
    DeserializationFailure(DeserializationFailureRejectReason),
    UnsupportedOperation(UnsupportedOperationRejectReason),
    OperationNotPermitted (OperationNotPermittedRejectReason),
    MintWouldOverflow (MintWouldOverflowRejectReason),
    /// Represents unknown reject reason type
    Other(RawTokenModuleRejectReason),
}

/// Raw, unparsed token module reject reason.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawTokenModuleRejectReason {
    /// The type of the reject reason.
    pub reason_type: TokenModuleRejectReasonTypeString,
    /// (Optional) CBOR-encoded details.
    pub details: Option<RawCbor>,
}

/// A token holder address was not valid.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressNotFoundRejectReason {
    /// The index in the list of operations of the failing operation.
    pub index: usize,
    /// The address that could not be resolved.
    pub address: TokenHolder,
}

/// The balance of tokens on the sender account is insufficient
/// to perform the operation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenBalanceInsufficientRejectReason {
    /// The index in the list of operations of the failing operation.
    pub index: usize,
    /// The available balance of the sender.
    pub available_balance: TokenAmount,
    /// The minimum required balance to perform the operation.
    pub required_balance: TokenAmount,
}

/// The transaction could not be deserialized.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeserializationFailureRejectReason {
    /// Text description of the failure mode.
    pub cause: Option<String>,
}

/// The operation is not supported by the token module.
/// This may be because the operation is not implemented by the module, or because the
/// token is not configured to support the operation. If the operation is not authorized
/// (i.e. the particular participants do not have the authority to perform the operation)
/// then the reject reason is [`Self::operationNotPermitted`] instead.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnsupportedOperationRejectReason {
    /// The index in the list of operations of the failing operation.
    pub index: usize,
    /// The type of operation that was not supported.
    pub operation_type: String,
    /// The reason why the operation was not supported.
    pub reason: Option<String>,
}

/// The operation requires that a participating account has a certain
/// permission, but the account does not have that permission.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationNotPermittedRejectReason {
    /// The index in the list of operations of the failing operation.
    pub index: usize,
    /// (Optionally) the address that does not have the necessary permissions to perform the
    /// operation.
    pub address: Option<TokenHolder>,
    /// The reason why the operation is not permitted.
    pub reason: Option<String>,
}

/// Minting the requested amount would overflow the representable token amount.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MintWouldOverflowRejectReason {
    /// The index in the list of operations of the failing operation.
    pub index: usize,
    /// The requested amount to mint.
    pub requested_amount: TokenAmount,
    /// The current supply of the token.
    pub current_supply: TokenAmount,
    /// The maximum representable token amount.
    pub max_representable_amount: TokenAmount,
}

/// A destination that can receive and hold tokens.
/// Currently, this can only be a Concordium account address.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TokenHolder {
    HolderAccount(HolderAccount),
}

/// Account address that holds tokens
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HolderAccount {
    address: AccountAddress,
}


/// Maximum number of bytes allowed for an encoding of a token event type 
/// and token module reject reason type.
const TYPE_MAX_BYTE_LEN: usize = 255;

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
    "Byte encoding of TokenEventType must be within {TYPE_MAX_BYTE_LEN} bytes, \
     instead got {actual_size}"
)]
pub struct TypeFromStringError {
    /// The byte size of the provided string.
    actual_size: usize,
}

impl AsRef<str> for TokenEventType {
    fn as_ref(&self) -> &str {
        self.value.as_str()
    }
}

impl std::str::FromStr for TokenEventType {
    type Err = TypeFromStringError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.to_owned().try_into()
    }
}

impl TryFrom<String> for TokenEventType {
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

impl From<TokenEventType> for String {
    fn from(event_type: TokenEventType) -> Self {
        event_type.value
    }
}




/// String representing the type of token event produced.
///
/// Limited to 255 bytes in length and must be valid UTF-8.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
#[repr(transparent)]
pub struct TokenModuleRejectReasonTypeString {
    value: String,
}


impl AsRef<str> for TokenModuleRejectReasonTypeString {
    fn as_ref(&self) -> &str {
        self.value.as_str()
    }
}

impl std::str::FromStr for TokenModuleRejectReasonTypeString {
    type Err = TypeFromStringError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.to_owned().try_into()
    }
}

impl TryFrom<String> for TokenModuleRejectReasonTypeString {
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

impl From<TokenModuleRejectReasonTypeString> for String {
    fn from(reject_reason_type: TokenModuleRejectReasonTypeString) -> Self {
        reject_reason_type.value
    }
}
