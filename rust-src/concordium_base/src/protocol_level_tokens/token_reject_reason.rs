use crate::internal::cbor::{
    CborDecoder, CborDeserialize, CborEncoder, CborError, CborResult, CborSerialize, MapKey,
    MapKeyRef,
};
use crate::protocol_level_tokens::{
    token_holder::TokenHolder, RawCbor, TokenAmount, TokenId, TokenModuleCborTypeDiscriminator,
};
use concordium_base_derive::{CborDeserialize, CborSerialize};

/// Details provided by the token module in the event of rejecting a
/// transaction.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenModuleRejectReason {
    /// The unique symbol of the token, which produced this event.
    pub token_id: TokenId,
    /// The type of the reject reason.
    pub reason_type: TokenModuleCborTypeDiscriminator,
    /// (Optional) CBOR-encoded details.
    pub details: Option<RawCbor>,
}

impl TokenModuleRejectReason {
    pub fn to_reject_reason_type(&self) -> TokenModuleRejectReasonType {
        use TokenModuleRejectReasonType::*;

        Other
    }
}

/// Token module reject reason parsed from type and CBOR if possible
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TokenModuleRejectReasonType {
    AddressNotFound(AddressNotFoundRejectReason),
    TokenBalanceInsufficient(TokenBalanceInsufficientRejectReason),
    DeserializationFailure(DeserializationFailureRejectReason),
    UnsupportedOperation(UnsupportedOperationRejectReason),
    OperationNotPermitted(OperationNotPermittedRejectReason),
    MintWouldOverflow(MintWouldOverflowRejectReason),
    /// Represents unknown reject reason type
    Other,
}

/// A token holder address was not valid.
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
pub struct AddressNotFoundRejectReason {
    /// The index in the list of operations of the failing operation.
    pub index: usize,
    /// The address that could not be resolved.
    pub address: TokenHolder,
}

/// The balance of tokens on the sender account is insufficient
/// to perform the operation.
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
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
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeserializationFailureRejectReason {
    /// Text description of the failure mode.
    pub cause: Option<String>,
}

/// The operation is not supported by the token module.
/// This may be because the operation is not implemented by the module, or
/// because the token is not configured to support the operation. If the
/// operation is not authorized (i.e. the particular participants do not have
/// the authority to perform the operation) then the reject reason is
/// [`Self::operationNotPermitted`] instead.
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
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
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationNotPermittedRejectReason {
    /// The index in the list of operations of the failing operation.
    pub index: usize,
    /// (Optionally) the address that does not have the necessary permissions to
    /// perform the operation.
    pub address: Option<TokenHolder>,
    /// The reason why the operation is not permitted.
    pub reason: Option<String>,
}

/// Minting the requested amount would overflow the representable token amount.
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::internal::cbor;
    use crate::protocol_level_tokens::{token_holder, HolderAccount};

    #[test]
    fn test_address_not_found_reject_reason_cbor() {
        let reject_reason = AddressNotFoundRejectReason {
            index: 3,
            address: TokenHolder::HolderAccount(HolderAccount {
                address: token_holder::test::ADDRESS,
                coin_info: None,
            }),
        };

        let cbor = cbor::cbor_encode(&reject_reason).unwrap();
        assert_eq!(hex::encode(&cbor), "a265696e646578036761646472657373d99d73a10358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let token_holder_decoded: AddressNotFoundRejectReason = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(token_holder_decoded, reject_reason);
    }
}
