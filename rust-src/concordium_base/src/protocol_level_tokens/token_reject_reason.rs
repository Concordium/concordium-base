use crate::common::cbor;
use crate::common::cbor::CborSerializationResult;
use crate::protocol_level_tokens::{
    token_holder::CborHolderAccount, RawCbor, TokenAmount, TokenModuleCborTypeDiscriminator,
};
use concordium_base_derive::{CborDeserialize, CborSerialize};
use std::str::FromStr;

/// Token module reject reason type
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum TokenModuleRejectReasonType {
    /// Address not found: [`AddressNotFoundRejectReason`]
    AddressNotFound,
    /// Token balance is insufficient ([`TokenBalanceInsufficientRejectReason`])
    TokenBalanceInsufficient,
    /// The transaction could not be deserialized ([`DeserializationFailureRejectReason`])
    DeserializationFailure,
    /// The operation is not supported by the token module ([`UnsupportedOperationRejectReason`])
    UnsupportedOperation,
    /// Operation authorization check failed ([`OperationNotPermittedRejectReason`])
    OperationNotPermitted,
    /// Minting the requested amount would overflow the representable token
    /// amount ([`MintWouldOverflowRejectReason`])
    MintWouldOverflow,
}

/// Unknown token module reject reason
#[derive(Debug, thiserror::Error)]
#[error("Unknown token module reject reason type: {0}")]
pub struct UnknownTokenModuleRejectReasonTypeError(String);

impl TokenModuleRejectReasonType {
    /// String identifier for the reject reason type
    const fn as_str(&self) -> &'static str {
        match self {
            TokenModuleRejectReasonType::AddressNotFound => "addressNotFound",
            TokenModuleRejectReasonType::TokenBalanceInsufficient => "tokenBalanceInsufficient",
            TokenModuleRejectReasonType::DeserializationFailure => "deserializationFailure",
            TokenModuleRejectReasonType::UnsupportedOperation => "unsupportedOperation",
            TokenModuleRejectReasonType::OperationNotPermitted => "operationNotPermitted",
            TokenModuleRejectReasonType::MintWouldOverflow => "mintWouldOverflow",
        }
    }

    /// Convert to the "dynamic" representation of the reject reason type
    pub fn to_type_discriminator(&self) -> TokenModuleCborTypeDiscriminator {
        TokenModuleCborTypeDiscriminator::from_str(self.as_str()).expect("static length")
    }

    /// Convert from "dynamic" representation of the reject reason type to static
    pub fn try_from_type_discriminator(
        type_discriminator: &TokenModuleCborTypeDiscriminator,
    ) -> Result<Self, UnknownTokenModuleRejectReasonTypeError> {
        Ok(match type_discriminator.as_ref() {
            "addressNotFound" => TokenModuleRejectReasonType::AddressNotFound,
            "tokenBalanceInsufficient" => TokenModuleRejectReasonType::TokenBalanceInsufficient,
            "deserializationFailure" => TokenModuleRejectReasonType::DeserializationFailure,
            "unsupportedOperation" => TokenModuleRejectReasonType::UnsupportedOperation,
            "operationNotPermitted" => TokenModuleRejectReasonType::OperationNotPermitted,
            "mintWouldOverflow" => TokenModuleRejectReasonType::MintWouldOverflow,
            _ => {
                return Err(UnknownTokenModuleRejectReasonTypeError(
                    type_discriminator.to_string(),
                ))
            }
        })
    }
}

/// Token module reject reason parsed from type and CBOR
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TokenModuleRejectReasonEnum {
    /// Address not found
    AddressNotFound(AddressNotFoundRejectReason),
    /// Token balance is insufficient
    TokenBalanceInsufficient(TokenBalanceInsufficientRejectReason),
    /// The transaction could not be deserialized
    DeserializationFailure(DeserializationFailureRejectReason),
    /// The operation is not supported by the token module
    UnsupportedOperation(UnsupportedOperationRejectReason),
    /// Operation authorization check failed
    OperationNotPermitted(OperationNotPermittedRejectReason),
    /// Minting the requested amount would overflow the representable token
    /// amount.
    MintWouldOverflow(MintWouldOverflowRejectReason),
}

impl TokenModuleRejectReasonEnum {
    /// Token module reject reason type
    pub fn reject_reason_type(&self) -> TokenModuleRejectReasonType {
        match self {
            TokenModuleRejectReasonEnum::AddressNotFound(_) => {
                TokenModuleRejectReasonType::AddressNotFound
            }
            TokenModuleRejectReasonEnum::TokenBalanceInsufficient(_) => {
                TokenModuleRejectReasonType::TokenBalanceInsufficient
            }
            TokenModuleRejectReasonEnum::DeserializationFailure(_) => {
                TokenModuleRejectReasonType::DeserializationFailure
            }
            TokenModuleRejectReasonEnum::UnsupportedOperation(_) => {
                TokenModuleRejectReasonType::UnsupportedOperation
            }
            TokenModuleRejectReasonEnum::OperationNotPermitted(_) => {
                TokenModuleRejectReasonType::OperationNotPermitted
            }
            TokenModuleRejectReasonEnum::MintWouldOverflow(_) => {
                TokenModuleRejectReasonType::MintWouldOverflow
            }
        }
    }

    /// Encode reject reason as CBOR. Returns the reject reason type and its CBOR encoding.
    pub fn encode_reject_reason(&self) -> (TokenModuleRejectReasonType, RawCbor) {
        match self {
            TokenModuleRejectReasonEnum::AddressNotFound(reject_reason) => (
                TokenModuleRejectReasonType::AddressNotFound,
                RawCbor::from(cbor::cbor_encode(reject_reason)),
            ),
            TokenModuleRejectReasonEnum::TokenBalanceInsufficient(reject_reason) => (
                TokenModuleRejectReasonType::TokenBalanceInsufficient,
                RawCbor::from(cbor::cbor_encode(reject_reason)),
            ),
            TokenModuleRejectReasonEnum::DeserializationFailure(reject_reason) => (
                TokenModuleRejectReasonType::DeserializationFailure,
                RawCbor::from(cbor::cbor_encode(reject_reason)),
            ),
            TokenModuleRejectReasonEnum::UnsupportedOperation(reject_reason) => (
                TokenModuleRejectReasonType::UnsupportedOperation,
                RawCbor::from(cbor::cbor_encode(reject_reason)),
            ),
            TokenModuleRejectReasonEnum::OperationNotPermitted(reject_reason) => (
                TokenModuleRejectReasonType::OperationNotPermitted,
                RawCbor::from(cbor::cbor_encode(reject_reason)),
            ),
            TokenModuleRejectReasonEnum::MintWouldOverflow(reject_reason) => (
                TokenModuleRejectReasonType::MintWouldOverflow,
                RawCbor::from(cbor::cbor_encode(reject_reason)),
            ),
        }
    }

    /// Decode reject reason from CBOR encoding assuming it is of the type given by `reject_reason_type`.
    pub fn decode_reject_reason(
        reject_reason_type: TokenModuleRejectReasonType,
        cbor: &RawCbor,
    ) -> CborSerializationResult<Self> {
        Ok(match reject_reason_type {
            TokenModuleRejectReasonType::AddressNotFound => {
                TokenModuleRejectReasonEnum::AddressNotFound(cbor::cbor_decode(cbor)?)
            }
            TokenModuleRejectReasonType::TokenBalanceInsufficient => {
                TokenModuleRejectReasonEnum::TokenBalanceInsufficient(cbor::cbor_decode(cbor)?)
            }
            TokenModuleRejectReasonType::DeserializationFailure => {
                TokenModuleRejectReasonEnum::DeserializationFailure(cbor::cbor_decode(cbor)?)
            }
            TokenModuleRejectReasonType::UnsupportedOperation => {
                TokenModuleRejectReasonEnum::UnsupportedOperation(cbor::cbor_decode(cbor)?)
            }
            TokenModuleRejectReasonType::OperationNotPermitted => {
                TokenModuleRejectReasonEnum::OperationNotPermitted(cbor::cbor_decode(cbor)?)
            }
            TokenModuleRejectReasonType::MintWouldOverflow => {
                TokenModuleRejectReasonEnum::MintWouldOverflow(cbor::cbor_decode(cbor)?)
            }
        })
    }
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
    pub index: u64,
    /// The address that could not be resolved.
    pub address: CborHolderAccount,
}

/// The balance of tokens on the sender account is insufficient
/// to perform the operation.
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
pub struct TokenBalanceInsufficientRejectReason {
    /// The index in the list of operations of the failing operation.
    pub index: u64,
    /// The available balance of the sender.
    pub available_balance: TokenAmount,
    /// The minimum required balance to perform the operation.
    pub required_balance: TokenAmount,
}

/// The transaction could not be deserialized.
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
pub struct DeserializationFailureRejectReason {
    /// Text description of the failure mode.
    pub cause: Option<String>,
}

/// The operation is not supported by the token module.
///
/// This may be because the operation is not implemented by the module, or
/// because the token is not configured to support the operation. If the
/// operation is not authorized (i.e. the particular participants do not have
/// the authority to perform the operation) then the reject reason is
/// [`OperationNotPermittedRejectReason`] instead.
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
pub struct UnsupportedOperationRejectReason {
    /// The index in the list of operations of the failing operation.
    pub index: u64,
    /// The type of operation that was not supported.
    pub operation_type: String,
    /// The reason why the operation was not supported.
    pub reason: Option<String>,
}

/// The operation requires that a participating account has a certain
/// permission, but the account does not have that permission.
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
pub struct OperationNotPermittedRejectReason {
    /// The index in the list of operations of the failing operation.
    pub index: u64,
    /// (Optionally) the address that does not have the necessary permissions to
    /// perform the operation.
    pub address: Option<CborHolderAccount>,
    /// The reason why the operation is not permitted.
    pub reason: Option<String>,
}

/// Minting the requested amount would overflow the representable token amount.
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
pub struct MintWouldOverflowRejectReason {
    /// The index in the list of operations of the failing operation.
    pub index: u64,
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
    use crate::{
        common::cbor,
        protocol_level_tokens::{token_holder, CborHolderAccount},
    };

    #[test]
    fn test_address_not_found_reject_reason_cbor() {
        let reject_reason = AddressNotFoundRejectReason {
            index: 3,
            address: CborHolderAccount {
                address: token_holder::test_fixtures::ADDRESS,
                coin_info: None,
            },
        };
        let cbor = cbor::cbor_encode(&reject_reason);
        assert_eq!(hex::encode(&cbor), "a265696e646578036761646472657373d99d73a10358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");

        let reject_reason_decoded: AddressNotFoundRejectReason = cbor::cbor_decode(cbor).unwrap();
        assert_eq!(reject_reason_decoded, reject_reason);
    }

    #[test]
    fn test_token_balance_insufficient_reject_reason_cbor() {
        let reject_reason = TokenBalanceInsufficientRejectReason {
            index: 3,
            available_balance: TokenAmount::from_raw(12300, 3),
            required_balance: TokenAmount::from_raw(22300, 3),
        };
        let cbor = cbor::cbor_encode(&reject_reason);
        assert_eq!(hex::encode(&cbor), "a365696e646578036f726571756972656442616c616e6365c4822219571c70617661696c61626c6542616c616e6365c4822219300c");

        let reject_reason_decoded: TokenBalanceInsufficientRejectReason =
            cbor::cbor_decode(cbor).unwrap();
        assert_eq!(reject_reason_decoded, reject_reason);
    }

    #[test]
    fn test_deserialization_failure_reject_reason_cbor() {
        let reject_reason = DeserializationFailureRejectReason {
            cause: Some("testfailure".to_string()),
        };
        let cbor = cbor::cbor_encode(&reject_reason);
        assert_eq!(hex::encode(&cbor), "a16563617573656b746573746661696c757265");

        let reject_reason_decoded: DeserializationFailureRejectReason =
            cbor::cbor_decode(cbor).unwrap();
        assert_eq!(reject_reason_decoded, reject_reason);
    }

    #[test]
    fn test_unsupported_operation_reject_reason_cbor() {
        let reject_reason = UnsupportedOperationRejectReason {
            index: 0,
            operation_type: "testoperation".to_string(),
            reason: Some("testfailture".to_string()),
        };
        let cbor = cbor::cbor_encode(&reject_reason);
        assert_eq!(hex::encode(&cbor), "a365696e6465780066726561736f6e6c746573746661696c747572656d6f7065726174696f6e547970656d746573746f7065726174696f6e");

        let reject_reason_decoded: UnsupportedOperationRejectReason =
            cbor::cbor_decode(cbor).unwrap();
        assert_eq!(reject_reason_decoded, reject_reason);
    }

    #[test]
    fn test_operation_not_permitted_reject_reason_cbor() {
        let reject_reason = OperationNotPermittedRejectReason {
            index: 0,
            address: Some(CborHolderAccount {
                address: token_holder::test_fixtures::ADDRESS,
                coin_info: None,
            }),
            reason: Some("testfailture".to_string()),
        };
        let cbor = cbor::cbor_encode(&reject_reason);
        assert_eq!(hex::encode(&cbor), "a365696e6465780066726561736f6e6c746573746661696c747572656761646472657373d99d73a10358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");

        let reject_reason_decoded: OperationNotPermittedRejectReason =
            cbor::cbor_decode(cbor).unwrap();
        assert_eq!(reject_reason_decoded, reject_reason);
    }

    #[test]
    fn test_mint_would_overflow_reject_reason_cbor() {
        let reject_reason = MintWouldOverflowRejectReason {
            index: 0,
            requested_amount: TokenAmount::from_raw(20000, 3),
            current_supply: TokenAmount::from_raw(10000, 3),
            max_representable_amount: TokenAmount::from_raw(20000, 3),
        };
        let cbor = cbor::cbor_encode(&reject_reason);
        assert_eq!(hex::encode(&cbor), "a465696e646578006d63757272656e74537570706c79c482221927106f726571756573746564416d6f756e74c48222194e20766d6178526570726573656e7461626c65416d6f756e74c48222194e20");

        let reject_reason_decoded: MintWouldOverflowRejectReason = cbor::cbor_decode(cbor).unwrap();
        assert_eq!(reject_reason_decoded, reject_reason);
    }
}
