use crate::{
    common::{cbor, cbor::CborSerializationResult},
    protocol_level_tokens::{
        token_holder::CborHolderAccount, RawCbor, TokenAmount, TokenModuleCborTypeDiscriminator,
    },
};
use anyhow::{anyhow, Context};
use concordium_base_derive::{CborDeserialize, CborSerialize};
use crate::common::cbor::CborSerialize;

/// Details provided by the token module in the event of rejecting a
/// transaction.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenModuleRejectReason {
    /// The type of the reject reason.
    #[serde(rename = "type")]
    pub reason_type: TokenModuleCborTypeDiscriminator,
    /// (Optional) CBOR-encoded details.
    pub details: Option<RawCbor>,
}

pub const ADDRESS_NOT_FOUND_REJECT_REASON_TYPE: &'static str = "addressNotFound";
pub const TOKEN_BALANCE_INSUFFICIENT_REJECT_REASON_TYPE: &'static str = "tokenBalanceInsufficient";
pub const DESERIALIZATION_FAILURE_REJECT_REASON_TYPE: &'static str = "deserializationFailure";
pub const UNSUPPORTED_OPERATION_REJECT_REASON_TYPE: &'static str = "unsupportedOperation";
pub const OPERATION_NOT_PERMITTED_REJECT_REASON_TYPE: &'static str = "operationNotPermitted";
pub const MINT_WOULD_OVERFLOW_REJECT_REASON_TYPE: &'static str = "mintWouldOverflow";

impl TokenModuleRejectReason {
    /// Decode reject reason from CBOR
    pub fn decode_reject_reason(&self) -> CborSerializationResult<TokenModuleRejectReasonType> {
        use TokenModuleRejectReasonType::*;

        Ok(match self.reason_type.as_ref() {
            ADDRESS_NOT_FOUND_REJECT_REASON_TYPE => AddressNotFound(cbor::cbor_decode(
                self.details.as_ref().context("no CBOR details")?.as_ref(),
            )?),
            TOKEN_BALANCE_INSUFFICIENT_REJECT_REASON_TYPE => TokenBalanceInsufficient(
                cbor::cbor_decode(self.details.as_ref().context("no CBOR details")?.as_ref())?,
            ),
            DESERIALIZATION_FAILURE_REJECT_REASON_TYPE => DeserializationFailure(
                cbor::cbor_decode(self.details.as_ref().context("no CBOR details")?.as_ref())?,
            ),
            UNSUPPORTED_OPERATION_REJECT_REASON_TYPE => UnsupportedOperation(cbor::cbor_decode(
                self.details.as_ref().context("no CBOR details")?.as_ref(),
            )?),
            OPERATION_NOT_PERMITTED_REJECT_REASON_TYPE => OperationNotPermitted(cbor::cbor_decode(
                self.details.as_ref().context("no CBOR details")?.as_ref(),
            )?),
            MINT_WOULD_OVERFLOW_REJECT_REASON_TYPE => MintWouldOverflow(cbor::cbor_decode(
                self.details.as_ref().context("no CBOR details")?.as_ref(),
            )?),
            _ => {
                return Err(
                    anyhow!("unknown token module reject reason: {}", self.reason_type).into(),
                )
            }
        })
    }

    pub fn encode_reject_reason(
        reject_reason: TokenModuleRejectReasonType,
    ) -> CborSerializationResult<Self> {
        fn cbor_encode(value: &impl CborSerialize) -> CborSerializationResult<RawCbor> {
            cbor::cbor_encode(value).map(RawCbor::from)
        }

        // todo ar
        Ok(match reject_reason {
            TokenModuleRejectReasonType::AddressNotFound(reason) => Self {
                reason_type: ADDRESS_NOT_FOUND_REJECT_REASON_TYPE
                    .to_string()
                    .try_into()
                    .unwrap(),
                details: Some(cbor_encode(&reason)?),
            },
            TokenModuleRejectReasonType::TokenBalanceInsufficient(reason) => Self {
                reason_type: TOKEN_BALANCE_INSUFFICIENT_REJECT_REASON_TYPE
                    .to_string()
                    .try_into()
                    .unwrap(),
                details: Some(cbor_encode(&reason)?),
            },
            TokenModuleRejectReasonType::DeserializationFailure(reason) => Self {
                reason_type: DESERIALIZATION_FAILURE_REJECT_REASON_TYPE
                    .to_string()
                    .try_into()
                    .unwrap(),
                details: Some(cbor_encode(&reason)?),
            },
            TokenModuleRejectReasonType::UnsupportedOperation(reason) => Self {
                reason_type: UNSUPPORTED_OPERATION_REJECT_REASON_TYPE
                    .to_string()
                    .try_into()
                    .unwrap(),
                details: Some(cbor_encode(&reason)?),
            },
            TokenModuleRejectReasonType::OperationNotPermitted(reason) => Self {
                reason_type: OPERATION_NOT_PERMITTED_REJECT_REASON_TYPE
                    .to_string()
                    .try_into()
                    .unwrap(),
                details: Some(cbor_encode(&reason)?),
            },
            TokenModuleRejectReasonType::MintWouldOverflow(reason) => Self {
                reason_type: MINT_WOULD_OVERFLOW_REJECT_REASON_TYPE
                    .to_string()
                    .try_into()
                    .unwrap(),
                details: Some(cbor_encode(&reason)?),
            },
        })
    }
}

/// Token module reject reason parsed from type and CBOR if possible
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TokenModuleRejectReasonType {
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
    pub index: usize,
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
    pub index: usize,
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
    pub index: usize,
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
    use crate::{
        common::cbor,
        protocol_level_tokens::{token_holder, CborHolderAccount},
    };

    #[test]
    fn test_address_not_found_reject_reason_cbor() {
        let variant = AddressNotFoundRejectReason {
            index: 3,
            address: CborHolderAccount {
                address: token_holder::test_fixtures::ADDRESS,
                coin_info: None,
            },
        };
        let cbor = cbor::cbor_encode(&variant).unwrap();
        assert_eq!(hex::encode(&cbor), "a265696e646578036761646472657373d99d73a10358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let reject_reason = TokenModuleRejectReason {
            reason_type: "addressNotFound".to_string().try_into().unwrap(),
            details: Some(cbor.into()),
        };

        let reject_reason_type = reject_reason.decode_reject_reason().unwrap();
        assert_eq!(
            reject_reason_type,
            TokenModuleRejectReasonType::AddressNotFound(variant)
        );
    }

    #[test]
    fn test_token_balance_insufficient_reject_reason_cbor() {
        let variant = TokenBalanceInsufficientRejectReason {
            index: 3,
            available_balance: TokenAmount::from_raw(12300, 3),
            required_balance: TokenAmount::from_raw(22300, 3),
        };
        let cbor = cbor::cbor_encode(&variant).unwrap();
        assert_eq!(hex::encode(&cbor), "a365696e646578036f726571756972656442616c616e6365c4822219571c70617661696c61626c6542616c616e6365c4822219300c");
        let reject_reason = TokenModuleRejectReason {
            reason_type: "tokenBalanceInsufficient".to_string().try_into().unwrap(),
            details: Some(cbor.into()),
        };

        let reject_reason_type = reject_reason.decode_reject_reason().unwrap();
        assert_eq!(
            reject_reason_type,
            TokenModuleRejectReasonType::TokenBalanceInsufficient(variant)
        );
    }

    #[test]
    fn test_deserialization_failure_reject_reason_cbor() {
        let variant = DeserializationFailureRejectReason {
            cause: Some("testfailure".to_string()),
        };
        let cbor = cbor::cbor_encode(&variant).unwrap();
        assert_eq!(hex::encode(&cbor), "a16563617573656b746573746661696c757265");
        let reject_reason = TokenModuleRejectReason {
            reason_type: "deserializationFailure".to_string().try_into().unwrap(),
            details: Some(cbor.into()),
        };

        let reject_reason_type = reject_reason.decode_reject_reason().unwrap();
        assert_eq!(
            reject_reason_type,
            TokenModuleRejectReasonType::DeserializationFailure(variant)
        );
    }

    #[test]
    fn test_unsupported_operation_reject_reason_cbor() {
        let variant = UnsupportedOperationRejectReason {
            index: 0,
            operation_type: "testoperation".to_string(),
            reason: Some("testfailture".to_string()),
        };
        let cbor = cbor::cbor_encode(&variant).unwrap();
        assert_eq!(hex::encode(&cbor), "a365696e6465780066726561736f6e6c746573746661696c747572656d6f7065726174696f6e547970656d746573746f7065726174696f6e");
        let reject_reason = TokenModuleRejectReason {
            reason_type: "unsupportedOperation".to_string().try_into().unwrap(),
            details: Some(cbor.into()),
        };

        let reject_reason_type = reject_reason.decode_reject_reason().unwrap();
        assert_eq!(
            reject_reason_type,
            TokenModuleRejectReasonType::UnsupportedOperation(variant)
        );
    }

    #[test]
    fn test_operation_not_permitted_reject_reason_cbor() {
        let variant = OperationNotPermittedRejectReason {
            index: 0,
            address: Some(CborHolderAccount {
                address: token_holder::test_fixtures::ADDRESS,
                coin_info: None,
            }),
            reason: Some("testfailture".to_string()),
        };
        let cbor = cbor::cbor_encode(&variant).unwrap();
        assert_eq!(hex::encode(&cbor), "a365696e6465780066726561736f6e6c746573746661696c747572656761646472657373d99d73a10358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let reject_reason = TokenModuleRejectReason {
            reason_type: "operationNotPermitted".to_string().try_into().unwrap(),
            details: Some(cbor.into()),
        };

        let reject_reason_type = reject_reason.decode_reject_reason().unwrap();
        assert_eq!(
            reject_reason_type,
            TokenModuleRejectReasonType::OperationNotPermitted(variant)
        );
    }

    #[test]
    fn test_mint_would_overflow_reject_reason_cbor() {
        let variant = MintWouldOverflowRejectReason {
            index: 0,
            requested_amount: TokenAmount::from_raw(20000, 3),
            current_supply: TokenAmount::from_raw(10000, 3),
            max_representable_amount: TokenAmount::from_raw(20000, 3),
        };
        let cbor = cbor::cbor_encode(&variant).unwrap();
        assert_eq!(hex::encode(&cbor), "a465696e646578006d63757272656e74537570706c79c482221927106f726571756573746564416d6f756e74c48222194e20766d6178526570726573656e7461626c65416d6f756e74c48222194e20");
        let reject_reason = TokenModuleRejectReason {
            reason_type: "mintWouldOverflow".to_string().try_into().unwrap(),
            details: Some(cbor.into()),
        };

        let reject_reason_type = reject_reason.decode_reject_reason().unwrap();
        assert_eq!(
            reject_reason_type,
            TokenModuleRejectReasonType::MintWouldOverflow(variant)
        );
    }
}
