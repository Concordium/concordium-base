use crate::internal::cbor::{CborDecoder, CborDeserialize, CborEncoder, CborError, CborResult, CborSerialize, MapKey, MapKeyRef};
use crate::protocol_level_tokens::{
    token_holder::TokenHolder, RawCbor, TokenAmount, TokenId, TokenModuleCborTypeDiscriminator,
};

/// Details provided by the token module in the event of rejecting a
/// transaction.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenModuleRejectReason {
    /// The unique symbol of the token, which produced this event.
    pub token_id:    TokenId,
    /// The type of the reject reason.
    pub reason_type: TokenModuleCborTypeDiscriminator,
    /// (Optional) CBOR-encoded details.
    pub details:     Option<RawCbor>,
}

impl TokenModuleRejectReason {
    pub fn to_reject_reason_type(&self) -> TokenModuleRejectReasonType {
        use TokenModuleRejectReasonType::*;

        Other
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
    OperationNotPermitted(OperationNotPermittedRejectReason),
    MintWouldOverflow(MintWouldOverflowRejectReason),
    /// Represents unknown reject reason type
    Other,
}

/// A token holder address was not valid.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressNotFoundRejectReason {
    /// The index in the list of operations of the failing operation.
    pub index:   usize,
    /// The address that could not be resolved.
    pub address: TokenHolder,
}

impl CborSerialize for AddressNotFoundRejectReason {
    fn serialize<C: CborEncoder>(&self, encoder: &mut C) -> CborResult<()> {

        encoder.encode_map(
            if self.index.is_null() { 0 } else { 1 }
                + if self.address.is_null() { 0 } else { 1 },
        )?;

        if !self.index.is_null() {
            MapKeyRef::Text("index").serialize(encoder)?;
            self.index.serialize(encoder)?;
        }

        if !self.address.is_null() {
            MapKeyRef::Text("address").serialize(encoder)?;
            self.address.serialize(encoder)?;
        }
        Ok(())
    }
}

// todo ar test

impl CborDeserialize for AddressNotFoundRejectReason {
    fn deserialize<C: CborDecoder>(decoder: &mut C) -> CborResult<Self>
    where
        Self: Sized,
    {

        let mut index = None;
        let mut address = None;
        let map_size = decoder.decode_map()?;
        for _ in 0..map_size {
            let map_key = MapKey::deserialize(decoder)?;
            
            match map_key.as_ref() {
                MapKeyRef::Text("index") => {
                    index = Some(CborDeserialize::deserialize(decoder)?);
                }
                MapKeyRef::Text("address") => {
                    address = Some(CborDeserialize::deserialize(decoder)?);
                }
                key => return Err(CborError::unknown_map_key(key)),
            }
        }
        let index = match index {
            None => match CborDeserialize::null() {
                None => return Err(CborError::map_value_missing(MapKeyRef::Text("index"))),
                Some(null) => null,
            },
            Some(coin_info) => coin_info,
        };

        let address = match address {
            None => match CborDeserialize::null() {
                None => return Err(CborError::map_value_missing(MapKeyRef::Text("address"))),
                Some(null) => null,
            },
            Some(address) => address,
        };

        Ok(Self { address, index })
    }
}


/// The balance of tokens on the sender account is insufficient
/// to perform the operation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenBalanceInsufficientRejectReason {
    /// The index in the list of operations of the failing operation.
    pub index:             usize,
    /// The available balance of the sender.
    pub available_balance: TokenAmount,
    /// The minimum required balance to perform the operation.
    pub required_balance:  TokenAmount,
}

/// The transaction could not be deserialized.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnsupportedOperationRejectReason {
    /// The index in the list of operations of the failing operation.
    pub index:          usize,
    /// The type of operation that was not supported.
    pub operation_type: String,
    /// The reason why the operation was not supported.
    pub reason:         Option<String>,
}

/// The operation requires that a participating account has a certain
/// permission, but the account does not have that permission.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationNotPermittedRejectReason {
    /// The index in the list of operations of the failing operation.
    pub index:   usize,
    /// (Optionally) the address that does not have the necessary permissions to
    /// perform the operation.
    pub address: Option<TokenHolder>,
    /// The reason why the operation is not permitted.
    pub reason:  Option<String>,
}

/// Minting the requested amount would overflow the representable token amount.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MintWouldOverflowRejectReason {
    /// The index in the list of operations of the failing operation.
    pub index:                    usize,
    /// The requested amount to mint.
    pub requested_amount:         TokenAmount,
    /// The current supply of the token.
    pub current_supply:           TokenAmount,
    /// The maximum representable token amount.
    pub max_representable_amount: TokenAmount,
}
