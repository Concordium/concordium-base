use crate::protocol_level_tokens::{
    RawCbor, TokenId, TokenModuleCborTypeDiscriminator,
};

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

