use super::{cbor::RawCbor, TokenId};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenHolderEvent {
    pub token_id:   TokenId,
    pub event_type: String,
    pub details:    RawCbor,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenGovernanceEvent {
    pub token_id:   TokenId,
    pub event_type: String,
    pub details:    RawCbor,
}
