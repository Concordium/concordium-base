use crate::{
    protocol_level_tokens::{token_holder::TokenHolder, RawCbor, TokenAmount, TokenId},
    transactions::Memo,
};

const CBOR_TAG: u64 = 24;

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
/// Payload for token transaction. The transaction is a list of token
/// operations. Operations includes governance operations, transfers etc.
pub struct TokenOperationsPayload {
    /// Id of the token
    pub token_id:   TokenId,
    /// Token operations in the transaction
    pub operations: RawCbor,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TokenOperation {
    Transfer(TokenTransfer),
    Other,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenTransfer {
    /// The amount of tokens to transfer.
    pub amount:    TokenAmount,
    /// The recipient account.
    pub recipient: TokenHolder,
    /// An optional memo.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo:      Option<CborMemo>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CborMemo {
    /// Memo that is not encoded as CBOR
    Raw(Memo),
    /// Memo encoded as CBOR
    Cbor(Memo),
}
