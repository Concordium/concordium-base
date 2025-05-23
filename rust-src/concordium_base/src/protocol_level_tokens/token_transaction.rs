use crate::common::{types::*, Buffer};
use crate::protocol_level_tokens::token_holder::TokenHolder;
use crate::protocol_level_tokens::{RawCbor, TokenAmount, TokenId};
use crate::transactions::Memo;

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
/// Payload for token transaction. The transaction is a list of token operations.
/// Operations includes governance operations, transfers etc.
pub struct TokenOperationsPayload {
    /// Id of the token
    pub token_id: TokenId,
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
    pub amount: TokenAmount,
    /// The recipient account.
    pub recipient: TokenHolder,
    /// An optional memo.
    // todo consider memo type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo: Option<CborMemo>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CborMemo {
    /// Memo that is not encoded as CBOR
    Raw(Memo),
    /// Memo encoded as CBOR
    Cbor(Memo),
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::protocol_level_tokens::HolderAccount;

    const TEST_ADDRESS: AccountAddress = AccountAddress([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ]);

    fn cbor_serialize<T: serde::Serialize>(value: &T) -> Vec<u8> {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(value, &mut bytes).unwrap();
        bytes
    }
    
    #[test]
    fn test_transfer_cbor() {
        let operation = TokenOperation::Transfer(TokenTransfer {
            amount: TokenAmount::from_raw(12300, 4),
            recipient: TokenHolder::HolderAccount(HolderAccount {
                address: TEST_ADDRESS,
            }),
            memo: None,
        });
        
        let bytes = cbor_serialize(&operation);
        println!("{}", hex::encode(&bytes));
    }
}
