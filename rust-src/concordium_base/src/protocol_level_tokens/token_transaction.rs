use crate::{
    common::{
        cbor,
        cbor::{
            CborDecoder, CborDeserialize, CborEncoder, CborSerializationError,
            CborSerializationResult, CborSerialize, DataItemType,
        },
    },
    protocol_level_tokens::{token_holder::TokenHolder, RawCbor, TokenAmount, TokenId},
    transactions::Memo,
};
use concordium_base_derive::{CborDeserialize, CborSerialize};

/// Embedded CBOR, see <https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml>
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

impl TokenOperationsPayload {
    pub fn deserialize_operations(&self) -> CborSerializationResult<TokenOperations> {
        TokenOperations::try_from_cbor(&self.operations)
    }
}

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
#[cbor(transparent)]
pub struct TokenOperations {
    pub operations: Vec<TokenOperation>,
}

impl TokenOperations {
    pub fn try_from_cbor(cbor: &RawCbor) -> CborSerializationResult<Self> {
        cbor::cbor_decode(cbor.as_ref())
    }

    pub fn to_cbor(&self) -> CborSerializationResult<RawCbor> {
        Ok(RawCbor::from(cbor::cbor_encode(&self)?))
    }
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TokenOperation {
    Transfer(TokenTransfer),
    Unknown,
}

impl CborSerialize for TokenOperation {
    fn serialize<C: CborEncoder>(&self, encoder: &mut C) -> CborSerializationResult<()> {
        #[derive(Debug, CborSerialize)]
        struct TokenOperationCbor<'a> {
            transfer: Option<&'a TokenTransfer>,
        }

        match self {
            TokenOperation::Transfer(transfer) => {
                let cbor = TokenOperationCbor {
                    transfer: Some(transfer),
                };

                cbor.serialize(encoder)
            }
            TokenOperation::Unknown => Err(CborSerializationError::invalid_data(
                "cannot serialize unknown variant",
            )),
        }
    }
}

impl CborDeserialize for TokenOperation {
    fn deserialize<C: CborDecoder>(decoder: &mut C) -> CborSerializationResult<Self>
    where
        Self: Sized, {
        #[derive(Debug, CborDeserialize)]
        struct TokenOperationCbor {
            transfer: Option<TokenTransfer>,
        }

        let cbor = TokenOperationCbor::deserialize(decoder)?;

        Ok(if let Some(transfer) = cbor.transfer {
            Self::Transfer(transfer)
        } else {
            Self::Unknown
        })
    }
}

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
pub struct TokenTransfer {
    /// The amount of tokens to transfer.
    pub amount:    TokenAmount,
    /// The recipient account.
    pub recipient: TokenHolder,
    /// An optional memo.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo:      Option<CborMemo>,
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CborMemo {
    /// Memo that is not encoded as CBOR
    Raw(Memo),
    /// Memo encoded as CBOR
    Cbor(Memo),
}

impl CborSerialize for CborMemo {
    fn serialize<C: CborEncoder>(&self, encoder: &mut C) -> CborSerializationResult<()> {
        match self {
            Self::Raw(memo) => memo.serialize(encoder),
            Self::Cbor(memo) => {
                encoder.encode_tag(CBOR_TAG)?;
                memo.serialize(encoder)
            }
        }
    }
}

impl CborDeserialize for CborMemo {
    fn deserialize<C: CborDecoder>(decoder: &mut C) -> CborSerializationResult<Self>
    where
        Self: Sized, {
        Ok(match decoder.peek_data_item_type()? {
            DataItemType::Tag => {
                decoder.decode_tag_expect(CBOR_TAG)?;
                Self::Cbor(Memo::deserialize(decoder)?)
            }
            _ => Self::Raw(Memo::deserialize(decoder)?),
        })
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::{
        common::cbor,
        protocol_level_tokens::{token_holder::test_fixtures::ADDRESS, HolderAccount},
    };

    #[test]
    fn test_cbor_memo_cbor() {
        let memo = CborMemo::Raw(Memo::try_from(vec![0x01, 0x02, 0x03, 0x04]).unwrap());

        let cbor = cbor::cbor_encode(&memo).unwrap();
        assert_eq!(hex::encode(&cbor), "4401020304");
        let memo_decoded: CborMemo = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(memo_decoded, memo);

        let memo = CborMemo::Cbor(Memo::try_from(vec![0x01, 0x02, 0x03, 0x04]).unwrap());

        let cbor = cbor::cbor_encode(&memo).unwrap();
        assert_eq!(hex::encode(&cbor), "d8184401020304");
        let memo_decoded: CborMemo = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(memo_decoded, memo);
    }

    #[test]
    fn test_token_operations_transfer_cbor() {
        let operations = TokenOperations {
            operations: vec![TokenOperation::Transfer(TokenTransfer {
                amount:    TokenAmount::from_raw(12300, 3),
                recipient: TokenHolder::HolderAccount(HolderAccount {
                    address:   ADDRESS,
                    coin_info: None,
                }),
                memo:      None,
            })],
        };

        let cbor = cbor::cbor_encode(&operations).unwrap();
        assert_eq!(hex::encode(&cbor), "81a1687472616e73666572a266616d6f756e74c4822219300c69726563697069656e74d99d73a10358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let operation_decoded: TokenOperations = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(operation_decoded, operations);
    }
}
