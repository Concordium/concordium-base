use crate::{
    common::{
        cbor,
        cbor::{
            CborDecoder, CborDeserialize, CborEncoder, CborSerializationResult, CborSerialize,
            DataItemHeader,
        },
    },
    protocol_level_tokens::{
        token_holder::TokenHolder, CoinInfo, HolderAccount, RawCbor, TokenAmount, TokenId,
    },
    transactions::Memo,
};
use concordium_base_derive::{CborDeserialize, CborSerialize};
use concordium_contracts_common::AccountAddress;

pub mod operations {
    use super::*;

    /// Construct a tokens transfer operation.
    pub fn transfer_tokens(receiver: AccountAddress, amount: TokenAmount) -> TokenOperation {
        TokenOperation::Transfer(TokenTransfer {
            amount,
            recipient: TokenHolder::HolderAccount(HolderAccount {
                coin_info: Some(CoinInfo::CCD),
                address:   receiver,
            }),
            memo: None,
        })
    }

    /// Construct a tokens transfer operation with memo.
    pub fn transfer_tokens_with_memo(
        receiver: AccountAddress,
        amount: TokenAmount,
        memo: CborMemo,
    ) -> TokenOperation {
        TokenOperation::Transfer(TokenTransfer {
            amount,
            recipient: TokenHolder::HolderAccount(HolderAccount {
                coin_info: Some(CoinInfo::CCD),
                address:   receiver,
            }),
            memo: Some(memo),
        })
    }

    /// Construct a token mint operation.
    pub fn mint_tokens(amount: TokenAmount) -> TokenOperation {
        TokenOperation::Mint(TokenSupplyUpdateDetails { amount })
    }

    /// Construct a token burn operation.
    pub fn burn_tokens(amount: TokenAmount) -> TokenOperation {
        TokenOperation::Burn(TokenSupplyUpdateDetails { amount })
    }

    /// Construct operation to add target to token allow list.
    pub fn add_token_allow_list(target: AccountAddress) -> TokenOperation {
        TokenOperation::AddAllowList(TokenListUpdateDetails {
            target: TokenHolder::HolderAccount(HolderAccount {
                coin_info: Some(CoinInfo::CCD),
                address:   target,
            }),
        })
    }

    /// Construct operation to remove target from token allow.
    pub fn remove_token_allow_list(target: AccountAddress) -> TokenOperation {
        TokenOperation::RemoveAllowList(TokenListUpdateDetails {
            target: TokenHolder::HolderAccount(HolderAccount {
                coin_info: Some(CoinInfo::CCD),
                address:   target,
            }),
        })
    }

    /// Construct operation to add target to token deny list.
    pub fn add_token_deny_list(target: AccountAddress) -> TokenOperation {
        TokenOperation::AddDenyList(TokenListUpdateDetails {
            target: TokenHolder::HolderAccount(HolderAccount {
                coin_info: Some(CoinInfo::CCD),
                address:   target,
            }),
        })
    }

    /// Construct transaction to remove target from token deny list.
    pub fn remove_token_deny_list(target: AccountAddress) -> TokenOperation {
        TokenOperation::RemoveDenyList(TokenListUpdateDetails {
            target: TokenHolder::HolderAccount(HolderAccount {
                coin_info: Some(CoinInfo::CCD),
                address:   target,
            }),
        })
    }
}

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

impl FromIterator<TokenOperation> for TokenOperations {
    fn from_iter<T: IntoIterator<Item = TokenOperation>>(iter: T) -> Self {
        Self {
            operations: iter.into_iter().collect(),
        }
    }
}

impl TokenOperations {
    pub fn new(operations: Vec<TokenOperation>) -> Self { Self { operations } }

    pub fn try_from_cbor(cbor: &RawCbor) -> CborSerializationResult<Self> {
        cbor::cbor_decode(cbor.as_ref())
    }

    pub fn to_cbor(&self) -> CborSerializationResult<RawCbor> {
        Ok(RawCbor::from(cbor::cbor_encode(&self)?))
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
#[cbor(map)]
pub enum TokenOperation {
    Transfer(TokenTransfer),
    Mint(TokenSupplyUpdateDetails),
    Burn(TokenSupplyUpdateDetails),
    AddAllowList(TokenListUpdateDetails),
    RemoveAllowList(TokenListUpdateDetails),
    AddDenyList(TokenListUpdateDetails),
    RemoveDenyList(TokenListUpdateDetails),
    #[cbor(other)]
    Unknown,
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
pub struct TokenSupplyUpdateDetails {
    pub amount: TokenAmount,
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
pub struct TokenListUpdateDetails {
    pub target: TokenHolder,
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
        Ok(match decoder.peek_data_item_header()? {
            DataItemHeader::Tag(CBOR_TAG) => {
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
    fn test_token_operations_cbor() {
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
        let operations_decoded: TokenOperations = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(operations_decoded, operations);
    }

    #[test]
    fn test_token_operation_cbor_transfer() {
        let operation = TokenOperation::Transfer(TokenTransfer {
            amount:    TokenAmount::from_raw(12300, 3),
            recipient: TokenHolder::HolderAccount(HolderAccount {
                address:   ADDRESS,
                coin_info: None,
            }),
            memo:      None,
        });

        let cbor = cbor::cbor_encode(&operation).unwrap();
        assert_eq!(hex::encode(&cbor), "a1687472616e73666572a266616d6f756e74c4822219300c69726563697069656e74d99d73a10358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let operation_decoded: TokenOperation = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_token_operation_cbor_mint() {
        let operation = TokenOperation::Mint(TokenSupplyUpdateDetails {
            amount: TokenAmount::from_raw(12300, 3),
        });

        let cbor = cbor::cbor_encode(&operation).unwrap();
        assert_eq!(
            hex::encode(&cbor),
            "a1646d696e74a166616d6f756e74c4822219300c"
        );
        let operation_decoded: TokenOperation = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_token_operation_cbor_burn() {
        let operation = TokenOperation::Burn(TokenSupplyUpdateDetails {
            amount: TokenAmount::from_raw(12300, 3),
        });

        let cbor = cbor::cbor_encode(&operation).unwrap();
        assert_eq!(
            hex::encode(&cbor),
            "a1646275726ea166616d6f756e74c4822219300c"
        );
        let operation_decoded: TokenOperation = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_token_operation_cbor_add_allow_list() {
        let operation = TokenOperation::AddAllowList(TokenListUpdateDetails {
            target: TokenHolder::HolderAccount(HolderAccount {
                address:   ADDRESS,
                coin_info: None,
            }),
        });

        let cbor = cbor::cbor_encode(&operation).unwrap();
        assert_eq!(hex::encode(&cbor), "a16c616464416c6c6f774c697374a166746172676574d99d73a10358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let operation_decoded: TokenOperation = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_token_operation_cbor_remove_allow_list() {
        let operation = TokenOperation::RemoveAllowList(TokenListUpdateDetails {
            target: TokenHolder::HolderAccount(HolderAccount {
                address:   ADDRESS,
                coin_info: None,
            }),
        });

        let cbor = cbor::cbor_encode(&operation).unwrap();
        assert_eq!(hex::encode(&cbor), "a16f72656d6f7665416c6c6f774c697374a166746172676574d99d73a10358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let operation_decoded: TokenOperation = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_token_operation_cbor_add_deny_list() {
        let operation = TokenOperation::AddDenyList(TokenListUpdateDetails {
            target: TokenHolder::HolderAccount(HolderAccount {
                address:   ADDRESS,
                coin_info: None,
            }),
        });

        let cbor = cbor::cbor_encode(&operation).unwrap();
        assert_eq!(hex::encode(&cbor), "a16b61646444656e794c697374a166746172676574d99d73a10358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let operation_decoded: TokenOperation = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_token_operation_cbor_remove_deny_list() {
        let operation = TokenOperation::RemoveDenyList(TokenListUpdateDetails {
            target: TokenHolder::HolderAccount(HolderAccount {
                address:   ADDRESS,
                coin_info: None,
            }),
        });

        let cbor = cbor::cbor_encode(&operation).unwrap();
        assert_eq!(hex::encode(&cbor), "a16e72656d6f766544656e794c697374a166746172676574d99d73a10358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let operation_decoded: TokenOperation = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_token_operation_cbor_unknown_variant() {
        let cbor = hex::decode("a172736f6d65556e6b6e6f776e56617269616e74a266616d6f756e74c4822219300c69726563697069656e74d99d73a10358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20").unwrap();
        let operation_decoded: TokenOperation = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(operation_decoded, TokenOperation::Unknown);
    }
}
