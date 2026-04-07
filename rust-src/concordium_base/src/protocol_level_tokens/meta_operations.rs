use crate::{
    common::cbor::{self, CborSerializationResult},
    protocol_level_tokens::{
        CborHolderAccount, CborMemo, RawCbor, TokenAmount, TokenId, TokenOperation,
    },
};
use concordium_base_derive::{CborDeserialize, CborSerialize};

pub mod meta_operations {
    use super::*;
    use crate::protocol_level_tokens::operations;
    use concordium_contracts_common::AccountAddress;

    /// Construct a PLT transfer meta-update operation.
    pub fn transfer_tokens(
        token_id: TokenId,
        receiver: AccountAddress,
        amount: TokenAmount,
    ) -> MetaUpdateOperation {
        (token_id, operations::transfer_tokens(receiver, amount)).into()
    }

    /// Construct a PLT transfer meta-update operation with a memo.
    pub fn transfer_tokens_with_memo(
        token_id: TokenId,
        receiver: AccountAddress,
        amount: TokenAmount,
        memo: CborMemo,
    ) -> MetaUpdateOperation {
        (
            token_id,
            operations::transfer_tokens_with_memo(receiver, amount, memo),
        )
            .into()
    }

    /// Construct a PLT mint meta-update operation.
    pub fn mint_tokens(token_id: TokenId, amount: TokenAmount) -> MetaUpdateOperation {
        (token_id, operations::mint_tokens(amount)).into()
    }

    /// Consturct a PLT burn meta-update operation.
    pub fn burn_tokens(token_id: TokenId, amount: TokenAmount) -> MetaUpdateOperation {
        (token_id, operations::burn_tokens(amount)).into()
    }

    /// Construct a PLT add-allow-list meta-update operation.
    pub fn add_token_allow_list(token_id: TokenId, target: AccountAddress) -> MetaUpdateOperation {
        (token_id, operations::add_token_allow_list(target)).into()
    }

    /// Construct a PLT remove-allow-list meta-update operation.
    pub fn remove_token_allow_list(
        token_id: TokenId,
        target: AccountAddress,
    ) -> MetaUpdateOperation {
        (token_id, operations::remove_token_allow_list(target)).into()
    }

    /// Construct a PLT add-deny-list meta-update operation.
    pub fn add_token_deny_list(token_id: TokenId, target: AccountAddress) -> MetaUpdateOperation {
        (token_id, operations::add_token_deny_list(target)).into()
    }

    /// Construct a PLT remove-deny-list meta-update operation.
    pub fn remove_token_deny_list(
        token_id: TokenId,
        target: AccountAddress,
    ) -> MetaUpdateOperation {
        (token_id, operations::remove_token_deny_list(target)).into()
    }

    /// Construct a pause meta-update operation.
    pub fn pause(token_id: TokenId) -> MetaUpdateOperation {
        MetaUpdateOperation::Pause(MetaTokenPauseDetails { token: token_id })
    }

    /// Construct an unpause meta-update operation.
    pub fn unpause(token_id: TokenId) -> MetaUpdateOperation {
        MetaUpdateOperation::Unpause(MetaTokenPauseDetails { token: token_id })
    }
}

/// Payload for meta-update transaction. The transaction is a list of meta-update operations
/// that can be decoded from CBOR using [`MetaUpdatePayload::decode_operations`].
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "serde_deprecated", serde(rename_all = "camelCase"))]
pub struct MetaUpdatePayload {
    /// Meta-update operations in the transaction.
    pub operations: RawCbor,
}

impl MetaUpdatePayload {
    /// Decode meta-update operations from CBOR
    pub fn decode_operations(&self) -> CborSerializationResult<MetaUpdateOperations> {
        cbor::cbor_decode(&self.operations)
    }
}

/// A list of meta-update operations. Can be composed into a meta-update
/// transaction via [`MetaUpdatePayload`]. The operations are CBOR encoded in the
/// transaction payload.
#[derive(Debug, Clone, PartialEq, CborSerialize, CborDeserialize)]
#[cbor(transparent)]
pub struct MetaUpdateOperations {
    /// List of meta-update operations.
    pub operations: Vec<MetaUpdateOperation>,
}

impl FromIterator<MetaUpdateOperation> for MetaUpdateOperations {
    fn from_iter<T: IntoIterator<Item = MetaUpdateOperation>>(iter: T) -> Self {
        MetaUpdateOperations {
            operations: iter.into_iter().collect(),
        }
    }
}

impl MetaUpdateOperations {
    pub fn new(operations: Vec<MetaUpdateOperation>) -> Self {
        Self { operations }
    }
}

/// Meta-update operation. Operation can be composed to a meta-update
/// transaction via [`MetaUpdateOperations`] and [`MetaUpdatePayload`].
/// The operation is CBOR encoded in the transaction payload.
///
/// Meta-update operations are a superset of [`TokenOperation`]s augmented
/// with the token ID that the operation applies to. This allows meta-update
/// transactions to perform multiple operations on different tokens in a single
/// transaction.
#[derive(Debug, Clone, PartialEq, CborSerialize, CborDeserialize)]
#[cbor(map)]
pub enum MetaUpdateOperation {
    /// Protocol-level token transfer operation
    Transfer(MetaTokenTransfer),
    /// Protocol-level token mint operation
    Mint(MetaTokenSupplyUpdateDetails),
    /// Protocol-level token burn operation
    Burn(MetaTokenSupplyUpdateDetails),
    /// Operation that adds an account to the allow list of a protocol-level
    /// token
    AddAllowList(MetaTokenListUpdateDetails),
    /// Operation that removes an account from the allow list of a protocol-
    /// level token
    RemoveAllowList(MetaTokenListUpdateDetails),
    /// Operation that adds an account to the deny list of a protocol-level
    /// token
    AddDenyList(MetaTokenListUpdateDetails),
    /// Operation that removes an account from the deny list of a protocol-level
    /// token
    RemoveDenyList(MetaTokenListUpdateDetails),
    /// Operation that pauses execution of any balance changing operations for a
    /// protocol-level token
    Pause(MetaTokenPauseDetails),
    /// Operation that unpauses execution of any balance changing operations for
    /// a protocol-level token
    Unpause(MetaTokenPauseDetails),
}

impl From<(TokenId, TokenOperation)> for MetaUpdateOperation {
    fn from((token_id, operation): (TokenId, TokenOperation)) -> Self {
        match operation {
            TokenOperation::Transfer(details) => {
                MetaUpdateOperation::Transfer((token_id, details).into())
            }
            TokenOperation::Mint(details) => MetaUpdateOperation::Mint((token_id, details).into()),
            TokenOperation::Burn(details) => MetaUpdateOperation::Burn((token_id, details).into()),
            TokenOperation::AddAllowList(details) => {
                MetaUpdateOperation::AddAllowList((token_id, details).into())
            }
            TokenOperation::RemoveAllowList(details) => {
                MetaUpdateOperation::RemoveAllowList((token_id, details).into())
            }
            TokenOperation::AddDenyList(details) => {
                MetaUpdateOperation::AddDenyList((token_id, details).into())
            }
            TokenOperation::RemoveDenyList(details) => {
                MetaUpdateOperation::RemoveDenyList((token_id, details).into())
            }
            TokenOperation::Pause(details) => {
                MetaUpdateOperation::Pause((token_id, details).into())
            }
            TokenOperation::Unpause(details) => {
                MetaUpdateOperation::Unpause((token_id, details).into())
            }
        }
    }
}

/// A discriminated version of [`MetaUpdateOperation`] for the purpose of
/// dispatching to the appropriate operation handler.
#[derive(PartialEq, Debug)]
pub enum MetaUpdateOperationKind {
    /// A [`TokenOperation`] for a specific [`TokenId`].
    Token((TokenId, TokenOperation)),
}

impl From<MetaUpdateOperation> for MetaUpdateOperationKind {
    fn from(value: MetaUpdateOperation) -> Self {
        match value {
            MetaUpdateOperation::Transfer(details) => {
                let (token_id, details) = details.into();
                Self::Token((token_id, TokenOperation::Transfer(details)))
            }
            MetaUpdateOperation::Mint(details) => {
                let (token_id, details) = details.into();
                Self::Token((token_id, TokenOperation::Mint(details)))
            }
            MetaUpdateOperation::Burn(details) => {
                let (token_id, details) = details.into();
                Self::Token((token_id, TokenOperation::Burn(details)))
            }
            MetaUpdateOperation::AddAllowList(details) => {
                let (token_id, details) = details.into();
                Self::Token((token_id, TokenOperation::AddAllowList(details)))
            }
            MetaUpdateOperation::RemoveAllowList(details) => {
                let (token_id, details) = details.into();
                Self::Token((token_id, TokenOperation::RemoveAllowList(details)))
            }
            MetaUpdateOperation::AddDenyList(details) => {
                let (token_id, details) = details.into();
                Self::Token((token_id, TokenOperation::AddDenyList(details)))
            }
            MetaUpdateOperation::RemoveDenyList(details) => {
                let (token_id, details) = details.into();
                Self::Token((token_id, TokenOperation::RemoveDenyList(details)))
            }
            MetaUpdateOperation::Pause(details) => {
                let (token_id, details) = details.into();
                Self::Token((token_id, TokenOperation::Pause(details)))
            }
            MetaUpdateOperation::Unpause(details) => {
                let (token_id, details) = details.into();
                Self::Token((token_id, TokenOperation::Unpause(details)))
            }
        }
    }
}

/// Details of an operation that changes a protocol-level token supply.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "serde_deprecated", serde(rename_all = "camelCase"))]
pub struct MetaTokenSupplyUpdateDetails {
    /// Token the operation applies to.
    pub token: TokenId,
    /// Change in supply of the token. Must be interpreted as an increment or
    /// decrement depending on whether the operation is a mint or burn.
    pub amount: TokenAmount,
}

impl From<(TokenId, super::TokenSupplyUpdateDetails)> for MetaTokenSupplyUpdateDetails {
    fn from(value: (TokenId, super::TokenSupplyUpdateDetails)) -> Self {
        MetaTokenSupplyUpdateDetails {
            token: value.0,
            amount: value.1.amount,
        }
    }
}

impl From<MetaTokenSupplyUpdateDetails> for (TokenId, super::TokenSupplyUpdateDetails) {
    fn from(value: MetaTokenSupplyUpdateDetails) -> Self {
        (
            value.token,
            super::TokenSupplyUpdateDetails {
                amount: value.amount,
            },
        )
    }
}

/// Details of an operation that changes the `paused` state of a protocol level
/// token.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "serde_deprecated", serde(rename_all = "camelCase"))]
pub struct MetaTokenPauseDetails {
    /// Token the operation applies to.
    pub token: TokenId,
}

impl From<(TokenId, super::TokenPauseDetails)> for MetaTokenPauseDetails {
    fn from((token, _): (TokenId, super::TokenPauseDetails)) -> Self {
        MetaTokenPauseDetails { token }
    }
}

impl From<MetaTokenPauseDetails> for (TokenId, super::TokenPauseDetails) {
    fn from(value: MetaTokenPauseDetails) -> Self {
        (value.token, super::TokenPauseDetails {})
    }
}

/// Details of an operation that adds or removes an account from
/// an allow or deny list.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "serde_deprecated", serde(rename_all = "camelCase"))]
pub struct MetaTokenListUpdateDetails {
    /// Token the operation applies to.
    pub token: TokenId,
    /// Account that is added to or removed from a list
    pub target: CborHolderAccount,
}

impl From<(TokenId, super::TokenListUpdateDetails)> for MetaTokenListUpdateDetails {
    fn from((token, details): (TokenId, super::TokenListUpdateDetails)) -> Self {
        MetaTokenListUpdateDetails {
            token,
            target: details.target,
        }
    }
}

impl From<MetaTokenListUpdateDetails> for (TokenId, super::TokenListUpdateDetails) {
    fn from(value: MetaTokenListUpdateDetails) -> Self {
        (
            value.token,
            super::TokenListUpdateDetails {
                target: value.target,
            },
        )
    }
}

/// Protocol-level token transfer
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "serde_deprecated", serde(rename_all = "camelCase"))]
pub struct MetaTokenTransfer {
    /// Token the operation applies to.
    pub token: TokenId,
    /// The amount of tokens to transfer.
    pub amount: TokenAmount,
    /// The recipient account.
    pub recipient: CborHolderAccount,
    /// An optional memo.
    #[cfg_attr(
        feature = "serde_deprecated",
        serde(skip_serializing_if = "Option::is_none")
    )]
    pub memo: Option<CborMemo>,
}

impl From<(TokenId, super::TokenTransfer)> for MetaTokenTransfer {
    fn from((token, transfer): (TokenId, super::TokenTransfer)) -> Self {
        MetaTokenTransfer {
            token,
            amount: transfer.amount,
            recipient: transfer.recipient,
            memo: transfer.memo,
        }
    }
}

impl From<MetaTokenTransfer> for (TokenId, super::TokenTransfer) {
    fn from(value: MetaTokenTransfer) -> Self {
        (
            value.token,
            super::TokenTransfer {
                amount: value.amount,
                recipient: value.recipient,
                memo: value.memo,
            },
        )
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::common::cbor;
    use crate::protocol_level_tokens::test_fixtures::ADDRESS;
    use crate::transactions::Memo;

    #[test]
    fn test_meta_operation_cbor_transfer() {
        let operation = MetaUpdateOperation::Transfer(MetaTokenTransfer {
            token: "tokenid1".parse().unwrap(),
            amount: TokenAmount::from_raw(100000, 2),
            recipient: CborHolderAccount::from(ADDRESS),
            memo: Some(CborMemo::Raw(Memo::try_from(vec![1, 2, 3, 4]).unwrap())),
        });
        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(hex::encode(&cbor), "a1687472616e73666572a4646d656d6f440102030465746f6b656e68746f6b656e69643166616d6f756e74c482211a000186a069726563697069656e74d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let operation_decoded: MetaUpdateOperation =
            cbor::cbor_decode(&cbor).expect("CBOR deserialize");
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_meta_operation_cbor_mint() {
        let operation = MetaUpdateOperation::Mint(MetaTokenSupplyUpdateDetails {
            token: "PLTx".parse().unwrap(),
            amount: TokenAmount::from_raw(1000, 0),
        });
        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(
            hex::encode(&cbor),
            "a1646d696e74a265746f6b656e64504c547866616d6f756e74c482001903e8"
        );
        let operation_decoded: MetaUpdateOperation =
            cbor::cbor_decode(&cbor).expect("CBOR deserialize");
        assert_eq!(operation_decoded, operation);
        // An alternative CBOR encoding that uses indefinite length strings, oversize ints, and
        // non-canonical key ordering.
        let operation_decoded: MetaUpdateOperation =
            cbor::cbor_decode(hex::decode("a17f646d696e74ffa266616d6f756e74c482001b00000000000003e865746f6b656e7f63504c546178ff").unwrap()).expect("CBOR deserialize");
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_meta_operation_cbor_burn() {
        let operation = MetaUpdateOperation::Burn(MetaTokenSupplyUpdateDetails {
            token: "xxx2".parse().unwrap(),
            amount: TokenAmount::from_raw(9999999999999, 27),
        });
        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(
            hex::encode(&cbor),
            "a1646275726ea265746f6b656e647878783266616d6f756e74c482381a1b000009184e729fff"
        );
        let operation_decoded: MetaUpdateOperation =
            cbor::cbor_decode(&cbor).expect("CBOR deserialize");
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_meta_operation_cbor_add_allow_list() {
        let operation = MetaUpdateOperation::AddAllowList(MetaTokenListUpdateDetails {
            token: "testPLT".parse().unwrap(),
            target: CborHolderAccount::from(ADDRESS),
        });
        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(
            hex::encode(&cbor),
            "a16c616464416c6c6f774c697374a265746f6b656e6774657374504c5466746172676574d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        );
        let operation_decoded: MetaUpdateOperation =
            cbor::cbor_decode(&cbor).expect("CBOR deserialize");
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_meta_operation_cbor_remove_allow_list() {
        let operation = MetaUpdateOperation::RemoveAllowList(MetaTokenListUpdateDetails {
            token: "testPLT".parse().unwrap(),
            target: CborHolderAccount::from(ADDRESS),
        });
        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(
            hex::encode(&cbor),
            "a16f72656d6f7665416c6c6f774c697374a265746f6b656e6774657374504c5466746172676574d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        );
        let operation_decoded: MetaUpdateOperation =
            cbor::cbor_decode(&cbor).expect("CBOR deserialize");
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_meta_operation_cbor_add_deny_list() {
        let operation = MetaUpdateOperation::AddDenyList(MetaTokenListUpdateDetails {
            token: "testPLT".parse().unwrap(),
            target: CborHolderAccount::from(ADDRESS),
        });
        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(
            hex::encode(&cbor),
            "a16b61646444656e794c697374a265746f6b656e6774657374504c5466746172676574d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        );
        let operation_decoded: MetaUpdateOperation =
            cbor::cbor_decode(&cbor).expect("CBOR deserialize");
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_meta_operation_cbor_remove_deny_list() {
        let operation = MetaUpdateOperation::RemoveDenyList(MetaTokenListUpdateDetails {
            token: "testPLT".parse().unwrap(),
            target: CborHolderAccount::from(ADDRESS),
        });
        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(
            hex::encode(&cbor),
            "a16e72656d6f766544656e794c697374a265746f6b656e6774657374504c5466746172676574d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        );
        let operation_decoded: MetaUpdateOperation =
            cbor::cbor_decode(&cbor).expect("CBOR deserialize");
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_meta_operation_cbor_pause() {
        let operation = MetaUpdateOperation::Pause(MetaTokenPauseDetails {
            token: "testPLT".parse().unwrap(),
        });
        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(
            hex::encode(&cbor),
            "a1657061757365a165746f6b656e6774657374504c54"
        );
        let operation_decoded: MetaUpdateOperation =
            cbor::cbor_decode(&cbor).expect("CBOR deserialize");
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_meta_operation_cbor_unpause() {
        let operation = MetaUpdateOperation::Unpause(MetaTokenPauseDetails {
            token: "testPLT".parse().unwrap(),
        });
        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(
            hex::encode(&cbor),
            "a167756e7061757365a165746f6b656e6774657374504c54"
        );
        let operation_decoded: MetaUpdateOperation =
            cbor::cbor_decode(&cbor).expect("CBOR deserialize");
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_meta_operation_token_operation_conversion() {
        // For each meta-update operation variant:
        // - construct a meta-update operation with some test data
        // - construct the corresponding token operation with the same test data
        // - convert in each direction and check that the result matches the original
        let token_id: TokenId = "tokenid1".parse().unwrap();
        let amount = TokenAmount::from_raw(100000, 2);
        let account = CborHolderAccount::from(ADDRESS);
        let memo = Some(CborMemo::Raw(Memo::try_from(vec![1, 2, 3, 4]).unwrap()));

        let token_transfer = TokenOperation::Transfer(super::super::TokenTransfer {
            amount,
            recipient: account.clone(),
            memo: memo.clone(),
        });
        let meta_transfer = MetaUpdateOperation::Transfer(MetaTokenTransfer {
            token: token_id.clone(),
            amount: amount,
            recipient: account.clone(),
            memo: memo.clone(),
        });
        assert_eq!(
            MetaUpdateOperation::from((token_id.clone(), token_transfer.clone())),
            meta_transfer
        );
        assert_eq!(
            MetaUpdateOperationKind::Token((token_id.clone(), token_transfer)),
            meta_transfer.into(),
        );

        let token_mint = TokenOperation::Mint(super::super::TokenSupplyUpdateDetails { amount });
        let meta_mint = MetaUpdateOperation::Mint(MetaTokenSupplyUpdateDetails {
            token: token_id.clone(),
            amount,
        });
        assert_eq!(
            MetaUpdateOperation::from((token_id.clone(), token_mint.clone())),
            meta_mint
        );
        assert_eq!(
            MetaUpdateOperationKind::Token((token_id.clone(), token_mint)),
            meta_mint.into(),
        );

        let token_burn = TokenOperation::Burn(super::super::TokenSupplyUpdateDetails { amount });
        let meta_burn = MetaUpdateOperation::Burn(MetaTokenSupplyUpdateDetails {
            token: token_id.clone(),
            amount,
        });
        assert_eq!(
            MetaUpdateOperation::from((token_id.clone(), token_burn.clone())),
            meta_burn
        );
        assert_eq!(
            MetaUpdateOperationKind::Token((token_id.clone(), token_burn)),
            meta_burn.into(),
        );

        let token_add_allow_list =
            TokenOperation::AddAllowList(super::super::TokenListUpdateDetails {
                target: account.clone(),
            });
        let meta_add_allow_list = MetaUpdateOperation::AddAllowList(MetaTokenListUpdateDetails {
            token: token_id.clone(),
            target: account.clone(),
        });
        assert_eq!(
            MetaUpdateOperation::from((token_id.clone(), token_add_allow_list.clone())),
            meta_add_allow_list
        );
        assert_eq!(
            MetaUpdateOperationKind::Token((token_id.clone(), token_add_allow_list)),
            meta_add_allow_list.into(),
        );

        let token_remove_allow_list =
            TokenOperation::RemoveAllowList(super::super::TokenListUpdateDetails {
                target: account.clone(),
            });
        let meta_remove_allow_list =
            MetaUpdateOperation::RemoveAllowList(MetaTokenListUpdateDetails {
                token: token_id.clone(),
                target: account.clone(),
            });
        assert_eq!(
            MetaUpdateOperation::from((token_id.clone(), token_remove_allow_list.clone())),
            meta_remove_allow_list
        );
        assert_eq!(
            MetaUpdateOperationKind::Token((token_id.clone(), token_remove_allow_list)),
            meta_remove_allow_list.into(),
        );

        let token_add_deny_list =
            TokenOperation::AddDenyList(super::super::TokenListUpdateDetails {
                target: account.clone(),
            });
        let meta_add_deny_list = MetaUpdateOperation::AddDenyList(MetaTokenListUpdateDetails {
            token: token_id.clone(),
            target: account.clone(),
        });
        assert_eq!(
            MetaUpdateOperation::from((token_id.clone(), token_add_deny_list.clone())),
            meta_add_deny_list
        );
        assert_eq!(
            MetaUpdateOperationKind::Token((token_id.clone(), token_add_deny_list)),
            meta_add_deny_list.into(),
        );

        let token_remove_deny_list =
            TokenOperation::RemoveDenyList(super::super::TokenListUpdateDetails {
                target: account.clone(),
            });
        let meta_remove_deny_list =
            MetaUpdateOperation::RemoveDenyList(MetaTokenListUpdateDetails {
                token: token_id.clone(),
                target: account.clone(),
            });
        assert_eq!(
            MetaUpdateOperation::from((token_id.clone(), token_remove_deny_list.clone())),
            meta_remove_deny_list
        );
        assert_eq!(
            MetaUpdateOperationKind::Token((token_id.clone(), token_remove_deny_list)),
            meta_remove_deny_list.into(),
        );

        let token_pause = TokenOperation::Pause(super::super::TokenPauseDetails {});
        let meta_pause = MetaUpdateOperation::Pause(MetaTokenPauseDetails {
            token: token_id.clone(),
        });
        assert_eq!(
            MetaUpdateOperation::from((token_id.clone(), token_pause.clone())),
            meta_pause
        );
        assert_eq!(
            MetaUpdateOperationKind::Token((token_id.clone(), token_pause)),
            meta_pause.into(),
        );

        let token_unpause = TokenOperation::Unpause(super::super::TokenPauseDetails {});
        let meta_unpause = MetaUpdateOperation::Unpause(MetaTokenPauseDetails {
            token: token_id.clone(),
        });
        assert_eq!(
            MetaUpdateOperation::from((token_id.clone(), token_unpause.clone())),
            meta_unpause
        );
        assert_eq!(
            MetaUpdateOperationKind::Token((token_id.clone(), token_unpause)),
            meta_unpause.into(),
        );
    }
}
