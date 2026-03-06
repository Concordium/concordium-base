use crate::common::cbor::{
    CborDecoder, CborDeserialize, CborEncoder, CborMaybeKnown, CborSerialize,
};
use crate::{
    common::cbor::{self, CborSerializationResult},
    protocol_level_tokens::{CborHolderAccount, CoinInfo, RawCbor, TokenAmount, TokenId},
    transactions::Memo,
};
use concordium_base_derive::{CborDeserialize, CborSerialize};
use concordium_contracts_common::AccountAddress;

/// Module that implements easy construction of protocol level token operations.
///
/// The operations are composed to transactions via
/// [`construct::token_update_operations`](crate::transactions::construct::token_update_operations)
/// To construct and sign transactions, use
/// [`send::token_update_operations`](crate::transactions::send::token_update_operations)
pub mod operations {
    use super::*;

    /// Construct a protocol level tokens transfer operation.
    pub fn transfer_tokens(receiver: AccountAddress, amount: TokenAmount) -> TokenOperation {
        TokenOperation::Transfer(TokenTransfer {
            amount,
            recipient: CborHolderAccount {
                coin_info: Some(CoinInfo::CCD),
                address: receiver,
            },
            memo: None,
        })
    }

    /// Construct a protocol level tokens transfer operation with memo.
    pub fn transfer_tokens_with_memo(
        receiver: AccountAddress,
        amount: TokenAmount,
        memo: CborMemo,
    ) -> TokenOperation {
        TokenOperation::Transfer(TokenTransfer {
            amount,
            recipient: CborHolderAccount {
                coin_info: Some(CoinInfo::CCD),
                address: receiver,
            },
            memo: Some(memo),
        })
    }

    /// Construct a protocol level token mint operation.
    pub fn mint_tokens(amount: TokenAmount) -> TokenOperation {
        TokenOperation::Mint(TokenSupplyUpdateDetails { amount })
    }

    /// Construct a protocol level token burn operation.
    pub fn burn_tokens(amount: TokenAmount) -> TokenOperation {
        TokenOperation::Burn(TokenSupplyUpdateDetails { amount })
    }

    /// Construct operation to add target to protocol level token allow list.
    pub fn add_token_allow_list(target: AccountAddress) -> TokenOperation {
        TokenOperation::AddAllowList(TokenListUpdateDetails {
            target: CborHolderAccount {
                coin_info: Some(CoinInfo::CCD),
                address: target,
            },
        })
    }

    /// Construct operation to remove target from protocol level token allow.
    pub fn remove_token_allow_list(target: AccountAddress) -> TokenOperation {
        TokenOperation::RemoveAllowList(TokenListUpdateDetails {
            target: CborHolderAccount {
                coin_info: Some(CoinInfo::CCD),
                address: target,
            },
        })
    }

    /// Construct operation to add target to protocol level token deny list.
    pub fn add_token_deny_list(target: AccountAddress) -> TokenOperation {
        TokenOperation::AddDenyList(TokenListUpdateDetails {
            target: CborHolderAccount {
                coin_info: Some(CoinInfo::CCD),
                address: target,
            },
        })
    }

    /// Construct operation to remove target from protocol level token deny
    /// list.
    pub fn remove_token_deny_list(target: AccountAddress) -> TokenOperation {
        TokenOperation::RemoveDenyList(TokenListUpdateDetails {
            target: CborHolderAccount {
                coin_info: Some(CoinInfo::CCD),
                address: target,
            },
        })
    }

    /// Construct operation to pause protocol level token.
    pub fn pause() -> TokenOperation {
        TokenOperation::Pause(TokenPauseDetails {})
    }

    /// Construct operation to unpause protocol level token.
    pub fn unpause() -> TokenOperation {
        TokenOperation::Unpause(TokenPauseDetails {})
    }

    /// Construct operation to assign admin roles to an Address
    /// for a protocol level token.
    pub fn assign_admin_roles(
        account: AccountAddress,
        roles: Vec<TokenAdminRole>,
    ) -> TokenOperation {
        TokenOperation::AssignAdminRoles(TokenUpdateAdminRolesDetails {
            account: CborHolderAccount {
                coin_info: Some(CoinInfo::CCD),
                address: account,
            },
            roles,
        })
    }

    /// Construct operation to revoke admin roles from an Address
    /// for a protocol level token.
    pub fn revoke_admin_roles(
        account: AccountAddress,
        roles: Vec<TokenAdminRole>,
    ) -> TokenOperation {
        TokenOperation::RevokeAdminRoles(TokenUpdateAdminRolesDetails {
            account: CborHolderAccount {
                coin_info: Some(CoinInfo::CCD),
                address: account,
            },
            roles,
        })
    }
}

/// Embedded CBOR, see <https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml>
const CBOR_TAG: u64 = 24;

/// Payload for protocol level transaction. The transaction is a list of token
/// operations that can be decoded from CBOR using
/// [`TokenOperationsPayload::decode_operations`]. Operations includes
/// governance operations, transfers etc.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "serde_deprecated", serde(rename_all = "camelCase"))]
pub struct TokenOperationsPayload {
    /// Id of the token
    pub token_id: TokenId,
    /// Token operations in the transaction. CBOR encoding of [`TokenOperations`]
    pub operations: RawCbor,
}

impl TokenOperationsPayload {
    /// Decode token operations from CBOR
    pub fn decode_operations(&self) -> CborSerializationResult<TokenOperations> {
        cbor::cbor_decode(&self.operations)
    }

    /// Decode token operations from CBOR. Unknown operations are wrapped
    /// in [`CborMaybeKnown::Unknown`].
    ///
    /// Handling [`CborMaybeKnown::Unknown`] can be used to implement forwards compatability
    /// with future token operations. Unknown token operations can e.g. be ignored, if the handler is only interested
    /// in specific and known token operations.
    pub fn decode_operations_maybe_known(
        &self,
    ) -> CborSerializationResult<Vec<CborMaybeKnown<TokenOperation>>> {
        cbor::cbor_decode(&self.operations)
    }
}

/// A list of protocol level token operations. Can be composed to a protocol
/// level token transaction via [`TokenOperationsPayload`]. The operations are
/// CBOR encoded in the transaction payload.
#[derive(Debug, Clone, PartialEq, CborSerialize, CborDeserialize)]
#[cbor(transparent)]
pub struct TokenOperations {
    /// List of protocol level token operations
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
    pub fn new(operations: Vec<TokenOperation>) -> Self {
        Self { operations }
    }
}

/// Protocol level token operation. An operation can be composed to a protocol
/// level token transaction via [`TokenOperations`] and
/// [`TokenOperationsPayload`]. The operation is CBOR encoded in the transaction
/// payload.
#[derive(Debug, Clone, PartialEq, CborSerialize, CborDeserialize)]
#[cbor(map)]
pub enum TokenOperation {
    /// Protocol level token transfer operation
    Transfer(TokenTransfer),
    /// Protocol level token mint operation
    Mint(TokenSupplyUpdateDetails),
    /// Protocol level token burn operation
    Burn(TokenSupplyUpdateDetails),
    /// Operation that adds an account to the allow list of a protocol level
    /// token
    AddAllowList(TokenListUpdateDetails),
    /// Operation that removes an account from the allow list of a protocol
    /// level token
    RemoveAllowList(TokenListUpdateDetails),
    /// Operation that adds an account to the deny list of a protocol level
    /// token
    AddDenyList(TokenListUpdateDetails),
    /// Operation that removes an account from the deny list of a protocol level
    /// token
    RemoveDenyList(TokenListUpdateDetails),
    /// Operation that pauses execution of any balance changing operations for a
    /// protocol level token
    Pause(TokenPauseDetails),
    /// Operation that unpauses execution of any balance changing operations for
    /// a protocol level token
    Unpause(TokenPauseDetails),
    /// Operation to assign roles to an account for a protocol level token.
    AssignAdminRoles(TokenUpdateAdminRolesDetails),
    /// Operation to revoke roles for an account for a protocol level token.
    RevokeAdminRoles(TokenUpdateAdminRolesDetails),
}

/// Details of an operation that changes a protocol level token supply.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "serde_deprecated", serde(rename_all = "camelCase"))]
pub struct TokenSupplyUpdateDetails {
    /// Change in supply of the token. Must be interpreted as an increment or
    /// decrement depending on whether the operation is a mint or burn.
    pub amount: TokenAmount,
}

/// Details of an operation that changes the `paused` state of a protocol level
/// token.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "serde_deprecated", serde(rename_all = "camelCase"))]
pub struct TokenPauseDetails {}

/// Details of an operation that adds or removes an account from
/// an allow or deny list.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "serde_deprecated", serde(rename_all = "camelCase"))]
pub struct TokenListUpdateDetails {
    /// Account that is added to or removed from a list
    pub target: CborHolderAccount,
}

/// Details of an operation to assign or revoke roles for an account
/// for a protocol level token.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "serde_deprecated", serde(rename_all = "camelCase"))]
pub struct TokenUpdateAdminRolesDetails {
    /// roles to be assigned or revoked
    pub roles: Vec<TokenAdminRole>,
    /// Account that that will be assigned or revoked roles.
    pub account: CborHolderAccount,
}

/// Protocol level token transfer
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "serde_deprecated", serde(rename_all = "camelCase"))]
pub struct TokenTransfer {
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

/// Memo attached to a protocol level token transfer
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "serde_deprecated", serde(rename_all = "camelCase"))]
#[cbor(tagged)]
pub enum CborMemo {
    /// Memo that is not encoded as CBOR
    Raw(Memo),
    /// Memo encoded as CBOR
    #[cbor(tag = CBOR_TAG)]
    Cbor(Memo),
}

impl From<CborMemo> for Memo {
    fn from(value: CborMemo) -> Self {
        match value {
            CborMemo::Raw(memo) => memo,
            CborMemo::Cbor(memo) => memo,
        }
    }
}

/// Defines roles that can be assigned or revoked for an account, for a protocol
/// level token.
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum TokenAdminRole {
    UpdateAdminRoles,
    Mint,
    Burn,
    UpdateAllowList,
    UpdateDenyList,
    Pause,
    UpdateMetadata,
}

/// Admin Role names
const UPDATE_ADMIN_ROLES_ROLE_NAME: &str = "updateAdminRoles";
const MINT_ROLE_NAME: &str = "mint";
const BURN_ROLE_NAME: &str = "burn";
const UPDATE_ALLOW_LIST_ROLE_NAME: &str = "updateAllowList";
const UPDATE_DENY_LIST_ROLE_NAME: &str = "updateDenyList";
const PAUSE_ROLE_NAME: &str = "pause";
const UPDATE_METADATA_ROLE_NAME: &str = "updateMetadata";

/// Encoding the `TokenAdminRole` to string for Cbor
impl CborSerialize for TokenAdminRole {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> Result<(), C::WriteError> {
        let s = match self {
            TokenAdminRole::UpdateAdminRoles => UPDATE_ADMIN_ROLES_ROLE_NAME,
            TokenAdminRole::Mint => MINT_ROLE_NAME,
            TokenAdminRole::Burn => BURN_ROLE_NAME,
            TokenAdminRole::UpdateAllowList => UPDATE_ALLOW_LIST_ROLE_NAME,
            TokenAdminRole::UpdateDenyList => UPDATE_DENY_LIST_ROLE_NAME,
            TokenAdminRole::Pause => PAUSE_ROLE_NAME,
            TokenAdminRole::UpdateMetadata => UPDATE_METADATA_ROLE_NAME,
        };
        encoder.encode_text(s)
    }
}

/// Decoding the Cbor for a `TokenAdminRole`. Decoding gives text as bytes which can be
/// mapped back to the Admin Role constant names.
impl CborDeserialize for TokenAdminRole {
    fn deserialize<C: CborDecoder>(decoder: C) -> CborSerializationResult<Self>
    where
        Self: Sized,
    {
        let bytes = decoder.decode_text()?;
        let s = String::from_utf8(bytes)
            .map_err(crate::common::cbor::CborSerializationError::invalid_data)?;
        match s.as_str() {
            UPDATE_ADMIN_ROLES_ROLE_NAME => Ok(Self::UpdateAdminRoles),
            MINT_ROLE_NAME => Ok(Self::Mint),
            BURN_ROLE_NAME => Ok(Self::Burn),
            UPDATE_ALLOW_LIST_ROLE_NAME => Ok(Self::UpdateAllowList),
            UPDATE_DENY_LIST_ROLE_NAME => Ok(Self::UpdateDenyList),
            PAUSE_ROLE_NAME => Ok(Self::Pause),
            UPDATE_METADATA_ROLE_NAME => Ok(Self::UpdateMetadata),
            _ => Err(crate::common::cbor::CborSerializationError::invalid_data(
                format!("unknown token admin role: {s}"),
            )),
        }
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::{
        common::cbor::{self, value},
        protocol_level_tokens::{token_holder::test_fixtures::ADDRESS, CborHolderAccount},
    };
    use assert_matches::assert_matches;

    #[test]
    fn test_cbor_memo_cbor() {
        let memo = CborMemo::Raw(Memo::try_from(vec![0x01, 0x02, 0x03, 0x04]).unwrap());

        let cbor = cbor::cbor_encode(&memo);
        assert_eq!(hex::encode(&cbor), "4401020304");
        let memo_decoded: CborMemo = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(memo_decoded, memo);

        let memo = CborMemo::Cbor(Memo::try_from(vec![0x01, 0x02, 0x03, 0x04]).unwrap());

        let cbor = cbor::cbor_encode(&memo);
        assert_eq!(hex::encode(&cbor), "d8184401020304");
        let memo_decoded: CborMemo = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(memo_decoded, memo);
    }

    #[test]
    fn test_token_operations_cbor() {
        let operations = TokenOperations {
            operations: vec![TokenOperation::Transfer(TokenTransfer {
                amount: TokenAmount::from_raw(12300, 3),
                recipient: CborHolderAccount {
                    address: ADDRESS,
                    coin_info: None,
                },
                memo: None,
            })],
        };

        let cbor = cbor::cbor_encode(&operations);
        assert_eq!(hex::encode(&cbor), "81a1687472616e73666572a266616d6f756e74c4822219300c69726563697069656e74d99d73a10358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let operations_decoded: TokenOperations = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(operations_decoded, operations);
    }

    #[test]
    fn test_token_operation_cbor_transfer() {
        let operation = TokenOperation::Transfer(TokenTransfer {
            amount: TokenAmount::from_raw(12300, 3),
            recipient: CborHolderAccount {
                address: ADDRESS,
                coin_info: None,
            },
            memo: None,
        });

        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(hex::encode(&cbor), "a1687472616e73666572a266616d6f756e74c4822219300c69726563697069656e74d99d73a10358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let operation_decoded: TokenOperation = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_token_operation_cbor_mint() {
        let operation = TokenOperation::Mint(TokenSupplyUpdateDetails {
            amount: TokenAmount::from_raw(12300, 3),
        });

        let cbor = cbor::cbor_encode(&operation);
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

        let cbor = cbor::cbor_encode(&operation);
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
            target: CborHolderAccount {
                address: ADDRESS,
                coin_info: None,
            },
        });

        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(hex::encode(&cbor), "a16c616464416c6c6f774c697374a166746172676574d99d73a10358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let operation_decoded: TokenOperation = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_token_operation_cbor_remove_allow_list() {
        let operation = TokenOperation::RemoveAllowList(TokenListUpdateDetails {
            target: CborHolderAccount {
                address: ADDRESS,
                coin_info: None,
            },
        });

        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(hex::encode(&cbor), "a16f72656d6f7665416c6c6f774c697374a166746172676574d99d73a10358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let operation_decoded: TokenOperation = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_token_operation_cbor_add_deny_list() {
        let operation = TokenOperation::AddDenyList(TokenListUpdateDetails {
            target: CborHolderAccount {
                address: ADDRESS,
                coin_info: None,
            },
        });

        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(hex::encode(&cbor), "a16b61646444656e794c697374a166746172676574d99d73a10358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let operation_decoded: TokenOperation = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_token_operation_cbor_remove_deny_list() {
        let operation = TokenOperation::RemoveDenyList(TokenListUpdateDetails {
            target: CborHolderAccount {
                address: ADDRESS,
                coin_info: None,
            },
        });

        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(hex::encode(&cbor), "a16e72656d6f766544656e794c697374a166746172676574d99d73a10358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let operation_decoded: TokenOperation = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_token_operation_cbor_pause() {
        let operation = TokenOperation::Pause(TokenPauseDetails {});

        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(hex::encode(&cbor), "a1657061757365a0");
        let operation_decoded: TokenOperation = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_token_operation_cbor_unpause() {
        let operation = TokenOperation::Unpause(TokenPauseDetails {});

        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(hex::encode(&cbor), "a167756e7061757365a0");
        let operation_decoded: TokenOperation = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_token_operation_cbor_unknown_variant() {
        let cbor = hex::decode("a172736f6d65556e6b6e6f776e56617269616e74a266616d6f756e74c4822219300c69726563697069656e74d99d73a10358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20").unwrap();
        let operation_decoded: CborMaybeKnown<TokenOperation> = cbor::cbor_decode(&cbor).unwrap();
        assert_matches!(
            operation_decoded,
            CborMaybeKnown::Unknown(value::Value::Map(v)) if matches!(
                v.as_slice(),
                [(value::Value::Text(s), _), ..] if s == "someUnknownVariant"
            )
        );
    }

    #[test]
    fn test_token_operation_cbor_assign_admin_roles() {
        let operation = TokenOperation::AssignAdminRoles(TokenUpdateAdminRolesDetails {
            account: CborHolderAccount {
                address: ADDRESS,
                coin_info: None,
            },
            roles: vec![
                TokenAdminRole::UpdateAdminRoles,
                TokenAdminRole::Mint,
                TokenAdminRole::Burn,
                TokenAdminRole::UpdateAllowList,
                TokenAdminRole::UpdateDenyList,
                TokenAdminRole::Pause,
                TokenAdminRole::UpdateMetadata,
            ],
        });

        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(hex::encode(&cbor), "a17061737369676e41646d696e526f6c6573a265726f6c6573877075706461746541646d696e526f6c6573646d696e74646275726e6f757064617465416c6c6f774c6973746e75706461746544656e794c6973746570617573656e7570646174654d65746164617461676163636f756e74d99d73a10358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let operation_decoded: TokenOperation = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_token_operation_cbor_revoke_admin_roles() {
        let operation = TokenOperation::RevokeAdminRoles(TokenUpdateAdminRolesDetails {
            account: CborHolderAccount {
                address: ADDRESS,
                coin_info: None,
            },
            roles: vec![
                TokenAdminRole::UpdateAdminRoles,
                TokenAdminRole::Mint,
                TokenAdminRole::Burn,
                TokenAdminRole::UpdateAllowList,
                TokenAdminRole::UpdateDenyList,
                TokenAdminRole::Pause,
                TokenAdminRole::UpdateMetadata,
            ],
        });

        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(hex::encode(&cbor), "a1707265766f6b6541646d696e526f6c6573a265726f6c6573877075706461746541646d696e526f6c6573646d696e74646275726e6f757064617465416c6c6f774c6973746e75706461746544656e794c6973746570617573656e7570646174654d65746164617461676163636f756e74d99d73a10358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let operation_decoded: TokenOperation = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_token_operations_payload() {
        let operations = TokenOperations {
            operations: vec![TokenOperation::Transfer(TokenTransfer {
                amount: TokenAmount::from_raw(12300, 3),
                recipient: CborHolderAccount {
                    address: ADDRESS,
                    coin_info: None,
                },
                memo: None,
            })],
        };
        let payload = TokenOperationsPayload {
            token_id: "tk1".parse().unwrap(),
            operations: RawCbor::from(cbor::cbor_encode(&operations)),
        };

        let operations_decoded = payload.decode_operations().unwrap();
        assert_eq!(operations_decoded, operations);

        let operations_known: Vec<_> = operations
            .operations
            .iter()
            .map(|op| CborMaybeKnown::Known(op.clone()))
            .collect();
        let operations_decoded = payload.decode_operations_maybe_known().unwrap();
        assert_eq!(operations_decoded, operations_known);
    }
}
