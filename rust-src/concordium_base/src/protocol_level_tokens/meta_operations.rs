use crate::{
    common::cbor::{self, CborSerializationResult},
    protocol_level_locks::{LockConfig, LockId},
    protocol_level_tokens::{
        operations, CborHolderAccount, CborMemo, MetadataUrl, RawCbor, TokenAdminRole, TokenAmount,
        TokenId, TokenOperation,
    },
};
use concordium_base_derive::{CborDeserialize, CborSerialize};
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
pub fn remove_token_allow_list(token_id: TokenId, target: AccountAddress) -> MetaUpdateOperation {
    (token_id, operations::remove_token_allow_list(target)).into()
}

/// Construct a PLT add-deny-list meta-update operation.
pub fn add_token_deny_list(token_id: TokenId, target: AccountAddress) -> MetaUpdateOperation {
    (token_id, operations::add_token_deny_list(target)).into()
}

/// Construct a PLT remove-deny-list meta-update operation.
pub fn remove_token_deny_list(token_id: TokenId, target: AccountAddress) -> MetaUpdateOperation {
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

/// Construct an operation to assign admin roles to an address
/// for a protocol-level token.
pub fn assign_admin_roles(
    token_id: TokenId,
    account: AccountAddress,
    roles: Vec<TokenAdminRole>,
) -> MetaUpdateOperation {
    (token_id, operations::assign_admin_roles(account, roles)).into()
}

/// Construct an operation to revoke admin roles from an address
/// for a protocol-level token.
pub fn revoke_admin_roles(
    token_id: TokenId,
    account: AccountAddress,
    roles: Vec<TokenAdminRole>,
) -> MetaUpdateOperation {
    (token_id, operations::revoke_admin_roles(account, roles)).into()
}

/// Construct an operation to update token metadata for a
/// protocol-level token.
pub fn update_metadata(token_id: TokenId, metadata_url: MetadataUrl) -> MetaUpdateOperation {
    (token_id, operations::update_metadata(metadata_url)).into()
}

/// Construct an operation to fund a lock.
pub fn lock_fund(
    token_id: TokenId,
    lock_id: LockId,
    amount: TokenAmount,
    memo: Option<CborMemo>,
) -> MetaUpdateOperation {
    MetaUpdateOperation::LockFund(MetaLockFundDetails {
        token: token_id,
        lock: lock_id,
        amount,
        memo,
    })
}

/// Construct an operation to send funds controlled by a lock.
pub fn lock_send(
    token_id: TokenId,
    lock_id: LockId,
    source: AccountAddress,
    recipient: AccountAddress,
    amount: TokenAmount,
    memo: Option<CborMemo>,
) -> MetaUpdateOperation {
    MetaUpdateOperation::LockSend(MetaLockSendDetails {
        token: token_id,
        lock: lock_id,
        source: CborHolderAccount::from(source),
        recipient: CborHolderAccount::from(recipient),
        amount,
        memo,
    })
}

/// Construct an operation to return funds controlled by a lock to the owner.
pub fn lock_return(
    token_id: TokenId,
    lock_id: LockId,
    source: AccountAddress,
    amount: TokenAmount,
    memo: Option<CborMemo>,
) -> MetaUpdateOperation {
    MetaUpdateOperation::LockReturn(MetaLockReturnDetails {
        token: token_id,
        lock: lock_id,
        source: CborHolderAccount::from(source),
        amount,
        memo,
    })
}

/// Construct an operation to create a lock.
pub fn lock_create(config: LockConfig) -> MetaUpdateOperation {
    MetaUpdateOperation::LockCreate(MetaLockCreateDetails { config })
}

/// Construct an operation to cancel a lock.
pub fn lock_cancel(lock_id: LockId, memo: Option<CborMemo>) -> MetaUpdateOperation {
    MetaUpdateOperation::LockCancel(MetaLockCancelDetails {
        lock: lock_id,
        memo,
    })
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
    /// Operation to assign roles to an account for a protocol-level token.
    AssignAdminRoles(MetaTokenUpdateAdminRolesDetails),
    /// Operation to revoke roles for an account for a protocol-level token.
    RevokeAdminRoles(MetaTokenUpdateAdminRolesDetails),
    /// Operation to update token metadata
    UpdateMetadata(MetaMetadataUrlDetails),
    /// Operation to fund a lock.
    LockFund(MetaLockFundDetails),
    /// Operation to send funds controlled by a lock.
    LockSend(MetaLockSendDetails),
    /// Operation to return funds controlled by a lock to the owner.
    LockReturn(MetaLockReturnDetails),
    /// Operation to create a lock.
    LockCreate(MetaLockCreateDetails),
    /// Operation to cancel a lock.
    LockCancel(MetaLockCancelDetails),
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
            TokenOperation::AssignAdminRoles(details) => {
                MetaUpdateOperation::AssignAdminRoles((token_id, details).into())
            }
            TokenOperation::RevokeAdminRoles(details) => {
                MetaUpdateOperation::RevokeAdminRoles((token_id, details).into())
            }
            TokenOperation::UpdateMetadata(details) => {
                MetaUpdateOperation::UpdateMetadata((token_id, details).into())
            }
        }
    }
}

/// Lock operations.
#[derive(PartialEq, Debug, Clone)]
pub enum LockOperation {
    /// Operation to fund a lock.
    Fund(MetaLockFundDetails),
    /// Operation to send funds controlled by a lock.
    Send(MetaLockSendDetails),
    /// Operation to return funds controlled by a lock to the owner.
    Return(MetaLockReturnDetails),
    /// Operation to create a lock.
    Create(MetaLockCreateDetails),
    /// Operation to cancel a lock.
    Cancel(MetaLockCancelDetails),
}

/// A discriminated version of [`MetaUpdateOperation`] for the purpose of
/// dispatching to the appropriate operation handler.
#[derive(PartialEq, Debug, Clone)]
pub enum MetaUpdateOperationKind {
    /// A [`TokenOperation`] for a specific [`TokenId`].
    Token((TokenId, TokenOperation)),
    /// A [`LockOperation`].
    Lock(LockOperation),
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
            MetaUpdateOperation::AssignAdminRoles(details) => {
                let (token_id, details) = details.into();
                Self::Token((token_id, TokenOperation::AssignAdminRoles(details)))
            }
            MetaUpdateOperation::RevokeAdminRoles(details) => {
                let (token_id, details) = details.into();
                Self::Token((token_id, TokenOperation::RevokeAdminRoles(details)))
            }
            MetaUpdateOperation::UpdateMetadata(details) => {
                let (token_id, details) = details.into();
                Self::Token((token_id, TokenOperation::UpdateMetadata(details)))
            }
            MetaUpdateOperation::LockFund(details) => Self::Lock(LockOperation::Fund(details)),
            MetaUpdateOperation::LockSend(details) => Self::Lock(LockOperation::Send(details)),
            MetaUpdateOperation::LockReturn(details) => Self::Lock(LockOperation::Return(details)),
            MetaUpdateOperation::LockCreate(details) => Self::Lock(LockOperation::Create(details)),
            MetaUpdateOperation::LockCancel(details) => Self::Lock(LockOperation::Cancel(details)),
        }
    }
}

/// Details of an operation that changes a protocol-level token supply.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
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

/// Details of an operation to assign or revoke roles for an account
/// for a protocol-level token.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
pub struct MetaTokenUpdateAdminRolesDetails {
    /// Token the operation applies to.
    pub token: TokenId,
    /// Roles to be assigned or revoked.
    pub roles: Vec<super::TokenAdminRole>,
    /// Account that that will be assigned or revoked roles.
    pub account: CborHolderAccount,
}

impl From<(TokenId, super::TokenUpdateAdminRolesDetails)> for MetaTokenUpdateAdminRolesDetails {
    fn from((token, details): (TokenId, super::TokenUpdateAdminRolesDetails)) -> Self {
        MetaTokenUpdateAdminRolesDetails {
            token,
            roles: details.roles,
            account: details.account,
        }
    }
}

impl From<MetaTokenUpdateAdminRolesDetails> for (TokenId, super::TokenUpdateAdminRolesDetails) {
    fn from(value: MetaTokenUpdateAdminRolesDetails) -> Self {
        (
            value.token,
            super::TokenUpdateAdminRolesDetails {
                roles: value.roles,
                account: value.account,
            },
        )
    }
}

/// Protocol-level token transfer
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
pub struct MetaTokenTransfer {
    /// Token the operation applies to.
    pub token: TokenId,
    /// The amount of tokens to transfer.
    pub amount: TokenAmount,
    /// The recipient account.
    pub recipient: CborHolderAccount,
    /// An optional memo.
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

/// Details of an operation to update token metadata.
#[derive(Debug, Clone, PartialEq, CborSerialize, CborDeserialize)]
pub struct MetaMetadataUrlDetails {
    /// Token to update.
    pub token: TokenId,
    /// New metadata URL.
    pub metadata_url: super::MetadataUrl,
}

impl From<(TokenId, super::MetadataUrl)> for MetaMetadataUrlDetails {
    fn from((token, metadata_url): (TokenId, super::MetadataUrl)) -> Self {
        MetaMetadataUrlDetails {
            token,
            metadata_url,
        }
    }
}

impl From<MetaMetadataUrlDetails> for (TokenId, super::MetadataUrl) {
    fn from(value: MetaMetadataUrlDetails) -> Self {
        (value.token, value.metadata_url)
    }
}

/// Fund a lock by locking the specified amount on the sender account under the
/// control of the specified lock.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
pub struct MetaLockFundDetails {
    /// Token to fund the lock with.
    pub token: TokenId,
    /// The lock that will control the funds.
    pub lock: LockId,
    /// The amount to lock.
    pub amount: TokenAmount,
    /// An optional memo.
    pub memo: Option<CborMemo>,
}

/// Send funds under the control of a lock from a source account to a recipient.
/// The funds will be transferred to the available balance of the recipient.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
pub struct MetaLockSendDetails {
    /// Token to send.
    pub token: TokenId,
    /// The lock that controls the funds.
    pub lock: LockId,
    /// The account holding the funds.
    pub source: CborHolderAccount,
    /// The amount of tokens to transfer.
    pub amount: TokenAmount,
    /// The recipient of the funds.
    pub recipient: CborHolderAccount,
    /// An optional memo.
    pub memo: Option<CborMemo>,
}

/// Return funds under the control of a lock to the owner account.
/// The funds are moved from the locked balance to the available balance
/// of the owner.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
pub struct MetaLockReturnDetails {
    /// The token the operation applies to.
    pub token: TokenId,
    /// The lock controlling the funds.
    pub lock: LockId,
    /// The account holding the funds.
    pub source: CborHolderAccount,
    /// The amount of tokens to return.
    pub amount: TokenAmount,
    /// An optional memo.
    pub memo: Option<CborMemo>,
}

/// Create a lock with the specified configuration.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
#[cbor(transparent)]
pub struct MetaLockCreateDetails {
    pub config: LockConfig,
}

/// Cancel a lock, returning funds to their owners and destroying the lock.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
pub struct MetaLockCancelDetails {
    /// The lock to cancel.
    pub lock: LockId,
    /// An optional memo.
    pub memo: Option<CborMemo>,
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::common::cbor;
    use crate::common::types::TransactionTime;
    use crate::protocol_level_locks::{
        LockController, LockControllerSimpleV0, LockControllerSimpleV0Capability,
        LockControllerSimpleV0Grant,
    };
    use crate::protocol_level_tokens::{test_fixtures::ADDRESS, MetadataUrl, TokenAdminRole};
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
    fn test_meta_operation_cbor_assign_admin_roles() {
        let operation = MetaUpdateOperation::AssignAdminRoles(MetaTokenUpdateAdminRolesDetails {
            token: "testPLT".parse().unwrap(),
            roles: vec![TokenAdminRole::Mint, TokenAdminRole::Pause],
            account: CborHolderAccount::from(ADDRESS),
        });
        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(
            hex::encode(&cbor),
            "a17061737369676e41646d696e526f6c6573a365726f6c657382646d696e7465706175736565746f6b656e6774657374504c54676163636f756e74d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        );
        let operation_decoded: MetaUpdateOperation =
            cbor::cbor_decode(&cbor).expect("CBOR deserialize");
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_meta_operation_cbor_revoke_admin_roles() {
        let operation = MetaUpdateOperation::RevokeAdminRoles(MetaTokenUpdateAdminRolesDetails {
            token: "testPLT".parse().unwrap(),
            roles: vec![
                TokenAdminRole::UpdateAdminRoles,
                TokenAdminRole::Burn,
                TokenAdminRole::UpdateMetadata,
            ],
            account: CborHolderAccount::from(ADDRESS),
        });
        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(
            hex::encode(&cbor),
            "a1707265766f6b6541646d696e526f6c6573a365726f6c6573837075706461746541646d696e526f6c6573646275726e6e7570646174654d6574616461746165746f6b656e6774657374504c54676163636f756e74d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        );
        let operation_decoded: MetaUpdateOperation =
            cbor::cbor_decode(&cbor).expect("CBOR deserialize");
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_meta_operation_cbor_update_metadata() {
        let operation = MetaUpdateOperation::UpdateMetadata(MetaMetadataUrlDetails {
            token: "testPLT".parse().unwrap(),
            metadata_url: MetadataUrl {
                url: "https://example.com/metadata.json".to_string(),
                checksum_sha_256: Some([255u8; 32].into()),
                additional: Default::default(),
            },
        });
        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(
            hex::encode(&cbor),
            "a16e7570646174654d65746164617461a265746f6b656e6774657374504c546b6d6574616461746155726ca26375726c782168747470733a2f2f6578616d706c652e636f6d2f6d657461646174612e6a736f6e6e636865636b73756d5368613235365820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
        let operation_decoded: MetaUpdateOperation =
            cbor::cbor_decode(&cbor).expect("CBOR deserialize");
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_meta_operation_cbor_lock_fund() {
        let operation = MetaUpdateOperation::LockFund(MetaLockFundDetails {
            token: "testPLT".parse().unwrap(),
            lock: LockId::new(20, 7, 0),
            amount: TokenAmount::from_raw(5000, 0),
            memo: Some(CborMemo::Cbor(Memo::try_from(vec![0xa0]).unwrap())),
        });
        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(
            hex::encode(&cbor),
            "a1686c6f636b46756e64a4646c6f636bd99fd883140700646d656d6fd81841a065746f6b656e6774657374504c5466616d6f756e74c48200191388"
        );
        let operation_decoded: MetaUpdateOperation =
            cbor::cbor_decode(&cbor).expect("CBOR deserialize");
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_meta_operation_cbor_lock_send() {
        let operation = MetaUpdateOperation::LockSend(MetaLockSendDetails {
            token: "testPLT".parse().unwrap(),
            lock: LockId::new(20, 7, 0),
            source: CborHolderAccount::from(ADDRESS),
            amount: TokenAmount::from_raw(5000, 2),
            recipient: CborHolderAccount::from(AccountAddress([0x11; 32])),
            memo: None,
        });
        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(
            hex::encode(&cbor),
            "a1686c6f636b53656e64a5646c6f636bd99fd88314070065746f6b656e6774657374504c5466616d6f756e74c4822119138866736f75726365d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2069726563697069656e74d99d73a201d99d71a1011903970358201111111111111111111111111111111111111111111111111111111111111111"
        );
        let operation_decoded: MetaUpdateOperation =
            cbor::cbor_decode(&cbor).expect("CBOR deserialize");
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_meta_operation_cbor_lock_return() {
        let operation = MetaUpdateOperation::LockReturn(MetaLockReturnDetails {
            token: "testPLT".parse().unwrap(),
            lock: LockId::new(20, 7, 0),
            source: CborHolderAccount::from(ADDRESS),
            amount: TokenAmount::from_raw(5000, 0),
            memo: None,
        });
        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(
            hex::encode(&cbor),
            "a16a6c6f636b52657475726ea4646c6f636bd99fd88314070065746f6b656e6774657374504c5466616d6f756e74c4820019138866736f75726365d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        );
        let operation_decoded: MetaUpdateOperation =
            cbor::cbor_decode(&cbor).expect("CBOR deserialize");
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_meta_operation_cbor_lock_create() {
        let operation = MetaUpdateOperation::LockCreate(MetaLockCreateDetails {
            config: LockConfig {
                recipients: vec![CborHolderAccount::from(ADDRESS)],
                expiry: TransactionTime::from_seconds(1_000_000),
                controller: LockController::SimpleV0(LockControllerSimpleV0 {
                    grants: vec![
                        LockControllerSimpleV0Grant {
                            account: CborHolderAccount::from(ADDRESS),
                            roles: vec![
                                LockControllerSimpleV0Capability::Fund,
                                LockControllerSimpleV0Capability::Cancel,
                            ],
                        },
                        LockControllerSimpleV0Grant {
                            account: CborHolderAccount::from(AccountAddress([0x11; 32])),
                            roles: vec![LockControllerSimpleV0Capability::Send],
                        },
                    ],
                    tokens: vec!["testPLT".parse().unwrap(), "TKN".parse().unwrap()],
                    keep_alive: false,
                    memo: None,
                }),
            },
        });
        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(
            hex::encode(&cbor),
            "a16a6c6f636b437265617465a366657870697279c11a000f42406a636f6e74726f6c6c6572a16873696d706c655630a2666772616e747382a265726f6c6573826466756e646663616e63656c676163636f756e74d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20a265726f6c6573816473656e64676163636f756e74d99d73a201d99d71a101190397035820111111111111111111111111111111111111111111111111111111111111111166746f6b656e73826774657374504c5463544b4e6a726563697069656e747381d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        );
        let operation_decoded: MetaUpdateOperation =
            cbor::cbor_decode(&cbor).expect("CBOR deserialize");
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_meta_operation_cbor_lock_cancel() {
        let operation = MetaUpdateOperation::LockCancel(MetaLockCancelDetails {
            lock: LockId::new(20, 7, 0),
            memo: Some(CborMemo::Cbor(Memo::try_from(vec![0xa0]).unwrap())),
        });
        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(
            hex::encode(&cbor),
            "a16a6c6f636b43616e63656ca2646c6f636bd99fd883140700646d656d6fd81841a0"
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
        // - construct the meta-update operation using the `meta_operations` helper function
        //   and check that it matches the original
        let token_id: TokenId = "tokenid1".parse().unwrap();
        let amount = TokenAmount::from_raw(100000, 2);
        let account = CborHolderAccount::from(ADDRESS);
        let cbor_memo = CborMemo::Raw(Memo::try_from(vec![1, 2, 3, 4]).unwrap());
        let memo = Some(cbor_memo.clone());

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
            transfer_tokens_with_memo(token_id.clone(), ADDRESS, amount, cbor_memo.clone()),
            meta_transfer
        );
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
        assert_eq!(mint_tokens(token_id.clone(), amount), meta_mint);
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
        assert_eq!(burn_tokens(token_id.clone(), amount), meta_burn);
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
            add_token_allow_list(token_id.clone(), ADDRESS),
            meta_add_allow_list
        );
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
            remove_token_allow_list(token_id.clone(), ADDRESS),
            meta_remove_allow_list
        );
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
            add_token_deny_list(token_id.clone(), ADDRESS),
            meta_add_deny_list
        );
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
            remove_token_deny_list(token_id.clone(), ADDRESS),
            meta_remove_deny_list
        );
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
        assert_eq!(pause(token_id.clone()), meta_pause);
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
        assert_eq!(unpause(token_id.clone()), meta_unpause);
        assert_eq!(
            MetaUpdateOperation::from((token_id.clone(), token_unpause.clone())),
            meta_unpause
        );
        assert_eq!(
            MetaUpdateOperationKind::Token((token_id.clone(), token_unpause)),
            meta_unpause.into(),
        );

        let assign_roles = vec![TokenAdminRole::Mint, TokenAdminRole::Pause];
        let token_assign_admin_roles =
            TokenOperation::AssignAdminRoles(super::super::TokenUpdateAdminRolesDetails {
                roles: assign_roles.clone(),
                account: account.clone(),
            });
        let meta_assign_admin_roles =
            MetaUpdateOperation::AssignAdminRoles(MetaTokenUpdateAdminRolesDetails {
                token: token_id.clone(),
                roles: assign_roles.clone(),
                account: account.clone(),
            });
        assert_eq!(
            assign_admin_roles(token_id.clone(), ADDRESS, assign_roles.clone()),
            meta_assign_admin_roles
        );
        assert_eq!(
            MetaUpdateOperation::from((token_id.clone(), token_assign_admin_roles.clone())),
            meta_assign_admin_roles
        );
        assert_eq!(
            MetaUpdateOperationKind::Token((token_id.clone(), token_assign_admin_roles)),
            meta_assign_admin_roles.into(),
        );

        let revoke_roles = vec![
            TokenAdminRole::Burn,
            TokenAdminRole::UpdateMetadata,
            TokenAdminRole::UpdateDenyList,
        ];
        let token_revoke_admin_roles =
            TokenOperation::RevokeAdminRoles(super::super::TokenUpdateAdminRolesDetails {
                roles: revoke_roles.clone(),
                account: account.clone(),
            });
        let meta_revoke_admin_roles =
            MetaUpdateOperation::RevokeAdminRoles(MetaTokenUpdateAdminRolesDetails {
                token: token_id.clone(),
                roles: revoke_roles.clone(),
                account: account.clone(),
            });
        assert_eq!(
            revoke_admin_roles(token_id.clone(), ADDRESS, revoke_roles.clone()),
            meta_revoke_admin_roles
        );
        assert_eq!(
            MetaUpdateOperation::from((token_id.clone(), token_revoke_admin_roles.clone())),
            meta_revoke_admin_roles
        );
        assert_eq!(
            MetaUpdateOperationKind::Token((token_id.clone(), token_revoke_admin_roles)),
            meta_revoke_admin_roles.into(),
        );

        let metadata_url = MetadataUrl {
            url: "https://example.com/metadata.json".to_string(),
            checksum_sha_256: Some([0u8; 32].into()),
            additional: Default::default(),
        };
        let token_update_metadata = TokenOperation::UpdateMetadata(metadata_url.clone());
        let meta_update_metadata = MetaUpdateOperation::UpdateMetadata(MetaMetadataUrlDetails {
            token: token_id.clone(),
            metadata_url: metadata_url.clone(),
        });
        assert_eq!(
            update_metadata(token_id.clone(), metadata_url.clone()),
            meta_update_metadata
        );
        assert_eq!(
            MetaUpdateOperation::from((token_id.clone(), token_update_metadata.clone())),
            meta_update_metadata
        );
        assert_eq!(
            MetaUpdateOperationKind::Token((token_id.clone(), token_update_metadata)),
            meta_update_metadata.into(),
        );
    }
}
