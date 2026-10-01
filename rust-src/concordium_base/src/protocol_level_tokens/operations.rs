use crate::{
    common::cbor::{self, CborSerializationResult},
    protocol_level_locks::{LockConfig, LockId},
    protocol_level_tokens::{
        token_operations, CborHolderAccount, CborMemo, RawCbor, TokenAdminRole, TokenAmount,
        TokenId, TokenMetadataUrlDetails, TokenOperation,
    },
};
use concordium_base_derive::{CborDeserialize, CborSerialize};
use concordium_contracts_common::{hashes::Hash, AccountAddress};

/// Builders for unscoped token and lock operations.
pub mod operations {
    use super::*;

    /// Construct a PLT transfer unscoped operation.
    pub fn transfer_tokens(
        token_id: TokenId,
        receiver: AccountAddress,
        amount: TokenAmount,
    ) -> Operation {
        (
            token_id,
            token_operations::transfer_tokens(receiver, amount),
        )
            .into()
    }

    /// Construct a PLT transfer unscoped operation with a memo.
    pub fn transfer_tokens_with_memo(
        token_id: TokenId,
        receiver: AccountAddress,
        amount: TokenAmount,
        memo: CborMemo,
    ) -> Operation {
        (
            token_id,
            token_operations::transfer_tokens_with_memo(receiver, amount, memo),
        )
            .into()
    }

    /// Construct a PLT mint unscoped operation.
    pub fn mint_tokens(token_id: TokenId, amount: TokenAmount) -> Operation {
        (token_id, token_operations::mint_tokens(amount)).into()
    }

    /// Consturct a PLT burn unscoped operation.
    pub fn burn_tokens(token_id: TokenId, amount: TokenAmount) -> Operation {
        (token_id, token_operations::burn_tokens(amount)).into()
    }

    /// Construct a PLT add-allow-list unscoped operation.
    pub fn add_token_allow_list(token_id: TokenId, target: AccountAddress) -> Operation {
        (token_id, token_operations::add_token_allow_list(target)).into()
    }

    /// Construct a PLT remove-allow-list unscoped operation.
    pub fn remove_token_allow_list(token_id: TokenId, target: AccountAddress) -> Operation {
        (token_id, token_operations::remove_token_allow_list(target)).into()
    }

    /// Construct a PLT add-deny-list unscoped operation.
    pub fn add_token_deny_list(token_id: TokenId, target: AccountAddress) -> Operation {
        (token_id, token_operations::add_token_deny_list(target)).into()
    }

    /// Construct a PLT remove-deny-list unscoped operation.
    pub fn remove_token_deny_list(token_id: TokenId, target: AccountAddress) -> Operation {
        (token_id, token_operations::remove_token_deny_list(target)).into()
    }

    /// Construct a pause unscoped operation.
    pub fn pause_token(token_id: TokenId) -> Operation {
        Operation::TokenPause(TokenPauseDetailsWithId { token: token_id })
    }

    /// Construct an unpause unscoped operation.
    pub fn unpause_token(token_id: TokenId) -> Operation {
        Operation::TokenUnpause(TokenPauseDetailsWithId { token: token_id })
    }

    /// Construct an operation to assign admin roles to an address
    /// for a protocol-level token.
    pub fn assign_token_admin_roles(
        token_id: TokenId,
        account: AccountAddress,
        roles: Vec<TokenAdminRole>,
    ) -> Operation {
        (
            token_id,
            token_operations::assign_admin_roles(account, roles),
        )
            .into()
    }

    /// Construct an operation to revoke admin roles from an address
    /// for a protocol-level token.
    pub fn revoke_token_admin_roles(
        token_id: TokenId,
        account: AccountAddress,
        roles: Vec<TokenAdminRole>,
    ) -> Operation {
        (
            token_id,
            token_operations::revoke_admin_roles(account, roles),
        )
            .into()
    }

    /// Construct an operation to update token metadata for a
    /// protocol-level token.
    pub fn update_token_metadata(
        token_id: TokenId,
        metadata_url: TokenMetadataUrlDetails,
    ) -> Operation {
        (token_id, token_operations::update_metadata(metadata_url)).into()
    }

    /// Construct an operation to fund a lock.
    pub fn fund_lock(
        token_id: TokenId,
        lock_id: LockId,
        amount: TokenAmount,
        memo: Option<CborMemo>,
    ) -> Operation {
        Operation::LockFund(LockFund {
            token: token_id,
            lock: lock_id,
            amount,
            memo,
        })
    }

    /// Construct an operation to send funds controlled by a lock.
    pub fn send_locked_tokens(
        token_id: TokenId,
        lock_id: LockId,
        source: AccountAddress,
        recipient: AccountAddress,
        amount: TokenAmount,
        memo: Option<CborMemo>,
    ) -> Operation {
        Operation::LockSend(LockSend {
            token: token_id,
            lock: lock_id,
            source: CborHolderAccount::from(source),
            recipient: CborHolderAccount::from(recipient),
            amount,
            memo,
        })
    }

    /// Construct an operation to release funds controlled by a lock to the owner.
    pub fn release_locked_tokens(
        token_id: TokenId,
        lock_id: LockId,
        source: AccountAddress,
        amount: TokenAmount,
        memo: Option<CborMemo>,
    ) -> Operation {
        Operation::LockRelease(LockRelease {
            token: token_id,
            lock: lock_id,
            source: CborHolderAccount::from(source),
            amount,
            memo,
        })
    }

    /// Construct an operation to create a lock.
    pub fn create_lock(config: LockConfig) -> Operation {
        Operation::LockCreate(LockCreate { config })
    }

    /// Construct an operation to cancel a lock.
    pub fn cancel_lock(lock_id: LockId, memo: Option<CborMemo>) -> Operation {
        Operation::LockCancel(LockCancel {
            lock: lock_id,
            memo,
        })
    }
}

/// Payload for "unscoped" token update transaction. The transaction is a list of unscoped operations
/// that can be decoded from CBOR using [`OperationsPayload::decode_operations`].
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "serde_deprecated", serde(rename_all = "camelCase"))]
pub struct OperationsPayload {
    /// Unscoped operations in the transaction.
    pub operations: RawCbor,
}

impl OperationsPayload {
    /// Decodes the CBOR-encoded unscoped operations.
    ///
    /// # Errors
    ///
    /// Returns an error when the embedded bytes are not a valid `operations`
    /// CBOR sequence.
    pub fn decode_operations(&self) -> CborSerializationResult<Operations> {
        cbor::cbor_decode(&self.operations)
    }
}

/// A list of unscoped operations. Can be composed into a token update
/// transaction via [`OperationsPayload`]. The operations are CBOR encoded in the
/// transaction payload.
#[derive(Debug, Clone, PartialEq, CborSerialize, CborDeserialize)]
#[cbor(transparent)]
pub struct Operations {
    /// List of unscoped operations.
    pub operations: Vec<Operation>,
}

impl FromIterator<Operation> for Operations {
    fn from_iter<T: IntoIterator<Item = Operation>>(iter: T) -> Self {
        Operations {
            operations: iter.into_iter().collect(),
        }
    }
}

impl Operations {
    /// Creates an unscoped operation collection from `operations`.
    ///
    /// # Examples
    ///
    /// ```
    /// use concordium_base::protocol_level_tokens::Operations;
    ///
    /// let operations = Operations::new(Vec::new());
    /// assert!(operations.operations.is_empty());
    /// ```
    pub fn new(operations: Vec<Operation>) -> Self {
        Self { operations }
    }
}

/// Unscoped operation can be composed to a token update
/// transaction via [`Operations`] and [`OperationsPayload`].
/// The operation is CBOR encoded in the transaction payload.
///
/// Unscoped operations are a superset of [`TokenOperation`]s augmented
/// with the token ID that the operation applies to. This allows token update
/// transactions to perform multiple operations on different tokens in a single
/// transaction.
#[derive(Debug, Clone, PartialEq, CborSerialize, CborDeserialize)]
#[cbor(map)]
pub enum Operation {
    /// Protocol-level token transfer operation
    TokenTransfer(TokenTransferWithId),
    /// Protocol-level token mint operation
    TokenMint(TokenSupplyUpdateDetailsWithId),
    /// Protocol-level token burn operation
    TokenBurn(TokenSupplyUpdateDetailsWithId),
    /// Operation that adds an account to the allow list of a protocol-level
    /// token
    TokenAddAllowList(TokenListUpdateDetailsWithId),
    /// Operation that removes an account from the allow list of a protocol-
    /// level token
    TokenRemoveAllowList(TokenListUpdateDetailsWithId),
    /// Operation that adds an account to the deny list of a protocol-level
    /// token
    TokenAddDenyList(TokenListUpdateDetailsWithId),
    /// Operation that removes an account from the deny list of a protocol-level
    /// token
    TokenRemoveDenyList(TokenListUpdateDetailsWithId),
    /// Operation that pauses execution of any balance changing operations for a
    /// protocol-level token
    TokenPause(TokenPauseDetailsWithId),
    /// Operation that unpauses execution of any balance changing operations for
    /// a protocol-level token
    TokenUnpause(TokenPauseDetailsWithId),
    /// Operation to assign roles to an account for a protocol-level token.
    TokenAssignAdminRoles(TokenUpdateAdminRolesDetailsWithId),
    /// Operation to revoke roles for an account for a protocol-level token.
    TokenRevokeAdminRoles(TokenUpdateAdminRolesDetailsWithId),
    /// Operation to update token metadata
    TokenUpdateMetadata(TokenMetadataUrlDetailsWithId),
    /// Operation to fund a lock using the operation's token ID.
    LockFund(LockFund),
    /// Operation to send funds controlled by a lock using the operation's token ID.
    LockSend(LockSend),
    /// Operation to release funds controlled by a lock using the operation's token ID.
    LockRelease(LockRelease),
    /// Operation to create a lock.
    LockCreate(LockCreate),
    /// Operation to cancel a lock.
    LockCancel(LockCancel),
}

impl From<(TokenId, TokenOperation)> for Operation {
    fn from((token_id, operation): (TokenId, TokenOperation)) -> Self {
        match operation {
            TokenOperation::Transfer(details) => {
                Operation::TokenTransfer((token_id, details).into())
            }
            TokenOperation::Mint(details) => Operation::TokenMint((token_id, details).into()),
            TokenOperation::Burn(details) => Operation::TokenBurn((token_id, details).into()),
            TokenOperation::AddAllowList(details) => {
                Operation::TokenAddAllowList((token_id, details).into())
            }
            TokenOperation::RemoveAllowList(details) => {
                Operation::TokenRemoveAllowList((token_id, details).into())
            }
            TokenOperation::AddDenyList(details) => {
                Operation::TokenAddDenyList((token_id, details).into())
            }
            TokenOperation::RemoveDenyList(details) => {
                Operation::TokenRemoveDenyList((token_id, details).into())
            }
            TokenOperation::Pause(details) => Operation::TokenPause((token_id, details).into()),
            TokenOperation::Unpause(details) => Operation::TokenUnpause((token_id, details).into()),
            TokenOperation::AssignAdminRoles(details) => {
                Operation::TokenAssignAdminRoles((token_id, details).into())
            }
            TokenOperation::RevokeAdminRoles(details) => {
                Operation::TokenRevokeAdminRoles((token_id, details).into())
            }
            TokenOperation::UpdateMetadata(details) => {
                Operation::TokenUpdateMetadata((token_id, details).into())
            }
        }
    }
}

/// Details of an operation that changes a protocol-level token supply.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
pub struct TokenSupplyUpdateDetailsWithId {
    /// Token the operation applies to.
    pub token: TokenId,
    /// Change in supply of the token. Must be interpreted as an increment or
    /// decrement depending on whether the operation is a mint or burn.
    pub amount: TokenAmount,
}

impl From<(TokenId, super::TokenSupplyUpdateDetails)> for TokenSupplyUpdateDetailsWithId {
    fn from(value: (TokenId, super::TokenSupplyUpdateDetails)) -> Self {
        TokenSupplyUpdateDetailsWithId {
            token: value.0,
            amount: value.1.amount,
        }
    }
}

impl From<TokenSupplyUpdateDetailsWithId> for (TokenId, super::TokenSupplyUpdateDetails) {
    fn from(value: TokenSupplyUpdateDetailsWithId) -> Self {
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
pub struct TokenPauseDetailsWithId {
    /// Token the operation applies to.
    pub token: TokenId,
}

impl From<(TokenId, super::TokenPauseDetails)> for TokenPauseDetailsWithId {
    fn from((token, _): (TokenId, super::TokenPauseDetails)) -> Self {
        TokenPauseDetailsWithId { token }
    }
}

impl From<TokenPauseDetailsWithId> for (TokenId, super::TokenPauseDetails) {
    fn from(value: TokenPauseDetailsWithId) -> Self {
        (value.token, super::TokenPauseDetails {})
    }
}

/// Details of an operation that adds or removes an account from
/// an allow or deny list.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
pub struct TokenListUpdateDetailsWithId {
    /// Token the operation applies to.
    pub token: TokenId,
    /// Account that is added to or removed from a list
    pub target: CborHolderAccount,
}

impl From<(TokenId, super::TokenListUpdateDetails)> for TokenListUpdateDetailsWithId {
    fn from((token, details): (TokenId, super::TokenListUpdateDetails)) -> Self {
        TokenListUpdateDetailsWithId {
            token,
            target: details.target,
        }
    }
}

impl From<TokenListUpdateDetailsWithId> for (TokenId, super::TokenListUpdateDetails) {
    fn from(value: TokenListUpdateDetailsWithId) -> Self {
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
pub struct TokenUpdateAdminRolesDetailsWithId {
    /// Token the operation applies to.
    pub token: TokenId,
    /// Roles to be assigned or revoked.
    pub roles: Vec<super::TokenAdminRole>,
    /// Account that that will be assigned or revoked roles.
    pub account: CborHolderAccount,
}

impl From<(TokenId, super::TokenUpdateAdminRolesDetails)> for TokenUpdateAdminRolesDetailsWithId {
    fn from((token, details): (TokenId, super::TokenUpdateAdminRolesDetails)) -> Self {
        TokenUpdateAdminRolesDetailsWithId {
            token,
            roles: details.roles,
            account: details.account,
        }
    }
}

impl From<TokenUpdateAdminRolesDetailsWithId> for (TokenId, super::TokenUpdateAdminRolesDetails) {
    fn from(value: TokenUpdateAdminRolesDetailsWithId) -> Self {
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
pub struct TokenTransferWithId {
    /// Token the operation applies to.
    pub token: TokenId,
    /// The amount of tokens to transfer.
    pub amount: TokenAmount,
    /// The recipient account.
    pub recipient: CborHolderAccount,
    /// An optional memo.
    pub memo: Option<CborMemo>,
}

impl From<(TokenId, super::TokenTransfer)> for TokenTransferWithId {
    fn from((token, transfer): (TokenId, super::TokenTransfer)) -> Self {
        TokenTransferWithId {
            token,
            amount: transfer.amount,
            recipient: transfer.recipient,
            memo: transfer.memo,
        }
    }
}

impl From<TokenTransferWithId> for (TokenId, super::TokenTransfer) {
    fn from(value: TokenTransferWithId) -> Self {
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
pub struct TokenMetadataUrlDetailsWithId {
    /// Token to update.
    pub token: TokenId,
    /// A string field representing the URL
    pub url: String,

    /// An optional sha256 checksum value tied to the content of the URL
    pub checksum_sha_256: Option<Hash>,
}

impl From<(TokenId, super::TokenMetadataUrlDetails)> for TokenMetadataUrlDetailsWithId {
    fn from((token, metadata_url): (TokenId, super::TokenMetadataUrlDetails)) -> Self {
        TokenMetadataUrlDetailsWithId {
            token,
            url: metadata_url.url,
            checksum_sha_256: metadata_url.checksum_sha_256,
        }
    }
}

impl From<TokenMetadataUrlDetailsWithId> for (TokenId, super::TokenMetadataUrlDetails) {
    fn from(value: TokenMetadataUrlDetailsWithId) -> Self {
        (
            value.token,
            TokenMetadataUrlDetails {
                url: value.url,
                checksum_sha_256: value.checksum_sha_256,
            },
        )
    }
}

/// Fund a lock by locking the specified amount on the sender account under the
/// control of the specified lock.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
pub struct LockFund {
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
pub struct LockSend {
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

/// Release funds under the control of a lock to the owner account.
/// The funds are moved from the locked balance to the available balance
/// of the owner.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
pub struct LockRelease {
    /// The token the operation applies to.
    pub token: TokenId,
    /// The lock controlling the funds.
    pub lock: LockId,
    /// The account holding the funds.
    pub source: CborHolderAccount,
    /// The amount of tokens to release.
    pub amount: TokenAmount,
    /// An optional memo.
    pub memo: Option<CborMemo>,
}

/// Create a lock with the specified configuration.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
#[cbor(transparent)]
pub struct LockCreate {
    /// The configuration for the new lock.
    pub config: LockConfig,
}

/// Cancel a lock, returning funds to their owners and destroying the lock.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
pub struct LockCancel {
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
        LockConfig, LockConfigSimpleV0, LockControllerSimpleV0Capability,
        LockControllerSimpleV0Grant, LockRecipients,
    };
    use crate::protocol_level_tokens::{test_fixtures::ADDRESS, TokenAdminRole};
    use crate::transactions::Memo;

    #[test]
    fn test_public_builders_and_required_token_ids() {
        use crate::protocol_level_tokens::{operations, token_operations};

        let amount = TokenAmount::from_raw(100000, 2);
        let token: TokenId = "tokenid1".parse().unwrap();
        let scoped = token_operations::transfer_tokens(ADDRESS, amount);
        assert_eq!(
            operations::transfer_tokens(token.clone(), ADDRESS, amount),
            (token, scoped).into()
        );
        // Unscoped operations cannot silently default a missing token ID.
        for bytes in [
            "a169746f6b656e4d696e74a166616d6f756e74c482001903e8",
            "a1686c6f636b46756e64a2646c6f636bd99fd88314070066616d6f756e74c48200191388",
            "a16a746f6b656e5061757365a0",
        ] {
            assert!(cbor::cbor_decode::<Operation>(hex::decode(bytes).unwrap()).is_err());
        }
        // Scoped P9/P10 operation keys are not accepted as unscoped keys.
        assert!(cbor::cbor_decode::<Operation>(
            hex::decode("a1657061757365a165746f6b656e6774657374504c54").unwrap()
        )
        .is_err());
    }

    #[test]
    fn test_operation_cbor_transfer() {
        let operation = Operation::TokenTransfer(TokenTransferWithId {
            token: "tokenid1".parse().unwrap(),
            amount: TokenAmount::from_raw(100000, 2),
            recipient: CborHolderAccount::from(ADDRESS),
            memo: Some(CborMemo::Raw(Memo::try_from(vec![1, 2, 3, 4]).unwrap())),
        });
        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(hex::encode(&cbor), "a16d746f6b656e5472616e73666572a4646d656d6f440102030465746f6b656e68746f6b656e69643166616d6f756e74c482211a000186a069726563697069656e74d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let operation_decoded: Operation = cbor::cbor_decode(&cbor).expect("CBOR deserialize");
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_operation_cbor_mint() {
        let operation = Operation::TokenMint(TokenSupplyUpdateDetailsWithId {
            token: "PLTx".parse().unwrap(),
            amount: TokenAmount::from_raw(1000, 0),
        });
        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(
            hex::encode(&cbor),
            "a169746f6b656e4d696e74a265746f6b656e64504c547866616d6f756e74c482001903e8"
        );
        let operation_decoded: Operation = cbor::cbor_decode(&cbor).expect("CBOR deserialize");
        assert_eq!(operation_decoded, operation);
        // An alternative CBOR encoding that uses indefinite length strings, oversize ints, and
        // non-canonical key ordering.
        let operation_decoded: Operation =
            cbor::cbor_decode(hex::decode("a17f69746f6b656e4d696e74ffa266616d6f756e74c482001b00000000000003e865746f6b656e7f63504c546178ff").unwrap()).expect("CBOR deserialize");
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_operation_cbor_burn() {
        let operation = Operation::TokenBurn(TokenSupplyUpdateDetailsWithId {
            token: "xxx2".parse().unwrap(),
            amount: TokenAmount::from_raw(9999999999999, 27),
        });
        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(
            hex::encode(&cbor),
            "a169746f6b656e4275726ea265746f6b656e647878783266616d6f756e74c482381a1b000009184e729fff"
        );
        let operation_decoded: Operation = cbor::cbor_decode(&cbor).expect("CBOR deserialize");
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_operation_cbor_add_allow_list() {
        let operation = Operation::TokenAddAllowList(TokenListUpdateDetailsWithId {
            token: "testPLT".parse().unwrap(),
            target: CborHolderAccount::from(ADDRESS),
        });
        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(
            hex::encode(&cbor),
            "a171746f6b656e416464416c6c6f774c697374a265746f6b656e6774657374504c5466746172676574d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        );
        let operation_decoded: Operation = cbor::cbor_decode(&cbor).expect("CBOR deserialize");
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_operation_cbor_remove_allow_list() {
        let operation = Operation::TokenRemoveAllowList(TokenListUpdateDetailsWithId {
            token: "testPLT".parse().unwrap(),
            target: CborHolderAccount::from(ADDRESS),
        });
        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(
            hex::encode(&cbor),
            "a174746f6b656e52656d6f7665416c6c6f774c697374a265746f6b656e6774657374504c5466746172676574d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        );
        let operation_decoded: Operation = cbor::cbor_decode(&cbor).expect("CBOR deserialize");
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_operation_cbor_add_deny_list() {
        let operation = Operation::TokenAddDenyList(TokenListUpdateDetailsWithId {
            token: "testPLT".parse().unwrap(),
            target: CborHolderAccount::from(ADDRESS),
        });
        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(
            hex::encode(&cbor),
            "a170746f6b656e41646444656e794c697374a265746f6b656e6774657374504c5466746172676574d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        );
        let operation_decoded: Operation = cbor::cbor_decode(&cbor).expect("CBOR deserialize");
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_operation_cbor_remove_deny_list() {
        let operation = Operation::TokenRemoveDenyList(TokenListUpdateDetailsWithId {
            token: "testPLT".parse().unwrap(),
            target: CborHolderAccount::from(ADDRESS),
        });
        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(
            hex::encode(&cbor),
            "a173746f6b656e52656d6f766544656e794c697374a265746f6b656e6774657374504c5466746172676574d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        );
        let operation_decoded: Operation = cbor::cbor_decode(&cbor).expect("CBOR deserialize");
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_operation_cbor_pause() {
        let operation = Operation::TokenPause(TokenPauseDetailsWithId {
            token: "testPLT".parse().unwrap(),
        });
        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(
            hex::encode(&cbor),
            "a16a746f6b656e5061757365a165746f6b656e6774657374504c54"
        );
        let operation_decoded: Operation = cbor::cbor_decode(&cbor).expect("CBOR deserialize");
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_operation_cbor_unpause() {
        let operation = Operation::TokenUnpause(TokenPauseDetailsWithId {
            token: "testPLT".parse().unwrap(),
        });
        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(
            hex::encode(&cbor),
            "a16c746f6b656e556e7061757365a165746f6b656e6774657374504c54"
        );
        let operation_decoded: Operation = cbor::cbor_decode(&cbor).expect("CBOR deserialize");
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_operation_cbor_assign_admin_roles() {
        let operation = Operation::TokenAssignAdminRoles(TokenUpdateAdminRolesDetailsWithId {
            token: "testPLT".parse().unwrap(),
            roles: vec![TokenAdminRole::Mint, TokenAdminRole::Pause],
            account: CborHolderAccount::from(ADDRESS),
        });
        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(
            hex::encode(&cbor),
            "a175746f6b656e41737369676e41646d696e526f6c6573a365726f6c657382646d696e7465706175736565746f6b656e6774657374504c54676163636f756e74d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        );
        let operation_decoded: Operation = cbor::cbor_decode(&cbor).expect("CBOR deserialize");
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_operation_cbor_revoke_admin_roles() {
        let operation = Operation::TokenRevokeAdminRoles(TokenUpdateAdminRolesDetailsWithId {
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
            "a175746f6b656e5265766f6b6541646d696e526f6c6573a365726f6c6573837075706461746541646d696e526f6c6573646275726e6e7570646174654d6574616461746165746f6b656e6774657374504c54676163636f756e74d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        );
        let operation_decoded: Operation = cbor::cbor_decode(&cbor).expect("CBOR deserialize");
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_operation_cbor_update_metadata() {
        let operation = Operation::TokenUpdateMetadata(TokenMetadataUrlDetailsWithId {
            token: "testPLT".parse().unwrap(),
            url: "https://example.com/metadata.json".to_string(),
            checksum_sha_256: Some([255u8; 32].into()),
        });
        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(
            hex::encode(&cbor),
            "a173746f6b656e5570646174654d65746164617461a36375726c782168747470733a2f2f6578616d706c652e636f6d2f6d657461646174612e6a736f6e65746f6b656e6774657374504c546e636865636b73756d5368613235365820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
        let operation_decoded: Operation = cbor::cbor_decode(&cbor).expect("CBOR deserialize");
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_operation_cbor_update_metadata_builders() {
        let token: TokenId = "testPLT".parse().unwrap();
        let metadata = TokenMetadataUrlDetails {
            url: "https://example.com".to_string(),
            checksum_sha_256: None,
        };
        let details = TokenMetadataUrlDetailsWithId::from((token.clone(), metadata.clone()));
        let expected = "a173746f6b656e5570646174654d65746164617461a26375726c7368747470733a2f2f6578616d706c652e636f6d65746f6b656e6774657374504c54";
        for operation in [
            Operation::TokenUpdateMetadata(details.clone()),
            operations::update_token_metadata(token.clone(), metadata.clone()),
            (
                token.clone(),
                token_operations::update_metadata(metadata.clone()),
            )
                .into(),
        ] {
            let bytes = cbor::cbor_encode(&operation);
            assert_eq!(hex::encode(&bytes), expected);
            assert_eq!(cbor::cbor_decode::<Operation>(&bytes).unwrap(), operation);
        }
        assert_eq!(
            <(TokenId, TokenMetadataUrlDetails)>::from(details),
            (token, metadata)
        );
    }

    #[test]
    fn test_metadata_details_unknown_fields_and_invalid_maps() {
        let bytes = hex::decode("a173746f6b656e5570646174654d65746164617461a365746f6b656e6774657374504c546375726c6178645f666f6f182a").unwrap();
        assert!(cbor::cbor_decode_with_options::<Operation>(
            bytes,
            cbor::SerializationOptions::default().unknown_map_keys(cbor::UnknownMapKeys::Fail),
        )
        .is_err());
        for invalid in [
            "a16375726c6178",                 // Missing token.
            "a165746f6b656e6774657374504c54", // Missing URL.
            "a265746f6b656e6774657374504c546b6d6574616461746155726ca16375726c6178", // Old nested map.
            "a265746f6b656e006375726c6178", // Wrong token type.
            "a265746f6b656e6774657374504c546375726c00", // Wrong URL type.
            "a365746f6b656e6774657374504c546375726c61786e636865636b73756d53686132353600",
            "a365746f6b656e6774657374504c546375726c61780000", // Non-text additional key.
        ] {
            assert!(
                cbor::cbor_decode_with_options::<TokenMetadataUrlDetailsWithId>(
                    hex::decode(invalid).unwrap(),
                    cbor::SerializationOptions::default()
                        .unknown_map_keys(cbor::UnknownMapKeys::Fail)
                )
                .is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn test_operation_cbor_lock_fund() {
        let operation = Operation::LockFund(LockFund {
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
        let operation_decoded: Operation = cbor::cbor_decode(&cbor).expect("CBOR deserialize");
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_operation_cbor_lock_send() {
        let operation = Operation::LockSend(LockSend {
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
        let operation_decoded: Operation = cbor::cbor_decode(&cbor).expect("CBOR deserialize");
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_operation_cbor_lock_release() {
        let operation = Operation::LockRelease(LockRelease {
            token: "testPLT".parse().unwrap(),
            lock: LockId::new(20, 7, 0),
            source: CborHolderAccount::from(ADDRESS),
            amount: TokenAmount::from_raw(5000, 0),
            memo: None,
        });
        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(
            hex::encode(&cbor),
            "a16b6c6f636b52656c65617365a4646c6f636bd99fd88314070065746f6b656e6774657374504c5466616d6f756e74c4820019138866736f75726365d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        );
        let operation_decoded: Operation = cbor::cbor_decode(&cbor).expect("CBOR deserialize");
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_operation_cbor_lock_create() {
        let operation = Operation::LockCreate(LockCreate {
            config: LockConfig::SimpleV0(LockConfigSimpleV0 {
                recipients: LockRecipients::Limited(vec![CborHolderAccount::from(ADDRESS)]),
                expiry: TransactionTime::from_seconds(1_000_000),
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
                metadata: None,
            }),
        });
        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(
            hex::encode(&cbor),
            "a16a6c6f636b437265617465a16873696d706c655630a466657870697279c11a000f4240666772616e747382a265726f6c6573826466756e646663616e63656c676163636f756e74d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20a265726f6c6573816473656e64676163636f756e74d99d73a201d99d71a101190397035820111111111111111111111111111111111111111111111111111111111111111166746f6b656e73826774657374504c5463544b4e6a726563697069656e747381d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        );
        let operation_decoded: Operation = cbor::cbor_decode(&cbor).expect("CBOR deserialize");
        assert_eq!(operation_decoded, operation);
    }

    #[test]
    fn test_operation_cbor_lock_cancel() {
        let operation = Operation::LockCancel(LockCancel {
            lock: LockId::new(20, 7, 0),
            memo: Some(CborMemo::Cbor(Memo::try_from(vec![0xa0]).unwrap())),
        });
        let cbor = cbor::cbor_encode(&operation);
        assert_eq!(
            hex::encode(&cbor),
            "a16a6c6f636b43616e63656ca2646c6f636bd99fd883140700646d656d6fd81841a0"
        );
        let operation_decoded: Operation = cbor::cbor_decode(&cbor).expect("CBOR deserialize");
        assert_eq!(operation_decoded, operation);
    }
}
