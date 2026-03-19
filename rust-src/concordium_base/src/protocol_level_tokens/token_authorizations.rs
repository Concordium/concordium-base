use crate::protocol_level_tokens::CborHolderAccount;
use concordium_base_derive::{CborDeserialize, CborSerialize};

/// Describes the authorizations structure for protocol level tokens.
#[derive(Debug, Clone, PartialEq, Eq, CborSerialize, CborDeserialize, Default)]
pub struct TokenAuthorizations {
    /// Gives authority to perform `token-assign-admin-roles` and `token-revoke-admin-roles` operations.
    pub update_admin_roles: TokenRoleAuthorizationsCbor,
    /// Gives authority to perform `token-mint` operations.
    pub mint: TokenRoleAuthorizationsCbor,
    /// Gives authority to perform `token-burn` operations.
    pub burn: TokenRoleAuthorizationsCbor,
    /// Gives authority to perform `token-add-allow-list` and `token-remove-allow-list` operations.
    pub update_allow_list: TokenRoleAuthorizationsCbor,
    /// Gives authority to perform `token-add-deny-list` and `token-remove-deny-list` operations.
    pub update_deny_list: TokenRoleAuthorizationsCbor,
    /// Gives authority to perform `token-pause` and `token-unpause` operations.
    pub pause: TokenRoleAuthorizationsCbor,
    /// Gives authority to perform `token-update-metadata` operations.
    pub update_metadata: TokenRoleAuthorizationsCbor,
}

/// Authorizations details applicable to any admin role.
#[derive(Debug, Clone, PartialEq, Eq, CborSerialize, CborDeserialize, Default)]
pub struct TokenRoleAuthorizationsCbor {
    /// The accounts that have the role assigned.
    pub accounts: Vec<CborHolderAccount>,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::common::cbor;
    use concordium_contracts_common::AccountAddress;

    #[test]
    fn test_token_authorizations_cbor() {
        let mut token_authorizations = TokenAuthorizations::default();

        assert_eq!(hex::encode(&cbor::cbor_encode(&token_authorizations)), "a7646275726ea1686163636f756e747380646d696e74a1686163636f756e747380657061757365a1686163636f756e7473806e75706461746544656e794c697374a1686163636f756e7473806e7570646174654d65746164617461a1686163636f756e7473806f757064617465416c6c6f774c697374a1686163636f756e7473807075706461746541646d696e526f6c6573a1686163636f756e747380");

        token_authorizations
            .update_admin_roles
            .accounts
            .push(CborHolderAccount::from(AccountAddress([5u8; 32])));

        token_authorizations
            .pause
            .accounts
            .push(CborHolderAccount::from(AccountAddress([1u8; 32])));
        token_authorizations
            .pause
            .accounts
            .push(CborHolderAccount::from(AccountAddress([2u8; 32])));
        assert_eq!(hex::encode(&cbor::cbor_encode(&token_authorizations)), "a7646275726ea1686163636f756e747380646d696e74a1686163636f756e747380657061757365a1686163636f756e747382d99d73a201d99d71a1011903970358200101010101010101010101010101010101010101010101010101010101010101d99d73a201d99d71a10119039703582002020202020202020202020202020202020202020202020202020202020202026e75706461746544656e794c697374a1686163636f756e7473806e7570646174654d65746164617461a1686163636f756e7473806f757064617465416c6c6f774c697374a1686163636f756e7473807075706461746541646d696e526f6c6573a1686163636f756e747381d99d73a201d99d71a1011903970358200505050505050505050505050505050505050505050505050505050505050505");
    }
}
