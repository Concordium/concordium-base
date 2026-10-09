use crate::protocol_level_tokens::CborHolderAccount;
use concordium_base_derive::{CborDeserialize, CborSerialize};

/// Describes the authorizations structure for protocol level tokens.
#[derive(Debug, CborSerialize, CborDeserialize, Clone, Default)]
pub struct TokenAuthorizations {
    /// Gives authority to perform `token-assign-admin-roles` and `token-revoke-admin-roles` operations.
    pub update_admin_roles: Option<TokenRoleAuthorizations>,
    /// Gives authority to perform `token-mint` operations.
    pub mint: Option<TokenRoleAuthorizations>,
    /// Gives authority to perform `token-burn` operations.
    pub burn: Option<TokenRoleAuthorizations>,
    /// Gives authority to perform `token-add-allow-list` and `token-remove-allow-list` operations.
    pub update_allow_list: Option<TokenRoleAuthorizations>,
    /// Gives authority to perform `token-add-deny-list` and `token-remove-deny-list` operations.
    pub update_deny_list: Option<TokenRoleAuthorizations>,
    /// Gives authority to perform `token-pause` and `token-unpause` operations.
    pub pause: Option<TokenRoleAuthorizations>,
    /// Gives authority to perform `token-update-metadata` operations.
    pub update_metadata: Option<TokenRoleAuthorizations>,
}

/// The collection of entities holding a specific role.
#[derive(Debug, CborSerialize, CborDeserialize, Clone, Default)]
pub struct TokenRoleAuthorizations {
    /// Accounts holding the role.
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

        assert_eq!(hex::encode(&cbor::cbor_encode(&token_authorizations)), "a0");

        token_authorizations.update_admin_roles = Some(TokenRoleAuthorizations {
            accounts: vec![AccountAddress([5u8; 32]).into()],
        });

        token_authorizations.pause = Some(TokenRoleAuthorizations {
            accounts: vec![
                AccountAddress([1u8; 32]).into(),
                AccountAddress([2u8; 32]).into(),
            ],
        });
        assert_eq!(hex::encode(&cbor::cbor_encode(&token_authorizations)), "a2657061757365a1686163636f756e747382d99d73a201d99d71a1011903970358200101010101010101010101010101010101010101010101010101010101010101d99d73a201d99d71a10119039703582002020202020202020202020202020202020202020202020202020202020202027075706461746541646d696e526f6c6573a1686163636f756e747381d99d73a201d99d71a1011903970358200505050505050505050505050505050505050505050505050505050505050505");
    }
}
