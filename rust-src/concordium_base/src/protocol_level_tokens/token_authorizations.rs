use crate::common::cbor::{CborDeserialize, CborSerialize};
use crate::protocol_level_tokens::CborHolderAccount;
use concordium_base_derive::{CborDeserialize, CborSerialize};
use concordium_contracts_common::AccountAddress;

/// Describes the authorizations structure for protocol level tokens.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TokenAuthorizations {
    /// Gives authority to perform `token-assign-admin-roles` and `token-revoke-admin-roles` operations.
    pub update_admin_roles: Vec<AccountAddress>,
    /// Gives authority to perform `token-mint` operations.
    pub mint: Vec<AccountAddress>,
    /// Gives authority to perform `token-burn` operations.
    pub burn: Vec<AccountAddress>,
    /// Gives authority to perform `token-add-allow-list` and `token-remove-allow-list` operations.
    pub update_allow_list: Vec<AccountAddress>,
    /// Gives authority to perform `token-add-deny-list` and `token-remove-deny-list` operations.
    pub update_deny_list: Vec<AccountAddress>,
    /// Gives authority to perform `token-pause` and `token-unpause` operations.
    pub pause: Vec<AccountAddress>,
    /// Gives authority to perform `token-update-metadata` operations.
    pub update_metadata: Vec<AccountAddress>,
}

impl CborSerialize for TokenAuthorizations {
    fn serialize<C: crate::common::cbor::CborEncoder>(
        &self,
        encoder: C,
    ) -> Result<(), C::WriteError> {
        fn mapper(authorized: &[AccountAddress]) -> Option<TokenRoleAuthorizationsCbor> {
            if authorized.is_empty() {
                None
            } else {
                Some(TokenRoleAuthorizationsCbor {
                    accounts: authorized
                        .iter()
                        .cloned()
                        .map(CborHolderAccount::from)
                        .collect(),
                })
            }
        }
        let model = TokenAuthorizationsCbor {
            update_admin_roles: mapper(&self.update_admin_roles),
            mint: mapper(&self.mint),
            burn: mapper(&self.burn),
            update_allow_list: mapper(&self.update_allow_list),
            update_deny_list: mapper(&self.update_deny_list),
            pause: mapper(&self.pause),
            update_metadata: mapper(&self.update_metadata),
        };
        model.serialize(encoder)
    }
}
impl CborDeserialize for TokenAuthorizations {
    fn deserialize<C: crate::common::cbor::CborDecoder>(
        decoder: C,
    ) -> crate::common::cbor::CborSerializationResult<Self>
    where
        Self: Sized,
    {
        let model = TokenAuthorizationsCbor::deserialize(decoder)?;
        fn mapper(authorized: Option<TokenRoleAuthorizationsCbor>) -> Vec<AccountAddress> {
            if let Some(authorized) = authorized {
                authorized
                    .accounts
                    .into_iter()
                    .map(|holder| holder.address)
                    .collect()
            } else {
                Vec::new()
            }
        }

        Ok(Self {
            update_admin_roles: mapper(model.update_admin_roles),
            mint: mapper(model.mint),
            burn: mapper(model.burn),
            update_allow_list: mapper(model.update_allow_list),
            update_deny_list: mapper(model.update_deny_list),
            pause: mapper(model.pause),
            update_metadata: mapper(model.update_metadata),
        })
    }
}

#[derive(Debug, CborSerialize, CborDeserialize)]
struct TokenAuthorizationsCbor {
    update_admin_roles: Option<TokenRoleAuthorizationsCbor>,
    mint: Option<TokenRoleAuthorizationsCbor>,
    burn: Option<TokenRoleAuthorizationsCbor>,
    update_allow_list: Option<TokenRoleAuthorizationsCbor>,
    update_deny_list: Option<TokenRoleAuthorizationsCbor>,
    pause: Option<TokenRoleAuthorizationsCbor>,
    update_metadata: Option<TokenRoleAuthorizationsCbor>,
}

#[derive(Debug, CborSerialize, CborDeserialize, Default)]
struct TokenRoleAuthorizationsCbor {
    accounts: Vec<CborHolderAccount>,
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

        token_authorizations
            .update_admin_roles
            .push(AccountAddress([5u8; 32]));

        token_authorizations.pause.push(AccountAddress([1u8; 32]));
        token_authorizations.pause.push(AccountAddress([2u8; 32]));
        assert_eq!(hex::encode(&cbor::cbor_encode(&token_authorizations)), "a2657061757365a1686163636f756e747382d99d73a201d99d71a1011903970358200101010101010101010101010101010101010101010101010101010101010101d99d73a201d99d71a10119039703582002020202020202020202020202020202020202020202020202020202020202027075706461746541646d696e526f6c6573a1686163636f756e747381d99d73a201d99d71a1011903970358200505050505050505050505050505050505050505050505050505050505050505");
    }
}
