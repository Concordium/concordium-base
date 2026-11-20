use crate::{
    common::cbor::{
        self, CborDecoder, CborDeserialize, CborEncoder, CborMapDecoder, CborMapEncoder,
        CborSerializationError, CborSerializationResult, CborSerialize, MapKeyRef,
    },
    protocol_level_locks::LockId,
    protocol_level_tokens::TokenAmount,
};
use concordium_base_derive::{CborDeserialize, CborSerialize};

/// The account state represents account-specific information that is
/// maintained by the Token Module, and is returned as part of a
/// `GetAccountInfo` query. It does not include state that is managed by
/// the Token Kernel, such as the token identifier and account balance.
///
/// All fields are optional, and can be omitted if the module implementation
/// does not support them. The structure supports additional fields for future
/// extensibility. Non-standard fields (i.e. any fields that are not defined by
/// a standard, and are specific to the module implementation) may be included,
/// and their tags should be prefixed with an underscore ("_") to distinguish
/// them as such.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct TokenModuleAccountState {
    /// Whether the account is on the allow list.
    /// If `None`, the token does not support an allow list.
    pub allow_list: Option<bool>,
    /// Whether the account is on the deny list.
    /// If `None`, the token does not support a deny list.
    pub deny_list: Option<bool>,
    /// The locks that control funds associated with this account.
    ///
    /// An empty vector means no locks control funds associated with the account.
    /// Empty `locks` are omitted from the CBOR encoding, and an absent CBOR
    /// `locks` field decodes to an empty vector.
    pub locks: Vec<AccountLockAmount>,
    /// The total unencumbered balance on the account.
    /// If `None`, the unencumbered balance is the total balance.
    pub available: Option<TokenAmount>,
}

impl CborSerialize for TokenModuleAccountState {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> Result<(), C::WriteError> {
        let mut map_encoder = encoder.encode_map()?;
        if let Some(allow_list) = self.allow_list {
            map_encoder.serialize_entry("allowList", &allow_list)?;
        }
        if let Some(deny_list) = self.deny_list {
            map_encoder.serialize_entry("denyList", &deny_list)?;
        }
        if !self.locks.is_empty() {
            map_encoder.serialize_entry("locks", &self.locks)?;
        }
        if let Some(available) = self.available {
            map_encoder.serialize_entry("available", &available)?;
        }
        map_encoder.end()
    }
}

impl CborDeserialize for TokenModuleAccountState {
    fn deserialize<C: CborDecoder>(decoder: C) -> CborSerializationResult<Self>
    where
        Self: Sized,
    {
        let options = decoder.options();
        let mut map_decoder = decoder.decode_map()?;
        let mut account_state = TokenModuleAccountState::default();

        while let Some(key) = map_decoder.deserialize_key::<String>()? {
            match key.as_str() {
                "allowList" => account_state.allow_list = Some(map_decoder.deserialize_value()?),
                "denyList" => account_state.deny_list = Some(map_decoder.deserialize_value()?),
                "locks" => account_state.locks = map_decoder.deserialize_value()?,
                "available" => account_state.available = Some(map_decoder.deserialize_value()?),
                key => match options.unknown_map_keys {
                    cbor::UnknownMapKeys::Fail => {
                        return Err(CborSerializationError::unknown_map_key(MapKeyRef::Text(
                            key,
                        )))
                    }
                    cbor::UnknownMapKeys::Ignore => map_decoder.skip_value()?,
                },
            }
        }

        Ok(account_state)
    }
}

/// An amount controlled by a particular lock.
#[derive(Debug, Clone, PartialEq, CborSerialize, CborDeserialize)]
pub struct AccountLockAmount {
    /// The lock controlling the funds.
    pub lock: LockId,
    /// The amount of the token controlled by the lock.
    pub amount: TokenAmount,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::common::cbor;

    macro_rules! assert_round_trip {
        ($account_state:expr) => {{
            let account_state = $account_state;
            let cbor = cbor::cbor_encode(&account_state);
            let decoded: TokenModuleAccountState = cbor::cbor_decode(cbor).unwrap();
            assert_eq!(account_state, decoded);
        }};
    }

    #[test]
    fn test_token_module_account_state_permission_list_cbor() {
        let mut token_module_account_state = TokenModuleAccountState {
            allow_list: Some(true),
            ..Default::default()
        };

        let cbor = cbor::cbor_encode(&token_module_account_state);
        assert_eq!(hex::encode(&cbor), "a169616c6c6f774c697374f5");
        assert_round_trip!(token_module_account_state.clone());

        token_module_account_state.allow_list = None;
        let cbor = cbor::cbor_encode(&token_module_account_state);
        assert_eq!(hex::encode(&cbor), "a0");
        assert_round_trip!(token_module_account_state.clone());

        token_module_account_state.deny_list = Some(false);
        let cbor = cbor::cbor_encode(&token_module_account_state);
        assert_eq!(hex::encode(&cbor), "a16864656e794c697374f4");
        assert_round_trip!(token_module_account_state);
    }

    #[test]
    fn test_token_module_account_state_available_cbor() {
        let token_module_account_state = TokenModuleAccountState {
            available: Some(TokenAmount::from_raw(12300, 3)),
            ..Default::default()
        };

        let cbor = cbor::cbor_encode(&token_module_account_state);
        assert_eq!(hex::encode(&cbor), "a169617661696c61626c65c4822219300c");
        assert_round_trip!(token_module_account_state);
    }

    #[test]
    fn test_token_module_account_state_locks_cbor() {
        let amount = AccountLockAmount {
            lock: LockId::new(10001, 5, 0),
            amount: TokenAmount::from_raw(12300, 3),
        };

        let token_module_account_state = TokenModuleAccountState {
            locks: vec![amount],
            ..Default::default()
        };

        let cbor = cbor::cbor_encode(&token_module_account_state);
        assert_eq!(
            hex::encode(&cbor),
            "a1656c6f636b7381a2646c6f636bd99fd883192711050066616d6f756e74c4822219300c"
        );
        assert_round_trip!(token_module_account_state);
    }

    #[test]
    fn test_token_module_account_state_full() {
        let amount = AccountLockAmount {
            lock: LockId::new(10001, 5, 0),
            amount: TokenAmount::from_raw(12300, 3),
        };
        let token_module_account_state = TokenModuleAccountState {
            allow_list: Some(true),
            deny_list: Some(false),
            locks: vec![amount],
            available: Some(TokenAmount::from_raw(12300, 3)),
        };

        let cbor = cbor::cbor_encode(&token_module_account_state);
        assert_eq!(
            hex::encode(&cbor),
            "a4656c6f636b7381a2646c6f636bd99fd883192711050066616d6f756e74c4822219300c6864656e794c697374f469616c6c6f774c697374f569617661696c61626c65c4822219300c"
        );
        assert_round_trip!(token_module_account_state);
    }

    #[test]
    fn test_token_module_account_state_empty() {
        let account_state = TokenModuleAccountState::default();
        let cbor = cbor::cbor_encode(&account_state);
        assert_eq!(hex::encode(&cbor), "a0");

        let decoded: TokenModuleAccountState = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(decoded.locks, Vec::new());
        assert_eq!(decoded, account_state);
    }
}
