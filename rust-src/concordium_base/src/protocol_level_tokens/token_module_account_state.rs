use std::collections::HashMap;

use concordium_base_derive::{CborDeserialize, CborSerialize};

use crate::common::cbor::value;

#[derive(Debug, Clone, PartialEq, CborSerialize, CborDeserialize, Default)]
///  The account state represents account-specific information that is
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
pub struct TokenModuleAccountState {
    /// Whether the account is on the allow list.
    /// If `None`, the token does not support an allow list.
    pub allow_list: Option<bool>,
    /// Whether the account is on the deny list.
    /// If `None`, the token does not support a deny list.
    pub deny_list:  Option<bool>,
    /// Additional state information may be provided under further text keys,
    /// the meaning of which are not defined in the present specification.
    #[cbor(other)]
    pub additional: HashMap<String, value::Value>,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::common::cbor;

    #[test]
    fn test_token_module_account_state_cbor() {
        let mut token_module_account_state = TokenModuleAccountState {
            allow_list: Some(true),
            deny_list:  None,
            additional: Default::default(),
        };

        let cbor = cbor::cbor_encode(&token_module_account_state).unwrap();
        assert_eq!(hex::encode(&cbor), "a169616c6c6f774c697374f5");
        let decoded: TokenModuleAccountState = cbor::cbor_decode(cbor).unwrap();
        assert_eq!(token_module_account_state, decoded);

        token_module_account_state.allow_list = None;
        let cbor = cbor::cbor_encode(&token_module_account_state).unwrap();
        assert_eq!(hex::encode(&cbor), "a0");
        let decoded: TokenModuleAccountState = cbor::cbor_decode(cbor).unwrap();
        assert_eq!(token_module_account_state, decoded);

        token_module_account_state.deny_list = Some(false);
        let cbor = cbor::cbor_encode(&token_module_account_state).unwrap();
        assert_eq!(hex::encode(&cbor), "a16864656e794c697374f4");
        let decoded: TokenModuleAccountState = cbor::cbor_decode(cbor).unwrap();
        assert_eq!(token_module_account_state, decoded);

        token_module_account_state.additional.insert(
            "customKey".to_string(),
            value::Value::Text("customValue".to_string()),
        );
        let cbor = cbor::cbor_encode(&token_module_account_state).unwrap();
        assert_eq!(
            hex::encode(&cbor),
            "a26864656e794c697374f469637573746f6d4b65796b637573746f6d56616c7565"
        );
        let decoded: TokenModuleAccountState = cbor::cbor_decode(cbor).unwrap();
        assert_eq!(token_module_account_state, decoded);
    }
}
