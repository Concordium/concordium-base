use crate::{
    common::{
        cbor,
        cbor::{CborSerializationResult, SerializationOptions, UnknownMapKeys},
    },
    protocol_level_tokens::RawCbor,
};

use concordium_base_derive::{CborDeserialize, CborSerialize};

#[derive(Debug, Clone, PartialEq, CborSerialize, CborDeserialize)]
pub struct TokenModuleAccountState {
    /// Whether the account is on the allow list.
    /// If `None`, the token does not support an allow list.
    pub allow_list: Option<bool>,
    /// Whether the account is on the deny list.
    /// If `None`, the token does not support a deny list.
    pub deny_list:  Option<bool>,
}

impl TokenModuleAccountState {
    pub fn try_from_cbor(cbor: &RawCbor) -> CborSerializationResult<Self> {
        cbor::cbor_decode_with_options(
            cbor.as_ref(),
            SerializationOptions::default().unknown_map_keys(UnknownMapKeys::Ignore),
        )
    }

    pub fn to_cbor(&self) -> CborSerializationResult<RawCbor> {
        Ok(RawCbor::from(cbor::cbor_encode(&self)?))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::common::cbor;

    #[test]
    fn test_token_module_account_state_cbor() {
        let token_module_account_state = TokenModuleAccountState {
            allow_list: Some(true),
            deny_list:  None,
        };

        let cbor = token_module_account_state.to_cbor().unwrap();
        assert_eq!(hex::encode(&cbor), "a169616c6c6f774c697374f5");
        let decoded = TokenModuleAccountState::try_from_cbor(&cbor).unwrap();
        assert_eq!(token_module_account_state, decoded);
    }
}
