use std::collections::HashMap;

use concordium_base_derive::{CborDeserialize, CborSerialize};

use super::{MetadataUrl, RawCbor};
use crate::common::{
    cbor,
    cbor::{value, CborSerializationResult, SerializationOptions, UnknownMapKeys},
};

/// Protocol level token (PLT) module state
#[derive(Debug, Clone, PartialEq, CborSerialize, CborDeserialize)]
pub struct TokenModuleState {
    /// The name of the token
    pub name: String,
    // /// A URL pointing to the token metadata
    pub metadata: MetadataUrl,
    /// Whether the token supports an allow list.
    pub allow_list: Option<bool>,
    /// Whether the token supports a deny list.
    pub deny_list: Option<bool>,
    /// Whether the token is mintable.
    pub mintable: Option<bool>,
    /// Whether the token is burnable.
    pub burnable: Option<bool>,
    /// Additional state information may be provided under further text keys,
    /// the meaning of which are not defined in the present specification.
    #[cbor(other)]
    pub additional: HashMap<String, value::Value>,
}

impl TokenModuleState {
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
    use concordium_contracts_common::hashes::Hash;

    const TEST_HASH: [u8; 32] = [1; 32];

    #[test]
    fn test_token_module_state_cbor() {
        let mut token_module_state = TokenModuleState {
            name: "TK1".to_string(),
            metadata: MetadataUrl {
                url: "https://tokenurl1".to_string(),
                checksum_sha_256: Some(Hash::from(TEST_HASH)),
                additional: Default::default(),
            },
            allow_list: Some(true),
            deny_list: Some(true),
            mintable: Some(true),
            burnable: Some(true),
            additional: vec![
                ("other1".to_string(), value::Value::Positive(2)),
            ]
            .into_iter()
            .collect(),
        };

        let cbor = cbor::cbor_encode(&token_module_state).unwrap();
        assert_eq!(hex::encode(&cbor),
        "a7646e616d6563544b31686d65746164617461a26375726c7168747470733a2f2f746f6b656e75726c316e636865636b73756d5368613235365820010101010101010101010101010101010101010101010101010101010101010169616c6c6f774c697374f56864656e794c697374f5686d696e7461626c65f5686275726e61626c65f5666f746865723102"
        );
        let token_module_state_decoded: TokenModuleState = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(token_module_state_decoded, token_module_state);

        token_module_state.deny_list = None;
        token_module_state.burnable = None;

        let cbor = cbor::cbor_encode(&token_module_state).unwrap();
        assert_eq!(hex::encode(&cbor),
        "a5646e616d6563544b31686d65746164617461a26375726c7168747470733a2f2f746f6b656e75726c316e636865636b73756d5368613235365820010101010101010101010101010101010101010101010101010101010101010169616c6c6f774c697374f5686d696e7461626c65f5666f746865723102"
        );
        let token_module_state_decoded: TokenModuleState = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(token_module_state_decoded, token_module_state);

        token_module_state.allow_list = None;
        token_module_state.mintable = None;
        token_module_state.additional = HashMap::new();

        let cbor = cbor::cbor_encode(&token_module_state).unwrap();
        assert_eq!(hex::encode(&cbor),
        "a2646e616d6563544b31686d65746164617461a26375726c7168747470733a2f2f746f6b656e75726c316e636865636b73756d53686132353658200101010101010101010101010101010101010101010101010101010101010101"
        );
        let token_module_state_decoded: TokenModuleState = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(token_module_state_decoded, token_module_state);
    }
}
