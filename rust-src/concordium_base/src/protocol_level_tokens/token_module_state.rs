use crate::common::cbor::{Bytes, CborEncoder, CborResult, DecimalFraction};
use anyhow::Context;
use concordium_base_derive::{CborDeserialize, CborSerialize};

/// Protocol level token (PLT) module state
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
pub struct TokenModuleState {
    /// The name of the token
    name:       String,
    /// A URL pointing to the token metadata
    metadata:   MetadataUrl,
    /// Whether the token supports an allow list.
    allow_list: Option<bool>,
    /// Whether the token supports a deny list.
    deny_list:  Option<bool>,
    /// Whether the token is mintable.
    mintable:   Option<bool>,
    /// Whether the token is burnable.
    burnable:   Option<bool>,
}

#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
pub struct MetadataUrl {
    /// A string field representing the URL
    url:              Option<String>,
    /// An optional sha256 checksum value tied to the content of the URL
    checksum_sha_256: Option<Bytes>,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::common::cbor;

    #[test]
    fn test_token_module_state_cbor() {
        let token_module_state = TokenModuleState {
            name:       "TK1".to_string(),
            metadata:   MetadataUrl {
                url:              Some("https://tokenurl1".to_string()),
                checksum_sha_256: Some(Bytes(vec![ 0x01; 32])),
            },
            allow_list: Some(true),
            deny_list:  None,
            mintable:   Some(true),
            burnable:   None,
        };

        let cbor = cbor::cbor_encode(&token_module_state).unwrap();
        assert_eq!(hex::encode(&cbor), "a4646e616d6563544b31686d65746164617461a26375726c7168747470733a2f2f746f6b656e75726c316e636865636b73756d5368613235365820010101010101010101010101010101010101010101010101010101010101010169616c6c6f774c697374f5686d696e7461626c65f5");
        let token_module_state_decoded: TokenModuleState = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(token_module_state_decoded, token_module_state);
    }
}
