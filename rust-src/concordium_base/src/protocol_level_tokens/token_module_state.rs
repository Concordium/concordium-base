use std::collections::HashMap;

use concordium_base_derive::{CborDeserialize, CborSerialize};

use super::MetadataUrl;
use crate::{common::cbor::value, protocol_level_tokens::token_holder::CborTokenHolder};

/// Protocol level token (PLT) module state
#[derive(Debug, Clone, PartialEq, CborSerialize, CborDeserialize)]
pub struct TokenModuleState {
    /// The name of the token
    pub name:               String,
    // /// A URL pointing to the token metadata
    pub metadata:           MetadataUrl,
    /// The governance account of the token.
    pub governance_account: CborTokenHolder,
    /// Whether the token supports an allow list.
    pub allow_list:         Option<bool>,
    /// Whether the token supports a deny list.
    pub deny_list:          Option<bool>,
    /// Whether the token is mintable.
    pub mintable:           Option<bool>,
    /// Whether the token is burnable.
    pub burnable:           Option<bool>,
    /// Whether the execution of certain token operations is paused.
    pub paused:             Option<bool>,
    /// Additional state information may be provided under further text keys,
    /// the meaning of which are not defined in the present specification.
    #[cbor(other)]
    pub additional:         HashMap<String, value::Value>,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        common::cbor,
        protocol_level_tokens::{CborHolderAccount, CoinInfo},
    };
    use concordium_contracts_common::{hashes::Hash, AccountAddress};

    const TEST_HASH: [u8; 32] = [1; 32];
    const TEST_ADDRESS: AccountAddress = AccountAddress([0xff; 32]);

    #[test]
    fn test_token_module_state_cbor() {
        let mut token_module_state = TokenModuleState {
            name:               "TK1".to_string(),
            metadata:           MetadataUrl {
                url:              "https://tokenurl1".to_string(),
                checksum_sha_256: Some(Hash::from(TEST_HASH)),
                additional:       Default::default(),
            },
            governance_account: CborTokenHolder::Account(CborHolderAccount {
                address:   TEST_ADDRESS,
                coin_info: Some(CoinInfo::CCD),
            }),
            allow_list:         Some(true),
            deny_list:          Some(true),
            mintable:           Some(true),
            burnable:           Some(true),
            paused:             Some(false),
            additional:         vec![("other1".to_string(), value::Value::Positive(2))]
                .into_iter()
                .collect(),
        };

        let cbor = cbor::cbor_encode(&token_module_state).unwrap();
        assert_eq!(hex::encode(&cbor),
        "a9646e616d6563544b31666f74686572310266706175736564f4686275726e61626c65f56864656e794c697374f5686d65746164617461a26375726c7168747470733a2f2f746f6b656e75726c316e636865636b73756d53686132353658200101010101010101010101010101010101010101010101010101010101010101686d696e7461626c65f569616c6c6f774c697374f571676f7665726e616e63654163636f756e74d99d73a201d99d71a101190397035820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
        let token_module_state_decoded: TokenModuleState = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(token_module_state_decoded, token_module_state);

        token_module_state.deny_list = None;
        token_module_state.burnable = None;

        let cbor = cbor::cbor_encode(&token_module_state).unwrap();
        assert_eq!(hex::encode(&cbor),
        "a7646e616d6563544b31666f74686572310266706175736564f4686d65746164617461a26375726c7168747470733a2f2f746f6b656e75726c316e636865636b73756d53686132353658200101010101010101010101010101010101010101010101010101010101010101686d696e7461626c65f569616c6c6f774c697374f571676f7665726e616e63654163636f756e74d99d73a201d99d71a101190397035820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
        let token_module_state_decoded: TokenModuleState = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(token_module_state_decoded, token_module_state);

        token_module_state.allow_list = None;
        token_module_state.mintable = None;
        token_module_state.additional = HashMap::new();
        token_module_state.paused = None;

        let cbor = cbor::cbor_encode(&token_module_state).unwrap();
        assert_eq!(hex::encode(&cbor),
        "a3646e616d6563544b31686d65746164617461a26375726c7168747470733a2f2f746f6b656e75726c316e636865636b73756d5368613235365820010101010101010101010101010101010101010101010101010101010101010171676f7665726e616e63654163636f756e74d99d73a201d99d71a101190397035820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
        let token_module_state_decoded: TokenModuleState = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(token_module_state_decoded, token_module_state);
    }
}
