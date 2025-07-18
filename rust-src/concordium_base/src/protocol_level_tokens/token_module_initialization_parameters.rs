use concordium_base_derive::{CborDeserialize, CborSerialize};

use super::{MetadataUrl, TokenAmount};
use crate::protocol_level_tokens::token_holder::CborTokenHolder;

/// These parameters are passed to the token module to initialize the token.
/// The token initialization update will also include the ticker symbol,
/// number of decimals, and a reference to the token module implementation.
#[derive(Debug, Clone, PartialEq, CborSerialize, CborDeserialize)]
pub struct TokenModuleInitializationParameters {
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
    /// The initial supply of the token. If not present, no tokens are minted
    /// initially.
    pub initial_supply:     Option<TokenAmount>,
    /// Whether the token is mintable.
    pub mintable:           Option<bool>,
    /// Whether the token is burnable.
    pub burnable:           Option<bool>,
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
        let token_module_initialization_parameters = TokenModuleInitializationParameters {
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
            initial_supply:     Some(TokenAmount::from_raw(10000000, 8)),
            mintable:           Some(true),
            burnable:           Some(true),
        };

        let cbor = cbor::cbor_encode(&token_module_initialization_parameters).unwrap();
        assert_eq!(hex::encode(&cbor),
                   "a8646e616d6563544b31686275726e61626c65f56864656e794c697374f5686d65746164617461a26375726c7168747470733a2f2f746f6b656e75726c316e636865636b73756d53686132353658200101010101010101010101010101010101010101010101010101010101010101686d696e7461626c65f569616c6c6f774c697374f56d696e697469616c537570706c79c482271a0098968071676f7665726e616e63654163636f756e74d99d73a201d99d71a101190397035820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
        let token_module_initialization_parameters_decoded: TokenModuleInitializationParameters =
            cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(
            token_module_initialization_parameters_decoded,
            token_module_initialization_parameters
        );
    }
}
