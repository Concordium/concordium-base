use crate::common::cbor::{
    CborDecoder, CborDeserialize, CborEncoder, CborSerializationError, CborSerializationResult,
    CborSerialize,
};

use concordium_base_derive::{CborDeserialize, CborSerialize};
use concordium_contracts_common::AccountAddress;
use std::fmt::Debug;

const ACCOUNT_HOLDER_TAG: u64 = 40307;
const COIN_INFO_TAG: u64 = 40305;
/// Concordiums listing in https://github.com/satoshilabs/slips/blob/master/slip-0044.md
const CONCORDIUM_SLIP_0044_CODE: u64 = 919;

/// An entity that can receive and hold protocol level tokens.
/// Currently, this can only be a Concordium account address.
/// The type is used in the transaction payload, in reject reasons, and in the
/// `TokenModuleEvent`. This type shouldn't be confused with the `TokenHolder`
/// type that in contrast is used in the `TokenTransfer`, `TokenMint`, and
/// `TokenBurn` events.
#[derive(
    Debug,
    Eq,
    PartialEq,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    CborSerialize,
    CborDeserialize,
)]
#[serde(tag = "type")]
#[serde(rename_all = "camelCase")]
#[cbor(tagged)]
pub enum CborTokenHolder {
    #[cbor(peek_tag = ACCOUNT_HOLDER_TAG)]
    Account(CborHolderAccount),
}

/// Account address that holds protocol level tokens
#[derive(
    Debug,
    Eq,
    PartialEq,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    CborSerialize,
    CborDeserialize,
)]
#[serde(rename_all = "camelCase")]
#[cbor(tag = ACCOUNT_HOLDER_TAG)]
pub struct CborHolderAccount {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cbor(key = 1)]
    pub coin_info: Option<CoinInfo>,
    /// Concordium address
    #[cbor(key = 3)]
    pub address:   AccountAddress,
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CoinInfo {
    CCD,
}

/// [`CoinInfo`] representation that resembles CBOR structure, see <https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-007-hdkey.md>
#[derive(Debug, CborSerialize, CborDeserialize)]
#[cbor(tag = COIN_INFO_TAG)]
struct CoinInfoCbor {
    #[cbor(key = 1)]
    coin_info_code: u64,
}

impl CborSerialize for CoinInfo {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> CborSerializationResult<()> {
        let coin_info_code = match self {
            Self::CCD => CONCORDIUM_SLIP_0044_CODE,
        };

        CoinInfoCbor { coin_info_code }.serialize(encoder)
    }
}

impl CborDeserialize for CoinInfo {
    fn deserialize<C: CborDecoder>(decoder: C) -> CborSerializationResult<Self>
    where
        Self: Sized, {
        let cbor = CoinInfoCbor::deserialize(decoder)?;
        let coin_info = match cbor.coin_info_code {
            CONCORDIUM_SLIP_0044_CODE => CoinInfo::CCD,
            coin_info_code => {
                return Err(CborSerializationError::invalid_data(format_args!(
                    "coin info code must be {}, was {}",
                    CONCORDIUM_SLIP_0044_CODE, coin_info_code
                )))
            }
        };

        Ok(coin_info)
    }
}

#[cfg(test)]
pub mod test_fixtures {
    use super::*;

    pub const ADDRESS: AccountAddress = AccountAddress([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ]);
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{common::cbor, protocol_level_tokens::test_fixtures::ADDRESS};

    #[test]
    fn test_coin_info_cbor() {
        let coin_info = CoinInfo::CCD;

        let cbor = cbor::cbor_encode(&coin_info).unwrap();
        assert_eq!(hex::encode(&cbor), "d99d71a101190397");
        let coin_info_decoded: CoinInfo = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(coin_info_decoded, coin_info);
    }

    #[test]
    fn test_token_holder_cbor_no_coin_info() {
        let token_holder = CborTokenHolder::Account(CborHolderAccount {
            address:   ADDRESS,
            coin_info: None,
        });

        let cbor = cbor::cbor_encode(&token_holder).unwrap();
        assert_eq!(
            hex::encode(&cbor),
            "d99d73a10358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        );
        let token_holder_decoded: CborTokenHolder = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(token_holder_decoded, token_holder);
    }

    #[test]
    fn test_token_holder_cbor() {
        let token_holder = CborTokenHolder::Account(CborHolderAccount {
            address:   ADDRESS,
            coin_info: Some(CoinInfo::CCD),
        });

        let cbor = cbor::cbor_encode(&token_holder).unwrap();
        assert_eq!(hex::encode(&cbor), "d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let token_holder_decoded: CborTokenHolder = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(token_holder_decoded, token_holder);
    }
}
