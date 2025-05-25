use crate::internal::cbor::{CborDeserialize, CborDecoder, CborSerialize, CborEncoder, CborError, CborResult, MapKey, MapKeyRef};

use concordium_contracts_common::AccountAddress;
use std::fmt::Debug;

const ACCOUNT_HOLDER_TAG: u64 = 40307;
const COIN_INFO_TAG: u64 = 40305;
/// Concordiums listing in https://github.com/satoshilabs/slips/blob/master/slip-0044.md
const CONCORDIUM_SLIP_0044_CODE: u64 = 919;

/// A destination that can receive and hold tokens.
/// Currently, this can only be a Concordium account address.
#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TokenHolder {
    HolderAccount(HolderAccount),
}

impl CborSerialize for TokenHolder {
    fn serialize<C: CborEncoder>(&self, encoder: &mut C) -> CborResult<()> {
        match self {
            TokenHolder::HolderAccount(account) => {
                account.serialize(encoder)?;
            }
        }
        Ok(())
    }
}

impl CborDeserialize for TokenHolder {
    fn deserialize<C: CborDecoder>(decoder: &mut C) -> CborResult<Self>
    where
        Self: Sized,
    {
        Ok(Self::HolderAccount(HolderAccount::deserialize(decoder)?))
    }
}

/// Account address that holds tokens
#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HolderAccount {
    /// Concordium address
    pub address: AccountAddress,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coin_info: Option<CoinInfo>,
}

impl CborSerialize for AccountAddress {
    fn serialize<C: CborEncoder>(&self, encoder: &mut C) -> CborResult<()> {
        self.0.serialize(encoder)
    }
}

impl CborDeserialize for AccountAddress {
    fn deserialize<C: CborDecoder>(decoder: &mut C) -> CborResult<Self>
    where
        Self: Sized,
    {
        Ok(Self(CborDeserialize::deserialize(decoder)?))
    }
}

impl CborSerialize for HolderAccount {
    fn serialize<C: CborEncoder>(&self, encoder: &mut C) -> CborResult<()> {
        encoder.encode_tag(ACCOUNT_HOLDER_TAG)?;

        encoder.encode_map(
            if self.coin_info.is_null() { 0 } else { 1 }
                + if self.address.is_null() { 0 } else { 1 },
        )?;

        if !self.coin_info.is_null() {
            MapKeyRef::Positive(1).serialize(encoder)?;
            self.coin_info.serialize(encoder)?;
        }

        if !self.address.is_null() {
            MapKeyRef::Positive(3).serialize(encoder)?;
            self.address.serialize(encoder)?;
        }
        Ok(())
    }
}

impl CborDeserialize for HolderAccount {
    fn deserialize<C: CborDecoder>(decoder: &mut C) -> CborResult<Self>
    where
        Self: Sized,
    {
        decoder.decode_tag_expect(ACCOUNT_HOLDER_TAG)?;

        let mut coin_info = None;
        let mut address = None;
        let map_size = decoder.decode_map()?;
        for _ in 0..map_size {
            let map_key = MapKey::deserialize(decoder)?;
            match map_key.as_ref() {
                MapKeyRef::Positive(1) => {
                    coin_info = Some(CborDeserialize::deserialize(decoder)?);
                }
                MapKeyRef::Positive(3) => {
                    address = Some(CborDeserialize::deserialize(decoder)?);
                }
                key => return Err(CborError::unknown_map_key(key)),
            }
        }
        let coin_info = match coin_info {
            None => match CborDeserialize::null() {
                None => return Err(CborError::map_value_missing(MapKeyRef::Positive(1))),
                Some(null) => null,
            },
            Some(coin_info) => coin_info,
        };

        let address = match address {
            None => match CborDeserialize::null() {
                None => return Err(CborError::map_value_missing(MapKeyRef::Positive(3))),
                Some(null) => null,
            },
            Some(address) => address,
        };

        Ok(Self { address, coin_info })
    }
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CoinInfo {
    CCD,
}

impl CborSerialize for CoinInfo {
    fn serialize<C: CborEncoder>(&self, encoder: &mut C) -> CborResult<()> {
        encoder.encode_tag(COIN_INFO_TAG)?;
        encoder.encode_map(1)?;
        encoder.encode_positive(1)?;
        match self {
            Self::CCD => encoder.encode_positive(CONCORDIUM_SLIP_0044_CODE)?,
        };
        Ok(())
    }
}

impl CborDeserialize for CoinInfo {
    fn deserialize<C: CborDecoder>(decoder: &mut C) -> CborResult<Self>
    where
        Self: Sized,
    {
        decoder.decode_tag_expect(COIN_INFO_TAG)?;
        if decoder.decode_map()? != 1 {
            return Err(CborError::invalid_data(
                "coin info must have exactly one field",
            ));
        }
        decoder.decode_positive_expect_key(1)?;
        let coin_info = match decoder.decode_positive()? {
            CONCORDIUM_SLIP_0044_CODE => CoinInfo::CCD,
            coin_info_code => {
                return Err(CborError::invalid_data(format_args!(
                    "coin info code must be {}, was {}",
                    CONCORDIUM_SLIP_0044_CODE, coin_info_code
                )))
            }
        };
        Ok(coin_info)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::internal::cbor;

    const TEST_ADDRESS: AccountAddress = AccountAddress([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ]);

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
        let token_holder = TokenHolder::HolderAccount(HolderAccount {
            address: TEST_ADDRESS,
            coin_info: None,
        });

        let cbor = cbor::cbor_encode(&token_holder).unwrap();
        assert_eq!(
            hex::encode(&cbor),
            "d99d73a10358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        );
        let token_holder_decoded: TokenHolder = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(token_holder_decoded, token_holder);
    }

    #[test]
    fn test_token_holder_cbor() {
        let token_holder = TokenHolder::HolderAccount(HolderAccount {
            address: TEST_ADDRESS,
            coin_info: Some(CoinInfo::CCD),
        });

        let cbor = cbor::cbor_encode(&token_holder).unwrap();
        assert_eq!(hex::encode(&cbor), "d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
        let token_holder_decoded: TokenHolder = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(token_holder_decoded, token_holder);
    }
}
