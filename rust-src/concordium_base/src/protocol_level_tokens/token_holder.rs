use crate::internal::cbor::{
    CborDecode, CborDecoder, CborEncode, CborEncoder, CborResult,
};

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

impl CborEncode for TokenHolder {
    fn encode<C: CborEncoder>(&self, encoder: &mut C) -> CborResult<()> {
        match self {
            TokenHolder::HolderAccount(account) => {
                account.encode(encoder)?;
            }
        }
        Ok(())
    }
}

impl CborDecode for TokenHolder {
    fn decode<C: CborDecoder>(decoder: &mut C) -> CborResult<Self>
    where
        Self: Sized,
    {
        Ok(Self::HolderAccount(HolderAccount::decode(decoder)?))
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

impl CborEncode for AccountAddress {
    fn encode<C: CborEncoder>(&self, encoder: &mut C) -> CborResult<()> {
        encoder.push_bytes(self.as_ref())
    }
}

impl CborDecode for AccountAddress {
    fn decode<C: CborDecoder>(decoder: &mut C) -> CborResult<Self>
    where
        Self: Sized,
    {
        let mut address = AccountAddress(Default::default());
        decoder.pull_bytes_exact(&mut address.0)?;
        Ok(address)
    }
}

impl CborEncode for HolderAccount {
    fn encode<C: CborEncoder>(&self, encoder: &mut C) -> CborResult<()> {
        encoder.push_tag(ACCOUNT_HOLDER_TAG)?;
        if self.coin_info.is_some() {
            encoder.push_map(2)?;
        } else {
            encoder.push_map(1)?;
        }

        if let Some(coin_info) = self.coin_info.as_ref() {
            encoder.push_positive(1)?;
            coin_info.encode(encoder)?;
        }

        encoder.push_positive(3)?;
        self.address.encode(encoder)?;
        Ok(())
    }
}

impl CborDecode for HolderAccount {
    fn decode<C: CborDecoder>(decoder: &mut C) -> CborResult<Self>
    where
        Self: Sized,
    {
        decoder.pull_tag_expect(ACCOUNT_HOLDER_TAG)?;
        let map_size = decoder.pull_map()?;
        if map_size < 1 || map_size > 2 {
            todo!()
        };

        let coin_info = if map_size == 2 {
            if decoder.pull_positive()? != 1 {
                todo!()
            }
            Some(CoinInfo::decode(decoder)?)
        } else {
            None
        };

        if decoder.pull_positive()? != 3 {
            todo!()
        }
        let address = AccountAddress::decode(decoder)?;

        Ok(Self { address, coin_info })
    }
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CoinInfo {
    CCD,
}

impl CborEncode for CoinInfo {
    fn encode<C: CborEncoder>(&self, encoder: &mut C) -> CborResult<()> {
        encoder.push_tag(COIN_INFO_TAG)?;
        encoder.push_map(1)?;
        encoder.push_positive(1)?;
        match self {
            Self::CCD => encoder.push_positive(CONCORDIUM_SLIP_0044_CODE)?,
        };
        Ok(())
    }
}

impl CborDecode for CoinInfo {
    fn decode<C: CborDecoder>(decoder: &mut C) -> CborResult<Self>
    where
        Self: Sized,
    {
        decoder.pull_tag_expect(COIN_INFO_TAG)?;
        if decoder.pull_map()? != 1 {
            todo!()
        }
        if decoder.pull_positive()? != 1 {
            todo!()
        }
        let coin_info = match decoder.pull_positive()? {
            CONCORDIUM_SLIP_0044_CODE => CoinInfo::CCD,
            _ => todo!(),
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
