use super::{LockConfig, LockId};
use crate::protocol_level_tokens::{CborHolderAccount, TokenAmount, TokenId};
use concordium_base_derive::{CborDeserialize, CborSerialize};

/// CBOR-encoded result of the `GetLockInfo` query.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
pub struct LockInfo {
    /// The lock identifier.
    pub lock: LockId,
    /// Configuration of the lock.
    pub config: LockConfig,
    /// The locked balances currently controlled by the lock.
    pub funds: Vec<LockAccountFunds>,
}

/// Locked funds controlled by a lock for a single account.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
pub struct LockAccountFunds {
    /// The account whose balance is locked.
    pub account: CborHolderAccount,
    /// The token amounts controlled by the lock for the account.
    pub amounts: Vec<LockedTokenAmount>,
}

/// A single locked token amount under a lock.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
pub struct LockedTokenAmount {
    /// The token identifier.
    pub token: TokenId,
    /// The amount of the token controlled by the lock.
    pub amount: TokenAmount,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::{cbor, cbor::value::Value, types::TransactionTime},
        protocol_level_locks::{
            LockConfigSimpleV0, LockControllerSimpleV0Capability, LockControllerSimpleV0Grant,
            LockMetadata, LockRecipients,
        },
        protocol_level_tokens::{test_fixtures::ADDRESS, RawCbor},
    };
    use std::collections::HashMap;

    fn info(recipients: LockRecipients, metadata: Option<RawCbor>) -> LockInfo {
        LockInfo {
            lock: LockId {
                account_index: 10001,
                sequence_number: 5,
                creation_order: 0,
            },
            config: LockConfig::SimpleV0(LockConfigSimpleV0 {
                recipients,
                expiry: TransactionTime::from_seconds(1804806000),
                grants: vec![LockControllerSimpleV0Grant {
                    account: CborHolderAccount::from(ADDRESS),
                    roles: vec![
                        LockControllerSimpleV0Capability::Fund,
                        LockControllerSimpleV0Capability::Send,
                    ],
                }],
                tokens: vec!["tT".parse().unwrap()],
                keep_alive: false,
                memo: None,
                metadata,
            }),
            funds: vec![LockAccountFunds {
                account: CborHolderAccount::from(ADDRESS),
                amounts: vec![LockedTokenAmount {
                    token: "tT".parse().unwrap(),
                    amount: TokenAmount::from_raw(12300, 3),
                }],
            }],
        }
    }

    #[test]
    fn lock_info_fixture_limited_metadata_round_trips() {
        let value = info(
            LockRecipients::Limited(vec![CborHolderAccount::from(ADDRESS)]),
            Some(metadata()),
        );
        let expected = "a3646c6f636bd99fd88319271105006566756e647381a2676163636f756e74d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2067616d6f756e747381a265746f6b656e62745466616d6f756e74c4822219300c66636f6e666967a16873696d706c655630a566657870697279c11a6b932770666772616e747381a265726f6c6573826466756e646473656e64676163636f756e74d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2066746f6b656e7381627454686d657461646174615848a4646e616d656c56657374696e67206c6f636b666973737565726a436f6e636f726469756d6776657273696f6e016b6465736372697074696f6e6d546f6b656e73206c6f636b65646a726563697069656e747381d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        assert_eq!(hex::encode(cbor::cbor_encode(&value)), expected);
        assert_eq!(
            cbor::cbor_decode::<LockInfo>(&hex::decode(expected).unwrap()).unwrap(),
            value
        );
    }

    #[test]
    fn lock_info_fixture_any_recipients_round_trips() {
        let value = info(LockRecipients::Any, Some(metadata()));
        let encoded = cbor::cbor_encode(&value);
        let expected = "a3646c6f636bd99fd88319271105006566756e647381a2676163636f756e74d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2067616d6f756e747381a265746f6b656e62745466616d6f756e74c4822219300c66636f6e666967a16873696d706c655630a566657870697279c11a6b932770666772616e747381a265726f6c6573826466756e646473656e64676163636f756e74d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2066746f6b656e7381627454686d657461646174615848a4646e616d656c56657374696e67206c6f636b666973737565726a436f6e636f726469756d6776657273696f6e016b6465736372697074696f6e6d546f6b656e73206c6f636b65646a726563697069656e747363616e79";
        assert_eq!(hex::encode(encoded), expected);
        assert_eq!(
            cbor::cbor_decode::<LockInfo>(&hex::decode(expected).unwrap()).unwrap(),
            value
        );
    }

    fn metadata() -> RawCbor {
        LockMetadata {
            name: Some("Vesting lock".into()),
            description: Some("Tokens locked".into()),
            additional: HashMap::from([
                ("issuer".into(), Value::Text("Concordium".into())),
                ("version".into(), Value::Positive(1)),
            ]),
        }
        .encode_raw_cbor()
    }

    #[test]
    fn lock_info_round_trips_config_variants() {
        let variants = [
            info(
                LockRecipients::Limited(vec![CborHolderAccount::from(ADDRESS)]),
                None,
            ),
            info(
                LockRecipients::Limited(vec![CborHolderAccount::from(ADDRESS)]),
                Some(metadata()),
            ),
            info(LockRecipients::Any, None),
            info(LockRecipients::Limited(vec![]), None),
        ];
        for value in variants {
            assert_eq!(
                cbor::cbor_decode::<LockInfo>(&cbor::cbor_encode(&value)).unwrap(),
                value
            );
        }
    }
}
