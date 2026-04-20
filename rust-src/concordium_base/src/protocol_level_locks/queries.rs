use super::{LockConfig, LockId};
use crate::protocol_level_tokens::{CborHolderAccount, TokenAmount, TokenId};
use concordium_base_derive::{CborDeserialize, CborSerialize};

/// CBOR-encoded result of the `GetLockInfo` query.
///
/// The CBOR representation flattens the [`LockConfig`] fields into the
/// top-level map so the encoded shape is:
///
/// ```text
/// {
///   "lock": lock-id,
///   "recipients": [...],
///   "expiry": epoch-time,
///   "controller": lock-controller,
///   "funds": [...]
/// }
/// ```
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
pub struct LockInfo {
    /// The lock identifier.
    pub lock: LockId,
    /// The static configuration of the lock.
    #[cbor(flatten)]
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
mod test {
    use super::*;
    use crate::base::{AccountIndex, Nonce};
    use crate::common::cbor;
    use crate::common::types::TransactionTime;
    use crate::protocol_level_locks::{
        LockController, LockControllerSimpleV0, LockControllerSimpleV0Capability,
        LockControllerSimpleV0Grant,
    };
    use crate::protocol_level_tokens::test_fixtures::ADDRESS;

    fn example_lock_id() -> LockId {
        LockId {
            account_index: AccountIndex { index: 10001 },
            sequence_number: Nonce { nonce: 5 },
            creation_order: 0,
        }
    }

    fn example_lock_config() -> LockConfig {
        LockConfig {
            recipients: vec![CborHolderAccount::from(ADDRESS)],
            expiry: TransactionTime::from_seconds(1804806000),
            controller: LockController::SimpleV0(LockControllerSimpleV0 {
                grants: vec![LockControllerSimpleV0Grant {
                    account: CborHolderAccount::from(ADDRESS),
                    roles: vec![
                        LockControllerSimpleV0Capability::Fund,
                        LockControllerSimpleV0Capability::Send,
                    ],
                }],
                tokens: vec!["CCD".parse().unwrap()],
                keep_alive: None,
                memo: None,
            }),
        }
    }

    fn example_lock_info() -> LockInfo {
        LockInfo {
            lock: example_lock_id(),
            config: example_lock_config(),
            funds: vec![LockAccountFunds {
                account: CborHolderAccount::from(ADDRESS),
                amounts: vec![LockedTokenAmount {
                    token: "CCD".parse().unwrap(),
                    amount: TokenAmount::from_raw(12300, 3),
                }],
            }],
        }
    }

    #[test]
    fn test_lock_info_cbor_round_trip() {
        let lock_info = example_lock_info();
        let encoded = cbor::cbor_encode(&lock_info);
        let decoded: LockInfo = cbor::cbor_decode(&encoded).expect("CBOR decode failed");
        assert_eq!(decoded, lock_info);
    }

    #[test]
    fn test_lock_info_cbor_fixture() {
        let lock_info = example_lock_info();
        let encoded = cbor::cbor_encode(&lock_info);
        let expected = concat!(
            "a5",
            "646c6f636b",
            "d99fd8831927110500",
            "6566756e6473",
            "81",
            "a2",
            "676163636f756e74",
            "d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            "67616d6f756e7473",
            "81",
            "a2",
            "65746f6b656e",
            "63434344",
            "66616d6f756e74",
            "c4822219300c",
            "66657870697279",
            "c11a6b932770",
            "6a636f6e74726f6c6c6572",
            "a1",
            "6873696d706c655630",
            "a2",
            "666772616e7473",
            "81",
            "a2",
            "65726f6c6573",
            "82",
            "6466756e64",
            "6473656e64",
            "676163636f756e74",
            "d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            "66746f6b656e73",
            "81",
            "63434344",
            "6a726563697069656e7473",
            "81",
            "d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        );
        assert_eq!(hex::encode(&encoded), expected);
    }
}
