use super::{LockController, LockId, LockMetadata, LockRecipients};
use crate::common::{
    cbor::{
        self, Bytes, CborDecoder, CborDeserialize, CborEncoder, CborMapDecoder, CborMapEncoder,
        CborSerializationError, CborSerializationResult, CborSerialize,
    },
    types::TransactionTime,
};
use crate::protocol_level_tokens::{CborHolderAccount, TokenAmount, TokenId};
use concordium_base_derive::{CborDeserialize, CborSerialize};

/// CBOR-encoded result of the `GetLockInfo` query.
#[derive(Debug, Clone, PartialEq)]
pub struct LockInfo {
    /// The lock identifier.
    pub lock: LockId,
    /// Accounts that can receive funds from this lock, or `Any` for any
    /// eligible recipient.
    pub recipients: LockRecipients,
    /// Expiry time of the lock (seconds since epoch).
    pub expiry: TransactionTime,
    /// Controller configuration for the lock.
    pub controller: LockController,
    /// Optional user-facing metadata encoded externally as CBOR bytes.
    pub metadata: Option<LockMetadata>,
    /// The locked balances currently controlled by the lock.
    pub funds: Vec<LockAccountFunds>,
}

impl CborSerialize for LockInfo {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> Result<(), C::WriteError> {
        let mut map_encoder = encoder.encode_map()?;
        map_encoder.serialize_entry("lock", &self.lock)?;
        map_encoder.serialize_entry("recipients", &self.recipients)?;
        map_encoder.serialize_entry("expiry", &self.expiry)?;
        map_encoder.serialize_entry("controller", &self.controller)?;
        if let Some(metadata) = &self.metadata {
            map_encoder.serialize_entry("metadata", &Bytes(cbor::cbor_encode(metadata)))?;
        }
        map_encoder.serialize_entry("funds", &self.funds)?;
        map_encoder.end()
    }
}

impl CborDeserialize for LockInfo {
    fn deserialize<C: CborDecoder>(decoder: C) -> CborSerializationResult<Self>
    where
        Self: Sized,
    {
        let mut lock = None;
        let mut recipients = None;
        let mut expiry = None;
        let mut controller = None;
        let mut metadata = None;
        let mut funds = None;
        let mut map_decoder = decoder.decode_map()?;

        while let Some(key) = map_decoder.deserialize_key::<String>()? {
            match key.as_str() {
                "lock" => lock = Some(map_decoder.deserialize_value()?),
                "recipients" => recipients = Some(map_decoder.deserialize_value()?),
                "expiry" => expiry = Some(map_decoder.deserialize_value()?),
                "controller" => controller = Some(map_decoder.deserialize_value()?),
                "metadata" => {
                    let bytes: Bytes = map_decoder.deserialize_value()?;
                    metadata = Some(cbor::cbor_decode(bytes)?);
                }
                "funds" => funds = Some(map_decoder.deserialize_value()?),
                _ => {
                    return Err(CborSerializationError::invalid_data(format_args!(
                        "unexpected lock info key {key:?}"
                    )))
                }
            }
        }

        Ok(Self {
            lock: lock.ok_or_else(|| {
                CborSerializationError::invalid_data(format_args!(
                    "missing required lock info key \"lock\""
                ))
            })?,
            recipients: recipients.ok_or_else(|| {
                CborSerializationError::invalid_data(format_args!(
                    "missing required lock info key \"recipients\""
                ))
            })?,
            expiry: expiry.ok_or_else(|| {
                CborSerializationError::invalid_data(format_args!(
                    "missing required lock info key \"expiry\""
                ))
            })?,
            controller: controller.ok_or_else(|| {
                CborSerializationError::invalid_data(format_args!(
                    "missing required lock info key \"controller\""
                ))
            })?,
            metadata,
            funds: funds.ok_or_else(|| {
                CborSerializationError::invalid_data(format_args!(
                    "missing required lock info key \"funds\""
                ))
            })?,
        })
    }
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
    use crate::common::cbor;
    use crate::common::cbor::value::Value;
    use crate::common::types::TransactionTime;
    use crate::protocol_level_locks::{
        LockController, LockControllerSimpleV0, LockControllerSimpleV0Capability,
        LockControllerSimpleV0Grant,
    };
    use crate::protocol_level_tokens::test_fixtures::ADDRESS;
    use std::collections::HashMap;

    fn example_lock_id() -> LockId {
        LockId {
            account_index: 10001,
            sequence_number: 5,
            creation_order: 0,
        }
    }

    fn example_lock_info() -> LockInfo {
        example_lock_info_with_recipients(LockRecipients::Limited(vec![CborHolderAccount::from(
            ADDRESS,
        )]))
    }

    fn example_lock_info_with_recipients(recipients: LockRecipients) -> LockInfo {
        LockInfo {
            lock: example_lock_id(),
            recipients,
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
                keep_alive: false,
                memo: None,
            }),
            metadata: None,
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
    fn test_lock_info_cbor_fixture_with_metadata() {
        let mut lock_info = example_lock_info();
        lock_info.metadata = Some(example_lock_metadata());
        let encoded = cbor::cbor_encode(&lock_info);
        let expected = concat!(
            "a6",
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
            "686d65746164617461",
            "585d",
            "a4",
            "646e616d65",
            "6c56657374696e67206c6f636b",
            "66697373756572",
            "6a436f6e636f726469756d",
            "6776657273696f6e",
            "01",
            "6b6465736372697074696f6e",
            "7821546f6b656e73206c6f636b65642062792076657374696e67207363686564756c65",
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

    fn example_lock_metadata() -> LockMetadata {
        let mut additional = HashMap::new();
        additional.insert("issuer".to_string(), Value::Text("Concordium".to_string()));
        additional.insert("version".to_string(), Value::Positive(1));
        LockMetadata {
            name: Some("Vesting lock".to_string()),
            description: Some("Tokens locked by vesting schedule".to_string()),
            additional,
        }
    }

    #[test]
    fn test_lock_info_cbor_round_trip_with_metadata() {
        let mut lock_info = example_lock_info();
        lock_info.metadata = Some(example_lock_metadata());
        let encoded = cbor::cbor_encode(&lock_info);
        let decoded: LockInfo = cbor::cbor_decode(&encoded).expect("CBOR decode failed");
        assert_eq!(decoded, lock_info);
    }

    #[test]
    fn test_lock_info_cbor_round_trip_any_recipients() {
        let lock_info = example_lock_info_with_recipients(LockRecipients::Any);
        let encoded = cbor::cbor_encode(&lock_info);
        let decoded: LockInfo = cbor::cbor_decode(&encoded).expect("CBOR decode failed");
        assert_eq!(decoded, lock_info);
    }

    #[test]
    fn test_lock_info_cbor_round_trip_empty_limited_recipients() {
        let lock_info = example_lock_info_with_recipients(LockRecipients::Limited(vec![]));
        let encoded = cbor::cbor_encode(&lock_info);
        let decoded: LockInfo = cbor::cbor_decode(&encoded).expect("CBOR decode failed");
        assert_eq!(decoded, lock_info);
    }

    #[test]
    fn test_lock_info_cbor_fixture_any_recipients() {
        let lock_info = example_lock_info_with_recipients(LockRecipients::Any);
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
            "63616e79"
        );
        assert_eq!(hex::encode(&encoded), expected);
    }
}
