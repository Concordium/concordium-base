use super::LockController;
use crate::common::{
    cbor::{
        self, value, Bytes, CborDecoder, CborDeserialize, CborEncoder, CborMapDecoder,
        CborMapEncoder, CborSerializationError, CborSerializationResult, CborSerialize,
        DataItemHeader,
    },
    types::TransactionTime,
};
use crate::protocol_level_tokens::CborHolderAccount;
use concordium_base_derive::{CborDeserialize, CborSerialize};
use std::collections::HashMap;

/// Accounts that can receive funds controlled by a lock.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum LockRecipients {
    /// Any eligible account can receive funds from this lock.
    Any,
    /// Only the listed accounts can receive funds from this lock.
    Limited(Vec<CborHolderAccount>),
}

impl CborSerialize for LockRecipients {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> Result<(), C::WriteError> {
        match self {
            Self::Any => encoder.encode_text("any"),
            Self::Limited(accounts) => accounts.serialize(encoder),
        }
    }
}

impl CborDeserialize for LockRecipients {
    fn deserialize<C: CborDecoder>(mut decoder: C) -> CborSerializationResult<Self>
    where
        Self: Sized,
    {
        match decoder.peek_data_item_header()? {
            DataItemHeader::Text(_) => {
                let value = String::deserialize(decoder)?;
                if value == "any" {
                    Ok(Self::Any)
                } else {
                    Err(CborSerializationError::invalid_data(format_args!(
                        "unsupported lock recipients text value {value:?}"
                    )))
                }
            }
            DataItemHeader::Array(_) => Ok(Self::Limited(Vec::deserialize(decoder)?)),
            header => Err(CborSerializationError::invalid_data(format_args!(
                "lock recipients must be text \"any\" or an array of account addresses, was {header:?}"
            ))),
        }
    }
}

/// User-facing metadata attached to a lock at creation time.
#[derive(Debug, Clone, PartialEq, CborSerialize, CborDeserialize)]
pub struct LockMetadata {
    /// Optional user-facing lock name.
    pub name: Option<String>,
    /// Optional user-facing lock description.
    pub description: Option<String>,
    /// Additional text-keyed CBOR fields preserved for future extensibility and
    /// user-defined metadata.
    #[cbor(other)]
    pub additional: HashMap<String, value::Value>,
}

/// Top-level lock configuration.
///
/// Contains the recipients, the expiry time, the controller configuration, and
/// optional immutable metadata for a lock.
#[derive(Debug, Clone, PartialEq)]
pub struct LockConfig {
    /// Accounts that can receive funds from this lock, or `Any` for any
    /// eligible recipient.
    pub recipients: LockRecipients,
    /// Expiry time of the lock (seconds since epoch).
    pub expiry: TransactionTime,
    /// Controller configuration for the lock.
    pub controller: LockController,
    /// Optional user-facing metadata encoded externally as CBOR bytes.
    pub metadata: Option<LockMetadata>,
}

impl CborSerialize for LockConfig {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> Result<(), C::WriteError> {
        let mut map_encoder = encoder.encode_map()?;
        map_encoder.serialize_entry("recipients", &self.recipients)?;
        map_encoder.serialize_entry("expiry", &self.expiry)?;
        map_encoder.serialize_entry("controller", &self.controller)?;
        if let Some(metadata) = &self.metadata {
            map_encoder.serialize_entry("metadata", &Bytes(cbor::cbor_encode(metadata)))?;
        }
        map_encoder.end()
    }
}

impl CborDeserialize for LockConfig {
    fn deserialize<C: CborDecoder>(decoder: C) -> CborSerializationResult<Self>
    where
        Self: Sized,
    {
        let mut recipients = None;
        let mut expiry = None;
        let mut controller = None;
        let mut metadata = None;
        let mut map_decoder = decoder.decode_map()?;

        while let Some(key) = map_decoder.deserialize_key::<String>()? {
            match key.as_str() {
                "recipients" => recipients = Some(map_decoder.deserialize_value()?),
                "expiry" => expiry = Some(map_decoder.deserialize_value()?),
                "controller" => controller = Some(map_decoder.deserialize_value()?),
                "metadata" => {
                    let bytes: Bytes = map_decoder.deserialize_value()?;
                    metadata = Some(cbor::cbor_decode(bytes)?);
                }
                _ => {
                    return Err(CborSerializationError::invalid_data(format_args!(
                        "unexpected lock config key {key:?}"
                    )))
                }
            }
        }

        Ok(Self {
            recipients: recipients.ok_or_else(|| {
                CborSerializationError::invalid_data(format_args!(
                    "missing required lock config key \"recipients\""
                ))
            })?,
            expiry: expiry.ok_or_else(|| {
                CborSerializationError::invalid_data(format_args!(
                    "missing required lock config key \"expiry\""
                ))
            })?,
            controller: controller.ok_or_else(|| {
                CborSerializationError::invalid_data(format_args!(
                    "missing required lock config key \"controller\""
                ))
            })?,
            metadata,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::common::cbor;
    use crate::common::cbor::value::Value;
    use crate::protocol_level_locks::{
        LockControllerSimpleV0, LockControllerSimpleV0Capability, LockControllerSimpleV0Grant,
    };
    use crate::protocol_level_tokens::test_fixtures::ADDRESS;

    /// Build a full `LockConfig` for testing.
    fn example_lock_config() -> LockConfig {
        LockConfig {
            recipients: LockRecipients::Limited(vec![CborHolderAccount::from(ADDRESS)]),
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
        }
    }

    /// Round-trip test: encode then decode produces the same `LockConfig`.
    #[test]
    fn test_lock_config_cbor_round_trip() {
        let config = example_lock_config();
        let encoded = cbor::cbor_encode(&config);
        let decoded: LockConfig = cbor::cbor_decode(&encoded).expect("CBOR decode failed");
        assert_eq!(decoded, config);
    }

    /// Round-trip test with multiple recipients.
    #[test]
    fn test_lock_config_cbor_round_trip_multiple_recipients() {
        let mut config = example_lock_config();
        config.recipients = LockRecipients::Limited(vec![
            CborHolderAccount::from(ADDRESS),
            CborHolderAccount::from(ADDRESS),
        ]);
        let encoded = cbor::cbor_encode(&config);
        let decoded: LockConfig = cbor::cbor_decode(&encoded).expect("CBOR decode failed");
        assert_eq!(decoded, config);
    }

    /// Round-trip test with empty recipients.
    #[test]
    fn test_lock_config_cbor_round_trip_empty_recipients() {
        let mut config = example_lock_config();
        config.recipients = LockRecipients::Limited(vec![]);
        let encoded = cbor::cbor_encode(&config);
        let decoded: LockConfig = cbor::cbor_decode(&encoded).expect("CBOR decode failed");
        assert_eq!(decoded, config);
    }

    /// Round-trip test with any recipients.
    #[test]
    fn test_lock_config_cbor_round_trip_any_recipients() {
        let mut config = example_lock_config();
        config.recipients = LockRecipients::Any;
        let encoded = cbor::cbor_encode(&config);
        let decoded: LockConfig = cbor::cbor_decode(&encoded).expect("CBOR decode failed");
        assert_eq!(decoded, config);
    }

    /// Fixture test: verify the exact CBOR encoding of limited recipients.
    ///
    /// Expected CBOR structure (diagnostic notation):
    /// ```text
    /// {
    ///   "expiry": 1(1804806000),
    ///   "controller": {"simpleV0": {"grants": [], "tokens": []}},
    ///   "recipients": [40307({1: 40305({1: 919}), 3: h'0102...1f20'})]
    /// }
    /// ```
    ///
    /// Map keys sorted by encoded byte length, then lexicographically:
    /// - "expiry" (6 bytes)
    /// - "controller" (10 bytes)
    /// - "recipients" (10 bytes) — same length as "controller", sorted
    ///   lexicographically
    ///
    /// Note: `keep_alive: false` and `memo: None` are omitted from the CBOR
    /// map, so the inner `LockControllerSimpleV0` map has only 2 entries.
    #[test]
    fn test_lock_config_cbor_fixture_limited_recipients() {
        let config = LockConfig {
            recipients: LockRecipients::Limited(vec![CborHolderAccount::from(ADDRESS)]),
            expiry: TransactionTime::from_seconds(1804806000),
            controller: LockController::SimpleV0(LockControllerSimpleV0 {
                grants: vec![],
                tokens: vec![],
                keep_alive: false,
                memo: None,
            }),
            metadata: None,
        };
        let encoded = cbor::cbor_encode(&config);
        // Build expected hex:
        //
        // Map(3): a3
        //
        // Keys sorted by encoded byte length, then lexicographically:
        // "expiry" (6 bytes) → 66657870697279
        // "controller" (10 bytes) → 6a636f6e74726f6c6c6572
        // "recipients" (10 bytes) → 6a726563697069656e7473
        //
        // Values:
        // expiry: 1(1804806000) → c11a6b932770
        // controller: {"simpleV0": {grants: [], tokens: []}}
        //   Map(1): a1
        //     "simpleV0" (8): 6873696d706c655630
        //     Map(2): a2
        //       "grants" (6): 666772616e7473, []: 80
        //       "tokens" (6): 66746f6b656e73, []: 80
        // recipients: [CborHolderAccount]
        //   Array(1): 81
        //   CborHolderAccount: d99d73a201d99d71a1011903970358200102...1f20
        let expected = concat!(
            "a3",                       // map(3)
            "66657870697279",           // text "expiry"
            "c11a6b932770",             // tag(1) uint(1804806000)
            "6a636f6e74726f6c6c6572",   // text "controller"
            "a1",                       // map(1) — LockController
            "6873696d706c655630",       // text "simpleV0"
            "a2",                       // map(2) — LockControllerSimpleV0
            "666772616e7473",           // text "grants"
            "80",                       // array(0)
            "66746f6b656e73",           // text "tokens"
            "80",                       // array(0)
            "6a726563697069656e7473",   // text "recipients"
            "81",                       // array(1)
            "d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", // CborHolderAccount
        );
        assert_eq!(hex::encode(&encoded), expected);
    }

    /// Fixture test: verify the exact CBOR encoding of any recipients and metadata.
    #[test]
    fn test_lock_config_cbor_fixture_any_recipients_with_metadata() {
        let config = LockConfig {
            recipients: LockRecipients::Any,
            expiry: TransactionTime::from_seconds(1804806000),
            controller: LockController::SimpleV0(LockControllerSimpleV0 {
                grants: vec![],
                tokens: vec![],
                keep_alive: false,
                memo: None,
            }),
            metadata: Some(example_lock_metadata()),
        };
        let encoded = cbor::cbor_encode(&config);
        let expected = concat!(
            "a4",                                                                     // map(4)
            "66657870697279",             // text "expiry"
            "c11a6b932770",               // tag(1) uint(1804806000)
            "686d65746164617461",         // text "metadata"
            "585d",                       // bytes(93)
            "a4",                         // metadata map(4)
            "646e616d65",                 // text "name"
            "6c56657374696e67206c6f636b", // text "Vesting lock"
            "66697373756572",             // text "issuer"
            "6a436f6e636f726469756d",     // text "Concordium"
            "6776657273696f6e",           // text "version"
            "01",                         // uint(1)
            "6b6465736372697074696f6e",   // text "description"
            "7821546f6b656e73206c6f636b65642062792076657374696e67207363686564756c65", // text "Tokens locked by vesting schedule"
            "6a636f6e74726f6c6c6572", // text "controller"
            "a1",                     // map(1) — LockController
            "6873696d706c655630",     // text "simpleV0"
            "a2",                     // map(2) — LockControllerSimpleV0
            "666772616e7473",         // text "grants"
            "80",                     // array(0)
            "66746f6b656e73",         // text "tokens"
            "80",                     // array(0)
            "6a726563697069656e7473", // text "recipients"
            "63616e79",               // text "any"
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
    fn test_lock_metadata_cbor_fixture_known_and_additional_fields() {
        let metadata = example_lock_metadata();
        let encoded = cbor::cbor_encode(&metadata);
        let expected = concat!(
            "a4",
            "646e616d65",
            "6c56657374696e67206c6f636b",
            "66697373756572",
            "6a436f6e636f726469756d",
            "6776657273696f6e",
            "01",
            "6b6465736372697074696f6e",
            "7821546f6b656e73206c6f636b65642062792076657374696e67207363686564756c65",
        );
        assert_eq!(hex::encode(&encoded), expected);
        let decoded: LockMetadata = cbor::cbor_decode(&encoded).expect("CBOR decode failed");
        assert_eq!(decoded, metadata);
    }

    #[test]
    fn test_lock_config_cbor_round_trip_with_metadata() {
        let mut config = example_lock_config();
        config.metadata = Some(example_lock_metadata());
        let encoded = cbor::cbor_encode(&config);
        let decoded: LockConfig = cbor::cbor_decode(&encoded).expect("CBOR decode failed");
        assert_eq!(decoded, config);
    }

    /// Decode rejects unknown text recipient values.
    #[test]
    fn test_lock_recipients_cbor_rejects_unknown_text() {
        let err = cbor::cbor_decode::<LockRecipients>(hex::decode("63616c6c").unwrap())
            .expect_err("CBOR decode should fail");
        assert!(
            err.to_string()
                .contains("unsupported lock recipients text value"),
            "unexpected error: {err}"
        );
    }
}
