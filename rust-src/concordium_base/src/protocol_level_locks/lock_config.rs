use super::LockConfigSimpleV0;
use crate::common::cbor::{
    self, value, CborDecoder, CborDeserialize, CborEncoder, CborSerializationError,
    CborSerializationResult, CborSerialize, DataItemHeader,
};
use crate::protocol_level_tokens::{CborHolderAccount, RawCbor};
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
#[derive(Debug, Clone, PartialEq, CborSerialize, CborDeserialize, Default)]
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

impl LockMetadata {
    /// Decode typed lock metadata from raw CBOR bytes.
    ///
    /// # Arguments
    ///
    /// * `raw_cbor` - Raw bytes expected to contain a CBOR-encoded lock metadata map.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes are not valid CBOR for [`LockMetadata`].
    ///
    /// # Example
    ///
    /// ```
    /// use concordium_base::common::cbor;
    /// use concordium_base::protocol_level_locks::LockMetadata;
    /// use concordium_base::protocol_level_tokens::RawCbor;
    ///
    /// let raw = RawCbor::from(cbor::cbor_encode(&LockMetadata::default()));
    /// let metadata = LockMetadata::decode_raw_cbor(&raw)?;
    /// # Ok::<(), concordium_base::common::cbor::CborSerializationError>(())
    /// ```
    pub fn decode_raw_cbor(raw_cbor: &RawCbor) -> CborSerializationResult<Self> {
        cbor::cbor_decode(raw_cbor.as_ref())
    }

    /// Encode typed lock metadata to raw CBOR bytes.
    ///
    /// # Example
    ///
    /// ```
    /// use concordium_base::protocol_level_locks::LockMetadata;
    ///
    /// let raw = LockMetadata::default().encode_raw_cbor();
    /// assert!(!raw.as_ref().is_empty());
    /// ```
    pub fn encode_raw_cbor(&self) -> RawCbor {
        RawCbor::from(cbor::cbor_encode(self))
    }
}

/// Top-level lock configuration.
///
/// Each variant represents a different lock type.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
#[cbor(map)]
pub enum LockConfig {
    /// V0 simple lock configuration.
    SimpleV0(LockConfigSimpleV0),
}

/// Canonical parameters used to price lock creation.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct LockComplexityParameters {
    pub(crate) token_holders: u64,
    pub(crate) tokens: u64,
    pub(crate) grants: u64,
}

impl LockConfig {
    /// Canonical (Fund-authorized accounts, distinct tokens, account grants).
    /// Mirrors persistent grant union/empty-grant retention without resolving accounts.
    pub(crate) fn get_creation_complexity_parameters(&self) -> LockComplexityParameters {
        use super::LockControllerSimpleV0Capability::Fund;
        use crate::base::AccountAddressEq;
        use std::collections::HashSet;

        let Self::SimpleV0(config) = self;
        let mut grants = HashMap::<AccountAddressEq, bool>::new();
        for grant in &config.grants {
            *grants.entry(grant.account.address.into()).or_default() |= grant.roles.contains(&Fund);
        }
        let tokens: HashSet<_> = config
            .tokens
            .iter()
            .map(|token| token.as_ref().to_ascii_lowercase())
            .collect();
        LockComplexityParameters {
            token_holders: grants.values().filter(|&&fund| fund).count() as u64,
            tokens: tokens.len() as u64,
            grants: grants.len() as u64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::{cbor, cbor::value::Value, types::TransactionTime},
        protocol_level_locks::{LockControllerSimpleV0Capability, LockControllerSimpleV0Grant},
        protocol_level_tokens::{test_fixtures::ADDRESS, CborMemo},
        transactions::Memo,
    };

    fn metadata() -> LockMetadata {
        LockMetadata {
            name: Some("Vesting lock".into()),
            description: Some("Tokens locked by vesting schedule".into()),
            additional: HashMap::from([
                ("issuer".into(), Value::Text("Concordium".into())),
                ("version".into(), Value::Positive(1)),
            ]),
        }
    }

    fn config(recipients: LockRecipients, metadata: Option<RawCbor>) -> LockConfig {
        LockConfig::SimpleV0(LockConfigSimpleV0 {
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
            keep_alive: true,
            memo: Some(CborMemo::Raw(Memo::try_from(vec![1, 2, 3]).unwrap())),
            metadata,
        })
    }

    #[test]
    fn create_complexity_matches_persistent_grant_normalization() {
        use concordium_contracts_common::AccountAddress;
        use LockControllerSimpleV0Capability::*;
        let address = |n| AccountAddress([n; 32]);
        let grant = |account, roles| LockControllerSimpleV0Grant {
            account: CborHolderAccount::from(account),
            roles,
        };
        // Same grant pattern as persistent grants_normalize_union_lookup_and_hash_deterministically:
        // account 9 is split, account 5 has no roles, and account 1 can Fund.
        let mut alias = address(9);
        alias.0[31] = 42;
        let mut simple = match config(LockRecipients::Any, None) {
            LockConfig::SimpleV0(simple) => simple,
        };
        simple.grants = vec![
            grant(address(9), vec![Send]),
            grant(address(1), vec![Fund, Fund]),
            grant(alias, vec![Release, Fund]),
            grant(address(5), vec![]),
            grant(address(5), vec![]),
        ];
        simple.tokens = vec![
            "A".parse().unwrap(),
            "B".parse().unwrap(),
            "a".parse().unwrap(),
        ];
        let first = LockConfig::SimpleV0(simple.clone());
        assert_eq!(
            first.get_creation_complexity_parameters(),
            LockComplexityParameters {
                token_holders: 2,
                tokens: 2,
                grants: 3
            }
        );
        simple.grants.reverse();
        simple.tokens.reverse();
        let reordered = LockConfig::SimpleV0(simple.clone());
        assert_eq!(
            first.get_creation_complexity_parameters(),
            reordered.get_creation_complexity_parameters()
        );
        assert_eq!(
            crate::transactions::cost::plt_lock_create(&first).energy,
            2130
        );
        // Equivalent canonical grants, including the retained empty grant.
        simple.grants = vec![
            grant(address(1), vec![Fund]),
            grant(address(5), vec![]),
            grant(address(9), vec![Send, Release, Fund]),
        ];
        simple.tokens.pop();
        assert_eq!(
            LockConfig::SimpleV0(simple.clone()).get_creation_complexity_parameters(),
            LockComplexityParameters {
                token_holders: 2,
                tokens: 2,
                grants: 3
            }
        );
        simple.grants.clear();
        simple.tokens.clear();
        assert_eq!(
            LockConfig::SimpleV0(simple).get_creation_complexity_parameters(),
            LockComplexityParameters {
                token_holders: 0,
                tokens: 0,
                grants: 0
            }
        );
    }

    #[test]
    fn lock_config_fixture_limited_recipients_round_trips() {
        let config = config(
            LockRecipients::Limited(vec![CborHolderAccount::from(ADDRESS)]),
            None,
        );
        let expected = "a16873696d706c655630a6646d656d6f4301020366657870697279c11a6b932770666772616e747381a265726f6c6573826466756e646473656e64676163636f756e74d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2066746f6b656e7381627454696b656570416c697665f56a726563697069656e747381d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        assert_eq!(hex::encode(cbor::cbor_encode(&config)), expected);
        assert_eq!(
            cbor::cbor_decode::<LockConfig>(&hex::decode(expected).unwrap()).unwrap(),
            config
        );
    }

    #[test]
    fn lock_config_fixture_any_recipients_with_metadata_round_trips() {
        let config = config(LockRecipients::Any, Some(metadata().encode_raw_cbor()));
        let expected = "a16873696d706c655630a7646d656d6f4301020366657870697279c11a6b932770666772616e747381a265726f6c6573826466756e646473656e64676163636f756e74d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2066746f6b656e7381627454686d65746164617461585da4646e616d656c56657374696e67206c6f636b666973737565726a436f6e636f726469756d6776657273696f6e016b6465736372697074696f6e7821546f6b656e73206c6f636b65642062792076657374696e67207363686564756c65696b656570416c697665f56a726563697069656e747363616e79";
        assert_eq!(hex::encode(cbor::cbor_encode(&config)), expected);
        assert_eq!(
            cbor::cbor_decode::<LockConfig>(&hex::decode(expected).unwrap()).unwrap(),
            config
        );
    }

    #[test]
    fn lock_config_round_trips_recipient_and_metadata_variants() {
        let multiple = config(
            LockRecipients::Limited(vec![
                CborHolderAccount::from(ADDRESS),
                CborHolderAccount::from(ADDRESS),
            ]),
            None,
        );
        let empty = config(LockRecipients::Limited(vec![]), None);
        let any = config(LockRecipients::Any, None);
        let with_metadata = config(
            LockRecipients::Limited(vec![CborHolderAccount::from(ADDRESS)]),
            Some(metadata().encode_raw_cbor()),
        );
        for config in [multiple, empty, any, with_metadata] {
            assert_eq!(
                cbor::cbor_decode::<LockConfig>(&cbor::cbor_encode(&config)).unwrap(),
                config
            );
        }
    }

    #[test]
    fn metadata_matches_fixed_fixture() {
        let expected = "a4646e616d656c56657374696e67206c6f636b666973737565726a436f6e636f726469756d6776657273696f6e016b6465736372697074696f6e7821546f6b656e73206c6f636b65642062792076657374696e67207363686564756c65";
        assert_eq!(hex::encode(cbor::cbor_encode(&metadata())), expected);
        assert_eq!(
            LockMetadata::decode_raw_cbor(&RawCbor::from(hex::decode(expected).unwrap())).unwrap(),
            metadata()
        );
    }

    #[test]
    fn metadata_raw_decode_rejects_invalid_and_noncanonical_input() {
        assert!(LockMetadata::decode_raw_cbor(&RawCbor::from(vec![1])).is_err());
        assert!(LockMetadata::decode_raw_cbor(&RawCbor::from(
            hex::decode("b8646e616d656178").unwrap()
        ))
        .is_err());
    }

    #[test]
    fn recipients_reject_unknown_text() {
        let err = cbor::cbor_decode::<LockRecipients>(&hex::decode("63616c6c").unwrap())
            .expect_err("unknown recipient text must fail");
        assert!(
            err.to_string()
                .contains("unsupported lock recipients text value"),
            "unexpected error: {err}"
        );
    }
}
