use crate::common::cbor::{
    CborDecoder, CborDeserialize, CborEncoder, CborSerializationError, CborSerializationResult,
    CborSerialize,
};
use crate::{
    common::types::TransactionTime,
    protocol_level_locks::LockRecipients,
    protocol_level_tokens::{CborHolderAccount, CborMemo, RawCbor, TokenId},
};
use concordium_base_derive::{CborDeserialize, CborSerialize, Serialize};

/// Capability that can be granted to an account for a SimpleV0 lock
/// controller.
///
/// Each capability authorizes the grantee to perform the corresponding lock
/// operation.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize)]
pub enum LockControllerSimpleV0Capability {
    /// Authorizes funding the lock with a permitted token.
    Fund,
    /// Authorizes returning funds from the lock.
    Return,
    /// Authorizes sending funds from the lock to a recipient. This is subject to individual token
    /// policies such as pausation and allow/deny lists.
    Send,
    /// Authorizes cancelling the lock.
    Cancel,
}

impl LockControllerSimpleV0Capability {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Fund => "fund",
            Self::Return => "return",
            Self::Send => "send",
            Self::Cancel => "cancel",
        }
    }

    fn from_str(s: &str) -> Result<Self, CborSerializationError> {
        match s {
            "fund" => Ok(Self::Fund),
            "return" => Ok(Self::Return),
            "send" => Ok(Self::Send),
            "cancel" => Ok(Self::Cancel),
            other => Err(CborSerializationError::invalid_data(format_args!(
                "unknown LockControllerSimpleV0Capability: \"{}\"",
                other
            ))),
        }
    }
}

impl CborSerialize for LockControllerSimpleV0Capability {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> Result<(), C::WriteError> {
        encoder.encode_text(self.as_str())
    }
}

impl CborDeserialize for LockControllerSimpleV0Capability {
    fn deserialize<C: CborDecoder>(decoder: C) -> CborSerializationResult<Self>
    where
        Self: Sized,
    {
        let text_bytes = decoder.decode_text()?;
        let text = std::str::from_utf8(&text_bytes).map_err(|_| {
            CborSerializationError::invalid_data(format_args!(
                "LockControllerSimpleV0Capability text is not valid UTF-8"
            ))
        })?;
        Self::from_str(text)
    }
}

/// A grant of capabilities to a specific account for a SimpleV0 lock
/// controller.
///
/// Each grant assigns one or more [`LockControllerSimpleV0Capability`] roles
/// to the given account, authorizing it to perform the corresponding lock
/// operations.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
pub struct LockControllerSimpleV0Grant {
    /// The account receiving the grant.
    pub account: CborHolderAccount,
    /// The capabilities granted to the account.
    pub roles: Vec<LockControllerSimpleV0Capability>,
}

/// Configuration for a SimpleV0 lock controller.
///
/// Contains the list of capability grants, which tokens are affected,
/// a keep-alive flag, and an optional memo.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
pub struct LockConfigSimpleV0 {
    /// Accounts that can receive funds from this lock.
    pub recipients: LockRecipients,
    /// Expiry time of the lock.
    pub expiry: TransactionTime,
    /// Capability grants to accounts.
    pub grants: Vec<LockControllerSimpleV0Grant>,
    /// Tokens affected by this lock controller.
    pub tokens: Vec<TokenId>,
    /// Whether the lock should be kept alive after all funds are
    /// returned. Interpreted as `false` when omitted from the serialization.
    #[cbor(default = false)]
    pub keep_alive: bool,
    /// Optional memo attached to the lock.
    pub memo: Option<CborMemo>,
    /// Optional opaque CBOR-encoded user-facing metadata.
    pub metadata: Option<RawCbor>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::{cbor, serialize_deserialize, to_bytes},
        protocol_level_tokens::test_fixtures::ADDRESS,
        transactions::Memo,
    };

    fn full_config() -> LockConfigSimpleV0 {
        LockConfigSimpleV0 {
            recipients: LockRecipients::Limited(vec![CborHolderAccount::from(ADDRESS)]),
            expiry: TransactionTime::from_seconds(1804806000),
            grants: vec![LockControllerSimpleV0Grant {
                account: CborHolderAccount::from(ADDRESS),
                roles: vec![
                    LockControllerSimpleV0Capability::Fund,
                    LockControllerSimpleV0Capability::Cancel,
                ],
            }],
            tokens: vec!["CCD".parse().unwrap()],
            keep_alive: true,
            memo: Some(CborMemo::Raw(Memo::try_from(vec![1, 2, 3]).unwrap())),
            metadata: None,
        }
    }

    #[test]
    fn capability_cbor_round_trips_and_matches_fixtures() {
        let fixtures = [
            (LockControllerSimpleV0Capability::Fund, "6466756e64"),
            (LockControllerSimpleV0Capability::Return, "6672657475726e"),
            (LockControllerSimpleV0Capability::Send, "6473656e64"),
            (LockControllerSimpleV0Capability::Cancel, "6663616e63656c"),
        ];
        for (capability, fixture) in fixtures {
            assert_eq!(hex::encode(cbor::cbor_encode(&capability)), fixture);
            assert_eq!(
                cbor::cbor_decode::<LockControllerSimpleV0Capability>(
                    &hex::decode(fixture).unwrap()
                )
                .unwrap(),
                capability
            );
        }
    }

    #[test]
    fn grant_cbor_round_trips_and_matches_fixture() {
        let grant = LockControllerSimpleV0Grant {
            account: CborHolderAccount::from(ADDRESS),
            roles: vec![
                LockControllerSimpleV0Capability::Fund,
                LockControllerSimpleV0Capability::Cancel,
            ],
        };
        let fixture = "a265726f6c6573826466756e646663616e63656c676163636f756e74d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        assert_eq!(
            cbor::cbor_decode::<LockControllerSimpleV0Grant>(&cbor::cbor_encode(&grant)).unwrap(),
            grant
        );
        assert_eq!(hex::encode(cbor::cbor_encode(&grant)), fixture);
        assert_eq!(
            cbor::cbor_decode::<LockControllerSimpleV0Grant>(&hex::decode(fixture).unwrap())
                .unwrap(),
            grant
        );
    }

    #[test]
    fn config_cbor_round_trips_full_and_minimal() {
        let minimal = LockConfigSimpleV0 {
            recipients: LockRecipients::Limited(vec![]),
            expiry: TransactionTime::from_seconds(1804806000),
            grants: vec![],
            tokens: vec![],
            keep_alive: false,
            memo: None,
            metadata: None,
        };
        for config in [full_config(), minimal] {
            assert_eq!(
                cbor::cbor_decode::<LockConfigSimpleV0>(&cbor::cbor_encode(&config)).unwrap(),
                config
            );
        }
    }

    #[test]
    fn config_cbor_matches_full_and_minimal_fixtures() {
        let full = "a6646d656d6f4301020366657870697279c11a6b932770666772616e747381a265726f6c6573826466756e646663616e63656c676163636f756e74d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2066746f6b656e738163434344696b656570416c697665f56a726563697069656e747381d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let minimal =
            "a466657870697279c11a6b932770666772616e74738066746f6b656e73806a726563697069656e747380";
        let minimal_config = LockConfigSimpleV0 {
            recipients: LockRecipients::Limited(vec![]),
            expiry: TransactionTime::from_seconds(1804806000),
            grants: vec![],
            tokens: vec![],
            keep_alive: false,
            memo: None,
            metadata: None,
        };
        for (config, fixture) in [(full_config(), full), (minimal_config, minimal)] {
            assert_eq!(hex::encode(cbor::cbor_encode(&config)), fixture);
            assert_eq!(
                cbor::cbor_decode::<LockConfigSimpleV0>(&hex::decode(fixture).unwrap()).unwrap(),
                config
            );
        }
    }

    #[test]
    fn config_cbor_decodes_noncanonical_fixture() {
        let fixture = "a56a726563697069656e74738066746f6b656e738163434344696b656570416c697665f4666772616e747381a2676163636f756e74d99d73a201d99d71a1011a000003970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2065726f6c6573826466756e646663616e63656c66657870697279c11a6b932770";
        let expected = LockConfigSimpleV0 {
            recipients: LockRecipients::Limited(vec![]),
            keep_alive: false,
            memo: None,
            ..full_config()
        };
        assert_eq!(
            cbor::cbor_decode::<LockConfigSimpleV0>(&hex::decode(fixture).unwrap()).unwrap(),
            expected
        );
    }

    #[test]
    fn capability_serial_round_trips_and_matches_tag_fixtures() {
        let fixtures = [
            (LockControllerSimpleV0Capability::Fund, "00"),
            (LockControllerSimpleV0Capability::Return, "01"),
            (LockControllerSimpleV0Capability::Send, "02"),
            (LockControllerSimpleV0Capability::Cancel, "03"),
        ];
        for (capability, fixture) in fixtures {
            assert_eq!(serialize_deserialize(&capability).unwrap(), capability);
            assert_eq!(hex::encode(to_bytes(&capability)), fixture);
        }
    }
}
