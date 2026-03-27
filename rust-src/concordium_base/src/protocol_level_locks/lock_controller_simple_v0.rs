use crate::common::cbor::{
    CborDecoder, CborDeserialize, CborEncoder, CborMapDecoder, CborMapEncoder,
    CborSerializationError, CborSerializationResult, CborSerialize, MapKey, MapKeyRef,
};
use crate::protocol_level_tokens::{CborHolderAccount, CborMemo, TokenId};
use concordium_base_derive::{CborDeserialize, CborSerialize, Serialize};

/// Capability that can be granted to an account for a SimpleV0 lock
/// controller.
///
/// Each capability authorizes the grantee to perform the corresponding lock
/// operation.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize)]
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "serde_deprecated", serde(rename_all = "camelCase"))]
pub enum LockControllerSimpleV0Capability {
    Fund,
    Return,
    Send,
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
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "serde_deprecated", serde(rename_all = "camelCase"))]
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
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(feature = "serde_deprecated", serde(rename_all = "camelCase"))]
pub struct LockControllerSimpleV0 {
    /// Capability grants to accounts.
    pub grants: Vec<LockControllerSimpleV0Grant>,
    /// Tokens affected by this lock controller.
    pub tokens: Vec<TokenId>,
    /// Whether the lock should be kept alive after all funds are
    /// returned. Defaults to `false` when omitted from CBOR.
    #[cfg_attr(feature = "serde_deprecated", serde(default))]
    pub keep_alive: bool,
    /// Optional memo attached to the lock.
    #[cfg_attr(
        feature = "serde_deprecated",
        serde(skip_serializing_if = "Option::is_none")
    )]
    pub memo: Option<CborMemo>,
}

impl CborSerialize for LockControllerSimpleV0 {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> Result<(), C::WriteError> {
        let mut map_encoder = encoder.encode_map()?;
        map_encoder.serialize_entry(&MapKeyRef::Text("grants"), &self.grants)?;
        map_encoder.serialize_entry(&MapKeyRef::Text("tokens"), &self.tokens)?;
        // Always serialize keep_alive (even when false), matching normal CBOR
        // map behavior for non-optional fields.
        map_encoder.serialize_entry(&MapKeyRef::Text("keepAlive"), &self.keep_alive)?;
        if !CborSerialize::is_null(&self.memo) {
            map_encoder.serialize_entry(&MapKeyRef::Text("memo"), &self.memo)?;
        }
        map_encoder.end()?;
        Ok(())
    }
}

impl CborDeserialize for LockControllerSimpleV0 {
    fn deserialize<C: CborDecoder>(decoder: C) -> CborSerializationResult<Self>
    where
        Self: Sized,
    {
        let mut grants = None;
        let mut tokens = None;
        let mut keep_alive = None;
        let mut memo: Option<Option<CborMemo>> = None;

        let mut map_decoder = decoder.decode_map()?;
        while let Some(map_key) = CborMapDecoder::deserialize_key::<MapKey>(&mut map_decoder)? {
            match map_key.as_ref() {
                MapKeyRef::Text("grants") => {
                    grants = Some(CborMapDecoder::deserialize_value(&mut map_decoder)?);
                }
                MapKeyRef::Text("tokens") => {
                    tokens = Some(CborMapDecoder::deserialize_value(&mut map_decoder)?);
                }
                MapKeyRef::Text("keepAlive") => {
                    keep_alive = Some(CborMapDecoder::deserialize_value(&mut map_decoder)?);
                }
                MapKeyRef::Text("memo") => {
                    memo = Some(CborMapDecoder::deserialize_value(&mut map_decoder)?);
                }
                _ => {
                    CborMapDecoder::skip_value(&mut map_decoder)?;
                }
            }
        }

        let grants = grants
            .ok_or_else(|| CborSerializationError::map_value_missing(MapKeyRef::Text("grants")))?;
        let tokens = tokens
            .ok_or_else(|| CborSerializationError::map_value_missing(MapKeyRef::Text("tokens")))?;
        // Default to false when omitted from CBOR.
        let keep_alive = keep_alive.unwrap_or(false);
        let memo = memo.unwrap_or(None);

        Ok(LockControllerSimpleV0 {
            grants,
            tokens,
            keep_alive,
            memo,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::common::cbor;
    use crate::protocol_level_tokens::test_fixtures::ADDRESS;
    use crate::transactions::Memo;

    /// Round-trip test for all `LockControllerSimpleV0Capability` variants.
    #[test]
    fn test_capability_cbor_round_trip() {
        let variants = [
            LockControllerSimpleV0Capability::Fund,
            LockControllerSimpleV0Capability::Return,
            LockControllerSimpleV0Capability::Send,
            LockControllerSimpleV0Capability::Cancel,
        ];
        for variant in &variants {
            let encoded = cbor::cbor_encode(variant);
            let decoded: LockControllerSimpleV0Capability =
                cbor::cbor_decode(&encoded).expect("CBOR decode failed");
            assert_eq!(&decoded, variant);
        }
    }

    /// Fixture test: `Fund` → CBOR text "fund" → `6466756e64`
    #[test]
    fn test_capability_cbor_fixture_fund() {
        let encoded = cbor::cbor_encode(&LockControllerSimpleV0Capability::Fund);
        assert_eq!(hex::encode(&encoded), "6466756e64");
    }

    /// Fixture test: `Return` → CBOR text "return" → `6672657475726e`
    #[test]
    fn test_capability_cbor_fixture_return() {
        let encoded = cbor::cbor_encode(&LockControllerSimpleV0Capability::Return);
        assert_eq!(hex::encode(&encoded), "6672657475726e");
    }

    /// Fixture test: `Send` → CBOR text "send" → `6473656e64`
    #[test]
    fn test_capability_cbor_fixture_send() {
        let encoded = cbor::cbor_encode(&LockControllerSimpleV0Capability::Send);
        assert_eq!(hex::encode(&encoded), "6473656e64");
    }

    /// Fixture test: `Cancel` → CBOR text "cancel" → `6663616e63656c`
    #[test]
    fn test_capability_cbor_fixture_cancel() {
        let encoded = cbor::cbor_encode(&LockControllerSimpleV0Capability::Cancel);
        assert_eq!(hex::encode(&encoded), "6663616e63656c");
    }

    /// Round-trip test for `LockControllerSimpleV0Grant` with an account and
    /// multiple roles.
    #[test]
    fn test_grant_cbor_round_trip() {
        let grant = LockControllerSimpleV0Grant {
            account: CborHolderAccount::from(ADDRESS),
            roles: vec![
                LockControllerSimpleV0Capability::Fund,
                LockControllerSimpleV0Capability::Send,
            ],
        };
        let encoded = cbor::cbor_encode(&grant);
        let decoded: LockControllerSimpleV0Grant =
            cbor::cbor_decode(&encoded).expect("CBOR decode failed");
        assert_eq!(decoded, grant);
    }

    /// Fixture test for `LockControllerSimpleV0Grant` with a known account
    /// address and roles `[Fund, Cancel]`.
    ///
    /// Expected CBOR structure (diagnostic notation):
    /// ```text
    /// {
    ///   "roles": ["fund", "cancel"],
    ///   "account": 40307({1: 40305({1: 919}), 3: h'0102...1f20'})
    /// }
    /// ```
    ///
    /// Note: CBOR map keys are ordered by length (deterministic encoding),
    /// so `"roles"` (5 bytes) appears before `"account"` (7 bytes).
    #[test]
    fn test_grant_cbor_fixture() {
        let grant = LockControllerSimpleV0Grant {
            account: CborHolderAccount::from(ADDRESS),
            roles: vec![
                LockControllerSimpleV0Capability::Fund,
                LockControllerSimpleV0Capability::Cancel,
            ],
        };
        let encoded = cbor::cbor_encode(&grant);
        // Build expected hex:
        // Map(2) with text keys "account" and "roles"
        // "account" value: CborHolderAccount(ADDRESS) with coin_info = Some(CCD)
        //   Known encoding: d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
        // "roles" value: Array(2) ["fund", "cancel"]
        //   "fund" = 6466756e64, "cancel" = 6663616e63656c
        //   Array(2): 82 6466756e64 6663616e63656c
        //
        // Map(2): a2
        //   key "account" (7 bytes): 67 6163636f756e74
        //   key "roles" (5 bytes):   65 726f6c6573
        let expected = concat!(
            "a2",                                                                 // map(2)
            "65726f6c6573",                                                       // text "roles"
            "82",                                                                 // array(2)
            "6466756e64",                                                         // text "fund"
            "6663616e63656c",                                                     // text "cancel"
            "676163636f756e74",                                                   // text "account"
            "d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", // CborHolderAccount
        );
        assert_eq!(hex::encode(&encoded), expected);
    }

    /// Round-trip test for `LockControllerSimpleV0` with full configuration
    /// (including memo and keep_alive = true).
    #[test]
    fn test_simple_v0_cbor_round_trip_full() {
        let controller = LockControllerSimpleV0 {
            grants: vec![LockControllerSimpleV0Grant {
                account: CborHolderAccount::from(ADDRESS),
                roles: vec![
                    LockControllerSimpleV0Capability::Fund,
                    LockControllerSimpleV0Capability::Send,
                ],
            }],
            tokens: vec!["CCD".parse().unwrap()],
            keep_alive: true,
            memo: Some(CborMemo::Raw(
                Memo::try_from(vec![0x01, 0x02, 0x03]).unwrap(),
            )),
        };
        let encoded = cbor::cbor_encode(&controller);
        let decoded: LockControllerSimpleV0 =
            cbor::cbor_decode(&encoded).expect("CBOR decode failed");
        assert_eq!(decoded, controller);
    }

    /// Round-trip test for `LockControllerSimpleV0` with minimal configuration
    /// (no memo, keep_alive = false).
    #[test]
    fn test_simple_v0_cbor_round_trip_minimal() {
        let controller = LockControllerSimpleV0 {
            grants: vec![],
            tokens: vec![],
            keep_alive: false,
            memo: None,
        };
        let encoded = cbor::cbor_encode(&controller);
        let decoded: LockControllerSimpleV0 =
            cbor::cbor_decode(&encoded).expect("CBOR decode failed");
        assert_eq!(decoded, controller);
    }

    /// Test that `keep_alive` defaults to `false` when the key is missing
    /// from the CBOR map.
    #[test]
    fn test_simple_v0_cbor_keep_alive_default() {
        // Manually construct CBOR map without "keepAlive" key:
        // {"grants": [], "tokens": []}
        //
        // Map(2): a2
        // "grants" sorted before "tokens" (both 6-char keys, "g" < "t"):
        //   "grants": 666772616e7473, value []: 80
        //   "tokens": 66746f6b656e73, value []: 80
        let cbor_hex = "a2666772616e74738066746f6b656e7380";
        let cbor_bytes = hex::decode(cbor_hex).expect("valid hex");
        let decoded: LockControllerSimpleV0 = cbor::cbor_decode(&cbor_bytes)
            .expect("CBOR decode should succeed with missing keepAlive");
        assert!(!decoded.keep_alive, "keep_alive should default to false");
        assert!(decoded.memo.is_none(), "memo should be None when omitted");
    }

    /// Fixture test for `LockControllerSimpleV0` with a known configuration.
    ///
    /// Expected CBOR structure (diagnostic notation):
    /// ```text
    /// {
    ///   "memo": h'010203',
    ///   "grants": [{
    ///     "roles": ["fund", "cancel"],
    ///     "account": 40307({1: 40305({1: 919}), 3: h'0102...1f20'})
    ///   }],
    ///   "tokens": ["CCD"],
    ///   "keepAlive": true
    /// }
    /// ```
    ///
    /// Map keys sorted by encoded byte length:
    /// - "memo" (4 bytes)
    /// - "grants" (6 bytes)
    /// - "tokens" (6 bytes) — same length as "grants", sorted lexicographically
    /// - "keepAlive" (9 bytes)
    #[test]
    fn test_simple_v0_cbor_fixture() {
        let controller = LockControllerSimpleV0 {
            grants: vec![LockControllerSimpleV0Grant {
                account: CborHolderAccount::from(ADDRESS),
                roles: vec![
                    LockControllerSimpleV0Capability::Fund,
                    LockControllerSimpleV0Capability::Cancel,
                ],
            }],
            tokens: vec!["CCD".parse().unwrap()],
            keep_alive: true,
            memo: Some(CborMemo::Raw(
                Memo::try_from(vec![0x01, 0x02, 0x03]).unwrap(),
            )),
        };
        let encoded = cbor::cbor_encode(&controller);
        // Build expected hex:
        //
        // Map(4): a4
        //
        // Keys sorted by encoded byte length, then lexicographically:
        // "memo" (4 bytes) → 646d656d6f
        // "grants" (6 bytes) → 666772616e7473
        // "tokens" (6 bytes) → 66746f6b656e73
        // "keepAlive" (9 bytes) → 696b656570416c697665
        //
        // Values:
        // memo: Raw(h'010203') → 43010203 (bytes(3))
        // grants: [{roles: [fund, cancel], account: CborHolderAccount}]
        //   Array(1): 81
        //     Map(2): a2
        //       "roles" (5): 65726f6c6573
        //       ["fund", "cancel"]: 82 6466756e64 6663616e63656c
        //       "account" (7): 676163636f756e74
        //       CborHolderAccount: d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
        // tokens: ["CCD"]
        //   Array(1): 81
        //     "CCD": 63434344
        // keepAlive: true → f5
        let expected = concat!(
            "a4",                     // map(4)
            "646d656d6f",             // text "memo"
            "43010203",               // bytes(3) h'010203'
            "666772616e7473",         // text "grants"
            "81",                     // array(1)
            "a2",                     // map(2) — grant entry
            "65726f6c6573",           // text "roles"
            "82",                     // array(2)
            "6466756e64",             // text "fund"
            "6663616e63656c",         // text "cancel"
            "676163636f756e74",       // text "account"
            "d99d73a201d99d71a1011903970358200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", // CborHolderAccount
            "66746f6b656e73",         // text "tokens"
            "81",                     // array(1)
            "63434344",               // text "CCD"
            "696b656570416c697665",   // text "keepAlive"
            "f5",                     // true
        );
        assert_eq!(hex::encode(&encoded), expected);
    }
}
