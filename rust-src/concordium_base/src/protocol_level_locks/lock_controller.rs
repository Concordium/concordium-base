use super::LockControllerSimpleV0;
use concordium_base_derive::{CborDeserialize, CborSerialize};

/// Top-level lock controller type.
///
/// Each variant represents a different controller version.
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
#[cbor(map)]
pub enum LockController {
    /// SimpleV0 lock controller configuration.
    SimpleV0(LockControllerSimpleV0),
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::common::cbor;
    use crate::protocol_level_locks::{
        LockControllerSimpleV0Capability, LockControllerSimpleV0Grant,
    };
    use crate::protocol_level_tokens::test_fixtures::ADDRESS;
    use crate::protocol_level_tokens::CborHolderAccount;

    /// Round-trip test for `LockController::SimpleV0` with a full
    /// configuration.
    #[test]
    fn test_lock_controller_cbor_round_trip() {
        let controller = LockController::SimpleV0(LockControllerSimpleV0 {
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
        });
        let encoded = cbor::cbor_encode(&controller);
        let decoded: LockController = cbor::cbor_decode(&encoded).expect("CBOR decode failed");
        assert_eq!(decoded, controller);
    }

    /// Round-trip test for `LockController::SimpleV0` with minimal
    /// configuration (empty grants and tokens).
    #[test]
    fn test_lock_controller_cbor_round_trip_minimal() {
        let controller = LockController::SimpleV0(LockControllerSimpleV0 {
            grants: vec![],
            tokens: vec![],
            keep_alive: false,
            memo: None,
        });
        let encoded = cbor::cbor_encode(&controller);
        let decoded: LockController = cbor::cbor_decode(&encoded).expect("CBOR decode failed");
        assert_eq!(decoded, controller);
    }

    /// Fixture test: `LockController::SimpleV0` wraps the inner value in a
    /// single-entry CBOR map with key `"simpleV0"`.
    ///
    /// Expected CBOR structure (diagnostic notation):
    /// ```text
    /// {"simpleV0": {"grants": [], "tokens": []}}
    /// ```
    ///
    /// Map(1): a1
    ///   key "simpleV0" (8 bytes): 6873696d706c655630
    ///   value: Map(2) for LockControllerSimpleV0 with empty grants/tokens
    ///     "grants" (6): 666772616e7473, value []: 80
    ///     "tokens" (6): 66746f6b656e73, value []: 80
    ///
    /// Note: `keep_alive: false` and `memo: None` are omitted from the CBOR
    /// map.
    #[test]
    fn test_lock_controller_cbor_fixture() {
        let controller = LockController::SimpleV0(LockControllerSimpleV0 {
            grants: vec![],
            tokens: vec![],
            keep_alive: false,
            memo: None,
        });
        let encoded = cbor::cbor_encode(&controller);
        let expected = concat!(
            "a1",                 // map(1)
            "6873696d706c655630", // text "simpleV0"
            "a2",                 // map(2) — inner LockControllerSimpleV0
            "666772616e7473",     // text "grants"
            "80",                 // array(0)
            "66746f6b656e73",     // text "tokens"
            "80",                 // array(0)
        );
        assert_eq!(hex::encode(&encoded), expected);
    }
}
