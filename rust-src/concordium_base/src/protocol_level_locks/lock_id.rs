use crate::{
    base::{AccountIndex, Nonce},
    common::Serialize,
};
use concordium_base_derive::{CborDeserialize, CborSerialize};
use std::{
    fmt::{Display, Formatter},
    str::FromStr,
};

/// CBOR tag identifying a Lock ID.
const LOCK_ID_TAG: u64 = 40920;

#[derive(
    Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, CborSerialize, CborDeserialize, Serialize,
)]
#[cbor(tag = LOCK_ID_TAG, tuple)]
#[cfg_attr(
    feature = "serde_deprecated",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "camelCase")
)]
pub struct LockId {
    /// The account index of the account that created the lock.
    pub account_index: u64,
    /// The sequence number of the transaction that created the lock.
    pub sequence_number: u64,
    /// The 0-based creation order of the lock within the transaction that
    /// created it.
    pub creation_order: u64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LockIdFromStrError {
    #[error("LockId must have the form <account_index,sequence_number,creation_order>")]
    InvalidFormat,
}

impl Display for LockId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "<{}, {}, {}>",
            self.account_index, self.sequence_number, self.creation_order
        )
    }
}

impl FromStr for LockId {
    type Err = LockIdFromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let inner = s
            .trim()
            .strip_prefix('<')
            .and_then(|s| s.strip_suffix('>'))
            .ok_or(LockIdFromStrError::InvalidFormat)?;

        let convert = |s: &str| -> Result<u64, _> {
            str::trim(s)
                .parse()
                .map_err(|_| LockIdFromStrError::InvalidFormat)
        };
        let parts: Vec<_> = inner.split(',').map(convert).collect::<Result<_, _>>()?;
        if parts.len() != 3 {
            return Err(LockIdFromStrError::InvalidFormat);
        }

        Ok(LockId {
            account_index: parts[0],
            sequence_number: parts[1],
            creation_order: parts[2],
        })
    }
}

impl LockId {
    #[inline(always)]
    pub fn new(
        account_index: impl Into<AccountIndex>,
        sequence_number: impl Into<Nonce>,
        creation_order: u64,
    ) -> Self {
        LockId {
            account_index: account_index.into().index,
            sequence_number: sequence_number.into().nonce,
            creation_order,
        }
    }

    /// Get the account index of the lock ID.
    #[inline(always)]
    pub fn account_index(&self) -> AccountIndex {
        AccountIndex {
            index: self.account_index,
        }
    }

    /// Get the sequence number of the lock ID.
    #[inline(always)]
    pub fn sequence_number(&self) -> Nonce {
        Nonce {
            nonce: self.sequence_number,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::cbor;

    /// Test CBOR serialization of [`LockId`]
    #[test]
    fn test_lock_id_cbor_serialize() {
        let lock_id: LockId = LockId::new(99812, 33345, 17);
        let cbor = cbor::cbor_encode(&lock_id);
        assert_eq!(hex::encode(&cbor), "d99fd8831a000185e419824111");
        let lock_id_decoded: LockId = cbor::cbor_decode(&cbor).expect("CBOR deserialize");
        assert_eq!(lock_id_decoded, lock_id);
    }

    use crate::common::{serialize_deserialize, to_bytes};

    fn example_lock_id() -> LockId {
        LockId::new(AccountIndex { index: 10001 }, Nonce { nonce: 5 }, 0)
    }

    #[test]
    fn test_lock_id_display() {
        let lock_id = example_lock_id();
        assert_eq!(lock_id.to_string(), "<10001, 5, 0>");
    }

    #[test]
    fn test_lock_id_from_str() {
        let parsed: LockId = "<10001, 5, 0>".parse().expect("must parse");
        assert_eq!(parsed, example_lock_id());

        let parsed_no_spaces: LockId = "<10001,5,0>".parse().expect("must parse");
        assert_eq!(parsed_no_spaces, example_lock_id());
        assert_eq!(parsed, example_lock_id());
    }

    #[test]
    fn test_lock_id_from_str_invalid_format() {
        let err = "10001,5,0".parse::<LockId>().expect_err("must fail");
        assert_eq!(err, LockIdFromStrError::InvalidFormat);
    }

    #[test]
    fn test_lock_id_from_str_invalid_component() {
        let err = "<10001,abc,0>".parse::<LockId>().expect_err("must fail");
        assert_eq!(err, LockIdFromStrError::InvalidFormat);
    }

    /// Round-trip test: encode then decode produces the same `LockId`.
    #[test]
    fn test_lock_id_cbor_round_trip() {
        let lock_id = example_lock_id();
        let encoded = cbor::cbor_encode(&lock_id);
        let decoded: LockId = cbor::cbor_decode(&encoded).expect("CBOR decode failed");
        assert_eq!(decoded, lock_id);
    }

    /// Fixture test: verify the exact CBOR encoding.
    ///
    /// Expected encoding for `LockId { account_index: 10001, sequence_number:
    /// 5, creation_order: 0 }`:
    /// - Tag 40920 (0x9FD8): `d9 9f d8`
    /// - Array of 3: `83`
    /// - 10001 (0x2711, 2-byte uint): `19 27 11`
    /// - 5: `05`
    /// - 0: `00`
    ///
    /// Full: `d99fd8831927110500`
    #[test]
    fn test_lock_id_cbor_fixture() {
        let lock_id = example_lock_id();
        let encoded = cbor::cbor_encode(&lock_id);
        assert_eq!(hex::encode(&encoded), "d99fd8831927110500");
    }

    /// Round-trip test: binary (`Serial`/`Deserial`) encoding of `LockId`
    /// produces the same value.
    #[test]
    fn test_lock_id_serial_round_trip() {
        let lock_id = example_lock_id();
        let result = serialize_deserialize(&lock_id).expect("Serial round-trip should succeed");
        assert_eq!(result, lock_id);
    }

    /// Fixture test: verify the exact binary (`Serial`) encoding of `LockId`.
    ///
    /// `LockId { account_index: 10001, sequence_number: 5, creation_order: 0
    /// }`:
    /// - `account_index.index` = 10001 = `0x0000000000002711` (8 bytes BE u64)
    /// - `sequence_number.nonce` = 5 = `0x0000000000000005` (8 bytes BE u64)
    /// - `creation_order` = 0 = `0x0000000000000000` (8 bytes BE u64)
    ///
    /// Total 24 bytes:
    /// `000000000000271100000000000000050000000000000000`
    #[test]
    fn test_lock_id_serial_fixture() {
        let lock_id = example_lock_id();
        let bytes = to_bytes(&lock_id);
        assert_eq!(
            hex::encode(&bytes),
            "000000000000271100000000000000050000000000000000"
        );
    }

    /// Test with zero values.
    #[test]
    fn test_lock_id_cbor_zero_values() {
        let lock_id = LockId::new(0, 0, 0);
        let encoded = cbor::cbor_encode(&lock_id);
        let decoded: LockId = cbor::cbor_decode(&encoded).expect("CBOR decode failed");
        assert_eq!(decoded, lock_id);
    }

    /// Test with max u64 values.
    #[test]
    fn test_lock_id_cbor_max_values() {
        let lock_id = LockId::new(u64::MAX, u64::MAX, u64::MAX);
        let encoded = cbor::cbor_encode(&lock_id);
        let decoded: LockId = cbor::cbor_decode(&encoded).expect("CBOR decode failed");
        assert_eq!(decoded, lock_id);
    }
}
