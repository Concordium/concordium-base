use crate::{
    base::{AccountIndex, Nonce},
    common::{
        cbor::{
            CborArrayDecoder, CborArrayEncoder, CborDecoder, CborDeserialize, CborEncoder,
            CborSerializationResult, CborSerialize,
        },
        Serialize,
    },
};
use anyhow::anyhow;

/// CBOR tag for [`LockId`]
const LOCK_ID_TAG: u64 = 40920;

/// Number of elements in the CBOR array encoding of a [`LockId`].
const LOCK_ID_ARRAY_SIZE: usize = 3;

/// Unique identifier for a PLT lock.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize)]
pub struct LockId {
    /// Index of the account that created the lock.
    pub account_index: AccountIndex,
    /// Account sequence number at the time of lock creation.
    pub sequence_number: Nonce,
    /// Order of lock creation within the transaction.
    pub creation_order: u64,
}

impl CborSerialize for LockId {
    fn serialize<C: CborEncoder>(&self, mut encoder: C) -> Result<(), C::WriteError> {
        encoder.encode_tag(LOCK_ID_TAG)?;
        let mut array_encoder = encoder.encode_array()?;
        array_encoder.serialize_element(&self.account_index.index)?;
        array_encoder.serialize_element(&self.sequence_number.nonce)?;
        array_encoder.serialize_element(&self.creation_order)?;
        array_encoder.end()?;
        Ok(())
    }
}

impl CborDeserialize for LockId {
    fn deserialize<C: CborDecoder>(mut decoder: C) -> CborSerializationResult<Self>
    where
        Self: Sized,
    {
        decoder.decode_tag_expect(LOCK_ID_TAG)?;
        let mut array_decoder = decoder.decode_array_expect_size(LOCK_ID_ARRAY_SIZE)?;

        let Some(account_index_raw) =
            CborArrayDecoder::deserialize_element::<u64>(&mut array_decoder)?
        else {
            return Err(anyhow!("expected account_index element in LockId array").into());
        };
        let Some(sequence_number_raw) =
            CborArrayDecoder::deserialize_element::<u64>(&mut array_decoder)?
        else {
            return Err(anyhow!("expected sequence_number element in LockId array").into());
        };
        let Some(creation_order) =
            CborArrayDecoder::deserialize_element::<u64>(&mut array_decoder)?
        else {
            return Err(anyhow!("expected creation_order element in LockId array").into());
        };

        Ok(LockId {
            account_index: account_index_raw.into(),
            sequence_number: sequence_number_raw.into(),
            creation_order,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::common::cbor;
    use crate::common::{serialize_deserialize, to_bytes};

    fn example_lock_id() -> LockId {
        LockId {
            account_index: AccountIndex { index: 10001 },
            sequence_number: Nonce { nonce: 5 },
            creation_order: 0,
        }
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
        let lock_id = LockId {
            account_index: AccountIndex { index: 0 },
            sequence_number: Nonce { nonce: 0 },
            creation_order: 0,
        };
        let encoded = cbor::cbor_encode(&lock_id);
        let decoded: LockId = cbor::cbor_decode(&encoded).expect("CBOR decode failed");
        assert_eq!(decoded, lock_id);
    }

    /// Test with max u64 values.
    #[test]
    fn test_lock_id_cbor_max_values() {
        let lock_id = LockId {
            account_index: AccountIndex { index: u64::MAX },
            sequence_number: Nonce { nonce: u64::MAX },
            creation_order: u64::MAX,
        };
        let encoded = cbor::cbor_encode(&lock_id);
        let decoded: LockId = cbor::cbor_decode(&encoded).expect("CBOR decode failed");
        assert_eq!(decoded, lock_id);
    }
}
