use concordium_base_derive::{CborDeserialize, CborSerialize};

/// This tag ident
const LOCK_ID_TAG: u64 = 40920;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, CborSerialize, CborDeserialize, serde::Serialize, serde::Deserialize)]
#[cbor(tag = LOCK_ID_TAG, tuple)]
#[serde(rename_all = "camelCase")]
pub struct LockId {
    /// The account index of the account that created the lock.
    pub account_index: u64,
    /// The sequence number of the transaction that created the lock.
    pub sequence_number: u64,
    /// The 0-based creation order of the lock within the transaction that
    /// created it.
    pub creation_order: u64,
}

impl LockId {
    pub fn new(account_index: u64, sequence_number: u64, creation_order: u64) -> Self {
        LockId {
            account_index,
            sequence_number,
            creation_order,
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
}
