use crate::common::cbor::{
    CborDecoder, CborDeserialize, CborEncoder, CborSerializationResult, CborSerialize,
};
use concordium_contracts_common::{constants::SHA256, hashes::Hash, AccountAddress};

impl CborSerialize for AccountAddress {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> Result<(), C::WriteError> {
        self.0.serialize(encoder)
    }
}

impl CborDeserialize for AccountAddress {
    fn deserialize<C: CborDecoder>(decoder: C) -> CborSerializationResult<Self>
    where
        Self: Sized,
    {
        Ok(Self(CborDeserialize::deserialize(decoder)?))
    }
}

impl CborSerialize for Hash {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> Result<(), C::WriteError> {
        self.as_ref().serialize(encoder)
    }
}

impl CborDeserialize for Hash {
    fn deserialize<C: CborDecoder>(decoder: C) -> CborSerializationResult<Self>
    where
        Self: Sized,
    {
        let bytes = <[u8; SHA256]>::deserialize(decoder)?;
        Ok(Hash::from(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::cbor::{cbor_decode, cbor_encode};

    #[test]
    fn test_hash() {
        let hash = Hash::from([1; 32]);

        let cbor = cbor_encode(&hash);
        assert_eq!(
            hex::encode(&cbor),
            "58200101010101010101010101010101010101010101010101010101010101010101"
        );
        let hash_decoded: Hash = cbor_decode(&cbor).unwrap();
        assert_eq!(hash_decoded, hash);
    }

    #[test]
    fn test_account_address() {
        let address = AccountAddress([1; 32]);

        let cbor = cbor_encode(&address);
        assert_eq!(
            hex::encode(&cbor),
            "58200101010101010101010101010101010101010101010101010101010101010101"
        );
        let hash_decoded: AccountAddress = cbor_decode(&cbor).unwrap();
        assert_eq!(hash_decoded, address);
    }
}
