use crate::common::cbor::{
    CborDecoder, CborDeserialize, CborEncoder, CborSerializationResult, CborSerialize,
};
use concordium_contracts_common::{constants::SHA256, hashes::Hash, AccountAddress};

impl CborSerialize for AccountAddress {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> CborSerializationResult<()> {
        self.0.serialize(encoder)
    }
}

impl CborDeserialize for AccountAddress {
    fn deserialize<C: CborDecoder>(decoder: C) -> CborSerializationResult<Self>
    where
        Self: Sized, {
        Ok(Self(CborDeserialize::deserialize(decoder)?))
    }
}

impl CborSerialize for Hash {
    fn serialize<C: CborEncoder>(&self, encoder: C) -> CborSerializationResult<()> {
        self.as_ref().serialize(encoder)
    }
}

impl CborDeserialize for Hash {
    fn deserialize<C: CborDecoder>(decoder: C) -> CborSerializationResult<Self>
    where
        Self: Sized, {
        let bytes = <[u8; SHA256]>::deserialize(decoder)?;
        Ok(Hash::from(bytes))
    }
}
