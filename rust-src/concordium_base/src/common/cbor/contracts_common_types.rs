use crate::common::cbor::{
    CborDecoder, CborDeserialize, CborEncoder, CborSerializationResult, CborSerialize,
};
use concordium_contracts_common::AccountAddress;

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
