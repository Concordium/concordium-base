/// This module provides serialization and deserialization functions for hash
/// maps with string keys and CBOR values, where the values are represented as
/// hex strings of the CBOR encoding.
pub mod map_hex_cbor_values {
    use std::collections::HashMap;

    use hex::{FromHex, ToHex};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::common::cbor::{cbor_decode, cbor_encode, value};

    /// Serialize a `HashMap<String, value::Value>` as hex-encoded CBOR.
    pub fn serialize<S>(
        map: &HashMap<String, value::Value>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer, {
        let mut hex_map = HashMap::new();
        for (key, value) in map {
            let cbor_bytes = cbor_encode(value).map_err(serde::ser::Error::custom)?;
            hex_map.insert(key, cbor_bytes.encode_hex::<String>());
        }
        hex_map.serialize(serializer)
    }

    /// Deserialize a `HashMap<String, value::Value>` from hex-encoded CBOR.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<String, value::Value>, D::Error>
    where
        D: Deserializer<'de>, {
        let hex_map: HashMap<String, String> = HashMap::deserialize(deserializer)?;
        let mut map = HashMap::new();
        for (key, hex_str) in hex_map {
            let cbor_bytes = Vec::from_hex(&hex_str).map_err(serde::de::Error::custom)?;
            let value = cbor_decode(&cbor_bytes).map_err(serde::de::Error::custom)?;
            map.insert(key, value);
        }
        Ok(map)
    }
}
