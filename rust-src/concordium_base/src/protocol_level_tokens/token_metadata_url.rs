use std::collections::HashMap;

use concordium_base_derive::{CborDeserialize, CborSerialize};
use concordium_contracts_common::hashes::Hash;
use hex::{FromHex, ToHex};
use serde::{Deserialize, Deserializer, Serializer};

use crate::common::cbor::{serde::map_hex_cbor_values, value};

/// Metadata for a specific protocol level token
#[derive(
    Debug, Clone, PartialEq, CborSerialize, CborDeserialize, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub struct MetadataUrl {
    /// A string field representing the URL
    pub url: String,

    /// An optional sha256 checksum value tied to the content of the URL
    #[serde(
        serialize_with = "serialize_hex_bytes",
        deserialize_with = "deserialize_hex_bytes",
        skip_serializing_if = "Option::is_none"
    )]
    pub checksum_sha_256: Option<Hash>,

    /// Additional fields may be included for future extensibility, e.g. another
    /// hash algorithm.
    #[cbor(other)]
    #[serde(
        with = "map_hex_cbor_values",
        default,
        skip_serializing_if = "HashMap::is_empty"
    )]
    #[serde(rename = "_additional")]
    pub additional: HashMap<String, value::Value>,
}

/// Serialize `Bytes` as a hex string.
fn serialize_hex_bytes<S>(bytes: &Option<Hash>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer, {
    if let Some(bytes) = bytes {
        serializer.serialize_str(&bytes.encode_hex::<String>())
    } else {
        serializer.serialize_none()
    }
}

/// Deserialize `Bytes` from a hex string.
fn deserialize_hex_bytes<'de, D>(deserializer: D) -> Result<Option<Hash>, D::Error>
where
    D: Deserializer<'de>, {
    let opt: Option<String> = Option::deserialize(deserializer)?;
    if let Some(hex_str) = opt {
        let bytes = Vec::from_hex(&hex_str).map_err(serde::de::Error::custom)?;
        let hash = Hash::try_from(bytes.as_slice()).map_err(serde::de::Error::custom)?;
        Ok(Some(hash))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use crate::common::cbor::{cbor_decode, cbor_encode};

    use super::*;
    use hex::FromHex;
    use serde_json;
    use std::collections::HashMap;

    const TEST_HASH: [u8; 32] = [1; 32];

    #[test]
    fn test_metadata_url_json() {
        let checksum = Hash::from(TEST_HASH);
        let mut additional = HashMap::new();
        additional.insert("key".to_string(), value::Value::Text("value".to_string()));
        additional.insert("another".to_string(), value::Value::Positive(40));

        let metadata_url = MetadataUrl {
            url: "https://example.com".to_string(),
            checksum_sha_256: Some(checksum),
            additional,
        };

        let serialized = serde_json::to_string(&metadata_url).unwrap();
        let expected_json = r#"{
            "url": "https://example.com",
            "checksumSha256": "0101010101010101010101010101010101010101010101010101010101010101",
            "_additional": {
                "key": "6576616c7565",
                "another": "1828"
            }
        }"#;

        let expected: serde_json::Value = serde_json::from_str(expected_json).unwrap();
        let actual: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(actual, expected);

        let metadata_url = MetadataUrl {
            url:              "https://example.com".to_string(),
            checksum_sha_256: None,
            additional:       HashMap::new(),
        };

        let serialized = serde_json::to_string(&metadata_url).unwrap();
        let expected_json = r#"{
            "url": "https://example.com"
        }"#;

        let expected: serde_json::Value = serde_json::from_str(expected_json).unwrap();
        let actual: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(actual, expected);

        let metadata_url = MetadataUrl {
            url:              "https://example.com".to_string(),
            checksum_sha_256: Some(checksum),
            additional:       HashMap::new(),
        };

        let serialized = serde_json::to_string(&metadata_url).unwrap();
        let expected_json = r#"{
            "url": "https://example.com",
            "checksumSha256": "0101010101010101010101010101010101010101010101010101010101010101"
        }"#;

        let expected: serde_json::Value = serde_json::from_str(expected_json).unwrap();
        let actual: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_cbor_serialize_metadata_url() {
        let checksum = Hash::from(TEST_HASH);
        let mut additional = HashMap::new();
        additional.insert("key".to_string(), value::Value::Text("value".to_string()));
        additional.insert("another".to_string(), value::Value::Positive(40));

        let metadata_url = MetadataUrl {
            url: "https://example.com".to_string(),
            checksum_sha_256: Some(checksum),
            additional,
        };

        let cbor_encoded = cbor_encode(&metadata_url).unwrap();

        let expected_cbor = Vec::from_hex("a4636b65796576616c75656375726c7368747470733a2f2f6578616d706c652e636f6d67616e6f7468657218286e636865636b73756d53686132353658200101010101010101010101010101010101010101010101010101010101010101").unwrap();
        let expected: MetadataUrl = cbor_decode(&expected_cbor).unwrap();

        let cbor_redecoded: MetadataUrl = cbor_decode(&cbor_encoded).unwrap();
        assert_eq!(expected, cbor_redecoded);
    }
}
