use crate::common::cbor::{cbor_decode, cbor_encode, value, Bytes};
use concordium_base_derive::{CborDeserialize, CborSerialize};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;
use hex::{FromHex, ToHex};

/// Metadata for a specific protocol level token
#[derive(Debug, Clone, PartialEq, CborSerialize, CborDeserialize, serde::Serialize, serde::Deserialize)]
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
    pub checksum_sha_256: Option<Bytes>,

    /// Additional fields may be included for future extensibility, e.g. another hash algorithm.
    #[cbor(other)]
    #[serde(
        serialize_with = "serialize_hex_cbor_map",
        deserialize_with = "deserialize_hex_cbor_map",
        default,
        skip_serializing_if = "HashMap::is_empty"
    )]
    #[serde(rename = "_additional")]
    pub other: HashMap<String, value::Value>,
}

/// Serialize `Bytes` as a hex string.
fn serialize_hex_bytes<S>(bytes: &Option<Bytes>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if let Some(bytes) = bytes {
        serializer.serialize_str(&bytes.encode_hex::<String>())
    } else {
        serializer.serialize_none()
    }
}

/// Deserialize `Bytes` from a hex string.
fn deserialize_hex_bytes<'de, D>(deserializer: D) -> Result<Option<Bytes>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    if let Some(hex_str) = opt {
        let bytes = Vec::from_hex(&hex_str).map_err(serde::de::Error::custom)?;
        Ok(Some(Bytes(bytes)))
    } else {
        Ok(None)
    }
}

/// Serialize a `HashMap<String, value::Value>` as hex-encoded CBOR.
fn serialize_hex_cbor_map<S>(
    map: &HashMap<String, value::Value>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut hex_map = HashMap::new();
    for (key, value) in map {
        let cbor_bytes = cbor_encode(value).map_err(serde::ser::Error::custom)?;
        hex_map.insert(key, cbor_bytes.encode_hex::<String>());
    }
    hex_map.serialize(serializer)
}

/// Deserialize a `HashMap<String, value::Value>` from hex-encoded CBOR.
fn deserialize_hex_cbor_map<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, value::Value>, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_map: HashMap<String, String> = HashMap::deserialize(deserializer)?;
    let mut map = HashMap::new();
    for (key, hex_str) in hex_map {
        let cbor_bytes = Vec::from_hex(&hex_str).map_err(serde::de::Error::custom)?;
        let value = cbor_decode(&cbor_bytes).map_err(serde::de::Error::custom)?;
        map.insert(key, value);
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;
    use hex::FromHex;
    use std::collections::HashMap;

    #[test]
    fn test_metadata_url_json() {
        let checksum: Bytes = Bytes(Vec::from_hex("4d2c6df2364db5cc9e5c1f5b8dd7ccab").unwrap());
        let mut additional = HashMap::new();
        additional.insert("key1".to_string(), value::Value::Text("value".to_string()));
        additional.insert("key2".to_string(), value::Value::Positive(40));

        let metadata_url = MetadataUrl {
            url: "https://example.com/metadata".to_string(),
            checksum_sha_256: Some(checksum.clone()),
            other: additional,
        };

        let serialized = serde_json::to_string(&metadata_url).unwrap();
        let expected_json = r#"{
            "url": "https://example.com/metadata",
            "checksumSha256": "4d2c6df2364db5cc9e5c1f5b8dd7ccab",
            "_additional": {
                "key1": "6576616c7565",
                "key2": "1828"
            }
        }"#;

        let expected: serde_json::Value = serde_json::from_str(expected_json).unwrap();
        let actual: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(actual, expected);

        let metadata_url = MetadataUrl {
            url: "https://example.com/metadata".to_string(),
            checksum_sha_256: None,
            other: HashMap::new(),
        };

        let serialized = serde_json::to_string(&metadata_url).unwrap();
        let expected_json = r#"{
            "url": "https://example.com/metadata"
        }"#;

        let expected: serde_json::Value = serde_json::from_str(expected_json).unwrap();
        let actual: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(actual, expected);

        let metadata_url = MetadataUrl {
            url: "https://example.com/metadata".to_string(),
            checksum_sha_256: Some(checksum),
            other: HashMap::new(),
        };

        let serialized = serde_json::to_string(&metadata_url).unwrap();
        let expected_json = r#"{
            "url": "https://example.com/metadata",
            "checksumSha256": "4d2c6df2364db5cc9e5c1f5b8dd7ccab"
        }"#;

        let expected: serde_json::Value = serde_json::from_str(expected_json).unwrap();
        let actual: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(actual, expected);
    }
}
