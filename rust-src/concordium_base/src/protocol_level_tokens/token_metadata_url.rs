use crate::common::cbor::{value, Bytes};
use concordium_base_derive::{CborDeserialize, CborSerialize};
use std::collections::HashMap;

/// Metadata for a specific protocol level token
#[derive(Debug, Clone, PartialEq, CborSerialize, CborDeserialize)]
pub struct MetadataUrl {
    /// A string field representing the URL
    pub url:              String,
    /// An optional sha256 checksum value tied to the content of the URL
    pub checksum_sha_256: Option<Bytes>,
    /// Additional fields may be included for future extensibility, e.g. another
    /// hash algorithm.
    #[cbor(other)]
    pub additional:       HashMap<String, value::Value>,
}
