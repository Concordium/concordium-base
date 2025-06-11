use crate::common::cbor::Bytes;
use concordium_base_derive::{CborDeserialize, CborSerialize};

/// Metadata for a specific protocol level token
#[derive(Debug, Clone, Eq, PartialEq, CborSerialize, CborDeserialize)]
pub struct MetadataUrl {
    /// A string field representing the URL
    pub url:              String,
    /// An optional sha256 checksum value tied to the content of the URL
    pub checksum_sha_256: Option<Bytes>,
}
