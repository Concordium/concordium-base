// TODO Add JSON regression tests.
// TODO Use v1 presentation when ready.
//! Types used in Concordium verifiable presentation protocol version 1.

use crate::common::{cbor, Buffer, Deserial, Get, ParseResult, ReadBytesExt, Serial, Serialize};
use crate::id::{id_proof_types::AtomicStatement, types::AttributeTag};
use crate::web3id::{did, Web3IdAttribute};
use crate::{hashes, id};
use concordium_base_derive::{CborDeserialize, CborSerialize};
use concordium_contracts_common::hashes::HashBytes;
use sha2::Digest;
use std::collections::HashMap;

/// A verifiable presentation request that specifies what credentials and proofs
/// are being requested from a credential holder.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, Serialize)]
#[serde(tag = "type", rename = "ConcordiumVPRequestV1")]
pub struct VerifiablePresentationRequest {
    /// Presentation being requested.
    #[serde(flatten)]
    pub request: VerificationRequestData,
    /// Blockchain transaction hash that anchors the request.
    #[serde(rename = "requestTX")]
    pub anchor_transaction_hash: hashes::TransactionHash,
}

impl VerifiablePresentationRequest {
    pub fn new(
        request: VerificationRequestData,
        anchor_transaction_hash: hashes::TransactionHash,
    ) -> Self {
        Self {
            request,
            anchor_transaction_hash,
        }
    }
}

/// A verification audit record that contains the complete verifiable presentation
/// request and response data. This record maintains the full audit trail of a verification
/// interaction, *including all sensitive data that should be kept private*.
///
/// Audit records are used internally by verifiers to maintain complete records
/// of verification interactions, while only publishing hash-based public records/anchors on-chain
/// to preserve privacy, see [`VerificationAuditRecordOnChain`].
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, Serialize)]
#[serde(tag = "type", rename = "ConcordiumVerificationAuditRecord")]
pub struct VerificationAuditRecord {
    /// Version integer, for now it is always 1.
    pub version: u16,
    /// The verifiable presentation request to record.
    pub request: VerifiablePresentationRequest,
    /// Unique identifier chosen by the requester/merchant.
    pub id: String,
    // TODO Replace String with the actual v1 presentation when ready.
    pub presentation: String,
}

impl VerificationAuditRecord {
    pub fn new(id: String, request: VerifiablePresentationRequest, presentation: String) -> Self {
        Self {
            version: 1,
            request,
            id,
            presentation,
        }
    }

    /// Computes a hash of the verification audit record.
    ///
    /// This hash is used to create a tamper-evident anchor that can be stored
    /// on-chain to prove the an audit record was made at a specific time and with
    /// specific parameters.
    pub fn hash(&self) -> hashes::Hash {
        use crate::common::Serial;
        let mut hasher = sha2::Sha256::new();
        self.serial(&mut hasher);
        HashBytes::new(hasher.finalize().into())
    }

    pub fn anchor(
        &self,
        public_info: Option<HashMap<String, cbor::value::Value>>,
    ) -> VerificationAuditRecordOnChain {
        VerificationAuditRecordOnChain {
            // Concordium Verification Audit Record
            r#type: "CCDVAR".to_string(),
            version: 1,
            hash: self.hash(),
            public: public_info,
        }
    }
}

/// Data structure for CBOR-encoded verifiable audit
///
/// This format is used when anchoring a verification audit on the Concordium blockchain.
#[derive(Debug, Clone, PartialEq, CborSerialize, CborDeserialize)]
pub struct VerificationAuditRecordOnChain {
    /// Type identifier for Concordium Verifiable Request Audit Record. Always set to "CCDVAA".
    pub r#type: String,
    /// Data format version integer, for now it is always 1.
    pub version: u16,
    /// Hash computed from the [`VerificationAuditRecord`].
    pub hash: hashes::Hash,
    /// Optional public information.
    pub public: Option<HashMap<String, cbor::value::Value>>,
}

/// Description of the presentation being requested from a credential holder.
///
/// This is also used to compute the hash for in the [`VerificationRequestAnchorOnChain`].
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, Serialize)]
pub struct VerificationRequestData {
    /// Context information for a verifiable presentation request.
    pub request_context: Context,
    /// The credential statements being requested.
    pub credential_statements: Vec<CredentialStatementRequest>,
}

impl VerificationRequestData {
    pub fn new(context: Context) -> Self {
        Self {
            request_context: context,
            credential_statements: Vec::new(),
        }
    }

    pub fn add_statement_request(
        mut self,
        statement_request: impl Into<CredentialStatementRequest>,
    ) -> Self {
        self.credential_statements.push(statement_request.into());
        self
    }

    /// Computes a hash of the Verification request context and statements.
    ///
    /// This hash is used to create a tamper-evident anchor that can be stored
    /// on-chain to prove the request was made at a specific time and with
    /// specific parameters.
    pub fn hash(&self) -> hashes::Hash {
        use crate::common::Serial;
        let mut hasher = sha2::Sha256::new();
        self.serial(&mut hasher);
        HashBytes::new(hasher.finalize().into())
    }

    pub fn anchor(
        &self,
        public_info: Option<HashMap<String, cbor::value::Value>>,
    ) -> VerificationRequestAnchorOnChain {
        VerificationRequestAnchorOnChain {
            // Concordium Verification Request Anchor
            r#type: "CCDVRA".to_string(),
            version: 1,
            hash: self.hash(),
            public: public_info,
        }
    }
}

/// Context information for a verifiable presentation request.
///
/// Contains both the context data that is already known (given) and
/// the context data that needs to be provided by the presenter (requested).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, Serialize, Default)]
#[serde(tag = "type", rename = "ConcordiumContextInformationV1")]
pub struct Context {
    /// Context information that is already provided.
    pub given: Vec<GivenContext>,
    /// Context information that must be provided by the presenter.
    pub requested: Vec<ContextLabel>,
}

impl Context {
    /// Create an empty context.
    pub fn new() -> Self {
        Default::default()
    }

    /// Add to the given context.
    pub fn add_context(mut self, context: impl Into<GivenContext>) -> Self {
        self.given.push(context.into());
        self
    }

    /// Add to the requested context.
    pub fn add_request(mut self, label: ContextLabel) -> Self {
        self.requested.push(label);
        self
    }

    /// Creates a simple context with commonly used parameters for basic verification scenarios.
    ///
    /// This is a convenience function that creates a context with a nonce for freshness,
    /// a connection ID for session tracking, and a context string for additional information.
    /// It requests BlockHash and ResourceID to be provided by the presenter.
    ///
    /// # Parameters
    ///
    /// - `nonce` Cryptographic nonce for preventing replay attacks
    /// - `connectionId` Identifier for the verification session
    /// - `contextString` Additional context information
    pub fn new_simple(nonce: Vec<u8>, connection_id: String, context_string: String) -> Self {
        Self::default()
            .add_context(GivenContext::Nonce(nonce))
            .add_context(GivenContext::ConnectionId(connection_id))
            .add_context(GivenContext::ContextString(context_string))
            .add_request(ContextLabel::BlockHash)
            .add_request(ContextLabel::ResourceId)
    }
}

/// Data structure for CBOR-encoded verifiable presentation request anchors.
///
/// This format is used when anchoring presentation requests on the Concordium blockchain.
#[derive(Debug, Clone, PartialEq, CborSerialize, CborDeserialize)]
pub struct VerificationRequestAnchorOnChain {
    /// Type identifier for Concordium Verifiable Request Anchor. Always set to "CCDVRA".
    pub r#type: String,
    /// Data format version integer, for now it is always 1.
    pub version: u16,
    /// Hash computed from the [`VerificationRequestData`].
    pub hash: hashes::Hash,
    /// Optional public information.
    pub public: Option<HashMap<String, cbor::value::Value>>,
}

/// The credential statements being requested.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
pub enum CredentialStatementRequest {
    /// Statements based on the Concordium ID object.
    #[serde(rename = "identity")]
    Identity {
        #[serde(flatten)]
        request: IdentityStatementRequest,
    },
}

impl Serial for CredentialStatementRequest {
    fn serial<B: Buffer>(&self, out: &mut B) {
        match self {
            CredentialStatementRequest::Identity { request } => {
                0u8.serial(out);
                request.serial(out);
            }
        }
    }
}

impl Deserial for CredentialStatementRequest {
    fn deserial<R: byteorder::ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        match u8::deserial(source)? {
            0u8 => {
                let request = source.get()?;
                Ok(Self::Identity { request })
            }
            n => anyhow::bail!("Unrecognized CredentialStatementRequest tag {n}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, Default, Serialize)]
pub struct IdentityStatementRequest {
    /// The statements requested.
    pub statements: id::id_proof_types::Statement<id::constants::ArCurve, Web3IdAttribute>,
    /// The credential issuers allowed.
    pub issuers: Vec<IdentityProviderMethod>,
    /// Set of allowed credential types. Should never be empty or contain the same value twice.
    pub source: Vec<CredentialType>,
}

impl From<IdentityStatementRequest> for CredentialStatementRequest {
    fn from(request: IdentityStatementRequest) -> Self {
        Self::Identity { request }
    }
}

impl IdentityStatementRequest {
    /// Create an empty identity statement request.
    pub fn new() -> Self {
        Default::default()
    }

    /// Add a source to the given identity statement request.
    pub fn add_source(mut self, source: CredentialType) -> Self {
        if !self.source.contains(&source) {
            self.source.push(source);
        }
        self
    }

    /// Add sources to the given identity statement request.
    pub fn add_sources(mut self, sources: Vec<CredentialType>) -> Self {
        for src in sources {
            if !self.source.contains(&src) {
                self.source.push(src);
            }
        }
        self
    }

    /// Add an issuer to the given identity statement request.
    pub fn add_issuer(mut self, issuer: IdentityProviderMethod) -> Self {
        if !self.issuers.contains(&issuer) {
            self.issuers.push(issuer);
        }
        self
    }

    /// Add issuers to the given identity statement request.
    pub fn add_issuers(mut self, issuers: Vec<IdentityProviderMethod>) -> Self {
        for issuer in issuers {
            if !self.issuers.contains(&issuer) {
                self.issuers.push(issuer);
            }
        }
        self
    }

    /// Add a statement to the given identity statement request.
    pub fn add_statement(
        mut self,
        statement: AtomicStatement<id::constants::ArCurve, AttributeTag, Web3IdAttribute>,
    ) -> Self {
        if !self.statements.statements.contains(&statement) {
            self.statements.statements.push(statement);
        }
        self
    }

    /// Add statements to the given identity statement request.
    pub fn add_statements(
        mut self,
        statements: Vec<AtomicStatement<id::constants::ArCurve, AttributeTag, Web3IdAttribute>>,
    ) -> Self {
        for statement in statements {
            if !self.statements.statements.contains(&statement) {
                self.statements.statements.push(statement);
            }
        }
        self
    }
}

/// Labels for different types of context information that can be provided in verifiable
/// presentation requests and proofs.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ContextLabel {
    /// A nonce which should be at least of lenth bytes32.
    Nonce,
    /// Payment hash (Concordium transaction hash).
    PaymentHash,
    /// Concordium block hash.
    BlockHash,
    #[serde(rename = "ConnectionID")]
    /// Identifier for some connection (e.g. wallet-connect topic).
    ConnectionId,
    /// Identifier for some resource (e.g. Website URL or fingerprint of TLS certificate).
    #[serde(rename = "ResourceID")]
    ResourceId,
    /// String value for general purposes.
    ContextString,
}

impl Serial for ContextLabel {
    fn serial<B: Buffer>(&self, out: &mut B) {
        match self {
            ContextLabel::Nonce => {
                0u8.serial(out);
            }
            ContextLabel::PaymentHash => {
                1u8.serial(out);
            }
            ContextLabel::BlockHash => {
                2u8.serial(out);
            }
            ContextLabel::ConnectionId => {
                3u8.serial(out);
            }
            ContextLabel::ResourceId => {
                4u8.serial(out);
            }
            ContextLabel::ContextString => {
                5u8.serial(out);
            }
        }
    }
}

impl Deserial for ContextLabel {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        match u8::deserial(source)? {
            0u8 => Ok(Self::Nonce),
            1u8 => Ok(Self::PaymentHash),
            2u8 => Ok(Self::BlockHash),
            3u8 => Ok(Self::ConnectionId),
            4u8 => Ok(Self::ResourceId),
            5u8 => Ok(Self::ContextString),
            n => anyhow::bail!("Unknown ContextLabel tag: {}", n),
        }
    }
}

/// Identity based credential types.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialType {
    Identity,
    Account,
}

impl Serial for CredentialType {
    fn serial<B: Buffer>(&self, out: &mut B) {
        match self {
            CredentialType::Identity => 0u8.serial(out),
            CredentialType::Account => 1u8.serial(out),
        }
    }
}

impl Deserial for CredentialType {
    fn deserial<R: byteorder::ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        match u8::deserial(source)? {
            0u8 => Ok(Self::Identity),
            1u8 => Ok(Self::Account),
            n => anyhow::bail!("Unrecognized CredentialType tag {n}"),
        }
    }
}

/// DID method for a Concordium Identity Provider.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, Serialize)]
#[serde(into = "did::Method", try_from = "did::Method")]
pub struct IdentityProviderMethod {
    /// The network part of the method.
    pub network: did::Network,
    /// The on-chain identifier of the Concordium Identity Provider.
    pub identity_provider: id::types::IpIdentity,
}

impl IdentityProviderMethod {
    pub fn new(ip_identity: u32, network: did::Network) -> Self {
        Self {
            network,
            identity_provider: id::types::IpIdentity(ip_identity),
        }
    }
}

impl From<IdentityProviderMethod> for did::Method {
    fn from(value: IdentityProviderMethod) -> Self {
        Self {
            network: value.network,
            ty: did::IdentifierType::Idp {
                idp_identity: value.identity_provider,
            },
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Invalid DID method for a Concordium Identity Provider")]
pub struct TryFromDidMethodError;

impl TryFrom<did::Method> for IdentityProviderMethod {
    type Error = TryFromDidMethodError;

    fn try_from(value: did::Method) -> Result<Self, Self::Error> {
        if let did::IdentifierType::Idp { idp_identity } = value.ty {
            Ok(Self {
                network: value.network,
                identity_provider: idp_identity,
            })
        } else {
            Err(TryFromDidMethodError)
        }
    }
}

/// A single piece of context information that can be provided in verifiable presentation interactions.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(into = "GivenContextJson", try_from = "GivenContextJson")]
pub enum GivenContext {
    /// Cryptographic nonce context which should be at least of length bytes32.
    Nonce(Vec<u8>),
    /// Payment hash context (Concordium transaction hash).
    PaymentHash(hashes::Hash),
    /// Concordium block hash context.
    BlockHash(hashes::BlockHash),
    /// Identifier for some connection (e.g. wallet-connect topic).
    ConnectionId(String),
    /// Identifier for some resource (e.g. Website URL or fingerprint of TLS certificate).
    ResourceId(String),
    /// String value for general purposes.
    ContextString(String),
}

impl Serial for GivenContext {
    fn serial<B: Buffer>(&self, out: &mut B) {
        match self {
            GivenContext::Nonce(hash) => {
                0u8.serial(out);
                hash.serial(out);
            }
            GivenContext::PaymentHash(hash) => {
                1u8.serial(out);
                hash.serial(out);
            }
            GivenContext::BlockHash(hash) => {
                2u8.serial(out);
                hash.serial(out);
            }
            GivenContext::ConnectionId(connection_id) => {
                3u8.serial(out);
                connection_id.serial(out);
            }
            GivenContext::ResourceId(rescource_id) => {
                4u8.serial(out);
                rescource_id.serial(out);
            }
            GivenContext::ContextString(context_string) => {
                5u8.serial(out);
                context_string.serial(out);
            }
        }
    }
}

impl Deserial for GivenContext {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        match u8::deserial(source)? {
            0u8 => {
                let hash = source.get()?;
                Ok(Self::Nonce(hash))
            }
            1u8 => {
                let hash = source.get()?;
                Ok(Self::PaymentHash(hash))
            }
            2u8 => {
                let hash = source.get()?;
                Ok(Self::BlockHash(hash))
            }
            3u8 => {
                let nonce = source.get()?;
                Ok(Self::ConnectionId(nonce))
            }
            4u8 => {
                let rescource_id = source.get()?;
                Ok(Self::ResourceId(rescource_id))
            }
            5u8 => {
                let context_string = source.get()?;
                Ok(Self::ContextString(context_string))
            }
            n => anyhow::bail!("Unknown GivenContext tag: {}", n),
        }
    }
}

/// JSON representation of context information that is already provided in a request for a presentation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct GivenContextJson {
    /// The label identifying the type of context.
    pub label: ContextLabel,
    /// The context data serialized as a string.
    pub context: String,
}

impl From<GivenContext> for GivenContextJson {
    fn from(value: GivenContext) -> Self {
        match value {
            GivenContext::Nonce(nonce) => Self {
                label: ContextLabel::Nonce,
                context: hex::encode(nonce),
            },
            GivenContext::PaymentHash(hash_bytes) => Self {
                label: ContextLabel::PaymentHash,
                context: hex::encode(hash_bytes),
            },
            GivenContext::BlockHash(hash_bytes) => Self {
                label: ContextLabel::BlockHash,
                context: hex::encode(hash_bytes),
            },
            GivenContext::ConnectionId(context) => Self {
                label: ContextLabel::ConnectionId,
                context,
            },
            GivenContext::ResourceId(context) => Self {
                label: ContextLabel::ResourceId,
                context,
            },
            GivenContext::ContextString(context) => Self {
                label: ContextLabel::ContextString,
                context,
            },
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TryFromGivenContextJsonError {
    #[error("Failed decoding hex in nonce context: {0}")]
    Nonce(hex::FromHexError),
    #[error("Failed decoding block hash")]
    BlockHash(hashes::HashFromStrError),
    #[error("Failed decoding payment hash")]
    PaymentHash(hashes::HashFromStrError),
}

impl TryFrom<GivenContextJson> for GivenContext {
    type Error = TryFromGivenContextJsonError;

    fn try_from(value: GivenContextJson) -> Result<Self, Self::Error> {
        match value.label {
            ContextLabel::ContextString => Ok(Self::ContextString(value.context)),

            ContextLabel::ResourceId => Ok(Self::ResourceId(value.context)),
            ContextLabel::ConnectionId => Ok(Self::ConnectionId(value.context)),
            ContextLabel::Nonce => Ok(Self::Nonce(
                hex::decode(value.context).map_err(TryFromGivenContextJsonError::Nonce)?,
            )),
            ContextLabel::BlockHash => Ok(Self::BlockHash(
                value
                    .context
                    .parse()
                    .map_err(TryFromGivenContextJsonError::BlockHash)?,
            )),
            ContextLabel::PaymentHash => Ok(Self::PaymentHash(
                value
                    .context
                    .parse()
                    .map_err(TryFromGivenContextJsonError::PaymentHash)?,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        common::serialize_deserialize,
        id::{
            constants::AttributeKind,
            id_proof_types::{AttributeInRangeStatement, AttributeInSetStatement},
        },
    };
    use concordium_contracts_common::hashes::Hash;
    use hex::FromHex;
    use std::marker::PhantomData;

    // Tests about JSON serialization and deserialization roundtrips

    #[test]
    fn test_verification_presentation_request_json_roundtrip() -> anyhow::Result<()> {
        let attribute_in_range_statement = AtomicStatement::AttributeInRange {
            statement: AttributeInRangeStatement {
                attribute_tag: 17.into(),
                lower: Web3IdAttribute::Numeric(80),
                upper: Web3IdAttribute::Numeric(1237),
                _phantom: PhantomData,
            },
        };
        let attribute_in_set_statement = AtomicStatement::AttributeInSet {
            statement: AttributeInSetStatement {
                attribute_tag: 23.into(),
                set: [
                    Web3IdAttribute::String(AttributeKind::try_new("ff".into()).unwrap()),
                    Web3IdAttribute::String(AttributeKind::try_new("aa".into()).unwrap()),
                    Web3IdAttribute::String(AttributeKind::try_new("zz".into()).unwrap()),
                ]
                .into_iter()
                .collect(),
                _phantom: PhantomData,
            },
        };

        let context = Context::new_simple(
            vec![0u8; 32],
            "MyConnection".to_string(),
            "MyDappContext".to_string(),
        );

        let request_data = VerificationRequestData::new(context).add_statement_request(
            IdentityStatementRequest::default()
                .add_issuer(IdentityProviderMethod::new(0u32, did::Network::Testnet))
                .add_source(CredentialType::Identity)
                .add_statement(attribute_in_range_statement)
                .add_statement(attribute_in_set_statement),
        );

        let verification_request_anchor_transaction_hash = hashes::TransactionHash::new([0u8; 32]);

        let presentation_request = VerifiablePresentationRequest::new(
            request_data,
            verification_request_anchor_transaction_hash,
        );

        let json = anyhow::Context::context(
            serde_json::to_value(&presentation_request),
            "Failed verifiable presentation request to JSON value.",
        )?;
        let roundtrip = anyhow::Context::context(
            serde_json::from_value(json),
            "Failed verifiable presentation request from JSON value.",
        )?;
        assert_eq!(
            presentation_request, roundtrip,
            "Failed verifiable presentation request JSON roundtrip."
        );

        Ok(())
    }

    #[test]
    fn test_verification_audit_record_json_roundtrip() -> anyhow::Result<()> {
        let id = "MyUUID".to_string();
        let context = Context::new_simple(
            vec![0u8; 32],
            "MyConnection".to_string(),
            "MyDappContext".to_string(),
        );

        let attribute_in_range_statement = AtomicStatement::AttributeInRange {
            statement: AttributeInRangeStatement {
                attribute_tag: 17.into(),
                lower: Web3IdAttribute::Numeric(80),
                upper: Web3IdAttribute::Numeric(1237),
                _phantom: PhantomData,
            },
        };

        let request_data = VerificationRequestData::new(context).add_statement_request(
            IdentityStatementRequest::default()
                .add_issuer(IdentityProviderMethod::new(0u32, did::Network::Testnet))
                .add_source(CredentialType::Identity)
                .add_statement(attribute_in_range_statement),
        );

        let verification_request_anchor_transaction_hash = hashes::TransactionHash::new([0u8; 32]);

        let presentation_request = VerifiablePresentationRequest::new(
            request_data,
            verification_request_anchor_transaction_hash,
        );

        let presentation = "DummyPresentation".to_string();

        let verification_audit_record =
            VerificationAuditRecord::new(id, presentation_request, presentation);

        let json = anyhow::Context::context(
            serde_json::to_value(&verification_audit_record),
            "Failed verification audit record to JSON value.",
        )?;
        let roundtrip = anyhow::Context::context(
            serde_json::from_value(json),
            "Failed verification audit record from JSON value.",
        )?;
        assert_eq!(
            verification_audit_record, roundtrip,
            "Failed verification audit record JSON roundtrip."
        );

        Ok(())
    }

    // Tests about serialization and deserialization roundtrips

    #[test]
    fn test_verification_request_anchor_serialization_deserialization_roundtrip() {
        let context = Context::new_simple(
            vec![0u8; 32],
            "MyConnection".to_string(),
            "MyDappContext".to_string(),
        );

        let attribute_in_range_statement = AtomicStatement::AttributeInRange {
            statement: AttributeInRangeStatement {
                attribute_tag: 17.into(),
                lower: Web3IdAttribute::Numeric(80),
                upper: Web3IdAttribute::Numeric(1237),
                _phantom: PhantomData,
            },
        };

        let request_data = VerificationRequestData::new(context).add_statement_request(
            IdentityStatementRequest::default()
                .add_issuer(IdentityProviderMethod::new(0u32, did::Network::Testnet))
                .add_source(CredentialType::Identity)
                .add_statement(attribute_in_range_statement),
        );

        let deserialized = serialize_deserialize(&request_data).expect("Deserialization succeeds.");

        assert_eq!(
            request_data, deserialized,
            "Failed verification request anchor serialization deserialization roundtrip."
        );
    }

    #[test]
    fn test_verification_audit_record_serialization_deserialization_roundtrip() {
        let id = "MyUUID".to_string();
        let context = Context::new_simple(
            vec![0u8; 32],
            "MyConnection".to_string(),
            "MyDappContext".to_string(),
        );

        let attribute_in_range_statement = AtomicStatement::AttributeInRange {
            statement: AttributeInRangeStatement {
                attribute_tag: 17.into(),
                lower: Web3IdAttribute::Numeric(80),
                upper: Web3IdAttribute::Numeric(1237),
                _phantom: PhantomData,
            },
        };

        let request_data = VerificationRequestData::new(context).add_statement_request(
            IdentityStatementRequest::default()
                .add_issuer(IdentityProviderMethod::new(0u32, did::Network::Testnet))
                .add_source(CredentialType::Identity)
                .add_statement(attribute_in_range_statement),
        );

        let verification_request_anchor_transaction_hash = hashes::TransactionHash::new([0u8; 32]);

        let presentation_request = VerifiablePresentationRequest::new(
            request_data,
            verification_request_anchor_transaction_hash,
        );

        let presentation = "DummyPresentation".to_string();

        let verification_audit_record =
            VerificationAuditRecord::new(id, presentation_request, presentation);

        let deserialized =
            serialize_deserialize(&verification_audit_record).expect("Deserialization succeeds.");
        assert_eq!(
            verification_audit_record, deserialized,
            "Failed verification audit record serialization deserialization roundtrip."
        );
    }

    // Tests about cbor serialization and deserialization roundtrips for the anchors

    #[test]
    fn test_verification_audit_record_cbor_roundtrip() {
        let id = "MyUUID".to_string();
        let context = Context::new_simple(
            vec![0u8; 32],
            "MyConnection".to_string(),
            "MyDappContext".to_string(),
        );

        let attribute_in_range_statement = AtomicStatement::AttributeInRange {
            statement: AttributeInRangeStatement {
                attribute_tag: 17.into(),
                lower: Web3IdAttribute::Numeric(80),
                upper: Web3IdAttribute::Numeric(1237),
                _phantom: PhantomData,
            },
        };

        let request_data = VerificationRequestData::new(context).add_statement_request(
            IdentityStatementRequest::default()
                .add_issuer(IdentityProviderMethod::new(0u32, did::Network::Testnet))
                .add_source(CredentialType::Identity)
                .add_statement(attribute_in_range_statement),
        );

        let verification_request_anchor_transaction_hash = hashes::TransactionHash::new([0u8; 32]);

        let presentation_request = VerifiablePresentationRequest::new(
            request_data,
            verification_request_anchor_transaction_hash,
        );

        let presentation = "DummyPresentation".to_string();

        let verification_audit_record =
            VerificationAuditRecord::new(id, presentation_request, presentation);

        let mut public_info = HashMap::new();
        public_info.insert("key".to_string(), cbor::value::Value::Positive(4u64));

        let verification_audit_record_on_chain: VerificationAuditRecordOnChain =
            verification_audit_record.anchor(Some(public_info));

        let cbor = cbor::cbor_encode(&verification_audit_record_on_chain).unwrap();
        assert_eq!(hex::encode(&cbor), "a464686173685820190cec0f706b9590f92b7e20747f3ddbd9eba8a601c52554394dc2316634dc68667075626c6963a1636b65790466722374797065664343445641526776657273696f6e01");

        let decoded: VerificationAuditRecordOnChain = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(decoded, verification_audit_record_on_chain);
    }

    // Tests about computing anchor hashes

    #[test]
    fn test_compute_the_correct_verification_request_anchor() -> anyhow::Result<()> {
        let context = Context::new_simple(
            vec![0u8; 32],
            "MyConnection".to_string(),
            "MyDappContext".to_string(),
        );

        let attribute_in_range_statement = AtomicStatement::AttributeInRange {
            statement: AttributeInRangeStatement {
                attribute_tag: 17.into(),
                lower: Web3IdAttribute::Numeric(80),
                upper: Web3IdAttribute::Numeric(1237),
                _phantom: PhantomData,
            },
        };

        let request_data = VerificationRequestData::new(context).add_statement_request(
            IdentityStatementRequest::default()
                .add_issuer(IdentityProviderMethod::new(0u32, did::Network::Testnet))
                .add_source(CredentialType::Identity)
                .add_statement(attribute_in_range_statement),
        );

        let mut public_info = HashMap::new();
        public_info.insert("key".to_string(), cbor::value::Value::Positive(4u64));

        let verification_request_anchor: VerificationRequestAnchorOnChain =
            request_data.anchor(Some(public_info));
        let verification_request_anchor_hash = verification_request_anchor.hash;

        let expected_verification_request_anchor_hash = Hash::new(
            <[u8; 32]>::from_hex(
                "7326166760159b23dbfe8c6b585fa45883358d87e3fe4d784633aa0ebc6998fb",
            )
            .expect("Invalid hex"),
        );

        assert_eq!(
            verification_request_anchor_hash, expected_verification_request_anchor_hash,
            "Failed verification request anchor hash check."
        );

        Ok(())
    }

    #[test]
    fn test_compute_the_correct_verification_audit_record() -> anyhow::Result<()> {
        let id = "MyUUID".to_string();
        let context = Context::new_simple(
            vec![0u8; 32],
            "MyConnection".to_string(),
            "MyDappContext".to_string(),
        );

        let attribute_in_range_statement = AtomicStatement::AttributeInRange {
            statement: AttributeInRangeStatement {
                attribute_tag: 17.into(),
                lower: Web3IdAttribute::Numeric(80),
                upper: Web3IdAttribute::Numeric(1237),
                _phantom: PhantomData,
            },
        };

        let request_data = VerificationRequestData::new(context).add_statement_request(
            IdentityStatementRequest::default()
                .add_issuer(IdentityProviderMethod::new(0u32, did::Network::Testnet))
                .add_source(CredentialType::Identity)
                .add_statement(attribute_in_range_statement),
        );

        let verification_request_anchor_transaction_hash = hashes::TransactionHash::new([0u8; 32]);

        let presentation_request = VerifiablePresentationRequest::new(
            request_data,
            verification_request_anchor_transaction_hash,
        );

        let presentation = "DummyPresentation".to_string();

        let verification_audit_record =
            VerificationAuditRecord::new(id, presentation_request, presentation);

        let mut public_info = HashMap::new();
        public_info.insert("key".to_string(), cbor::value::Value::Positive(4u64));

        let verification_audit_record_on_chain: VerificationAuditRecordOnChain =
            verification_audit_record.anchor(Some(public_info));
        let verification_audit_record_hash = verification_audit_record_on_chain.hash;

        let expected_verification_audit_record_hash = Hash::new(
            <[u8; 32]>::from_hex(
                "190cec0f706b9590f92b7e20747f3ddbd9eba8a601c52554394dc2316634dc68",
            )
            .expect("Invalid hex"),
        );

        assert_eq!(
            verification_audit_record_hash, expected_verification_audit_record_hash,
            "Failed verification audit record hash check."
        );

        Ok(())
    }

    #[test]
    fn test_verification_request_anchor_cbor_roundtrip() {
        let context = Context::new_simple(
            vec![0u8; 32],
            "MyConnection".to_string(),
            "MyDappContext".to_string(),
        );

        let attribute_in_range_statement = AtomicStatement::AttributeInRange {
            statement: AttributeInRangeStatement {
                attribute_tag: 17.into(),
                lower: Web3IdAttribute::Numeric(80),
                upper: Web3IdAttribute::Numeric(1237),
                _phantom: PhantomData,
            },
        };

        let request_data = VerificationRequestData::new(context).add_statement_request(
            IdentityStatementRequest::default()
                .add_issuer(IdentityProviderMethod::new(0u32, did::Network::Testnet))
                .add_source(CredentialType::Identity)
                .add_statement(attribute_in_range_statement),
        );

        let mut public_info = HashMap::new();
        public_info.insert("key".to_string(), cbor::value::Value::Positive(4u64));

        let verification_request_anchor: VerificationRequestAnchorOnChain =
            request_data.anchor(Some(public_info));

        let cbor = cbor::cbor_encode(&verification_request_anchor).unwrap();
        assert_eq!(hex::encode(&cbor), "a4646861736858207326166760159b23dbfe8c6b585fa45883358d87e3fe4d784633aa0ebc6998fb667075626c6963a1636b65790466722374797065664343445652416776657273696f6e01");

        let decoded: VerificationRequestAnchorOnChain = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(decoded, verification_request_anchor);
    }
}
