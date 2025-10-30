// TODO Add JSON regression tests.
// TODO Add CBOR regression tests.
// TODO Use v1 presentation when ready.
// TODO Add test case for constructing a request.

//! Types used in Concordium verifiable presentation protocol version 1.

use crate::common::cbor;
use crate::id::id_proof_types::AtomicStatement;
use crate::id::types::AttributeTag;
use crate::web3id::{did, Web3IdAttribute};
use crate::{hashes, id};
use concordium_base_derive::{CborDeserialize, CborSerialize};
use std::collections::HashMap;

/// A verifiable presentation request that specifies what credentials and proofs
/// are being requested from a credential holder.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
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
/// of verification interactions, while only publishing hash-based public records on-chain
/// to preserve privacy, see [`VerificationAuditAnchorOnChain`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename = "ConcordiumVerificationAuditRecord")]
pub struct VerificationAuditRecord {
    /// Version integer, for now it is always 1.
    pub version: u16,
    /// The verifiable presentation request to record.
    pub request: VerifiablePresentationRequest,
    /// Unique identifier chosen by the requester/merchant.
    pub id: String,
    // TODO Replace serde_json::Value with the actual v1 presentation when ready.
    pub presentation: serde_json::Value,
}

/// Data structure for CBOR-encoded verifiable audit
///
/// This format is used when anchoring a verification audit on the Concordium blockchain.
#[derive(Debug, Clone, CborSerialize, CborDeserialize)]
pub struct VerificationAuditAnchorOnChain {
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
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
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

    pub fn hash(&self) -> hashes::Hash {
        todo!()
    }

    pub fn anchor(
        &self,
        public_info: Option<HashMap<String, cbor::value::Value>>,
    ) -> VerificationAuditAnchorOnChain {
        VerificationAuditAnchorOnChain {
            r#type: "CCDVAA".to_string(),
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
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize, Default)]
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
#[derive(Debug, Clone, CborSerialize, CborDeserialize)]
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
    /// Statements based on the Concordium Web3ID credentials.
    #[serde(rename = "web3Id")]
    Web3Id {
        #[serde(flatten)]
        request: Web3IdStatementRequest,
    },
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, Default)]
pub struct IdentityStatementRequest {
    /// Set of allowed credential types. Should never be empty or contain the same value twice.
    pub source: Vec<CredentialType>,
    /// The statements requested.
    pub statements: id::id_proof_types::Statement<id::constants::ArCurve, Web3IdAttribute>,
    /// The credential issuers allowed.
    pub issuers: Vec<IdentityProviderMethod>,
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

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize, Default)]
pub struct Web3IdStatementRequest {
    /// The statements requested.
    pub statements:
        Vec<id::id_proof_types::AtomicStatement<id::constants::ArCurve, String, Web3IdAttribute>>,
    /// The credential issuers allowed.
    pub issuers: Vec<did::Method>,
}
impl From<Web3IdStatementRequest> for CredentialStatementRequest {
    fn from(request: Web3IdStatementRequest) -> Self {
        Self::Web3Id { request }
    }
}

impl Web3IdStatementRequest {
    /// Create an empty Web3Id statement request.
    pub fn new() -> Self {
        Default::default()
    }

    /// Add an issuer to the given Web3Id statement request.
    pub fn add_issuer(mut self, issuer: did::Method) -> Self {
        if !self.issuers.contains(&issuer) {
            self.issuers.push(issuer);
        }
        self
    }

    /// Add issuers to the given Web3Id statement request.
    pub fn add_issuers(mut self, issuers: Vec<did::Method>) -> Self {
        for issuer in issuers {
            if !self.issuers.contains(&issuer) {
                self.issuers.push(issuer);
            }
        }
        self
    }

    /// Add a statement to the given Web3Id statement request.
    pub fn add_statement(
        mut self,
        statement: AtomicStatement<id::constants::ArCurve, String, Web3IdAttribute>,
    ) -> Self {
        if !self.statements.contains(&statement) {
            self.statements.push(statement);
        }
        self
    }

    /// Add statements to the given Web3Id statement request.
    pub fn add_statements(
        mut self,
        statements: Vec<AtomicStatement<id::constants::ArCurve, String, Web3IdAttribute>>,
    ) -> Self {
        for statement in statements {
            if !self.statements.contains(&statement) {
                self.statements.push(statement);
            }
        }
        self
    }
}

/// Labels for different types of context information that can be provided in verifiable
/// presentation requests and proofs.
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ContextLabel {
    ContextString,
    #[serde(rename = "ResourceID")]
    ResourceId,
    BlockHash,
    PaymentHash,
    #[serde(rename = "ConnectionID")]
    ConnectionId,
    Nonce,
}

/// Identity based credential types.
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialType {
    Identity,
    Account,
}

/// DID method for a Concordium Identity Provider.
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
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
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(into = "GivenContextJson", try_from = "GivenContextJson")]
pub enum GivenContext {
    /// Cryptographic nonce context.
    Nonce(Vec<u8>),
    /// Payment Hash context.
    PaymentHash(hashes::Hash),
    /// Concordium block hash context.
    BlockHash(hashes::BlockHash),
    /// Identifier for some connection.
    ConnectionId(String),
    /// Identifier for some resource.
    ResourceId(String),
    /// String value for general purposes.
    ContextString(String),
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
    use crate::id::constants::AttributeKind;
    use crate::id::id_proof_types::{AttributeInRangeStatement, AttributeInSetStatement};
    use crate::web3id::did::Network;
    use ed25519_dalek::VerifyingKey;
    use std::marker::PhantomData;

    #[test]
    fn verifiable_presentation_request_should_perform_successful_json_roundtrip(
    ) -> anyhow::Result<()> {
        let web3id_statements = vec![
            AtomicStatement::AttributeInRange {
                statement: AttributeInRangeStatement {
                    attribute_tag: "17".into(),
                    lower: Web3IdAttribute::Numeric(80),
                    upper: Web3IdAttribute::Numeric(1237),
                    _phantom: PhantomData,
                },
            },
            AtomicStatement::AttributeInSet {
                statement: AttributeInSetStatement {
                    attribute_tag: "23".into(),
                    set: [
                        Web3IdAttribute::String(AttributeKind::try_new("ff".into()).unwrap()),
                        Web3IdAttribute::String(AttributeKind::try_new("aa".into()).unwrap()),
                        Web3IdAttribute::String(AttributeKind::try_new("zz".into()).unwrap()),
                    ]
                    .into_iter()
                    .collect(),
                    _phantom: PhantomData,
                },
            },
        ];
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

        let request_data = VerificationRequestData::new(context)
            .add_statement_request(
                IdentityStatementRequest::default()
                    .add_issuer(IdentityProviderMethod::new(0u32, did::Network::Testnet))
                    .add_source(CredentialType::Identity)
                    .add_statement(attribute_in_range_statement)
                    .add_statement(attribute_in_set_statement),
            )
            .add_statement_request(
                Web3IdStatementRequest::default()
                    .add_issuer(did::Method {
                        network: Network::Testnet,
                        ty: did::IdentifierType::PublicKey {
                            key: VerifyingKey::from_bytes(&[0u8; 32])?,
                        },
                    })
                    .add_statements(web3id_statements),
            );

        let anchor_transaction_hash = hashes::TransactionHash::new([0u8; 32]);

        let presentation_request =
            VerifiablePresentationRequest::new(request_data, anchor_transaction_hash);

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
}
