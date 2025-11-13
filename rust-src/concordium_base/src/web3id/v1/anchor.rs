use crate::common::{cbor, Buffer, Deserial, Get, ParseResult, ReadBytesExt, Serial, Serialize};
use crate::id::{
    constants::{ArCurve, IpPairing},
    id_proof_types::AtomicStatement,
    types::AttributeTag,
};
use crate::web3id::v1::PresentationV1;
use crate::web3id::{did, Web3IdAttribute};
use crate::{hashes, id};
use concordium_base_derive::{CborDeserialize, CborSerialize};
use concordium_contracts_common::hashes::HashBytes;
use sha2::Digest;
use std::collections::HashMap;

const PROTOCOL_VERSION: u16 = 1u16;

/// A verifiable presentation request that specifies what credentials and proofs
/// are being requested from a credential holder.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "type", rename = "ConcordiumVerificationRequestV1")]
pub struct VerificationRequest {
    /// Context information for a verifiable presentation request.
    pub context: UnfilledContextInformation,
    /// The claims for a list of subjects containing requested statements about the subjects.
    pub subject_claims: Vec<RequestedSubjectClaims>,
    /// Blockchain transaction hash that anchors the request.
    #[serde(rename = "transactionRef")]
    pub anchor_transaction_hash: hashes::TransactionHash,
}

/// A verification audit record that contains the complete verifiable presentation
/// request and response data. The record contains the verification request
/// and the verifiable presentations and should generally be kept private by the verifier.
///
/// Audit records are used internally by verifiers to maintain complete records
/// of verification interactions, while only publishing hash-based public records/anchors on-chain
/// to preserve privacy, see [`VerificationAuditAnchor`].
#[derive(Debug, Clone, PartialEq, Serialize, serde::Deserialize, serde::Serialize)]
#[serde(tag = "type", rename = "ConcordiumVerificationAuditRecord")]
pub struct VerificationAuditRecord {
    /// Version integer, for now it is always 1.
    pub version: u16,
    /// The verifiable presentation request to record.
    pub request: VerificationRequest,
    /// Unique identifier chosen by the requester/merchant.
    pub id: String,
    /// The verifiable presentation including the proof.
    pub presentation: PresentationV1<IpPairing, ArCurve, Web3IdAttribute>,
}

impl VerificationAuditRecord {
    /// Create a new verifiable audit anchor
    pub fn new(
        request: VerificationRequest,
        id: String,
        presentation: PresentationV1<IpPairing, ArCurve, Web3IdAttribute>,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            request,
            id,
            presentation,
        }
    }

    /// Computes a hash of the verification audit record.
    ///
    /// This hash is used to create a tamper-evident anchor that can be stored
    /// on-chain to prove an audit record was made at a specific time and with
    /// specific parameters.
    pub fn hash(&self) -> hashes::Hash {
        use crate::common::Serial;
        let mut hasher = sha2::Sha256::new();
        self.serial(&mut hasher);
        HashBytes::new(hasher.finalize().into())
    }

    /// Generates the [`VerificationAuditAnchor`], a hash-based public record/anchor that can be published on-chain,
    /// from the internal audit anchor [`VerificationAuditRecord`] type. Verifiers maintain the private [`VerificationAuditAnchor`]
    /// in their backend database.
    pub fn to_anchor(
        &self,
        public_info: HashMap<String, cbor::value::Value>,
    ) -> VerificationAuditAnchor {
        VerificationAuditAnchor {
            // Concordium Verification Audit Anchor
            r#type: "CCDVAA".to_string(),
            version: PROTOCOL_VERSION,
            hash: self.hash(),
            public: public_info,
        }
    }
}

/// Data structure for CBOR-encoded verifiable audit
///
/// This format is used when anchoring a verification audit on the Concordium blockchain.
#[derive(Debug, Clone, PartialEq, CborSerialize, CborDeserialize)]
pub struct VerificationAuditAnchor {
    /// Type identifier for Concordium Verifiable Request Audit Anchor/Record. Always set to "CCDVAA".
    #[cbor(key = "type")]
    pub r#type: String,
    /// Data format version integer, for now it is always 1.
    pub version: u16,
    /// Hash computed from the [`VerificationAuditRecord`].
    pub hash: hashes::Hash,
    /// Optional public information.
    pub public: HashMap<String, cbor::value::Value>,
}

/// Description of the presentation being requested from a credential holder.
///
/// This is also used to compute the hash for in the [`VerificationRequestAnchor`].
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "type", rename = "ConcordiumVerificationRequestDataV1")]
pub struct VerificationRequestData {
    /// Context information for a verifiable presentation request.
    pub context: UnfilledContextInformation,
    /// The claims for a list of subjects containing requested statements about the subjects.
    pub subject_claims: Vec<RequestedSubjectClaims>,
}

impl VerificationRequestData {
    /// Create a new verifiable request data type with no statements.
    pub fn new(context: UnfilledContextInformation) -> Self {
        Self {
            context,
            subject_claims: Vec::new(),
        }
    }

    /// Add a new statement request to the verification request data.
    pub fn add_statement_request(
        mut self,
        statement_request: impl Into<RequestedSubjectClaims>,
    ) -> Self {
        self.subject_claims.push(statement_request.into());
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

    /// Generates the [`VerificationRequestAnchor`], a hash-based public record/anchor that can be published on-chain,
    /// from the the [`VerificationRequestData`] type.
    pub fn to_anchor(
        &self,
        public_info: HashMap<String, cbor::value::Value>,
    ) -> VerificationRequestAnchor {
        VerificationRequestAnchor {
            // Concordium Verification Request Anchor
            r#type: "CCDVRA".to_string(),
            version: PROTOCOL_VERSION,
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
#[serde(tag = "type", rename = "ConcordiumUnfilledContextInformationV1")]
pub struct UnfilledContextInformation {
    /// Context information that is already provided.
    pub given: Vec<GivenContext>,
    /// Context information that must be provided by the presenter.
    pub requested: Vec<ContextLabel>,
}

impl UnfilledContextInformation {
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
    /// - `nonce` Cryptographic nonce for preventing replay attacks and should be at least of length bytes32.
    /// - `connectionId` Identifier for the verification session (e.g. wallet-connect topic).
    /// - `contextString` Additional context information.
    pub fn new_simple(nonce: [u8; 32], connection_id: String, context_string: String) -> Self {
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
pub struct VerificationRequestAnchor {
    /// Type identifier for Concordium Verification Request Anchor. Always set to "CCDVRA".
    #[cbor(key = "type")]
    pub r#type: String,
    /// Data format version integer, for now it is always 1.
    pub version: u16,
    /// Hash computed from the [`VerificationRequestData`].
    pub hash: hashes::Hash,
    /// Optional public information.
    pub public: HashMap<String, cbor::value::Value>,
}

/// The credential statements being requested.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
pub enum RequestedSubjectClaims {
    /// Statements based on the Concordium ID object.
    #[serde(rename = "identity")]
    Identity {
        #[serde(flatten)]
        request: RequestedIdentitySubjectClaims,
    },
}

impl Serial for RequestedSubjectClaims {
    fn serial<B: Buffer>(&self, out: &mut B) {
        match self {
            RequestedSubjectClaims::Identity { request } => {
                0u8.serial(out);
                request.serial(out);
            }
        }
    }
}

impl Deserial for RequestedSubjectClaims {
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

/// A statement request concerning the Concordium ID object (held in the wallet).
/// The Concordium ID object has been signed by identity providers (IDPs).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, Default, Serialize)]
pub struct RequestedIdentitySubjectClaims {
    /// The statements requested.
    pub statements: id::id_proof_types::Statement<ArCurve, Web3IdAttribute>,
    /// The credential issuers allowed.
    pub issuers: Vec<IdentityProviderMethod>,
    /// Set of allowed credential types. Should never be empty or contain the same value twice.
    pub source: Vec<CredentialType>,
}

impl From<RequestedIdentitySubjectClaims> for RequestedSubjectClaims {
    fn from(request: RequestedIdentitySubjectClaims) -> Self {
        Self::Identity { request }
    }
}

impl RequestedIdentitySubjectClaims {
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
    pub fn add_sources(mut self, sources: impl IntoIterator<Item = CredentialType>) -> Self {
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
    pub fn add_issuers(
        mut self,
        issuers: impl IntoIterator<Item = IdentityProviderMethod>,
    ) -> Self {
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
pub enum CredentialType {
    /// The type of the credential is linked directly to the Concordium ID object
    /// hold in a wallet while no account is deployed on-chain.
    /// The Concordium ID object has been signed by the identity providers (IDPs).
    #[serde(rename = "identityCredential")]
    IdentityCredential,
    /// The type of the credential is linked to an account deployed on-chain.
    /// The account was deployed from a Concordium ID object
    /// hold in a wallet. The Concordium ID object has been signed by the identity providers (IDPs).
    #[serde(rename = "accountCredential")]
    AccountCredential,
}

impl Serial for CredentialType {
    fn serial<B: Buffer>(&self, out: &mut B) {
        match self {
            CredentialType::IdentityCredential => 0u8.serial(out),
            CredentialType::AccountCredential => 1u8.serial(out),
        }
    }
}

impl Deserial for CredentialType {
    fn deserial<R: byteorder::ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        match u8::deserial(source)? {
            0u8 => Ok(Self::IdentityCredential),
            1u8 => Ok(Self::AccountCredential),
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
    /// Create a new identity provider method.
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
    Nonce([u8; 32]),
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
            ContextLabel::Nonce => {
                let bytes =
                    hex::decode(value.context).map_err(TryFromGivenContextJsonError::Nonce)?;

                let arr: [u8; 32] = bytes.try_into().map_err(|_| {
                    TryFromGivenContextJsonError::Nonce(hex::FromHexError::InvalidStringLength)
                })?;

                Ok(Self::Nonce(arr))
            }
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
    use crate::hashes::Hash;
    use crate::{
        common::serialize_deserialize,
        id::{
            constants::{ArCurve, IpPairing},
            id_proof_types::AttributeInRangeStatement,
        },
    };
    use anyhow::Context as AnyhowContext;
    use hex::FromHex;
    use std::marker::PhantomData;

    fn remove_whitespace(str: &str) -> String {
        str.chars().filter(|c| !c.is_whitespace()).collect()
    }

    fn verification_request_data_fixture() -> VerificationRequestData {
        let context = UnfilledContextInformation::new_simple(
            [0u8; 32],
            "MyConnection".to_string(),
            "MyDappContext".to_string(),
        )
        // While above simple context is used in practice,
        // we add all possible context variants and context label variants to ensure test coverage.
        .add_context(GivenContext::PaymentHash(hashes::Hash::new([1u8; 32])))
        .add_context(GivenContext::BlockHash(hashes::BlockHash::new([2u8; 32])))
        .add_context(GivenContext::ResourceId("MyRescourceId".to_string()))
        .add_request(ContextLabel::Nonce)
        .add_request(ContextLabel::PaymentHash)
        .add_request(ContextLabel::ConnectionId)
        .add_request(ContextLabel::ContextString);

        let attribute_in_range_statement = AtomicStatement::AttributeInRange {
            statement: AttributeInRangeStatement {
                attribute_tag: 17.into(),
                lower: Web3IdAttribute::Numeric(80),
                upper: Web3IdAttribute::Numeric(1237),
                _phantom: PhantomData,
            },
        };

        VerificationRequestData::new(context).add_statement_request(
            RequestedIdentitySubjectClaims::default()
                .add_issuer(IdentityProviderMethod::new(3u32, did::Network::Testnet))
                .add_source(CredentialType::IdentityCredential)
                .add_statement(attribute_in_range_statement),
        )
    }

    fn verification_request_anchor_fixture() -> VerificationRequestAnchor {
        let request_data = verification_request_data_fixture();

        let mut public_info = HashMap::new();
        public_info.insert("key".to_string(), cbor::value::Value::Positive(4u64));

        request_data.to_anchor(public_info)
    }

    fn verification_audit_record_fixture() -> VerificationAuditRecord {
        let context = UnfilledContextInformation::new_simple(
            [1; 32],
            "MyConnection".to_string(),
            "MyDappContext".to_string(),
        )
        // While above simple context is used in practice,
        // we add all possible context variants and context label variants to ensure test coverage.
        .add_context(GivenContext::PaymentHash(hashes::Hash::new([2u8; 32])))
        .add_context(GivenContext::BlockHash(hashes::BlockHash::new([3u8; 32])))
        .add_context(GivenContext::ResourceId("MyRescourceId".to_string()))
        .add_request(ContextLabel::Nonce)
        .add_request(ContextLabel::PaymentHash)
        .add_request(ContextLabel::ConnectionId)
        .add_request(ContextLabel::ContextString);

        let attribute_in_range_statement = AtomicStatement::AttributeInRange {
            statement: AttributeInRangeStatement {
                attribute_tag: 17.into(),
                lower: Web3IdAttribute::Numeric(80),
                upper: Web3IdAttribute::Numeric(1237),
                _phantom: PhantomData,
            },
        };

        let request_data = VerificationRequestData::new(context).add_statement_request(
            RequestedIdentitySubjectClaims::default()
                .add_issuer(IdentityProviderMethod::new(3u32, did::Network::Testnet))
                .add_source(CredentialType::IdentityCredential)
                .add_statement(attribute_in_range_statement),
        );

        let verification_request_anchor_transaction_hash = hashes::TransactionHash::new([2u8; 32]);

        let presentation_request = VerificationRequest {
            context: request_data.context,
            subject_claims: request_data.subject_claims,
            anchor_transaction_hash: verification_request_anchor_transaction_hash,
        };

        let presentation_json = r#"
{
  "type": [
    "VerifiablePresentation",
    "ConcordiumVerifiablePresentationV1"
  ],
  "presentationContext": {
    "given": [
        {
            "context": "0101010101010101010101010101010101010101010101010101010101010101",
            "label": "Nonce"
        },
        {
            "context": "MyConnection",
            "label": "ConnectionID"
        },
        {
            "context": "MyDappContext",
            "label": "ContextString"
        },
        {
            "context": "0202020202020202020202020202020202020202020202020202020202020202",
            "label": "PaymentHash"
        },
        {
            "context": "0303030303030303030303030303030303030303030303030303030303030303",
            "label": "BlockHash"
        },
        {
            "context": "MyRescourceId",
            "label": "ResourceID"
        }
    ],
    "requested": [
        {
            "context": "0101010101010101010101010101010101010101010101010101010101010101",
            "label": "Nonce"
        },
        {
            "context": "MyConnection",
            "label": "ConnectionID"
        },
        {
            "context": "MyDappContext",
            "label": "ContextString"
        },
        {
            "context": "0202020202020202020202020202020202020202020202020202020202020202",
            "label": "PaymentHash"
        },
        {
            "context": "0303030303030303030303030303030303030303030303030303030303030303",
            "label": "BlockHash"
        },
        {
            "context": "MyRescourceId",
            "label": "ResourceID"
        }
    ],
    "type": "ConcordiumContextInformationV1"
  },
  "verifiableCredential": [
    {
      "type": [
        "VerifiableCredential",
        "ConcordiumVerifiableCredentialV1",
        "ConcordiumAccountBasedCredential"
      ],
      "credentialSubject": {
        "id": "did:ccd:testnet:cred:856793e4ba5d058cea0b5c3a1c8affb272efcf53bbab77ee28d3e2270d5041d220c1e1a9c6c8619c84e40ebd70fb583e",
        "statement": [
          {
            "type": "AttributeInRange",
            "attributeTag": "dob",
            "lower": 80,
            "upper": 1237
          },
          {
            "type": "AttributeInSet",
            "attributeTag": "sex",
            "set": [
              "aa",
              "ff",
              "zz"
            ]
          },
          {
            "type": "AttributeNotInSet",
            "attributeTag": "lastName",
            "set": [
              "aa",
              "ff",
              "zz"
            ]
          },
          {
            "type": "AttributeInRange",
            "attributeTag": "countryOfResidence",
            "lower": {
              "type": "date-time",
              "timestamp": "2023-08-27T23:12:15Z"
            },
            "upper": {
              "type": "date-time",
              "timestamp": "2023-08-29T23:12:15Z"
            }
          },
          {
            "type": "RevealAttribute",
            "attributeTag": "nationality"
          }
        ]
      },
      "issuer": "did:ccd:testnet:idp:17",
      "proof": {
        "created": "2023-08-28T23:12:15Z",
        "proofValue": "000000000000000501b12365d42dbcdda54216b524d94eda74809018b8179d90c747829da5d24df4b2d835d7f77879cf52d5b1809564c5ec49990998db469e5c04553de3f787a3998d660204fe2dd1033a310bfc06ab8a9e5426ff90fdaf554ac11e96bbf18b1e1da898425e0f42bb5b91f650cffc83890c5c3634217e1ca6df0150d100aedc6c49b36b548e9e853f9180b3b994f2b9e6e302840ce0d443ca529eba7fb3b15cd10987be5a40a2e5cf825467588a00584b228bea646482954922ae2bffad62c65eebb71a4ca5367d4ac3e3b4cb0e56190e95f6af1c47d0b45991d39e58ee3a25c32de75c9d91cabd2cc5bc4325a4699b8a1c2e486059d472917ba1c5e4a2b66f77dbcf08a2aa21cbd0ec8f78061aa92cc1b126e06e1fc0da0d03c30e444721fbe07a1100000007ae9f2dffa4e4102b834e7930e7bb9476b00b8f0077e5fb48bc953f44571a9f9f8bcf46ea1cc3e93ca6e635d85ee5a63fa2a1c92e0bf7fba3e61a37f858f8fa52f40644f59e1fb65b6fb34eaaa75a907e85e2c8efd664a0c6a9d40cbe3e96fd7ab0ff06a4a1e66fd3950cf1af6c8a7d30197ae6aec4ecf463c368f3b587b5b65b93a6b77167e112e724a5fe6e7b3ce16b8402d736cb9b207e0e3833bb47d0e3ddc581790c9539ecd3190bdee690120c9b8e322e3fb2799ada40f5e7d9b66a8774aa662ab85c9e330410a19d0c1311c13cf59c798fa021d24afd85fabfe151802cbde37dafc0046920345961db062e5fb9b2fe0334debe1670ef88142a625e6acd1b7ded9f63b68d7b938b108dbf4cca60257bdf32fed399b2d0f11a10c59a4089937a28cbeefc28a93e533722d6060856baf26ccd9470a9c50229acc54753534888e1c8f8c612b5e6af0705dceeac85a5ac3d641b3033c5d3af066f33147256b86b1fffaaceea3bf9e4fd98f7a5371e4a882dd3c7cbe5d9b34e933d6ac224d7198cc4c8d3e5f0cef03fad810ca36499dc3a5e157d435843d60eb6a3fc3c3624d9fef8b5f2f2335af0a8ecca5cf71a9ffab6651d7c899d560264a6c9e361ee10a17dcb18522acdc0a19ab004f15ba1e23fa2aa3bb75f3767678d12c6dc35b2a04bb5239ce2cf35649a42525f42f91d6b80266af0fbd86645611332203ac555250fc29f6bb1b50932c7e48418bbadf57db4931789a0dd44e9b70d437af1ae686ede83e6965108a655caf34bd7b0b587eef0a29350020abae08bd2d979752316f749ab4686da684dcae5b571213c7bfb914cb70965e9b643862f71bab5d22b7dbf7d3f84636ba514ef2cf0c87ecf225e3bdc99e15368b3d814fb1e257ac1fc0b9114cbb8ed594ce50688c88d8ea9d0e97f55e89fbddd282e13d7303d3604e969bc0e699388c2f6fbb310aa82f18af896019d79f26f72fbe3a5dfc6fd30c34ac8d57d499e49664ecfa76094c6fba2372dba87a2b55dd9dc30877af0d6fdd2b2ea54be02b39554bf77b9ad30ef725df82bdb6c5456adf9ac3187ffbeaab1b4ce68782829850f10182deb13eaa94edd3640768224a178b8bac224d12711c7d3bec925db4da9bd1424db872757a1f2e10c9dac40483a69972504e5d69163a9f13c5dc8fc60a1634554a5009d948704f92e701eeb0a5b2cbfdcf62fd7b8cc0db65b2ba52dd1bbe2e46eddeff70f5fb3686917587b82a9cf1e1c8a7b6cf44dbe57bbf83d541bfbfccac677a377ef4e1a5ced1e7e5147bde759150f531780bcfc5658b099787d68277d3d41d992022be434194d8307d2a90a518705017affec5796354ff2432f57f525cf014bdcf0b9fd84b9501d3938259c433b4e6181e2630b56826c4a0c7d03cc0a8768ce7226703cf97ee83d6bc1c0c044a2e0d4439780d1c7351ea8ece10000000298ff27cb9f1c4afb38c535cee5dbde71599f727976298c540cdb7ff0b10a439f1599c9bf879e35746e2fd04dda05368d966efc49f07a5c48baaca5853de36dd2f0c7fab8106f1158f34ece1d0fd8576eb727d834cb0c380c150086e2222ba38283d8c26a9af828584cbd90801cc0c3e1855b9a26f81efd3931000b8a2109ac9cd5070b98963d700560fd6c6de1df8202ac21dfbdf141bdf58ee96d7a72cb2dfba962159a2c9d0fe1d312aca7a56ce97716d7d16e47b7c59e651ee8fe8dbbf56c3048a31df649d9da46f669b80d5cb31c3ee70c5e6a05de8be814833934befaef06757e390f83ce84b4fd84fb9d86eb30a897faa4718d7b5a12c086255a0a21cc038b69df7282cd3234e4423e85d15c09d49fc2005e869a4876fec01369c3b0ec0ae6f710797b4e5294a7fdf72c05341b6887da98066400436af27e739c140e3a481df2845cd78df942a2c0fb01429d5b04cd96b18c0b2bbf764b533a6f095edbea844cbc0d196b4e423c7fd409c1ceb6572812707c9048ec5a373c29e3cefbbd128e1ebe72b84be67ae22e3dfee5b47f57b289755b558624daeb22ce521c432fbf2cab96826ec670f18a194b151ec0f49c31237f35caae1296715571520e22caff2912531b1ee43d555dee29e7105161dfe86f133b3fb7c194e72c12b1eaac010160a3e8a44cad0b1c1ef89d492014997603a37b26e9461572edcf93a011d639550e0505ad8932c2a205c688d70d6414717c7a31868b5d01c37993085cf28d1c670000000295c326f59171824b2fc3e09816b73c6f75a03fb50f611559855d295e0a565ff6d2505f970464ca12e81031d286866dd5b73c285de994b592f8d8c2e64227bcc5ae2058339d11af025cfcb126c2b3c9a7839b87c8d218f93b0f30a0876076eb9598e1ec92a57f4ce785b1a05c01e8db34b4cefe8e518a859aa6d9530bbe72a033af7e87a95433de67b86f389e178b1aaaa53eddcdf1be990d96ba7e7f18ffa83d60385e1a1130dbf245e1b4bac2e8bceb2c1184380e6e0f7876157d7ae074d1fb013266272083b5420b3fc654141046e5bee9e3ffe50497f372d55b3f0aec05873c7409c8a1507c38f6c87b726e9355d5d326658e1e7e67b349ef1a65185ec51801b2a44460fcbf28d7ce0fce6c677113a88b88ec272d3cfac24d33afc47b6fa15259af84fa6543ef673cbd18a44d47420c8c53d7eaf9272dfa62fadd8d118c2055480b6494a67b0346c9fa0b2ba2cba9c0591224a2ed7b399ea35b89111a53059cb410c51ffb45d0aab4b642087698fcb67d55d33a711db3f84a125f970705b68c5ae5b8ea2394c891911d7f1032ec08ec8df792bcbcb1a953214317be0085b4b7b23a45d52a83f77cade01752c7ae6fe1d81bb5dc3b6a74e3d2f4130178263b9e633914559cf75d5902b5fc696198bff1d25812b05ade020d0aadcae022336b3c49639dd8dd90381bb59828ca9a82d87610d1e01b4ee4827f30d11ac72fa911f4439ca4fbfe164dc370e5c96dcc329bbf9972d71e811d17f5dd2ffb760ac0e31400000007b9e19ad95babc1c31bf657ae20a5420cf05bbf024ae2ffe13b363d5404c5a0ef360c54d49e8725210a5bba290d29cb58a2607e5134fdb367631e10d8e159396e39bbc09bd7084038f6b5cebd5386da5cd18cfe3ce9dbf75b51f4d7de00e00c5993a3b4d05fb3f4edb2a8d05cece2da96d7d87081c1610eb949caed95520479c662d623ad1464fee46bc3486521d44427ad8d76db0cc6ab51cb69d1dfd59c1938b68b80a8813c9dad15f9466941e377836693dfdcfc96e12a296699ef77ab274293a917b64e48f413ee2908b574ad8875951ce40dceadaf104145a2a937bce6707a962355a61efbf9379a1da606f98915a21a9255eaf105b04651d789fc90ddab8a402d11fd8e5befece4956d1d0c9c47987c7d282cb045c053fc860e8c07365b9937aae7fa435190992a02a24e388bd0b0836775d0e01c7faba3e92c5d3e8975fcad16cce9e9b01f378a572ab4039e0b8582d4d3a47c3b3fb587483cd1a760e628d0f3d63ac9e8b10cefa8b94d02cade0ab47005ad368f4f9e5b766a5c353a6eb1a7fd5bed46fbd1554c4ec47d8b6d3b38dcc66db969c646a34928eeb40147adc94878a1b237fcbe21f779e723e8a4f6a6cec0cb57205789e8d781bf465a833608b5181ad27d420e0e1f7383c0222df32259ace41dc092dfc745bbfc4bd371cd99e5a1c73baeb8ad15c34e060af529a8babad63c3a131ca089053f498170afb30b26e0f2794b0d1f417d870af7daf37694430db13f00b7af5101723d656d334c72b5e0bbe13478722e954935e6701ecf3cc725d61e42edbb896b6d4dff5b51f48e194337fb086908d50edcb61a295dcf57f54b6b41d5a760f5ff8992a6e45acfec08157dc3640fa1878cdb5ce41cb27ab9096beb3ded0b7cd57c1c4a850abc08ac822a3be26b4deb5a3cd11914ae5ac2c29430fe91be97fea012981dbb389da64d4a794017f91fb40e3188bd7190025a5b39c323a90f5a8496d5f64e200093072f1379728f1f0e741b51db5e4967d1e5437ca1d531ed742fe9ad2708ba06b3f80000097465737476616c75656d9f6e451166c885818931efbf878b5d041b211441fa707013ebe73e41ca25da68cebf07b67ef99e5fef798d5bdff3378d766b8116e710384d1530280b79e945",
        "type": "ConcordiumZKProofV4"
      }
    }
  ],
  "proof": {
    "created": "2023-08-28T23:12:15Z",
    "proofValue": "",
    "type": "ConcordiumWeakLinkingProofV1"
  }
}
        "#;

        let presentation_deserialized: PresentationV1<IpPairing, ArCurve, Web3IdAttribute> =
            serde_json::from_str(&presentation_json).unwrap();
        let id = "MyUUID".to_string();

        VerificationAuditRecord::new(presentation_request, id, presentation_deserialized)
    }

    fn verification_audit_anchor_fixture() -> VerificationAuditAnchor {
        let verification_audit_anchor: VerificationAuditRecord =
            verification_audit_record_fixture();

        let mut public_info = HashMap::new();
        public_info.insert("key".to_string(), cbor::value::Value::Positive(4u64));

        verification_audit_anchor.to_anchor(public_info)
    }

    // Tests about JSON serialization and deserialization roundtrips

    #[test]
    fn test_verification_request_json_roundtrip() -> anyhow::Result<()> {
        let request_data = verification_request_data_fixture();

        let verification_request_anchor_transaction_hash = hashes::TransactionHash::new([0u8; 32]);

        let presentation_request = VerificationRequest {
            context: request_data.context,
            subject_claims: request_data.subject_claims,
            anchor_transaction_hash: verification_request_anchor_transaction_hash,
        };

        let json = serde_json::to_value(&presentation_request)
            .context("Failed verifiable presentation request to JSON value.")?;
        let roundtrip = serde_json::from_value(json)
            .context("Failed verifiable presentation request from JSON value.")?;
        assert_eq!(
            presentation_request, roundtrip,
            "Failed verifiable presentation request JSON roundtrip."
        );

        Ok(())
    }

    #[test]
    fn test_verification_request_anchor_json_roundtrip() -> anyhow::Result<()> {
        let verification_request_anchor = verification_request_data_fixture();

        let json = serde_json::to_value(&verification_request_anchor)
            .context("Failed verification request anchor to JSON value.")?;
        let roundtrip = serde_json::from_value(json)
            .context("Failed verification request anchor from JSON value.")?;
        assert_eq!(
            verification_request_anchor, roundtrip,
            "Failed verification request anchor JSON roundtrip."
        );

        Ok(())
    }

    #[test]
    fn test_verification_audit_anchor_json_roundtrip() -> anyhow::Result<()> {
        let verification_audit_anchor = verification_audit_record_fixture();

        let json = serde_json::to_value(&verification_audit_anchor)
            .context("Failed verification audit anchor to JSON value.")?;
        println!("{}", json);
        let roundtrip = serde_json::from_value(json)
            .context("Failed verification audit anchor from JSON value.")?;
        assert_eq!(
            verification_audit_anchor, roundtrip,
            "Failed verification audit anchor JSON roundtrip."
        );

        Ok(())
    }

    // Tests about the JSON interface (should align with the type representation in the webSDK/rustSDK)

    #[test]
    fn test_verification_request_data_json() -> anyhow::Result<()> {
        let expected_json = r#"
{
  "type": "ConcordiumVerificationRequestDataV1",
  "context": {
    "type": "ConcordiumUnfilledContextInformationV1",
    "given": [
      {
        "label": "Nonce",
        "context": "0000000000000000000000000000000000000000000000000000000000000000"
      },
      {
        "label": "ConnectionID",
        "context": "MyConnection"
      },
      {
        "label": "ContextString",
        "context": "MyDappContext"
      },
      {
        "label": "PaymentHash",
        "context": "0101010101010101010101010101010101010101010101010101010101010101"
      },
      {
        "label": "BlockHash",
        "context": "0202020202020202020202020202020202020202020202020202020202020202"
      },
      {
        "label": "ResourceID",
        "context": "MyRescourceId"
      }
    ],
    "requested": [
      "BlockHash",
      "ResourceID",
      "Nonce",
      "PaymentHash",
      "ConnectionID",
      "ContextString"
    ]
  },
  "subjectClaims": [
    {
      "type": "identity",
      "statements": [
        {
          "type": "AttributeInRange",
          "attributeTag": "registrationAuth",
          "lower": 80,
          "upper": 1237
        }
      ],
      "issuers": [
        "did:ccd:testnet:idp:3"
      ],
      "source": [
        "identityCredential"
      ]
    }
  ]
}
            "#;

        let actual_json =
            serde_json::to_string_pretty(&verification_request_data_fixture()).unwrap();
        println!("verification request data json:\n{}", actual_json);

        assert_eq!(
            remove_whitespace(&actual_json),
            remove_whitespace(expected_json),
            "verification request data"
        );

        Ok(())
    }

    #[test]
    fn test_verification_audit_record_json() -> anyhow::Result<()> {
        let expected_json = r#"
{
  "type": "ConcordiumVerificationAuditRecord",
  "version": 1,
  "request": {
    "type": "ConcordiumVerificationRequestV1",
    "context": {
      "type": "ConcordiumUnfilledContextInformationV1",
      "given": [
        {
          "label": "Nonce",
          "context": "0101010101010101010101010101010101010101010101010101010101010101"
        },
        {
          "label": "ConnectionID",
          "context": "MyConnection"
        },
        {
          "label": "ContextString",
          "context": "MyDappContext"
        },
        {
          "label": "PaymentHash",
          "context": "0202020202020202020202020202020202020202020202020202020202020202"
        },
        {
          "label": "BlockHash",
          "context": "0303030303030303030303030303030303030303030303030303030303030303"
        },
        {
          "label": "ResourceID",
          "context": "MyRescourceId"
        }
      ],
      "requested": [
        "BlockHash",
        "ResourceID",
        "Nonce",
        "PaymentHash",
        "ConnectionID",
        "ContextString"
      ]
    },
    "subjectClaims": [
      {
        "type": "identity",
        "statements": [
          {
            "type": "AttributeInRange",
            "attributeTag": "registrationAuth",
            "lower": 80,
            "upper": 1237
          }
        ],
        "issuers": [
          "did:ccd:testnet:idp:3"
        ],
        "source": [
          "identityCredential"
        ]
      }
    ],
    "transactionRef": "0202020202020202020202020202020202020202020202020202020202020202"
  },
  "id": "MyUUID",
  "presentation": {
    "type": [
      "VerifiablePresentation",
      "ConcordiumVerifiablePresentationV1"
    ],
    "presentationContext": {
      "type": "ConcordiumContextInformationV1",
      "given": [
        {
          "label": "Nonce",
          "context": "0101010101010101010101010101010101010101010101010101010101010101"
        },
        {
          "label": "ConnectionID",
          "context": "MyConnection"
        },
        {
          "label": "ContextString",
          "context": "MyDappContext"
        },
        {
          "label": "PaymentHash",
          "context": "0202020202020202020202020202020202020202020202020202020202020202"
        },
        {
          "label": "BlockHash",
          "context": "0303030303030303030303030303030303030303030303030303030303030303"
        },
        {
          "label": "ResourceID",
          "context": "MyRescourceId"
        }
      ],
      "requested": [
        {
          "label": "Nonce",
          "context": "0101010101010101010101010101010101010101010101010101010101010101"
        },
        {
          "label": "ConnectionID",
          "context": "MyConnection"
        },
        {
          "label": "ContextString",
          "context": "MyDappContext"
        },
        {
          "label": "PaymentHash",
          "context": "0202020202020202020202020202020202020202020202020202020202020202"
        },
        {
          "label": "BlockHash",
          "context": "0303030303030303030303030303030303030303030303030303030303030303"
        },
        {
          "label": "ResourceID",
          "context": "MyRescourceId"
        }
      ]
    },
    "verifiableCredential": [
      {
        "type": [
          "VerifiableCredential",
          "ConcordiumVerifiableCredentialV1",
          "ConcordiumAccountBasedCredential"
        ],
        "credentialSubject": {
          "id": "did:ccd:testnet:cred:856793e4ba5d058cea0b5c3a1c8affb272efcf53bbab77ee28d3e2270d5041d220c1e1a9c6c8619c84e40ebd70fb583e",
          "statement": [
            {
              "type": "AttributeInRange",
              "attributeTag": "dob",
              "lower": 80,
              "upper": 1237
            },
            {
              "type": "AttributeInSet",
              "attributeTag": "sex",
              "set": [
                "aa",
                "ff",
                "zz"
              ]
            },
            {
              "type": "AttributeNotInSet",
              "attributeTag": "lastName",
              "set": [
                "aa",
                "ff",
                "zz"
              ]
            },
            {
              "type": "AttributeInRange",
              "attributeTag": "countryOfResidence",
              "lower": {
                "type": "date-time",
                "timestamp": "2023-08-27T23:12:15Z"
              },
              "upper": {
                "type": "date-time",
                "timestamp": "2023-08-29T23:12:15Z"
              }
            },
            {
              "type": "RevealAttribute",
              "attributeTag": "nationality"
            }
          ]
        },
        "issuer": "did:ccd:testnet:idp:17",
        "proof": {
          "created": "2023-08-28T23:12:15Z",
          "proofValue": "000000000000000501b12365d42dbcdda54216b524d94eda74809018b8179d90c747829da5d24df4b2d835d7f77879cf52d5b1809564c5ec49990998db469e5c04553de3f787a3998d660204fe2dd1033a310bfc06ab8a9e5426ff90fdaf554ac11e96bbf18b1e1da898425e0f42bb5b91f650cffc83890c5c3634217e1ca6df0150d100aedc6c49b36b548e9e853f9180b3b994f2b9e6e302840ce0d443ca529eba7fb3b15cd10987be5a40a2e5cf825467588a00584b228bea646482954922ae2bffad62c65eebb71a4ca5367d4ac3e3b4cb0e56190e95f6af1c47d0b45991d39e58ee3a25c32de75c9d91cabd2cc5bc4325a4699b8a1c2e486059d472917ba1c5e4a2b66f77dbcf08a2aa21cbd0ec8f78061aa92cc1b126e06e1fc0da0d03c30e444721fbe07a1100000007ae9f2dffa4e4102b834e7930e7bb9476b00b8f0077e5fb48bc953f44571a9f9f8bcf46ea1cc3e93ca6e635d85ee5a63fa2a1c92e0bf7fba3e61a37f858f8fa52f40644f59e1fb65b6fb34eaaa75a907e85e2c8efd664a0c6a9d40cbe3e96fd7ab0ff06a4a1e66fd3950cf1af6c8a7d30197ae6aec4ecf463c368f3b587b5b65b93a6b77167e112e724a5fe6e7b3ce16b8402d736cb9b207e0e3833bb47d0e3ddc581790c9539ecd3190bdee690120c9b8e322e3fb2799ada40f5e7d9b66a8774aa662ab85c9e330410a19d0c1311c13cf59c798fa021d24afd85fabfe151802cbde37dafc0046920345961db062e5fb9b2fe0334debe1670ef88142a625e6acd1b7ded9f63b68d7b938b108dbf4cca60257bdf32fed399b2d0f11a10c59a4089937a28cbeefc28a93e533722d6060856baf26ccd9470a9c50229acc54753534888e1c8f8c612b5e6af0705dceeac85a5ac3d641b3033c5d3af066f33147256b86b1fffaaceea3bf9e4fd98f7a5371e4a882dd3c7cbe5d9b34e933d6ac224d7198cc4c8d3e5f0cef03fad810ca36499dc3a5e157d435843d60eb6a3fc3c3624d9fef8b5f2f2335af0a8ecca5cf71a9ffab6651d7c899d560264a6c9e361ee10a17dcb18522acdc0a19ab004f15ba1e23fa2aa3bb75f3767678d12c6dc35b2a04bb5239ce2cf35649a42525f42f91d6b80266af0fbd86645611332203ac555250fc29f6bb1b50932c7e48418bbadf57db4931789a0dd44e9b70d437af1ae686ede83e6965108a655caf34bd7b0b587eef0a29350020abae08bd2d979752316f749ab4686da684dcae5b571213c7bfb914cb70965e9b643862f71bab5d22b7dbf7d3f84636ba514ef2cf0c87ecf225e3bdc99e15368b3d814fb1e257ac1fc0b9114cbb8ed594ce50688c88d8ea9d0e97f55e89fbddd282e13d7303d3604e969bc0e699388c2f6fbb310aa82f18af896019d79f26f72fbe3a5dfc6fd30c34ac8d57d499e49664ecfa76094c6fba2372dba87a2b55dd9dc30877af0d6fdd2b2ea54be02b39554bf77b9ad30ef725df82bdb6c5456adf9ac3187ffbeaab1b4ce68782829850f10182deb13eaa94edd3640768224a178b8bac224d12711c7d3bec925db4da9bd1424db872757a1f2e10c9dac40483a69972504e5d69163a9f13c5dc8fc60a1634554a5009d948704f92e701eeb0a5b2cbfdcf62fd7b8cc0db65b2ba52dd1bbe2e46eddeff70f5fb3686917587b82a9cf1e1c8a7b6cf44dbe57bbf83d541bfbfccac677a377ef4e1a5ced1e7e5147bde759150f531780bcfc5658b099787d68277d3d41d992022be434194d8307d2a90a518705017affec5796354ff2432f57f525cf014bdcf0b9fd84b9501d3938259c433b4e6181e2630b56826c4a0c7d03cc0a8768ce7226703cf97ee83d6bc1c0c044a2e0d4439780d1c7351ea8ece10000000298ff27cb9f1c4afb38c535cee5dbde71599f727976298c540cdb7ff0b10a439f1599c9bf879e35746e2fd04dda05368d966efc49f07a5c48baaca5853de36dd2f0c7fab8106f1158f34ece1d0fd8576eb727d834cb0c380c150086e2222ba38283d8c26a9af828584cbd90801cc0c3e1855b9a26f81efd3931000b8a2109ac9cd5070b98963d700560fd6c6de1df8202ac21dfbdf141bdf58ee96d7a72cb2dfba962159a2c9d0fe1d312aca7a56ce97716d7d16e47b7c59e651ee8fe8dbbf56c3048a31df649d9da46f669b80d5cb31c3ee70c5e6a05de8be814833934befaef06757e390f83ce84b4fd84fb9d86eb30a897faa4718d7b5a12c086255a0a21cc038b69df7282cd3234e4423e85d15c09d49fc2005e869a4876fec01369c3b0ec0ae6f710797b4e5294a7fdf72c05341b6887da98066400436af27e739c140e3a481df2845cd78df942a2c0fb01429d5b04cd96b18c0b2bbf764b533a6f095edbea844cbc0d196b4e423c7fd409c1ceb6572812707c9048ec5a373c29e3cefbbd128e1ebe72b84be67ae22e3dfee5b47f57b289755b558624daeb22ce521c432fbf2cab96826ec670f18a194b151ec0f49c31237f35caae1296715571520e22caff2912531b1ee43d555dee29e7105161dfe86f133b3fb7c194e72c12b1eaac010160a3e8a44cad0b1c1ef89d492014997603a37b26e9461572edcf93a011d639550e0505ad8932c2a205c688d70d6414717c7a31868b5d01c37993085cf28d1c670000000295c326f59171824b2fc3e09816b73c6f75a03fb50f611559855d295e0a565ff6d2505f970464ca12e81031d286866dd5b73c285de994b592f8d8c2e64227bcc5ae2058339d11af025cfcb126c2b3c9a7839b87c8d218f93b0f30a0876076eb9598e1ec92a57f4ce785b1a05c01e8db34b4cefe8e518a859aa6d9530bbe72a033af7e87a95433de67b86f389e178b1aaaa53eddcdf1be990d96ba7e7f18ffa83d60385e1a1130dbf245e1b4bac2e8bceb2c1184380e6e0f7876157d7ae074d1fb013266272083b5420b3fc654141046e5bee9e3ffe50497f372d55b3f0aec05873c7409c8a1507c38f6c87b726e9355d5d326658e1e7e67b349ef1a65185ec51801b2a44460fcbf28d7ce0fce6c677113a88b88ec272d3cfac24d33afc47b6fa15259af84fa6543ef673cbd18a44d47420c8c53d7eaf9272dfa62fadd8d118c2055480b6494a67b0346c9fa0b2ba2cba9c0591224a2ed7b399ea35b89111a53059cb410c51ffb45d0aab4b642087698fcb67d55d33a711db3f84a125f970705b68c5ae5b8ea2394c891911d7f1032ec08ec8df792bcbcb1a953214317be0085b4b7b23a45d52a83f77cade01752c7ae6fe1d81bb5dc3b6a74e3d2f4130178263b9e633914559cf75d5902b5fc696198bff1d25812b05ade020d0aadcae022336b3c49639dd8dd90381bb59828ca9a82d87610d1e01b4ee4827f30d11ac72fa911f4439ca4fbfe164dc370e5c96dcc329bbf9972d71e811d17f5dd2ffb760ac0e31400000007b9e19ad95babc1c31bf657ae20a5420cf05bbf024ae2ffe13b363d5404c5a0ef360c54d49e8725210a5bba290d29cb58a2607e5134fdb367631e10d8e159396e39bbc09bd7084038f6b5cebd5386da5cd18cfe3ce9dbf75b51f4d7de00e00c5993a3b4d05fb3f4edb2a8d05cece2da96d7d87081c1610eb949caed95520479c662d623ad1464fee46bc3486521d44427ad8d76db0cc6ab51cb69d1dfd59c1938b68b80a8813c9dad15f9466941e377836693dfdcfc96e12a296699ef77ab274293a917b64e48f413ee2908b574ad8875951ce40dceadaf104145a2a937bce6707a962355a61efbf9379a1da606f98915a21a9255eaf105b04651d789fc90ddab8a402d11fd8e5befece4956d1d0c9c47987c7d282cb045c053fc860e8c07365b9937aae7fa435190992a02a24e388bd0b0836775d0e01c7faba3e92c5d3e8975fcad16cce9e9b01f378a572ab4039e0b8582d4d3a47c3b3fb587483cd1a760e628d0f3d63ac9e8b10cefa8b94d02cade0ab47005ad368f4f9e5b766a5c353a6eb1a7fd5bed46fbd1554c4ec47d8b6d3b38dcc66db969c646a34928eeb40147adc94878a1b237fcbe21f779e723e8a4f6a6cec0cb57205789e8d781bf465a833608b5181ad27d420e0e1f7383c0222df32259ace41dc092dfc745bbfc4bd371cd99e5a1c73baeb8ad15c34e060af529a8babad63c3a131ca089053f498170afb30b26e0f2794b0d1f417d870af7daf37694430db13f00b7af5101723d656d334c72b5e0bbe13478722e954935e6701ecf3cc725d61e42edbb896b6d4dff5b51f48e194337fb086908d50edcb61a295dcf57f54b6b41d5a760f5ff8992a6e45acfec08157dc3640fa1878cdb5ce41cb27ab9096beb3ded0b7cd57c1c4a850abc08ac822a3be26b4deb5a3cd11914ae5ac2c29430fe91be97fea012981dbb389da64d4a794017f91fb40e3188bd7190025a5b39c323a90f5a8496d5f64e200093072f1379728f1f0e741b51db5e4967d1e5437ca1d531ed742fe9ad2708ba06b3f80000097465737476616c75656d9f6e451166c885818931efbf878b5d041b211441fa707013ebe73e41ca25da68cebf07b67ef99e5fef798d5bdff3378d766b8116e710384d1530280b79e945",
          "type": "ConcordiumZKProofV4"
        }
      }
    ],
    "proof": {
      "created": "2023-08-28T23:12:15Z",
      "proofValue": "",
      "type": "ConcordiumWeakLinkingProofV1"
    }
  }
}
            "#;

        let actual_json =
            serde_json::to_string_pretty(&verification_audit_record_fixture()).unwrap();
        println!("audit record json:\n{}", actual_json);

        assert_eq!(
            remove_whitespace(&actual_json),
            remove_whitespace(expected_json),
            "audit record json"
        );

        Ok(())
    }

    // Tests about serialization and deserialization roundtrips

    #[test]
    fn test_verification_request_anchor_serialization_deserialization_roundtrip() {
        let request_data = verification_request_data_fixture();

        let deserialized = serialize_deserialize(&request_data).expect("Deserialization succeeds.");

        assert_eq!(
            request_data, deserialized,
            "Failed verification request anchor serialization deserialization roundtrip."
        );
    }

    #[test]
    fn test_verification_audit_anchor_serialization_deserialization_roundtrip() {
        let verification_audit_anchor = verification_audit_record_fixture();

        let deserialized =
            serialize_deserialize(&verification_audit_anchor).expect("Deserialization succeeds.");
        assert_eq!(
            verification_audit_anchor, deserialized,
            "Failed verification audit anchor serialization deserialization roundtrip."
        );
    }

    // Tests about cbor serialization and deserialization roundtrips for the anchors

    #[test]
    fn test_verification_request_anchor_cbor_roundtrip() {
        let verification_request_anchor = verification_request_anchor_fixture();

        let cbor = cbor::cbor_encode(&verification_request_anchor).unwrap();

        assert_eq!(hex::encode(&cbor), "a4646861736858205e7d3a608cb004f22633c958b2a203c516d0d4b3ad47f310d5fc29e606138a21647479706566434344565241667075626c6963a1636b6579046776657273696f6e01");

        let decoded: VerificationRequestAnchor = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(decoded, verification_request_anchor);
    }

    #[test]
    fn test_verification_audit_anchor_cbor_roundtrip() {
        let verification_audit_anchor_on_chain = verification_audit_anchor_fixture();

        let cbor = cbor::cbor_encode(&verification_audit_anchor_on_chain).unwrap();
        assert_eq!(hex::encode(&cbor), "a46468617368582037fc286317b8c68dfbeee7d2150cb4958694a979070ec36832c4f5032ffbab2b647479706566434344564141667075626c6963a1636b6579046776657273696f6e01");
        let decoded: VerificationAuditAnchor = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(decoded, verification_audit_anchor_on_chain);
    }

    // Tests about computing anchor hashes

    #[test]
    fn test_compute_the_correct_verification_request_anchor() -> anyhow::Result<()> {
        let verification_request_anchor_hash = verification_request_anchor_fixture().hash;

        let expected_verification_request_anchor_hash = Hash::new(
            <[u8; 32]>::from_hex(
                "5e7d3a608cb004f22633c958b2a203c516d0d4b3ad47f310d5fc29e606138a21",
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
    fn test_compute_the_correct_verification_audit_anchor() -> anyhow::Result<()> {
        let verification_audit_anchor_hash = verification_audit_anchor_fixture().hash;
        let expected_verification_audit_anchor_hash = Hash::new(
            <[u8; 32]>::from_hex(
                "37fc286317b8c68dfbeee7d2150cb4958694a979070ec36832c4f5032ffbab2b",
            )
            .expect("Invalid hex"),
        );

        println!("hash: {}", verification_audit_anchor_hash);
        assert_eq!(
            verification_audit_anchor_hash, expected_verification_audit_anchor_hash,
            "Failed verification audit anchor hash check."
        );

        Ok(())
    }
}
