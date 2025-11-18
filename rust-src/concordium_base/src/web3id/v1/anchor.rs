use crate::common::{
    cbor, Buffer, Deserial, Get, ParseResult, Put, ReadBytesExt, Serial, Serialize,
};
use crate::id::id_proof_types::{
    AttributeInRangeStatement, AttributeInSetStatement, AttributeNotInSetStatement,
    RevealAttributeStatement,
};
use crate::id::{
    constants::{ArCurve, IpPairing},
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
        public_info: Option<HashMap<String, cbor::value::Value>>,
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
    pub public: Option<HashMap<String, cbor::value::Value>>,
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

    /// Add a subject claims request to the verification request data.
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
        public_info: Option<HashMap<String, cbor::value::Value>>,
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
    pub public: Option<HashMap<String, cbor::value::Value>>,
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
    pub statements: Vec<RequestedStatement<AttributeTag>>,
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
    pub fn add_statement(mut self, statement: RequestedStatement<AttributeTag>) -> Self {
        if !self.statements.contains(&statement) {
            self.statements.push(statement);
        }
        self
    }

    /// Add statements to the given identity statement request.
    pub fn add_statements(
        mut self,
        statements: impl IntoIterator<Item = RequestedStatement<AttributeTag>>,
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

/// Statement that is requested to be proven.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, Eq)]
#[serde(tag = "type")]
pub enum RequestedStatement<TagType: Serialize> {
    /// The atomic statement stating that an attribute should be revealed.
    RevealAttribute(RevealAttributeStatement<TagType>),
    /// The atomic statement stating that an attribute is in a range.
    AttributeInRange(AttributeInRangeStatement<ArCurve, TagType, Web3IdAttribute>),
    /// The atomic statement stating that an attribute is in a set.
    AttributeInSet(AttributeInSetStatement<ArCurve, TagType, Web3IdAttribute>),
    /// The atomic statement stating that an attribute is not in a set.
    AttributeNotInSet(AttributeNotInSetStatement<ArCurve, TagType, Web3IdAttribute>),
}

impl<TagType: Serialize> Serial for RequestedStatement<TagType> {
    fn serial<B: Buffer>(&self, out: &mut B) {
        match self {
            Self::RevealAttribute(stmt) => {
                0u8.serial(out);
                out.put(stmt);
            }
            Self::AttributeInRange(stmt) => {
                1u8.serial(out);
                out.put(stmt);
            }
            Self::AttributeInSet(stmt) => {
                2u8.serial(out);
                out.put(stmt);
            }
            Self::AttributeNotInSet(stmt) => {
                3u8.serial(out);
                out.put(stmt);
            }
        }
    }
}

impl<TagType: Serialize> Deserial for RequestedStatement<TagType> {
    fn deserial<R: byteorder::ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        Ok(match u8::deserial(source)? {
            0u8 => {
                let stmt = source.get()?;
                Self::RevealAttribute(stmt)
            }
            1u8 => {
                let stmt = source.get()?;
                Self::AttributeInRange(stmt)
            }
            2u8 => {
                let stmt = source.get()?;
                Self::AttributeInSet(stmt)
            }
            3u8 => {
                let stmt = source.get()?;
                Self::AttributeNotInSet(stmt)
            }
            n => anyhow::bail!("Unrecognized CredentialType tag {n}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashes::Hash;
    use crate::id::constants::AttributeKind;
    use crate::id::id_proof_types::AttributeValueStatement;
    use crate::id::types::GlobalContext;
    use crate::web3id::did::Network;
    use crate::web3id::v1::{
        fixtures, AtomicStatementV1, ContextInformation, ContextProperty,
        IdentityBasedSubjectClaims, RequestV1, SubjectClaims,
    };
    use crate::{
        common::serialize_deserialize,
        id::{constants::ArCurve, id_proof_types::AttributeInRangeStatement},
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

        let statements = vec![
            RequestedStatement::AttributeInRange(AttributeInRangeStatement {
                attribute_tag: AttributeTag(3).to_string().parse().unwrap(),
                lower: Web3IdAttribute::Numeric(80),
                upper: Web3IdAttribute::Numeric(1237),
                _phantom: PhantomData,
            }),
            RequestedStatement::AttributeInSet(AttributeInSetStatement {
                attribute_tag: AttributeTag(2).to_string().parse().unwrap(),
                set: [
                    Web3IdAttribute::String(AttributeKind::try_new("ff".into()).unwrap()),
                    Web3IdAttribute::String(AttributeKind::try_new("aa".into()).unwrap()),
                    Web3IdAttribute::String(AttributeKind::try_new("zz".into()).unwrap()),
                ]
                .into_iter()
                .collect(),
                _phantom: PhantomData,
            }),
            RequestedStatement::AttributeNotInSet(AttributeNotInSetStatement {
                attribute_tag: AttributeTag(1).to_string().parse().unwrap(),
                set: [
                    Web3IdAttribute::String(AttributeKind::try_new("ff".into()).unwrap()),
                    Web3IdAttribute::String(AttributeKind::try_new("aa".into()).unwrap()),
                    Web3IdAttribute::String(AttributeKind::try_new("zz".into()).unwrap()),
                ]
                .into_iter()
                .collect(),
                _phantom: PhantomData,
            }),
            RequestedStatement::AttributeInRange(AttributeInRangeStatement {
                attribute_tag: AttributeTag(4).to_string().parse().unwrap(),
                lower: Web3IdAttribute::try_from(
                    chrono::DateTime::parse_from_rfc3339("2023-08-27T23:12:15Z")
                        .unwrap()
                        .to_utc(),
                )
                .unwrap(),
                upper: Web3IdAttribute::try_from(
                    chrono::DateTime::parse_from_rfc3339("2023-08-29T23:12:15Z")
                        .unwrap()
                        .to_utc(),
                )
                .unwrap(),
                _phantom: PhantomData,
            }),
            RequestedStatement::RevealAttribute(RevealAttributeStatement {
                attribute_tag: AttributeTag(5).to_string().parse().unwrap(),
            }),
        ];

        VerificationRequestData::new(context).add_statement_request(
            RequestedIdentitySubjectClaims::default()
                .add_issuer(IdentityProviderMethod::new(3u32, did::Network::Testnet))
                .add_source(CredentialType::IdentityCredential)
                .add_statements(statements),
        )
    }

    fn verification_request_anchor_fixture() -> VerificationRequestAnchor {
        let request_data = verification_request_data_fixture();

        let mut public_info = HashMap::new();
        public_info.insert("key".to_string(), cbor::value::Value::Positive(4u64));

        request_data.to_anchor(Some(public_info))
    }

    fn verification_audit_record_fixture() -> VerificationAuditRecord {
        let request_data = verification_request_data_fixture();

        let verification_request = VerificationRequest {
            context: request_data.context,
            subject_claims: request_data.subject_claims,
            anchor_transaction_hash: hashes::TransactionHash::new([2u8; 32]),
        };

        let challenge = ContextInformation {
            given: vec![ContextProperty {
                label: "prop1".to_string(),
                context: "val1".to_string(),
            }],
            requested: vec![ContextProperty {
                label: "prop2".to_string(),
                context: "val2".to_string(),
            }],
        };

        let global_context = GlobalContext::generate("Test".into());

        let id_cred_fixture = fixtures::identity_credentials_fixture(
            [
                (3.into(), Web3IdAttribute::Numeric(137)),
                (
                    1.into(),
                    Web3IdAttribute::String(AttributeKind::try_new("xkcd".into()).unwrap()),
                ),
                (
                    2.into(),
                    Web3IdAttribute::String(AttributeKind::try_new("aa".into()).unwrap()),
                ),
                (
                    5.into(),
                    Web3IdAttribute::String(AttributeKind::try_new("testvalue".into()).unwrap()),
                ),
                (
                    6.into(),
                    Web3IdAttribute::String(AttributeKind::try_new("bb".into()).unwrap()),
                ),
                (
                    AttributeTag(4).to_string().parse().unwrap(),
                    Web3IdAttribute::try_from(
                        chrono::DateTime::parse_from_rfc3339("2023-08-28T23:12:15Z")
                            .unwrap()
                            .to_utc(),
                    )
                    .unwrap(),
                ),
            ]
            .into_iter()
            .collect(),
            &global_context,
        );

        let credential_statements = vec![SubjectClaims::Identity(IdentityBasedSubjectClaims {
            network: Network::Testnet,
            issuer: id_cred_fixture.issuer,
            statements: vec![
                AtomicStatementV1::AttributeInRange(AttributeInRangeStatement {
                    attribute_tag: 3.into(),
                    lower: Web3IdAttribute::Numeric(80),
                    upper: Web3IdAttribute::Numeric(1237),
                    _phantom: PhantomData,
                }),
                AtomicStatementV1::AttributeInSet(AttributeInSetStatement {
                    attribute_tag: 2.into(),
                    set: [
                        Web3IdAttribute::String(AttributeKind::try_new("ff".into()).unwrap()),
                        Web3IdAttribute::String(AttributeKind::try_new("aa".into()).unwrap()),
                        Web3IdAttribute::String(AttributeKind::try_new("zz".into()).unwrap()),
                    ]
                    .into_iter()
                    .collect(),
                    _phantom: PhantomData,
                }),
                AtomicStatementV1::AttributeNotInSet(AttributeNotInSetStatement {
                    attribute_tag: 1.into(),
                    set: [
                        Web3IdAttribute::String(AttributeKind::try_new("ff".into()).unwrap()),
                        Web3IdAttribute::String(AttributeKind::try_new("aa".into()).unwrap()),
                        Web3IdAttribute::String(AttributeKind::try_new("zz".into()).unwrap()),
                    ]
                    .into_iter()
                    .collect(),
                    _phantom: PhantomData,
                }),
                AtomicStatementV1::AttributeInRange(AttributeInRangeStatement {
                    attribute_tag: AttributeTag(4).to_string().parse().unwrap(),
                    lower: Web3IdAttribute::try_from(
                        chrono::DateTime::parse_from_rfc3339("2023-08-27T23:12:15Z")
                            .unwrap()
                            .to_utc(),
                    )
                    .unwrap(),
                    upper: Web3IdAttribute::try_from(
                        chrono::DateTime::parse_from_rfc3339("2023-08-29T23:12:15Z")
                            .unwrap()
                            .to_utc(),
                    )
                    .unwrap(),
                    _phantom: PhantomData,
                }),
                AtomicStatementV1::AttributeValue(AttributeValueStatement {
                    attribute_tag: AttributeTag(5).to_string().parse().unwrap(),
                    attribute_value: Web3IdAttribute::String(
                        AttributeKind::try_new("testvalue".into()).unwrap(),
                    ),
                    _phantom: Default::default(),
                }),
            ],
        })];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            challenge,
            subject_claims: credential_statements,
        };

        // the easiest way to construct a presentation, is just to run the prover on a request
        let now = chrono::DateTime::parse_from_rfc3339("2023-08-28T23:12:15Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let presentation = request
            .clone()
            .prove_with_rng(
                &global_context,
                [id_cred_fixture.private_inputs()].into_iter(),
                &mut fixtures::seed0(),
                now,
            )
            .expect("prove");

        let id = "MyUUID".to_string();

        VerificationAuditRecord::new(verification_request, id, presentation)
    }

    fn verification_audit_anchor_fixture() -> VerificationAuditAnchor {
        let verification_audit_anchor: VerificationAuditRecord =
            verification_audit_record_fixture();

        let mut public_info = HashMap::new();
        public_info.insert("key".to_string(), cbor::value::Value::Positive(4u64));

        verification_audit_anchor.to_anchor(Some(public_info))
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
          "label": "prop1",
          "context": "val1"
        }
      ],
      "requested": [
        {
          "label": "prop2",
          "context": "val2"
        }
      ]
    },
    "verifiableCredential": [
      {
        "type": [
          "VerifiableCredential",
          "ConcordiumVerifiableCredentialV1",
          "ConcordiumIdBasedCredential"
        ],
        "credentialSubject": {
          "id": "did:ccd:testnet:encidcred:04000500000001a45064854acb7969f49e221ca4e57aaf5d3a7af2a012e667d9f123a96e7fab6f3c0458e59149062a37615fbaff4d412f959d6060a0b98ae6c2d1f08ab3e173f02ceb959c69c30eb55017c74af4179470adb3b3b7b5e382bc8fd3dc173d7bc6b400000002acb968eac3f7f940d80e2cc4dee7ef9256cb1d19fd61a8c2b6d8bf61cdbfb105975b4132cd73f9679567ad8501e698c280e2dc5cac96c5e428adcc4cd9de19b7704df058a5c938c894bf03a94298fc5f741930c575f8f0dd1af64052dcaf4f00000000038b3287ab16051907adab6558c887faae7d41384462d58b569b45ff4549c23325e763ebf98bb7b68090c9c23d11ae057787793917a120aaf73f3caeec5adfc74d43f7ab4d920d89940a8e1cf5e73df89ff49cf95ac38dbc127587259fcdd8baec00000004b5754b446925b3861025a250ab232c5a53da735d5cfb13250db74b37b28ef522242228ab0a3735825be48a37e18bbf7c962776f4a4698f6e30c4ed4d4aca5583296fd05ca86234abe88d347b506073c32d8b87b88f03e9e888aa8a6d76050b2200000005b0e9cd5f084c79d1d7beb52f58182962aebe2fad91740537faa2d409d31dec9af504b7ac8dc15eae6738698d2dc10410930a5f6bc26b8b3b65c82748119af60f17f1e114c62afa62f7783b20a455cd4747d6cda058f381e40185bb9e6618f4e4",
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
              "type": "AttributeValue",
              "attributeTag": "nationality",
              "attributeValue": "testvalue"
            }
          ]
        },
        "validFrom": "2020-05-01T00:00:00Z",
        "validUntil": "2022-05-31T23:59:59Z",
        "issuer": "did:ccd:testnet:idp:0",
        "proof": {
          "created": "2023-08-28T23:12:15Z",
          "proofValue": "0000000000000006010098ad4f48bcd0cf5440853e520858603f16058ee0fc1afdc3efe98abe98771e23c000d19119c28d704a5916929f66f2a30200abb05a0ff79b3b06f912f0ec642268d3a1ad1cdf4f050ab7d55c795aa1ab771f4be29f29134e0d7709566f9b2468805f03009158599821c271588f24e92db7ca30197ec5b0c901efaadd34cca707e56b9aab1a7f14e329816e2acf4d07a7edf1bd6b0400af07a1ba7a22bcb1602114921a48fa966a821354cd0dd63a87ce018caccc50b56f2c9f55a062cdc423657aa5cec8a4c9050100097465737476616c75650602aef4be258f8baca0ee44affd36bc9ca6299cc811ac6cb77d10792ff546153d6a84c0c0e030b131ed29111911794174859966f6ba8cafaf228cb921351c2cbc84358c0fa946ca862f8e30d920e46397bf96b56f50b66ae9c93953dc24de2904640000000000000004a547c8619f3ff2670efbefb21281e459b7cc9766c4f377f78e9f97e2c50569a8dcb155f2a502e936d2cb6ef1a73e92af9916e6353b7127d55bb525cb18074b5ec130463e03a4eda583b05c2d63db40a08ab8bf05f930ec234cc2f788d5f5bfbeab3e4881918ce964ffd55483219edd435ac865286bfd313cd834aabfa8061d2ae173cbe4b59ab2bda78faa4c2c937afba80d7fba0822579ac0ef6915f4820f968a74f00ff5ab74e90b0a7bcb2b92093a5e94a54aea1d48ffd1e5bb3fb48069bce0d38776200db38b2aa170f8b27c74ea497c638ec1b8462c490544c1ebe22a5e00000005000000012404b1242ad971ff6e57bfecd2e3068c0ed7a4be33c0558b042de299df63b9145b8d3ddb4ecbba76d96ff8288092d908ab184c8411753dcd5dc9c6d8897a15313597cc5db38f68c4c935053142d3c2da4eb167cdee40e5e4c2878d53342ded4c0000000246959ce33bb25348f64d0e585567b52253b24ce6229bd83b3fae46c03af515c83a652cd7e8fa07c78db0b70a1b7c35af6ee9f0d83521acf7569d285684ff7fc56f22277da5ab40b30a75cb1bcc60cb7a5762919a415740cc09ba27c5bb9fdaf7000000031ed1953514eda42ba220a54d745ec4b454f1f380716279ff43f0bca3cb111c732d09e8eb6edc8c23d8095a14006684127c48353d55c02d7a69d3b6f5451c0d853c6c09e1a4d07097f16ca2a3324081a7301d1810a7844d331ce3f6012eff6700000000040dd23dd94272e26b45418aea3d3cf75690cf88e17f7eb881ff95fe1f1ef61fd63778bb771eea088f2717e964ae8d3ca1b9d7814a57c0c0482b9a65103f616f9b6a4e943c333d4a6cd894f4802e57db6e9a5270c42f39ae770f4472eccea797da000000052ca1395e3dedb1e0842cd4481627aa55b2a592d64ca7f5bf6845baa3e22647d73ef788e3576f6467206a7c57b1a6b63e9ed774aad4ecb7eaa8fa6b440a7a76a665733b664b5ab5038897f85ab2cbcae9a5a58b6e1e0a442dae026c2b74174b4658e84db7c2c90b21acf4b39f23b83db7f98baf1c6c5153c0123932d329d73eee0000000c003349aa2906906b01ab75f6b6897787dcfc7ccf96212d74d02558468c8b5856405cff39ee6e21fd7db4a2b6b02ab8a6b770c6f2604b2b8db00b38706fb31efb3a025993bed7d839a22f09f5ddafa524032766f3d175cceb640c9a58a9308b3d7a980101010262c5c9fc27e61854fa91c43236139ba5d944e9e628cd1b57b9c045fa114c490000655c0c404889511e939c8c0bee6e4f8199363ca505203e3c4bc5fe45cb5664db6b82bf5f16c7aa92ca5988914f5db5202e23be8939f5225dc0aa2f3386f57cfe0044835f8e5a723bde4dad0488037806e4e094abac57d201a0d1c825023027c1aa1d057b2f767acce630ef8cffa0806f5c0a6a71b1bc3e4c4f011b267830644eb70054164b289d57391c9c6dc767624d83a6384af2ab164fc80a41a6c1fd88dc6dba69c64fa9892188c32340ca6807e9b382759453c52d4ddb7ea65bb1e76be70eab003845506b51d820542c77bc063d112d53ae60687e00b6d7d8b845ff69443167795062cbeb5af4316238d72efcf11237689c4fa7c78d31033f5f26baa14640aec901023f799320ea06418335530b3370f2a3ad555bc335f847e167a177ed5e7320384d000000000000000502803596b4ba5ea05b1fea2b78e292f935d621453cffcd207e10f3072b2813ca3e963cebf05b19cd82da4bd5aad1dcc7fda1492d7ffc8f532bc4b37e9bf4753b7ae6b8f08e05a851052fc6ac7617ce68293678747d11f9a508bab6f7a60edde9c4a27fecaacee7cac6eb0072b08de2040391f5aff1d39c1eca45e9e1ceef6a680dfdccb7c8ac5cff24ce02454dc58ca329b1413f5c39f6a27d2341d7d30041f5b52e38fa03b8888556cd7a2fd6a8012a233d7ed79910a46e4090e6e6bfffea9f0e0ade8a970e7b6480833d376652ae0c9777209a785c5a254fad593a7975d4ddeb5dd25dd7d83d97bdb2ce1cc891220eb3a4bed2913c5be128668a5a88973ef7a314fb5a6df50796cef77dec15ba05b11eb627ccc3db214a61a4017bc3120f09f8000000078a266d8f2078084649b2ed641128818654f98dc78097cf82fb9ce0c6991b18539fc1fcd9dfed877dd2deecf666001ad7b7423143d3fc06e26ceb0caa7fc4bfb01e93e4f9a526ea814ac0e62ea52c5c53822b0dd82eba58a098ab4f453b17fde6820cc74e023722080be7eaa211162d5b83c54a149d0e533efef9487747d1413d918ef00eb7fe7ace6a56b8ae115ee2f3b37c6638b3a0432be164f4a470a4242ca12f166a59d153f703cbb2642c303d2956292419c97b3f9ae170b24182789692b759e754eeb963745d43f97392774f02b6751fb299b4dfff4a56de20f26fa97da30dd49f48f282e177450959047edb1a8e44cfc98d5b2f5961aef7ba75aa7884977cb3fa85d994e532b9a1a8e9c858f7c5c2d6fb386f1d33d796006c868c6faea2d60fbb0d81cf2198f996553684c7b18d7d1bed0f264aedc6a7fcdf7f1650f39c049bdf5123299c02249c947826faa1826a28e100a24f229775f61490a8829edeea2ea86649e258875d4be63e98bd45143cb9681a1b2a3892b61f68c2b58cd793aa738350605769568745244a7a9c7d0514525745a2850f05eecfa3dd378b90b59678564617db5f7549bff21e5fa72f8229e28245371a7339831a004d8e2a2ebd935b1c7747514458f6bd6620f60ae168c5f27ae8cbf6fc43b2d4201e0ead6992978537653ffdb3b05b32aa8234a3ddf4e3cc2ea898e95b8b1be35976d65cd7f44509cd2ef2717e8fc362bedee81c0fa87f0cfaead1202669041d5f1f7d2ed362c7d1b6f1664081833912f0ea2965a332482e08fa46e1de20b0ce239a8797ddb19144d980add3e9e1fe8109868a83472cd5a495cf9674b6ec0a0a5ef5f8cb6991c40c6e96f625389cb56de87eca9526b6efd349f0bd44f1c232337c9176efa03e5ca6b78a80064793ea605a23d6e7d8ad865360d2e29e18647accbac4c5ae984b649fb9e5062f5a16f58324782bab8d4008f5eb944137a43bb031072d9127fa382cbb5eb07c7143f70e405edc38fd0d6bea2fba80388bf8a5aa0cf5e3ad9cec039035240c33b7dec4981aa53e914f67ac932328b31f3fc4d0aac1c19a4da4dab1b525a63008d0e40b86076a1b7e9f0f219955c76798ae8d5131eee35e9900c5cdc8b58badd7022044521d7ad239a91bb2ae1a02fc61472f7d3629d14070641a1eae899e6e379b568caab0141ab86ad93488e61340d917ae4f2871782b64bd070e7dc49c57ed667b35d3f84db8fc09847fb3693e84649dd1c57c317340cac5c6ef962b44e37e9bb84fc222677f00d1ec332e25e81531a84c524e23800e4ef69431345966a6ecf5aec3ce00979684c2861be62231ab74b97953a8197a39251d157a1304a673724ef8687b27beaa474a7056543dfe5cb70502ffc62af63e6ad983b75f4be55185c2b5bfafc698219dfb5079fbed6f7a21f480bae1111ad333f72f8f00000002843454765b3b8b53bb33880bad2ec21d3704ea9c04ec2a0ee82219519349767c74b93c03f3d6b35a7deba79a16051427930281f7b6e4477be5aee7cf3e365bacfa95c28a10afcf8627bae2eb4091d7270f05c56d39517bfc9fbe8c291bea271ba8490429e3a7dc4c30758f8a4c1481ae6e1b5e54187bc0476797d9a9ad2dc2035c58ba233a1faaa72f3c2503000eab59b4e01708ac8f549e4098cb764510681ddc21d86976771ace658329dacfc3232f921f7630948ae70af7c9093a42c596cb6710353288322c0a66f3e62935d8284ff9894a86fae2ee1ba619b96547e0056a192121dc406ecea4bd342d300124bd20d415606fc3c8a37fa0056cb3b4f64f9a0487cbd29bfc97194ed8868ed4e458c7b2bf8ab6f04efee532502cf588c4f26b9b2830baa635c56857be5fd6803fd35d508881bd7cf3b5872ff84640384e2576bd93d4d86fdafcba2df3f29036491573031ede2ddb09dd092ad890a68f07876aeea856a0eb127ca4c08896db9bdc0211918711eddb3175615dec61a6b00ac88ab5ece1be74a55d69d3b2d94815c542fc9da317b86f78570d167c356b0032e10cde818eeec642cc5e4a85aac3dc4ff60d6d747059218c3f3d0c918b5fdb5e0e7559404f25bd8f7ca73432e44261f4fe0c1e1a7bd944e21771168a80ca5529fb6d195bd1a150c3e8c6e8677102aba4b3bb0831c4c645bd6b0f7ed3db492b204e348738fa7a61a2f959ccb7747e3ae7471eca3f8fc2c66bf734b15f700acb82ed23c400000002a04cae736db5790f72295d165d68e0d9bda882cd9e46a4c724b4aec31b98ef396064f56d9e4884cd84aa415de23ca479b89e0735074fc47e66fb75f55308b2bf5ccdb176784ddb550f769586c9a9c154671b6f347a1f4419b1ebfe96e59142e68233bcff4b5be7957cc0bb8c436fd8617f1591c73687194346e8dce9fad3cb3decd80f4e742309707fc5a8927518611099e471bae562f9fe68af039631e6f5177fb5f7faae75f2c426ee6817b6f03a1fb104aea55f29069e3ae442f24f389e7f10399e22ff0c8438bd8475dd309b90cbeae55ef9724bd22ef44553c07eaecde90901fdd15084ee4e3f9b5b6cdacc1042e3277ba5127cdca7c66061b9503287be02b387e119ec10c4a8963ee52710d75c21710881bae7fb5a8595fd43a9156419f8080891e50139bd4af14f1ba25ebe0152b5e83d115be493372e147742d8bfe3a8269e8ecd27ec055a11055d5405192cda8c8db528f06b120fc2e3f47089897411b3cc9ed940ae6645bbc674a01a9babd2c8ed3909640ae91ef01a3039103e818c70ee3be85aa3f3804adca265c3fd97cd8d94f4f16aeaac2f6bbd06c218a421dbc1176d53c8192bca54a39ec1a4ade163b9b0c4f60b07980b7373a7e61a64dd7e28c3882ee5511a8bd20186e63bdb37713478816106bc23241851486d10ac03bb45c9df3032ffb14ce3e0d6870e6c9c8024dfebe9396a56aa408d73c719ee34052dcb8f90f3f327891ea1e6e67096e0cb22407f2d772cab457af6810288f6a867000000079348680adeaa4311e21fc4f31c2f50ffb0e427bd011455f0b3151b36b3f52c94ddf8d9079a9b485745bf99c6e5220a3ca6c115c208bc42493413fe641bb8326d37c1ba622785d04a8f7e104f591c0fafedb770c1363e67aa0d130fc434c8bf7f8ecdf1effd86e1f53c80ae9564e67ad747c84fb31c129d551ee311fbdf30c46a9cc5e7b9b8997bd91aad8de5589ffabf8a776bdbe60b2e463b90041b2247db219e6b4a5bf2ffa23c5af0bdbdedcdc8c080040061280a8394b27cb253951f8464b10f257f944db3d1545dad0cccd866d7da659256a0f104580190aad200cbb614ebf17552e8dd851b769fd19b49b0fa34b9e6a679e83101bc2f5b8a1d102aed0544d12d78bdb9a39e455da446d102d9ad21096ea853fe444923dc57c31d11ce2b8a5d882e831edc6cd2e9ad229a0c34263131854d77fdd15bd11d9820d617bd5ccacbc7c9407149fd92b46dab47e60afeb09001f49d837d5f09c0ac9da6697a5224d2808296855826429fe519a859a17158c21d38f7cf9c222602c320a2b5931a840237bc5674e3dfe9a217425a0660b349a9524c529a7b978f81488b45b9e93f7b8436e9c7d9ff19d85c2214a4fdcaab9261cd2add29201c3b9d6ce4ce657219400ae109ede3507f5057aeb85849cbb8f55593d43c18737c27b86fb33c1617fba13965a846407748fd33ae7352bb119ab71b8e09487842ce37569c13f212ad925041188a19a0bf71468ae290c5d5561bafd547949c4e5da973992729a849bf5fa4fd04eb55b3a8db7cccdc3a0ebdaa3cfdc7a7396ecca820682b40d078bdef188b609045d76fccafb6f8def22071b9eb1afed2082feeedd741b7cb89d073bbc63f773ae935249a3c50566ad71b42de17b8c7f24b153785c863be33115391516003c1d9989b78130bd7e74c0f9dcce55da0201a1eaacdb37549d84da95ee20ca70ae13e95a97a7b18b67e75b8ec1b41ad55049ada043a39a8f8282878c92ca3ba266d23195041e1198f125d0695f843b597aef1edace684e90b09abebaa85f6a101",
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

        assert_eq!(hex::encode(&cbor), "a464686173685820b4fbcf892fef3627717a333577921f76e41980d9ea4426f83aa98e221b39cf98647479706566434344565241667075626c6963a1636b6579046776657273696f6e01");

        let decoded: VerificationRequestAnchor = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(decoded, verification_request_anchor);
    }

    #[test]
    fn test_verification_audit_anchor_cbor_roundtrip() {
        let verification_audit_anchor_on_chain = verification_audit_anchor_fixture();

        let cbor = cbor::cbor_encode(&verification_audit_anchor_on_chain).unwrap();
        assert_eq!(hex::encode(&cbor), "a464686173685820ca347e796ce11a4617dc160f0c1ec5bc479d9de624e28ecb8829087b2e7f1b71647479706566434344564141667075626c6963a1636b6579046776657273696f6e01");
        let decoded: VerificationAuditAnchor = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(decoded, verification_audit_anchor_on_chain);
    }

    // Tests about computing anchor hashes

    #[test]
    fn test_compute_the_correct_verification_request_anchor() -> anyhow::Result<()> {
        let verification_request_anchor_hash = verification_request_anchor_fixture().hash;

        let expected_verification_request_anchor_hash = Hash::new(
            <[u8; 32]>::from_hex(
                "b4fbcf892fef3627717a333577921f76e41980d9ea4426f83aa98e221b39cf98",
            )
            .expect("Invalid hex"),
        );

        println!("hash: {}", verification_request_anchor_hash);
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
                "ca347e796ce11a4617dc160f0c1ec5bc479d9de624e28ecb8829087b2e7f1b71",
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
