//! Implements verification of presentations against an anchored verification request and
//! defines the types verification request anchor (VRA) and verification audit anchor (VAA)
//!
//! The module defines a higher level verification flow that adds additional verifications
//! to the cryptographic verification.

mod verify;

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
use std::borrow::Cow;

use crate::web3id::v1::ContextProperty;
use crate::web3id::{did, v1, Web3IdAttribute};
use crate::{hashes, id};
use concordium_base_derive::{CborDeserialize, CborSerialize};
use concordium_contracts_common::hashes::{HashBytes, HashFromStrError};
use serde::de::Error;
use serde::ser::SerializeMap;
use sha2::Digest;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
pub use verify::*;

const PROTOCOL_VERSION: u16 = 1u16;

pub type VerifiablePresentationV1 = v1::PresentationV1<IpPairing, ArCurve, Web3IdAttribute>;
pub type VerifiableCredentialV1 = v1::CredentialV1<IpPairing, ArCurve, Web3IdAttribute>;
pub type VerifiablePresentationRequestV1 = v1::RequestV1<ArCurve, Web3IdAttribute>;
pub type VerificationMaterial = v1::CredentialVerificationMaterial<IpPairing, ArCurve>;

/// A verification request that specifies which subject claims are requested from a credential holder
/// and in which context.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "type", rename = "ConcordiumVerificationRequestV1")]
pub struct VerificationRequest {
    /// Context information for the verification request.
    pub context: UnfilledContextInformation,
    /// A list of subject claims containing requested statements about each subject.
    pub subject_claims: Vec<RequestedSubjectClaims>,
    /// Blockchain transaction hash for the transaction that registers the [`VerificationRequestAnchor`] (VRA)
    /// that matches this verification request. The [`VerificationRequestAnchor`] is created from
    /// [`VerificationRequestData`].
    #[serde(rename = "transactionRef")]
    pub anchor_transaction_hash: hashes::TransactionHash,
}

/// A verification audit record that contains the complete verification request and
/// corresponding verifiable presentation.
///
/// The record should generally be kept private by the verifier.
/// Audit records are used internally by verifiers to maintain complete records
/// of verification interactions, while only publishing hash-based public records/anchors on-chain
/// to preserve privacy, see [`VerificationAuditAnchor`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize, serde::Serialize)]
#[serde(tag = "type", rename = "ConcordiumVerificationAuditRecord")]
pub struct VerificationAuditRecord {
    /// Version integer, for now it is always 1.
    pub version: u16,
    /// Unique identifier chosen by the requester/merchant.
    pub id: String,
    /// The verification request to record.
    pub request: VerificationRequest,
    /// The verifiable presentation containing verifiable credentials.
    pub presentation: VerifiablePresentationV1,
}

impl VerificationAuditRecord {
    /// Create a new verification audit record
    pub fn new(
        id: String,
        request: VerificationRequest,
        presentation: VerifiablePresentationV1,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            id,
            request,
            presentation,
        }
    }

    /// Computes a hash of the verification audit record.
    ///
    /// This hash is used to create a tamper-evident anchor that can be registered
    /// on-chain to prove an audit record was made at a specific time and with
    /// specific parameters.
    pub fn hash(&self) -> hashes::Hash {
        use crate::common::Serial;
        let mut hasher = sha2::Sha256::new();
        self.serial(&mut hasher);
        HashBytes::new(hasher.finalize().into())
    }

    /// Creates the [`VerificationAuditAnchor`] from the audit record.
    /// The anchor is a hash-based public anchor that can be registered on-chain.
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

/// The verification audit anchor (VAA). The data structure is CBOR-encodable and the CBOR
/// encoding defines the data that should be registered on chain to create the on chain anchor of the
/// audit record.
///
/// The anchor is created from a [`VerificationAuditRecord`].
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

/// Data that constitutes a verification request to create a verifiable presentation.
/// Described the subject claims being requested from a credential holder.
///
/// The data should be registered on chain via a [`VerificationRequestAnchor`].
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "type", rename = "ConcordiumVerificationRequestDataV1")]
pub struct VerificationRequestData {
    /// Context information for the verification request. Parts of the context must be
    /// filled in by the credential holder to form the context of the verifiable presentation.
    pub context: UnfilledContextInformation,
    /// Claims that most be proven in the verifiable presentation.
    pub subject_claims: Vec<RequestedSubjectClaims>,
}

impl VerificationRequestData {
    /// Computes the hash of the verification request data.
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

    /// Creates the [`VerificationRequestAnchor`] from the verification request data.
    /// The anchor is a hash-based public record/anchor that can be published on-chain.
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

/// Builder of [`VerificationRequestData`]
#[derive(Debug, Clone, PartialEq, Default)]
pub struct VerificationRequestDataBuilder {
    context: UnfilledContextInformation,
    subject_claims: Vec<RequestedSubjectClaims>,
}

impl VerificationRequestDataBuilder {
    /// Create builder with context but no claims
    pub fn new(context: UnfilledContextInformation) -> Self {
        Self {
            context,
            subject_claims: Vec::new(),
        }
    }

    /// Add a subject claims request to the verification request data.
    pub fn subject_claim(mut self, subject_claims: impl Into<RequestedSubjectClaims>) -> Self {
        self.subject_claims.push(subject_claims.into());
        self
    }

    /// Build the data type
    pub fn build(self) -> VerificationRequestData {
        VerificationRequestData {
            context: self.context,
            subject_claims: self.subject_claims,
        }
    }
}

/// Context information for a verification request.
///
/// Contains both the context data that is already known (given) and
/// the context data that needs to be provided by the credential holder (requested).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Serialize, Default)]
#[serde(tag = "type", rename = "ConcordiumUnfilledContextInformationV1")]
pub struct UnfilledContextInformation {
    /// Context information that is already provided.
    pub given: Vec<LabeledContextProperty>,
    /// Context information that must be provided by the credential holder.
    pub requested: Vec<ContextLabel>,
}

/// Builder of [`UnfilledContextInformation`]
#[derive(Debug, Clone, PartialEq, Default)]
pub struct UnfilledContextInformationBuilder {
    given: Vec<LabeledContextProperty>,
    requested: Vec<ContextLabel>,
}

impl UnfilledContextInformationBuilder {
    /// Create builder with no given or requested context
    pub fn new() -> Self {
        Default::default()
    }

    /// Add to the given context.
    pub fn given(mut self, context: impl Into<LabeledContextProperty>) -> Self {
        self.given.push(context.into());
        self
    }

    /// Add to the requested context.
    pub fn requested(mut self, label: ContextLabel) -> Self {
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
    /// - `nonce` Cryptographic nonce for preventing replay attacks.
    /// - `connectionId` Identifier for the verification session (e.g. wallet-connect topic).
    /// - `contextString` Additional context information.
    pub fn new_simple(nonce: hashes::Hash, connection_id: String, context_string: String) -> Self {
        Self::new()
            .given(LabeledContextProperty::Nonce(nonce))
            .given(LabeledContextProperty::ConnectionId(connection_id))
            .given(LabeledContextProperty::ContextString(context_string))
            .requested(ContextLabel::BlockHash)
            .requested(ContextLabel::ResourceId)
    }

    /// Build the data type
    pub fn build(self) -> UnfilledContextInformation {
        UnfilledContextInformation {
            given: self.given,
            requested: self.requested,
        }
    }
}

/// The verification request anchor (VRA). The data structure is CBOR-encodable and the CBOR
/// encoding defines the data that should be registered on chain to create the on chain anchor of the
/// verification request.
///
/// The anchor is created from a [`VerificationRequestData`].
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

/// The subject claims being requested proven.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
pub enum RequestedSubjectClaims {
    /// Claims based on the Concordium ID object.
    #[serde(rename = "identity")]
    Identity(RequestedIdentitySubjectClaims),
}

impl Serial for RequestedSubjectClaims {
    fn serial<B: Buffer>(&self, out: &mut B) {
        match self {
            RequestedSubjectClaims::Identity(claims) => {
                0u8.serial(out);
                claims.serial(out);
            }
        }
    }
}

impl Deserial for RequestedSubjectClaims {
    fn deserial<R: byteorder::ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        match u8::deserial(source)? {
            0u8 => {
                let claims = source.get()?;
                Ok(Self::Identity(claims))
            }
            n => anyhow::bail!("Unrecognized RequestedSubjectClaims tag {n}"),
        }
    }
}

/// A subject claims request concerning the Concordium ID object (held by the credential holder
/// in the wallet). The Concordium ID object has been signed by identity providers (IDPs).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default, Serialize)]
pub struct RequestedIdentitySubjectClaims {
    /// The statements/claims requested proven.
    pub statements: Vec<RequestedStatement<AttributeTag>>,
    /// The credential issuers allowed.
    pub issuers: Vec<IdentityProviderDid>,
    /// Set of allowed credential types. Should never be empty or contain the same value twice.
    pub source: Vec<IdentityCredentialType>,
}

impl From<RequestedIdentitySubjectClaims> for RequestedSubjectClaims {
    fn from(claims: RequestedIdentitySubjectClaims) -> Self {
        Self::Identity(claims)
    }
}

/// Builder of [`RequestedIdentitySubjectClaims`]
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RequestedIdentitySubjectClaimsBuilder {
    statements: Vec<RequestedStatement<AttributeTag>>,
    issuers: Vec<IdentityProviderDid>,
    source: Vec<IdentityCredentialType>,
}

impl RequestedIdentitySubjectClaimsBuilder {
    /// Create an empty identity subject claims request.
    pub fn new() -> Self {
        Default::default()
    }

    /// Add a source to the given identity subject claims request.
    pub fn source(mut self, source: IdentityCredentialType) -> Self {
        self.source.push(source);
        self
    }

    /// Add sources to the given identity subject claims request.
    pub fn sources(mut self, sources: impl IntoIterator<Item = IdentityCredentialType>) -> Self {
        for src in sources {
            self.source.push(src);
        }
        self
    }

    /// Add an issuer to the given identity subject claims request.
    pub fn issuer(mut self, issuer: IdentityProviderDid) -> Self {
        self.issuers.push(issuer);
        self
    }

    /// Add issuers to the given identity subject claims request.
    pub fn issuers(mut self, issuers: impl IntoIterator<Item = IdentityProviderDid>) -> Self {
        for issuer in issuers {
            self.issuers.push(issuer);
        }
        self
    }

    /// Add a statement/claim to the given identity subject claims.
    pub fn statement(mut self, statement: RequestedStatement<AttributeTag>) -> Self {
        self.statements.push(statement);
        self
    }

    /// Add statements/claims to the given identity subject claims.
    pub fn statements(
        mut self,
        statements: impl IntoIterator<Item = RequestedStatement<AttributeTag>>,
    ) -> Self {
        for statement in statements {
            self.statements.push(statement);
        }
        self
    }

    /// Build the data type
    pub fn build(self) -> RequestedIdentitySubjectClaims {
        RequestedIdentitySubjectClaims {
            statements: self.statements,
            issuers: self.issuers,
            source: self.source,
        }
    }
}

/// Labels for different types of context information that can be provided in verifiable
/// presentation requests and proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContextLabel {
    /// A nonce which should be at least of lenth bytes32.
    Nonce,
    /// Payment hash (Concordium transaction hash).
    PaymentHash,
    /// Concordium block hash.
    BlockHash,
    /// Identifier for some connection (e.g. wallet-connect topic).
    ConnectionId,
    /// Identifier for some resource (e.g. Website URL or fingerprint of TLS certificate).
    ResourceId,
    /// String value for general purposes.
    ContextString,
}

impl ContextLabel {
    /// String representation of the label
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nonce => "Nonce",
            Self::PaymentHash => "PaymentHash",
            Self::BlockHash => "BlockHash",
            Self::ConnectionId => "ConnectionID",
            Self::ResourceId => "ResourceID",
            Self::ContextString => "ContextString",
        }
    }
}

impl Display for ContextLabel {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Errors occurring when parsing attribute values.
#[derive(Debug, thiserror::Error)]
#[error("unknown context label {0}")]
pub struct UnknownContextLabelError(String);

impl FromStr for ContextLabel {
    type Err = UnknownContextLabelError;

    fn from_str(str: &str) -> Result<Self, Self::Err> {
        Ok(match str {
            "Nonce" => ContextLabel::Nonce,
            "PaymentHash" => ContextLabel::PaymentHash,
            "BlockHash" => ContextLabel::BlockHash,
            "ConnectionID" => ContextLabel::ConnectionId,
            "ResourceID" => ContextLabel::ResourceId,
            "ContextString" => ContextLabel::ContextString,
            _ => return Err(UnknownContextLabelError(str.to_string())),
        })
    }
}

impl serde::Serialize for ContextLabel {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for ContextLabel {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let str = Cow::<'de, str>::deserialize(deserializer)?;
        str.parse().map_err(D::Error::custom)
    }
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum IdentityCredentialType {
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

impl Serial for IdentityCredentialType {
    fn serial<B: Buffer>(&self, out: &mut B) {
        match self {
            IdentityCredentialType::IdentityCredential => 0u8.serial(out),
            IdentityCredentialType::AccountCredential => 1u8.serial(out),
        }
    }
}

impl Deserial for IdentityCredentialType {
    fn deserial<R: byteorder::ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        match u8::deserial(source)? {
            0u8 => Ok(Self::IdentityCredential),
            1u8 => Ok(Self::AccountCredential),
            n => anyhow::bail!("Unrecognized CredentialType tag {n}"),
        }
    }
}

/// DID for a Concordium Identity Provider.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Serialize)]
#[serde(into = "did::Method", try_from = "did::Method")]
pub struct IdentityProviderDid {
    /// The network part of the method.
    pub network: did::Network,
    /// The on-chain identifier of the Concordium Identity Provider.
    pub identity_provider: id::types::IpIdentity,
}

impl IdentityProviderDid {
    /// Create a new identity provider method.
    pub fn new(ip_identity: u32, network: did::Network) -> Self {
        Self {
            network,
            identity_provider: id::types::IpIdentity(ip_identity),
        }
    }
}

impl From<IdentityProviderDid> for did::Method {
    fn from(value: IdentityProviderDid) -> Self {
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

impl TryFrom<did::Method> for IdentityProviderDid {
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

/// A statically labeled and statically typed context value. Is used
/// in [`VerificationRequest`] context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabeledContextProperty {
    /// Cryptographic nonce context which should be of length 32 bytes.
    Nonce(hashes::Hash),
    /// Payment hash context (Concordium transaction hash).
    PaymentHash(hashes::TransactionHash),
    /// Concordium block hash context.
    BlockHash(hashes::BlockHash),
    /// Identifier for some connection (e.g. wallet-connect topic).
    ConnectionId(String),
    /// Identifier for some resource (e.g. Website URL or fingerprint of TLS certificate).
    ResourceId(String),
    /// String value for general purposes.
    ContextString(String),
}

/// Read-only view of the value in [`LabeledContextProperty`]
pub struct PropertyValueView<'a> {
    property: &'a LabeledContextProperty,
}

impl Display for PropertyValueView<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.property {
            LabeledContextProperty::Nonce(val) => val.fmt(f),
            LabeledContextProperty::PaymentHash(val) => val.fmt(f),
            LabeledContextProperty::BlockHash(val) => val.fmt(f),
            LabeledContextProperty::ConnectionId(val) => f.write_str(val),
            LabeledContextProperty::ResourceId(val) => f.write_str(val),
            LabeledContextProperty::ContextString(val) => f.write_str(val),
        }
    }
}

impl serde::Serialize for PropertyValueView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl LabeledContextProperty {
    /// The label for the property.
    pub fn label(&self) -> ContextLabel {
        match self {
            Self::Nonce(_) => ContextLabel::Nonce,
            Self::PaymentHash(_) => ContextLabel::PaymentHash,
            Self::BlockHash(_) => ContextLabel::BlockHash,
            Self::ConnectionId(_) => ContextLabel::ConnectionId,
            Self::ResourceId(_) => ContextLabel::ResourceId,
            Self::ContextString(_) => ContextLabel::ContextString,
        }
    }

    /// Read-only view of the context value in the property.
    pub fn value(&self) -> PropertyValueView<'_> {
        PropertyValueView { property: self }
    }

    /// Creates property from label and with value parsed from the given string.
    pub fn try_from_label_and_value_str(
        label: ContextLabel,
        str: &str,
    ) -> Result<Self, HashFromStrError> {
        Ok(match label {
            ContextLabel::Nonce => Self::Nonce(str.parse()?),
            ContextLabel::PaymentHash => Self::PaymentHash(str.parse()?),
            ContextLabel::BlockHash => Self::BlockHash(str.parse()?),
            ContextLabel::ConnectionId => Self::ConnectionId(str.to_string()),
            ContextLabel::ResourceId => Self::ResourceId(str.to_string()),
            ContextLabel::ContextString => Self::ContextString(str.to_string()),
        })
    }

    /// Convert to the dynamically labeled property type [`ContextProperty`]
    pub fn to_context_property(&self) -> ContextProperty {
        ContextProperty {
            label: self.label().to_string(),
            context: self.value().to_string(),
        }
    }

    /// Convert from the dynamically labeled property type [`ContextProperty`]
    pub fn try_from_context_property(
        prop: &ContextProperty,
    ) -> Result<Self, FromContextPropertyError> {
        let label = prop.label.parse()?;
        Ok(Self::try_from_label_and_value_str(label, &prop.context)?)
    }
}

/// Error parsing the dynamically typed [`ContextProperty`] to [`LabeledContextProperty`].
#[derive(Debug, thiserror::Error)]
pub enum FromContextPropertyError {
    #[error("parse label: {0}")]
    ParseLabel(#[from] UnknownContextLabelError),
    #[error("parse value: {0}")]
    ParseValue(#[from] HashFromStrError),
}

impl serde::Serialize for LabeledContextProperty {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map_serializer = serializer.serialize_map(Some(2))?;
        map_serializer.serialize_entry("label", &self.label())?;
        map_serializer.serialize_entry("context", &self.value())?;
        map_serializer.end()
    }
}

impl<'de> serde::Deserialize<'de> for LabeledContextProperty {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        struct LabeledContextPropertyRaw<'a> {
            label: ContextLabel,
            #[serde(borrow)]
            context: Cow<'a, str>,
        }

        let raw = LabeledContextPropertyRaw::deserialize(deserializer)?;
        Self::try_from_label_and_value_str(raw.label, &raw.context).map_err(D::Error::custom)
    }
}

impl Serial for LabeledContextProperty {
    fn serial<B: Buffer>(&self, out: &mut B) {
        match self {
            LabeledContextProperty::Nonce(hash) => {
                0u8.serial(out);
                hash.serial(out);
            }
            LabeledContextProperty::PaymentHash(hash) => {
                1u8.serial(out);
                hash.serial(out);
            }
            LabeledContextProperty::BlockHash(hash) => {
                2u8.serial(out);
                hash.serial(out);
            }
            LabeledContextProperty::ConnectionId(connection_id) => {
                3u8.serial(out);
                connection_id.serial(out);
            }
            LabeledContextProperty::ResourceId(rescource_id) => {
                4u8.serial(out);
                rescource_id.serial(out);
            }
            LabeledContextProperty::ContextString(context_string) => {
                5u8.serial(out);
                context_string.serial(out);
            }
        }
    }
}

impl Deserial for LabeledContextProperty {
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
                let resource_id = source.get()?;
                Ok(Self::ResourceId(resource_id))
            }
            5u8 => {
                let context_string = source.get()?;
                Ok(Self::ContextString(context_string))
            }
            n => anyhow::bail!("Unknown GivenContext tag: {}", n),
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
    use crate::common::serialize_deserialize;
    use crate::hashes::Hash;
    use anyhow::Context as AnyhowContext;
    use hex::FromHex;

    fn remove_whitespace(str: &str) -> String {
        str.chars().filter(|c| !c.is_whitespace()).collect()
    }

    #[test]
    fn test_verification_request_json_roundtrip() -> anyhow::Result<()> {
        let request_data = fixtures::verification_request_data_fixture();

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
        let verification_request_anchor = fixtures::verification_request_data_fixture();

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
        let verification_audit_anchor = fixtures::verification_audit_record_fixture();

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
        "context": "0101010101010101010101010101010101010101010101010101010101010101"
      },
      {
        "label": "ConnectionID",
        "context": "testconnection"
      },
      {
        "label": "ContextString",
        "context": "testcontext"
      }
    ],
    "requested": [
      "BlockHash",
      "ResourceID"
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
        "did:ccd:testnet:idp:0",
        "did:ccd:testnet:idp:1",
        "did:ccd:testnet:idp:17"
      ],
      "source": [
        "identityCredential",
        "accountCredential"
      ]
    }
  ]
}
            "#;

        let actual_json =
            serde_json::to_string_pretty(&fixtures::verification_request_data_fixture()).unwrap();
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
  "id": "MyUUID",
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
          "context": "testconnection"
        },
        {
          "label": "ContextString",
          "context": "testcontext"
        }
      ],
      "requested": [
        "BlockHash",
        "ResourceID"
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
          "did:ccd:testnet:idp:0",
          "did:ccd:testnet:idp:1",
          "did:ccd:testnet:idp:17"
        ],
        "source": [
          "identityCredential",
          "accountCredential"
        ]
      }
    ],
    "transactionRef": "0202020202020202020202020202020202020202020202020202020202020202"
  },
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
          "context": "testconnection"
        },
        {
          "label": "ContextString",
          "context": "testcontext"
        }
      ],
      "requested": [
        {
          "label": "BlockHash",
          "context": "0202020202020202020202020202020202020202020202020202020202020202"
        },
        {
          "label": "ResourceID",
          "context": "testresourceid"
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
          "proofValue": "0000000000000006010098ad4f48bcd0cf5440853e520858603f16058ee0fc1afdc3efe98abe98771e23c000d19119c28d704a5916929f66f2a30200abb05a0ff79b3b06f912f0ec642268d3a1ad1cdf4f050ab7d55c795aa1ab771f4be29f29134e0d7709566f9b2468805f03009158599821c271588f24e92db7ca30197ec5b0c901efaadd34cca707e56b9aab1a7f14e329816e2acf4d07a7edf1bd6b0400af07a1ba7a22bcb1602114921a48fa966a821354cd0dd63a87ce018caccc50b56f2c9f55a062cdc423657aa5cec8a4c9050100097465737476616c75650602aef4be258f8baca0ee44affd36bc9ca6299cc811ac6cb77d10792ff546153d6a84c0c0e030b131ed29111911794174859966f6ba8cafaf228cb921351c2cbc84358c0fa946ca862f8e30d920e46397bf96b56f50b66ae9c93953dc24de2904640000000000000004a547c8619f3ff2670efbefb21281e459b7cc9766c4f377f78e9f97e2c50569a8dcb155f2a502e936d2cb6ef1a73e92af9916e6353b7127d55bb525cb18074b5ec130463e03a4eda583b05c2d63db40a08ab8bf05f930ec234cc2f788d5f5bfbeab3e4881918ce964ffd55483219edd435ac865286bfd313cd834aabfa8061d2ae173cbe4b59ab2bda78faa4c2c937afba80d7fba0822579ac0ef6915f4820f968a74f00ff5ab74e90b0a7bcb2b92093a5e94a54aea1d48ffd1e5bb3fb48069bcadf8b1e6664e83c2e12f47291bdb470b47df740c2623fc0d7a0ad34fb9d64fb900000005000000015cc1f983b2a7a7debded95108cb89f65381917f8120e4deea665b9e3ca0a70212ffd481839d094662c2db50136796152e41cbbba6bf87bf02e78abee35933a9e67285f7d35a7d9bf24a37fe49620f6255f1ac78cb4aef1151e29944ecb702643000000024bce7d3ca07538e9aff9772b4cf9c2b24a67b91397f5994226a093d298b4a23633e46e7ade5ef65956edf9de27d9a975ce949f97d73a0d5258cf8e8f87adaa570463fd2f9559ef5f7dd364dc4abce05550d0e53475c9918b1e23c7b34d89d8e1000000036440ecd3c6c671a0c40ed70f884a9f5212c3d1e05af61e4d6da7c58dde7fb1ba05f41f668da5d1440ab95f5ba3691046c0b1ff3478c731785cefa5a4dda8cee6665ce1ac8c8040c932a44ed2bf077cdcca394d7eb8e3c3e91f40cc6512db24c5000000043912fd3c9a5e2167423188eebbbda54c616ded7580a3eb34500916687f11d4f00ce689c028a28370fdba1edaaf3b7a29881cf8c2602f961b2137779d7a6fa18356936262155f6b04dbda6b1d35c67248e9396ef932abed13006651b2882f155f000000056ebac799466813bd7f9ed65a9bb5c91ec3710d88aa4c1f6390e475170231bce41cd0d020868b143ce9d0a8f1543dd1ee2f5b3e85525dde8d04e1d12ac2063ada69d7bc2ac5b50cece6fc9e386d6c4b576417ae6ccee6321e5a61599eb3748d74206742d6126667ee04141b72104aacb32e580b5db3f549777b7f035a2a16a0860000000c002224a394b6edcf83998ee8d9b58095b38d6b6c5c42521d5c31b81dbc52ccc0264bda335a1e7f61ffa2bba8d356c1b48e01b58f266c50363c1798479f7a9365200266f9eb50ef10d0dc63ef4ddb238831148e01e0e38d8e0b94c373597dfb5d295501010102299f078d1e543497070baee391c060737354c015f1d0bf82faf3d78d3a48376e0005c7dc83b81accdb0954f6ad51d0ce35ad66b3201f5336ac20c3c1c08ff856272ce6116990d8266acd40309cf895f52e62e1bb357cff558e53e18d37e544ee7b006c88ea28f1502893beaac7e6d9c1905fc58c051cf077e1093c89c81cd7a671800f2b98037e637fe747200f9288272de1c67170fa3f2d3e29911784a49bcefd78004b04bc8c867d1afa3992d8a11f3a8ada1ee1ed48f348e7ddec33d32b824ebc25457b8151147ba053e00c478f95e6cd752578973ad575e09919fd6caf59d11f600024d5e6122667191464557a4e758cce911968ad9813e181522f6c2e2703576aeb69aaf0412219e752b222329904b4c29949a6d9b18c91604704dc071897bf05760102531993dd2439551210bfa191f9b66e49e693c6c189260aa605280886804ff692000000000000000502803596b4ba5ea05b1fea2b78e292f935d621453cffcd207e10f3072b2813ca3e963cebf05b19cd82da4bd5aad1dcc7fda1492d7ffc8f532bc4b37e9bf4753b7ae6b8f08e05a851052fc6ac7617ce68293678747d11f9a508bab6f7a60edde9c4a41e80bca9bbd4fad0a8dc8db2b4264dc25e35599bab793956d61dbc0c012f01b393c8cf7254a24c18b6b05f1180a555b712be45be9a9be20eed26c68683c81afb0de03c61af110d25cf10e364996a30b29fb0d4543f9bc2ed0dd1a6def19cdb09ef7c0f24f29ae9dcd5aaf809bd67d86b9cf8e639ebd28385a2ad954db1851f59737318d78ad8a990cfdc208f2229fe33ceba14c7b34dd9f0687454384206f36bbc7762e015510952538f10e502b1be9cab7e8f6637964aa58a100eb72eed7d00000007aa3d9d70c9a1112cd8bbf2f23f5d436bb038970c1cd718b65865369ac172f3edee2e353d68ca75a309e1299d03f7a50083914b99232b25f106f4cb9fea1f5ec988aa749975a9f0cd1ba56682bb2b90d2f9cb33be146d6fc81584707dedf3d660ab47522d8bb4d47e832121c792e5278040eca2900b7a8ce4c073554602a1feaa82c210550bb95f35bd4aceb1b0bf08bd8fc4e5b6c0432fcddc18e086d915bf7a5076df3be63b3ce6087abbf7e0a3f8f530407803f8fac559437c881a99c1282fa5856086c95f71ebb957d9db6514796dead2b87375f97c24bbab00d666c024872a84c8b8e26097352d10eeaed535055a85ad5c6827309fc69583c5a6e7533572222c9b38c509feb71eaec826ff703b9c9442a9c807e4a530b07912360708f441b742162d2708308e50a6a213efcccaa755288a0b8008bb7310f7cabc4a6ef02f4257ba0f91ffa237c88a3d4640c61870acfe90ce01f8112a6e4ed0e38b717c2895e438068b952e78b58461d83764d0b6e375398a5f5ebd492365b16fca7f96648f85a67c865334e72a44f5753a74fb20a49778648a6832c5eabfd6c75eea8b72235b1d4493149fbdf9cd61ca31b97d9d851188135e28dce14b0911a42c014fce1040a46d53e226011a686c216476c1775cc05b7388b72444d3c0be400c543b8588ffc4bcc9fe12a56824164b7f46c69bff954199f0df17ef4de3da2849f94e503c1d5ecee6303f58d70c61df996c383c8673869287b27a490f120a8c881087df070f3592d60322efe69da5cd4493a9c373faabfe517942a1c4d04157f18052dd87803dc0fcdf15f61f938f80ba8c44010d0950a7f8d6a5e500d74e10252a2024c5474a7a03479f929811c0ba0b6d5befb5ec49396f1c578880d587e4b949a80bf50eacff5f3180963723fcc2fb53b386547e87ce814b34d7721e8bd65fe49d594d21ae53cbf8207c14e5afc034542804febe2dcfd61dc28b7d73d3eeeeb87d5c64a83e378487375585888dc7bef240bf88f8c43782c49d7964dd3b5f0ab7f219039035240c33b7dec4981aa53e914f67ac932328b31f3fc4d0aac1c19a4da4dab1b525a63008d0e40b86076a1b7e9f0f219955c76798ae8d5131eee35e9900c5cdc8b58badd7022044521d7ad239a91bb2ae1a02fc61472f7d3629d14070641a1eb279dda86a693d9bd31eb38e677c5f85070e2cc05cb574ffc4340fe23bd4682a7faa8b4c2b7c86486dc9a3f6977442028f9adf7b0e8211df3770f580eb6f0ee86a7cea689a6888c31bb81a72fd82d7138f3cb5fbea85460d59faae9ec97e7ee914fecabac546163a683af1858ba5dd471653021a0c170b9ffdf2f63b00c225a3545ee75f4b4d1fae8e5ae3ab2a82616cfd1d28a7194606eec6a7820a4330771c0a652d08e02a418cdfa8f77915e1598b1c9c3ee01f6f2c84da643c23182c0bfc00000002934c0abe8b38512e0a8f2cdda0f7a4ccfdb8892ac0c47577b1736ff0a8760da7ab80078380f9a3f76c29c450f01e7846b7c265e81c7820c1069a01ec112e4c9f5ef2224beea1b6726f9d571a817e7878dc0081e58a2e2d6d8897590ca8bbfad592c86a5dfa048c11a1d5256168e1abbec3294fff524270dcb4e2ccf4ad1c01b2f50617bdea7cde01dfd40abceb826b72907e4627a972d0d94ac18d90b070e5138542620c162fee11e35b615c1332af593d165ad2124ee700c905eafb47bb8c1c3efa9dee61560288af752e95391e6ba8931ee2a555706893f47e4e1db4cb6ef8495975561f3d7ab3cf72a254d2d09143ab8b72a20fc808b0007d465bf25359ec0487cbd29bfc97194ed8868ed4e458c7b2bf8ab6f04efee532502cf588c4f26b9b2830baa635c56857be5fd6803fd35d508881bd7cf3b5872ff84640384e2576bd93d4d86fdafcba2df3f29036491573031ede2ddb09dd092ad890a68f07876aeeb1670ef988687963f3e3481e448df81c3887471be037c05e55b9ffa04295049a53a7bf2dc6f8f444bcdb55aa860b68c59860c8918ec080cf9da5e53ef614446784f1a59370c718c3f22b1951bf719e97e5af289407f6162ca5c790f93ca249db4999d4f766193d965457595fd708fdd1d5e45929132988a250cbb6d49047ceea5a7d229ba568f9022cdfbe5e6cd7c201ba74ac1ba1a90679a02797e3661300ea1a0cfd5b1b5f013992653794a219d4ecdaae19e0598582f48ad7496557fa709200000002b52319c25eabb5fddbf0f1329721ff50aaf0ebd5adafe2886f458f0c7f2b004d206168484605a5a9b504465ba59d254f8cadc1bd5a2ab181ddfdfafbf205f0b40ba5593e87176e42872e5e3e46e42f28eb15d389bc08e95a05bd6fe04dddd7ddb240dbca64d7b462884689308b73495a273780a25c953d32d5c298c888972df69d450581a07e6465d284b56b4eeacdd2811b655cbb86a9c7c19649bbe5df94d24b840d895c372374af8e8692e9bf66b142b3214f70c3da25c0258bc8c2eab1555f1fa270c6d9fec15b2bffdb1905f86ed286cf41ee3fb30bf7cf3e51bdf05e943fc018f613b86e8ff48aa3d9ebe0cdf6bf8a6d35626ec7b0934b6094160c087202b387e119ec10c4a8963ee52710d75c21710881bae7fb5a8595fd43a9156419f8080891e50139bd4af14f1ba25ebe0152b5e83d115be493372e147742d8bfe3a8269e8ecd27ec055a11055d5405192cda8c8db528f06b120fc2e3f470898974118e681c1b99e40a986ff74b97d61f5c4e88e52c7aef82fabd2f44256ffdbf980635cdf40bdda88c767ddbe643aae7ac4ab61f5b500bc405db39d6d0ff790878a76c5d09f8a5a21010b71ea9bccf811db26d23f437bf196fc0e42ef701068d51d33e4afcecc6ee66ed2addf6ebd1480dfdc2f9e25462d573493bd645e8a7a1336118677a442c14009d33e4bfc1756b09039789a7e806d5050c2fc70e33842b904042dce8c4121c2e82db496052715bca21c7706daf66b0990c88c2c628c1d4f23500000007a23a41c1b755d06289d7546233e2ae891c82f7f17ed0422d1f8754a20e0c7bce8b7159ea6d0680246f5542f662195263a45c271dd1a930a5791e9a2fe7d8a64cf235b20f07eb1e5af8664c15686c45e5e2811b570e27a8dfab1f71936f038320aa43184c3d0ef0bf81fc71b55d7130275eda4f851c02843c47bf5632bcddfa1797116ece6d63df159b63a22215a1f28988f6d990c1ab70d364d886e322f3147783665325302327ba4ead49d6bb759b6f45e95e391081185357516860fbf607b0932cb683faf83fbb9f31d8530facc9f9fdf04fdcbd2d83ca60f8f7f73852cb0410eaf3868c2e0d42dd2cc3cb96ecb7498dc3c337260451ee86b551c8bbac56ba350a2767f4afc4c891c00030c60629f6bbe0df10804206ed13fbe92971eb40868a9758765fa6499efeb9d1b3f924be03dae0815318a70a42a9bc836139cca5cae5239482d6a65affa6fedcc9776e77c9b65eb66297aed36094dc65d7d9f13302bb6d2b6a079cb6285e96bfb14809a8fff7fa35b63a68f295b6b977f73a4055e682ab6564c3a56bd9b63cc39c6fbdd01646b75c9d35974c4dd5cc4ad44113cd0635f903d48339fdf5276585b1ed66a991ad291af87e3b5c4f2a9247272977fdc8b74fb9dd5eba894f6e78184602e73e2045fcd3cdf8192fc038e3778599338cd9a4920be187e5b212a010a6351e865722a5ea0f55cecc492ec52b11679f8e3d2e9ce2e9bbd37683c44fef05e8c5c84dd0b8920b14c2aa9dd0e47ef96f2442a2969938fa8235eb06b166ee46115c3be5ad83cc73a0175564b6080401ca5ebe79ad8b383b94b8d167eef0459deea932a3200ee323c1542543b71b15bcf84a0d6bfdca76d30e1c5e593602a6d119e488db1b91fa39572973fc2e47ab7eaac489df7379fb9b4c2b5939f5a84b21d13545673640bc9750d94ea0aebd5fbddbc811692004e66eae5c8461c1d31a812bae721d8c76c44939b499779660f27b6bcc89168941199c1edfd9175ee71cf46036c9b362ac72922e504c42731eecfe146629257d01",
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
            serde_json::to_string_pretty(&fixtures::verification_audit_record_fixture()).unwrap();
        println!("audit record json:\n{}", actual_json);

        assert_eq!(
            remove_whitespace(&actual_json),
            remove_whitespace(expected_json),
            "audit record json"
        );

        Ok(())
    }

    #[test]
    fn test_verification_request_anchor_serialization_deserialization_roundtrip() {
        let request_data = fixtures::verification_request_data_fixture();

        let deserialized = serialize_deserialize(&request_data).expect("Deserialization succeeds.");

        assert_eq!(
            request_data, deserialized,
            "Failed verification request anchor serialization deserialization roundtrip."
        );
    }

    #[test]
    fn test_verification_audit_anchor_serialization_deserialization_roundtrip() {
        let verification_audit_anchor = fixtures::verification_audit_record_fixture();

        let deserialized =
            serialize_deserialize(&verification_audit_anchor).expect("Deserialization succeeds.");
        assert_eq!(
            verification_audit_anchor, deserialized,
            "Failed verification audit anchor serialization deserialization roundtrip."
        );
    }

    #[test]
    fn test_verification_request_anchor_cbor_roundtrip() {
        let verification_request_anchor = fixtures::verification_request_anchor_fixture();

        let cbor = cbor::cbor_encode(&verification_request_anchor).unwrap();

        assert_eq!(hex::encode(&cbor), "a464686173685820954ff8287b13b7d0925b55e75edf700d78e16dae07941d32be83ed177793815f647479706566434344565241667075626c6963a1636b6579046776657273696f6e01");

        let decoded: VerificationRequestAnchor = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(decoded, verification_request_anchor);
    }

    #[test]
    fn test_verification_audit_anchor_cbor_roundtrip() {
        let verification_audit_anchor_on_chain = fixtures::verification_audit_anchor_fixture();

        let cbor = cbor::cbor_encode(&verification_audit_anchor_on_chain).unwrap();
        assert_eq!(hex::encode(&cbor), "a4646861736858209eb4aa6091914e2c5a5e64a6c5d2e23f5172b40ad8bc4d53088acf7bf43d1766647479706566434344564141667075626c6963a1636b6579046776657273696f6e01");
        let decoded: VerificationAuditAnchor = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(decoded, verification_audit_anchor_on_chain);
    }

    #[test]
    fn test_compute_the_correct_verification_request_anchor() -> anyhow::Result<()> {
        let verification_request_anchor_hash = fixtures::verification_request_anchor_fixture().hash;

        let expected_verification_request_anchor_hash = Hash::new(
            <[u8; 32]>::from_hex(
                "954ff8287b13b7d0925b55e75edf700d78e16dae07941d32be83ed177793815f",
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
        let verification_audit_anchor_hash = fixtures::verification_audit_anchor_fixture().hash;
        let expected_verification_audit_anchor_hash = Hash::new(
            <[u8; 32]>::from_hex(
                "9eb4aa6091914e2c5a5e64a6c5d2e23f5172b40ad8bc4d53088acf7bf43d1766",
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

    #[test]
    fn test_context_label_string_roundtrip() {
        use ContextLabel::*;
        for label in [
            Nonce,
            PaymentHash,
            BlockHash,
            ConnectionId,
            ResourceId,
            ContextString,
        ] {
            assert_eq!(
                label.to_string().parse::<ContextLabel>().expect("parse"),
                label
            );
        }
    }

    #[test]
    fn test_context_label_json_roundtrip() {
        use ContextLabel::*;
        for label in [
            Nonce,
            PaymentHash,
            BlockHash,
            ConnectionId,
            ResourceId,
            ContextString,
        ] {
            let json = serde_json::to_string(&label).expect("to json");
            let deserialized_label: ContextLabel = serde_json::from_str(&json).expect("from json");
            assert_eq!(deserialized_label, label);
        }
    }

    #[test]
    fn test_labeled_context_property_string_roundtrip() {
        use LabeledContextProperty::*;
        for labeled_prop in [
            Nonce(hashes::Hash::from([1u8; 32])),
            PaymentHash(hashes::TransactionHash::from([1u8; 32])),
            BlockHash(hashes::BlockHash::from([1u8; 32])),
            ConnectionId("testvalue".to_string()),
            ResourceId("testvalue".to_string()),
            ContextString("testvalue".to_string()),
        ] {
            let label_str = labeled_prop.label().to_string();
            let value_str = labeled_prop.value().to_string();
            let label_from_str = ContextLabel::from_str(&label_str).expect("label");
            let labeled_prop_from_str =
                LabeledContextProperty::try_from_label_and_value_str(label_from_str, &value_str)
                    .expect("property");
            assert_eq!(labeled_prop_from_str, labeled_prop);
        }
    }

    #[test]
    fn test_labeled_context_property_context_property_roundtrip() {
        use LabeledContextProperty::*;
        for labeled_prop in [
            Nonce(hashes::Hash::from([1u8; 32])),
            PaymentHash(hashes::TransactionHash::from([1u8; 32])),
            BlockHash(hashes::BlockHash::from([1u8; 32])),
            ConnectionId("testvalue".to_string()),
            ResourceId("testvalue".to_string()),
            ContextString("testvalue".to_string()),
        ] {
            let context_prop = labeled_prop.to_context_property();
            let labeled_prop_from_str =
                LabeledContextProperty::try_from_context_property(&context_prop).expect("property");
            assert_eq!(labeled_prop_from_str, labeled_prop);
        }
    }

    #[test]
    fn test_labeled_context_property_json_roundtrip() {
        use LabeledContextProperty::*;
        for labeled_prop in [
            Nonce(hashes::Hash::from([1u8; 32])),
            PaymentHash(hashes::TransactionHash::from([1u8; 32])),
            BlockHash(hashes::BlockHash::from([1u8; 32])),
            ConnectionId("testvalue".to_string()),
            ResourceId("testvalue".to_string()),
            ContextString("testvalue".to_string()),
        ] {
            let json = serde_json::to_string(&labeled_prop).expect("json");
            let labeled_prop_deserialized: LabeledContextProperty =
                serde_json::from_str(&json).expect("property");
            assert_eq!(labeled_prop_deserialized, labeled_prop);
        }
    }
}

#[cfg(test)]
mod fixtures {
    use super::*;
    use crate::common;
    use crate::id::constants::AttributeKind;
    use crate::id::id_proof_types::{AttributeInRangeStatement, AttributeValueStatement};
    use crate::id::types::GlobalContext;
    use crate::web3id::did::Network;
    use crate::web3id::v1::{
        fixtures, AccountBasedSubjectClaims, AtomicStatementV1, ContextInformation,
        IdentityBasedSubjectClaims, SubjectClaims,
    };
    use std::collections::BTreeMap;
    use std::fmt::Debug;
    use std::marker::PhantomData;
    use std::sync::LazyLock;

    pub static NONCE: LazyLock<hashes::Hash> = LazyLock::new(|| hashes::Hash::from([1u8; 32]));
    pub const VRA_BLOCK_HASH: LazyLock<hashes::BlockHash> =
        LazyLock::new(|| hashes::BlockHash::from([2u8; 32]));
    pub const VRA_TXN_HASH: LazyLock<hashes::TransactionHash> =
        LazyLock::new(|| hashes::TransactionHash::from([5u8; 32]));

    pub use crate::web3id::v1::fixtures::*;

    pub fn unfilled_context_fixture() -> UnfilledContextInformation {
        UnfilledContextInformationBuilder::new_simple(
            *NONCE,
            "testconnection".to_string(),
            "testcontext".to_string(),
        )
        .build()
    }

    pub fn identity_subject_claims_fixture() -> RequestedIdentitySubjectClaims {
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

        RequestedIdentitySubjectClaimsBuilder::default()
            .issuer(IdentityProviderDid::new(0u32, did::Network::Testnet))
            .issuer(IdentityProviderDid::new(1u32, did::Network::Testnet))
            .issuer(IdentityProviderDid::new(17u32, did::Network::Testnet))
            .source(IdentityCredentialType::IdentityCredential)
            .source(IdentityCredentialType::AccountCredential)
            .statements(statements)
            .build()
    }

    pub fn verification_request_data_fixture() -> VerificationRequestData {
        let context = unfilled_context_fixture();
        let subject_claims = identity_subject_claims_fixture();

        VerificationRequestDataBuilder::new(context)
            .subject_claim(subject_claims)
            .build()
    }

    pub fn verification_request_data_to_request_and_anchor(
        request_data: VerificationRequestData,
    ) -> (VerificationRequest, VerificationRequestAnchor) {
        let mut public_info = HashMap::new();
        public_info.insert("key".to_string(), cbor::value::Value::Positive(4u64));

        let anchor = request_data.to_anchor(Some(public_info));
        let request = VerificationRequest {
            context: request_data.context,
            subject_claims: request_data.subject_claims,
            anchor_transaction_hash: *VRA_TXN_HASH,
        };

        (request, anchor)
    }

    pub fn verification_request_anchor_fixture() -> VerificationRequestAnchor {
        let request_data = verification_request_data_fixture();

        let mut public_info = HashMap::new();
        public_info.insert("key".to_string(), cbor::value::Value::Positive(4u64));

        request_data.to_anchor(Some(public_info))
    }

    pub fn verification_request_fixture() -> VerificationRequest {
        let context = unfilled_context_fixture();
        let subject_claims = identity_subject_claims_fixture();

        VerificationRequest {
            context,
            subject_claims: vec![RequestedSubjectClaims::Identity(subject_claims)],
            anchor_transaction_hash: *VRA_TXN_HASH,
        }
    }

    pub fn unfilled_context_information_to_context_information(
        context: &UnfilledContextInformation,
    ) -> ContextInformation {
        ContextInformation {
            given: context
                .given
                .iter()
                .map(|prop| prop.to_context_property())
                .collect(),
            requested: context
                .requested
                .iter()
                .map(|label| match label {
                    ContextLabel::BlockHash => LabeledContextProperty::BlockHash(*VRA_BLOCK_HASH),
                    ContextLabel::ResourceId => {
                        LabeledContextProperty::ResourceId("testresourceid".to_string())
                    }
                    _ => panic!("unexpected label"),
                })
                .map(|prop| prop.to_context_property())
                .collect(),
        }
    }

    pub fn verification_request_to_verifiable_presentation_request_identity(
        id_cred: &IdentityCredentialsFixture<Web3IdAttribute>,
        verification_request: &VerificationRequest,
    ) -> VerifiablePresentationRequestV1 {
        VerifiablePresentationRequestV1 {
            context: unfilled_context_information_to_context_information(
                &verification_request.context,
            ),
            subject_claims: verification_request
                .subject_claims
                .iter()
                .map(|claims| requested_subject_claims_to_subject_claims_identity(id_cred, claims))
                .collect(),
        }
    }

    pub fn verification_request_to_verifiable_presentation_request_account(
        account_cred: &AccountCredentialsFixture<Web3IdAttribute>,
        verification_request: &VerificationRequest,
    ) -> VerifiablePresentationRequestV1 {
        VerifiablePresentationRequestV1 {
            context: unfilled_context_information_to_context_information(
                &verification_request.context,
            ),
            subject_claims: verification_request
                .subject_claims
                .iter()
                .map(|claims| {
                    requested_subject_claims_to_subject_claims_account(account_cred, claims)
                })
                .collect(),
        }
    }

    pub fn requested_subject_claims_to_subject_claims_identity(
        id_cred: &IdentityCredentialsFixture<Web3IdAttribute>,
        claims: &RequestedSubjectClaims,
    ) -> SubjectClaims<ArCurve, Web3IdAttribute> {
        match claims {
            RequestedSubjectClaims::Identity(claims) => {
                let statements = claims
                    .statements
                    .iter()
                    .map(|stmt| requested_statement_to_statement(stmt))
                    .collect();

                SubjectClaims::Identity(IdentityBasedSubjectClaims {
                    network: Network::Testnet,
                    issuer: id_cred.issuer,
                    statements,
                })
            }
        }
    }

    pub fn requested_subject_claims_to_subject_claims_account(
        account_cred: &AccountCredentialsFixture<Web3IdAttribute>,
        claims: &RequestedSubjectClaims,
    ) -> SubjectClaims<ArCurve, Web3IdAttribute> {
        match claims {
            RequestedSubjectClaims::Identity(id_claims) => {
                let statements = id_claims
                    .statements
                    .iter()
                    .map(|stmt| requested_statement_to_statement(stmt))
                    .collect();

                SubjectClaims::Account(AccountBasedSubjectClaims {
                    network: Network::Testnet,
                    issuer: account_cred.issuer,
                    cred_id: account_cred.cred_id,
                    statements,
                })
            }
        }
    }

    fn requested_statement_to_statement(
        statement: &RequestedStatement<AttributeTag>,
    ) -> AtomicStatementV1<ArCurve, AttributeTag, Web3IdAttribute> {
        match statement {
            RequestedStatement::RevealAttribute(stmt) => {
                AtomicStatementV1::AttributeValue(AttributeValueStatement {
                    attribute_tag: stmt.attribute_tag,
                    attribute_value: Web3IdAttribute::String(
                        AttributeKind::try_new("testvalue".into()).unwrap(),
                    ),
                    _phantom: Default::default(),
                })
            }
            RequestedStatement::AttributeInRange(stmt) => {
                AtomicStatementV1::AttributeInRange(stmt.clone())
            }
            RequestedStatement::AttributeInSet(stmt) => {
                AtomicStatementV1::AttributeInSet(stmt.clone())
            }
            RequestedStatement::AttributeNotInSet(stmt) => {
                AtomicStatementV1::AttributeNotInSet(stmt.clone())
            }
        }
    }

    /// Statements and attributes that make the statements true
    pub fn default_attributes<TagType: FromStr + common::Serialize + Ord>(
    ) -> BTreeMap<TagType, Web3IdAttribute>
    where
        <TagType as FromStr>::Err: Debug,
    {
        let attributes = [
            (
                AttributeTag(3).to_string().parse().unwrap(),
                Web3IdAttribute::Numeric(137),
            ),
            (
                AttributeTag(1).to_string().parse().unwrap(),
                Web3IdAttribute::String(AttributeKind::try_new("xkcd".into()).unwrap()),
            ),
            (
                AttributeTag(2).to_string().parse().unwrap(),
                Web3IdAttribute::String(AttributeKind::try_new("aa".into()).unwrap()),
            ),
            (
                AttributeTag(5).to_string().parse().unwrap(),
                Web3IdAttribute::String(AttributeKind::try_new("testvalue".into()).unwrap()),
            ),
            (
                AttributeTag(6).to_string().parse().unwrap(),
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
        .collect();

        attributes
    }

    pub fn generate_and_prove_presentation_identity(
        id_cred: &IdentityCredentialsFixture<Web3IdAttribute>,
        request: VerifiablePresentationRequestV1,
    ) -> VerifiablePresentationV1 {
        let global_context = GlobalContext::generate("Test".into());

        // the easiest way to construct a presentation, is just to run the prover on a request
        let now = chrono::DateTime::parse_from_rfc3339("2023-08-28T23:12:15Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let presentation = request
            .prove_with_rng(
                &global_context,
                [id_cred.private_inputs()].into_iter(),
                &mut fixtures::seed0(),
                now,
            )
            .expect("prove");

        presentation
    }

    pub fn generate_and_prove_presentation_account(
        account_cred: &AccountCredentialsFixture<Web3IdAttribute>,
        request: VerifiablePresentationRequestV1,
    ) -> VerifiablePresentationV1 {
        let global_context = GlobalContext::generate("Test".into());

        // the easiest way to construct a presentation, is just to run the prover on a request
        let now = chrono::DateTime::parse_from_rfc3339("2023-08-28T23:12:15Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let presentation = request
            .prove_with_rng(
                &global_context,
                [account_cred.private_inputs()].into_iter(),
                &mut fixtures::seed0(),
                now,
            )
            .expect("prove");

        presentation
    }

    pub fn verifiable_presentation_fixture() -> VerifiablePresentationV1 {
        let global_context = GlobalContext::generate("Test".into());

        let id_cred = fixtures::identity_credentials_fixture(default_attributes(), &global_context);

        let request = verification_request_to_verifiable_presentation_request_identity(
            &id_cred,
            &verification_request_fixture(),
        );

        let id_cred = fixtures::identity_credentials_fixture(default_attributes(), &global_context);

        generate_and_prove_presentation_identity(&id_cred, request)
    }

    pub fn verification_audit_record_fixture() -> VerificationAuditRecord {
        let request_data = verification_request_data_fixture();

        let verification_request = VerificationRequest {
            context: request_data.context,
            subject_claims: request_data.subject_claims,
            anchor_transaction_hash: hashes::TransactionHash::new([2u8; 32]),
        };

        let presentation = verifiable_presentation_fixture();

        let id = "MyUUID".to_string();

        VerificationAuditRecord::new(id, verification_request, presentation)
    }

    pub fn verification_audit_anchor_fixture() -> VerificationAuditAnchor {
        let verification_audit_anchor: VerificationAuditRecord =
            verification_audit_record_fixture();

        let mut public_info = HashMap::new();
        public_info.insert("key".to_string(), cbor::value::Value::Positive(4u64));

        verification_audit_anchor.to_anchor(Some(public_info))
    }
}
