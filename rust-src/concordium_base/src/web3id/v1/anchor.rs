//! Implements verification of presentations against an anchored verification request and
//! defines the types verification request anchor (VRA) and verification audit anchor (VAA)
//!
//! The module defines a higher level verification flow that adds additional verifications
//! to the cryptographic verification.

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
use crate::{common, hashes, id};
use concordium_base_derive::{CborDeserialize, CborSerialize};
use concordium_contracts_common::hashes::{HashBytes, HashFromStrError};
use serde::de::Error;
use serde::ser::SerializeMap;
use sha2::Digest;
use std::collections::HashMap;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

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
    pub fn new_simple(nonce: Nonce, connection_id: String, context_string: String) -> Self {
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

/// Nonce used in verification request. Should be randomly generated such that the
/// context in the verification request cannot be obtained from the request anchor hash
/// by trying different preimages of the hash.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, common::Serialize)]
#[repr(transparent)]
pub struct Nonce(pub [u8; 32]);

/// Error parsing nonce
#[derive(Debug, thiserror::Error)]
#[error("parse nonce: {0}")]
pub struct NonceParseError(String);

impl FromStr for Nonce {
    type Err = NonceParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex_decoded = hex::decode(s).map_err(|err| NonceParseError(err.to_string()))?;
        let bytes = hex_decoded
            .try_into()
            .map_err(|_| NonceParseError("invalid length".to_string()))?;
        Ok(Nonce(bytes))
    }
}

impl Display for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.0.iter() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl serde::Serialize for Nonce {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for Nonce {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let str = Cow::<'de, str>::deserialize(deserializer)?;
        str.parse().map_err(D::Error::custom)
    }
}

/// A statically labeled and statically typed context value. Is used
/// in [`VerificationRequest`] context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabeledContextProperty {
    /// Cryptographic nonce context which should be of length 32 bytes. Should be randomly
    /// generated, see [`Nonce`].
    Nonce(Nonce),
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

/// Error parsing nonce
#[derive(Debug, thiserror::Error)]
pub enum ParsePropertyValueError {
    #[error("parse nonce property value: {0}")]
    ParseNonce(#[from] NonceParseError),
    #[error("parse hash property value: {0}")]
    ParseHash(#[from] HashFromStrError),
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
    ) -> Result<Self, ParsePropertyValueError> {
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
    ) -> Result<Self, ParseContextPropertyError> {
        let label = prop.label.parse()?;
        Ok(Self::try_from_label_and_value_str(label, &prop.context)?)
    }
}

/// Error parsing the dynamically typed [`ContextProperty`] to [`LabeledContextProperty`].
#[derive(Debug, thiserror::Error)]
pub enum ParseContextPropertyError {
    #[error("parse label: {0}")]
    ParseLabel(#[from] UnknownContextLabelError),
    #[error("parse value: {0}")]
    ParseValue(#[from] ParsePropertyValueError),
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
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

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
          "proofValue": "0000000000000006010098ad4f48bcd0cf5440853e520858603f16058ee0fc1afdc3efe98abe98771e23c000d19119c28d704a5916929f66f2a30200abb05a0ff79b3b06f912f0ec642268d3a1ad1cdf4f050ab7d55c795aa1ab771f4be29f29134e0d7709566f9b2468805f03009158599821c271588f24e92db7ca30197ec5b0c901efaadd34cca707e56b9aab1a7f14e329816e2acf4d07a7edf1bd6b0400af07a1ba7a22bcb1602114921a48fa966a821354cd0dd63a87ce018caccc50b56f2c9f55a062cdc423657aa5cec8a4c9050100097465737476616c75650602aef4be258f8baca0ee44affd36bc9ca6299cc811ac6cb77d10792ff546153d6a84c0c0e030b131ed29111911794174859966f6ba8cafaf228cb921351c2cbc84358c0fa946ca862f8e30d920e46397bf96b56f50b66ae9c93953dc24de2904640000000000000004a547c8619f3ff2670efbefb21281e459b7cc9766c4f377f78e9f97e2c50569a8dcb155f2a502e936d2cb6ef1a73e92af9916e6353b7127d55bb525cb18074b5ec130463e03a4eda583b05c2d63db40a08ab8bf05f930ec234cc2f788d5f5bfbeab3e4881918ce964ffd55483219edd435ac865286bfd313cd834aabfa8061d2ae173cbe4b59ab2bda78faa4c2c937afba80d7fba0822579ac0ef6915f4820f968a74f00ff5ab74e90b0a7bcb2b92093a5e94a54aea1d48ffd1e5bb3fb48069bc8a3c5994b768eec8fe6aea7422b208e8167d1baac746a147148d64214f29909c00000005000000013611d8317f5d7e7fe664dfb14bd4a96e7937ed67de385acacb15ffff3a99cc892df76dd074efecad1e6515831e4b1ec778cd8d2da5aebc15fb5c7bccb3821169132da1660bec909f4ac6e09f3c0f6240fe6e01fde4d6ee52a70f4d8e49a40bcf000000021ab19f671563117ad0fcb561cf74382eb4af7ca968ba235cc651504ba4dd494b319215d7739191f254ee4948a7b011539fdfb99af441f7bcb593dcae25d564db670c7e6b7717950abd02db9ceee5b7d53737618ec4e09da403c2c509d126caee000000033e6c099e09eb27f21d93e1bd089c893e315a3c67265b885436b9679e102e2a55140b5127ed5c437b7e2767c45b7ffd50e34609235b6166bd3b9b7f7f24f056e75c8758c979c197f0049b7b3fd2e0eb76b1a450449b74d9dc0b6ce86a7694870c000000046f2801039ba3be90a43ebea75250e647f4cf059e8f31a6a110cb1588365556e9170b69418fd565551d60d3e98c6a25d345d5f11d8d8be4e368a013e662de5c296eab8ec4ca9a86278b435d63f733d93157de64b80d4124d238b780d382ba26f40000000547a3e190d199824f5ac60691d5a8891d2927b7d4c0a822ee7bfcbaeb7c8e08d15d8342ab285881e5ecdaffe89998ac605b001ef4f2999f9390aa8fcbb2c408b22c447a1bc21a5eaa5c14c6dcacf33121b5fe53aaf6129895c033aa22d78868c033b5e05df1cb5fa44901ec217a94c7c839abb17fafba113a745dd37e6d424fd40000000c00563335ce3be272031c7bfaf658ee24d1c5034576d80825c06bf4539eca4921980bfb1e4079d68736f26ee2e7f08d6ba6e58fc43e0207e2a151d47d82f20fc6910209a63b45c21f41c9c95c59da2cfa9646e2694e2cc835441b29188f1519f73b4a010101020f4d02af83526c2bdad4e86a66337dc9c818e1a3ec13d1df09cc7b17766e639a00423ce5c7937023ee8da438f9c54e087be280494edb4d104c527b63868b27a8f22dc0271521a65a32dc88989947f5b92f9df35bc024f6a9e0fd2048c424dee66600637632095291f1069b034ce85d2ffb8e378c0ed6c3718288a1fafc7b740ef1ab6af8ac0efb4d57b305e580ebca489307927a3cc6e4103c2fc690143c6b49e32e0048085153d8b392da92841612799165e7dc7f11fb79260d777ce2be2093cb6abe2d0fee3c51fe931ece33231e64fd157a9075e46b390c6034e9d1092fb7f54010000f4f82dc331afe2bec7dae2224c5dc2f48672aa702d1393feb8506cb053e6de849d151a88a252bba3c61375ae3115b976e9766e6eec2ed58ecb58cd6090d860601022b0a1e8bbb07aea43fd95f51d06a6a76cb92f1686daa5441f913d226c7cd55a0000000000000000502803596b4ba5ea05b1fea2b78e292f935d621453cffcd207e10f3072b2813ca3e963cebf05b19cd82da4bd5aad1dcc7fda1492d7ffc8f532bc4b37e9bf4753b7ae6b8f08e05a851052fc6ac7617ce68293678747d11f9a508bab6f7a60edde9c4b3637248644343e17b1925ae5b646201871d5bf9284509687fc88d5b8b637d75f601c12010f145d8a63f505d7e82e2d992c005cf70a37d099d6b077d4daa89786630eafe881f4179ca6f691a02d9a0b252b51a0f720d56527dee9e2eb76c64bc2afd13518eb9a4a9da74583aea387f165dbd0de9bf5cfc7f0ded32823a3bd1262968d7b7c187847720aa8283d75c3b6889cf377551123f951f0421ef1e23d8da17f9435c24a6d7f80f0473d6c6f0962bb26b02ae06318c6793e5d7d88ed6a83f00000007906d504f1c33cc09e1b23357e439cb1530aa2f3a84acbdb13cedf9c9c4a8248b1d139719566508a427cece0c11cd4ea9a9ede51badf9a23af022cf949adbea2425a7c8a2b1a330992fb51f42251c183dd9ea7620ecd22f1a5de743385cf981308f38c286d8fef790b59dd56a9b9fc0daf85bd7156f5526dd76e185362bb8eb77e3873c7d8d9d8ec02ddb0b6635bed14ea639d1b450b82f2151497f4dd5ff4fa5147d2189a7d76083f037fd2b188f1a7e64be188f1108441f9c734a30869ee6f994f7b58cedd6ffc267333a228ece5af5efebea335272e07ba2639da4b1db916807ccb56e614618a6d6a80e4b1bb90614a5575ccf209ff423668b169e5c6c339ac9b9806d1f1aee2712643f1c2e8d4d3ab142f3d544a5a420fd95fab2a7f9485ba06b6e7183332c307b764bc3efb1328993c11e731f00bc5fa52f331b9beda38420ce031b496aa9c0601cac5ce88ad96fa7182f4bc37f3c55b5d0335f0bbae7f790a90d5a1dd9223fba087f30b2fd559436f34bfdc2fde7bf4114f3f1176bcf86ac987a4f67f72450465149a47614a2ac5cd896368ae130a69609368b3c51cb9ec2c6c93fe38b8b30b1f640cbd3f5fa12876a30cd7ae255c714317ded74e4560db84a83ac48b667dc2d2ab822e2e1ffdda2fef0c3224f8796c73b01c11868fe97a3164f7f6273c7a8ae7b896c233073886b8201557aebdd6eb9c185d1840376b79d986682269702a27532aaa7908f73cda14f76d41dd0c28fe2bb1e24783900290e41ba730adeff83eecfe8017cbc68b5dd0a28dff847ff9553537401b14f5ef8acfefb4d9f508ff996668ee48719bf01837149a2486c8664df6c3dceea0cb70670d5a6912419343577db2fa0350318b4ab6d687dc8f9cb2953b8ea16f0a47cd05ef5109b3e1df46272023e8e4c4afec00f6c13dae62dbd723615a391ccd4717a1296a6c81d1d81f63a8a51efc3707b824286bbe306e317cf2b41bc35660fed74698782d282d2f69ac1c1f31fb89e1ab76e7317de765e001b2db373e1f055c5a0039035240c33b7dec4981aa53e914f67ac932328b31f3fc4d0aac1c19a4da4dab1b525a63008d0e40b86076a1b7e9f0f219955c76798ae8d5131eee35e9900c5cdc8b58badd7022044521d7ad239a91bb2ae1a02fc61472f7d3629d14070641a1eaaa06cfe8c01b96f2254b36a1e7a445f0805b302bab4a1ecda6016acd72efe6ecf261bad14a2431c531e993b3d4edec087cb5b0309f7319144d4b02cfe57a68949b0727de4dea9d1af3e6dbe8ed19bac11a8550e09cd8fe7423606bbcd111d930a6b695031be96c52eed85183e8526e48b9767739fbe92537742461e74076e3d5d70057b84f7963edb32772d5a981acc48fbf1dfa5806489194d6e22691bc11744ffb8266dfd7b409491df1a49c45faf85142788f22862f4584e4f49f381b3a800000002895eb0d679eba6b7539e8a2b0b1593c83b27eac57a909c956c70edc6194cdc5f1ffc68f199a3827fd6d51a6f92a7867c8db5d07f65e3670f828988a749df72aa80ef3823fff83cbab6b522fc1afc3a93d8d2803e6001f19d3704b2cddb98e9f1b9365f7588bb1ddbfc1340e80b170bb11617ad54880298559b2ac1daf12fc471ea99eb1b56a8de4872f833e978453a8788fbb260bf39c041ffa245b63cd346e5c81e4fa28faf45a06d1b9c52466965bb06656084cb352f77a2daa642658b3b20551173ad0ad5875a56c8fac0b4ba34c299c8eed82801262003b39ba5175627274148b7ceb112d4a60595ece65ec79a344640182ccf47f460c0abde90a395c8d30487cbd29bfc97194ed8868ed4e458c7b2bf8ab6f04efee532502cf588c4f26b9b2830baa635c56857be5fd6803fd35d508881bd7cf3b5872ff84640384e2576bd93d4d86fdafcba2df3f29036491573031ede2ddb09dd092ad890a68f07876aeeae64ac01d87cfd5b294df3604878d69c638415a713c448ea07c33ce8ee8def76defce22f36b1938c065375a4ff3dc3f3a287286ba2af7313c1ee8458a4a1d37b8c047b348321dd2fc7686161fa590066053cb19a074c9ebdb3dc901c419dba9c1eb54e1848c57956d524ed9988ec72c9dc3b6e2dae09ba5d5bb6def93cc94d01385855e2d07c2ca376bebe2e8d985866408bf6aa8e5f09e083e0e955d18a4c0a2f815ef41d55b3a5542059475e7ae32c006874827c4714abe9bf685acea9c8d200000002889d435b67a7d22a5e89dcde9e74854edbfd4b8906484b9f8838ce87ecc08e0f85c1df44034803872580e6cc59588fa98d3ddf938916ef2a168e61a2a02cbd4d719cb604a8d63faa6eca2e0c140d9a5e198c62eafa21848a9f977e92e9588a06b496235e3809417f4ac918e86211454b646eb8be272f48b503b40e58bf3c71919e30838fe4ebd5e6bdb74d51b772a8c582781302207fedc6fb0cf6e16cbc268fafb14539d567e7d1d75745888631a7eb4a9960df79a76d6224b2b8ecfffcfb351059e7e9e5151c41ee44f0fd8d2f9dbc6015e8f635078a0e9956d96a3116829d73e40244ae0bdf2e3f29a0518651c4c5b7c1e28f58bf427c41817d6474b8898102b387e119ec10c4a8963ee52710d75c21710881bae7fb5a8595fd43a9156419f8080891e50139bd4af14f1ba25ebe0152b5e83d115be493372e147742d8bfe3a8269e8ecd27ec055a11055d5405192cda8c8db528f06b120fc2e3f4708989741199065975bd9bffa642c317a3579783739fe66d2f738d43d39a25b5a33e06dc7879a5cc876541b617a913d50245f764b6b4b4a2fb1203c1174d39433137bb356f715cd5c8825d00e6192a3cbc78695374a2e8a7819dd1467bcec221251212a3782fd9d837f48b30b1de67becb0138eef162bbf1dc9641a8ccaaed97da8e253c501ae725c2e8b57e431e73e4b0f78a527a731f3663fa401cc7ab36aaadb095ed1255b51a600ffed9e5062b10905648089a4de17ccfaa8ecd73007a58516b3e758600000007ad7f37adf760c84b9675bb6e973fcb08cb08027049ac8d3ff522e5401ef7c83530def9308baf50fabd8c15360bddf704ac0b749c36c320eeb495cbc8daf41bf295c25a1646fe4b78f2c2eb3356877aeb57840f486b6192fd08397a72c3c94c7491ced14d277013dd038254f32a5c9b73ace5d919f7431d32c80c08658da8d002d10dcfb9d7c8fb742795df16e91e35fc832e498220be36f84ed8f89736d4d766a43477700e12904118db7992a814a6c9000c4ea11d93bbd41a64a77190131d9c86fba98f9f650002ff6bd1d2a82754ea85d30fd1002fd7da18dbcdd3323a18c88468750dbf5dec7e0904e7535ab48570a3e7a9f665c3b2dfb72b5da2adf39da4747ee3020b520add6925aa1a5c440e0a57954e43773240991a1f34e971fa70c5991e30f96c8ba34d075d47b3c0162f6068f5eb3df5802a05ce5fc9461a51edbda829ef8607eca819c13ca9e4459de90682e07af1b1c338d2359663a14e01b91c8495d97d3081c1badea61e58fb7c62c116203ecc7f26c04c9deb9cabdf7bb0cdaf2b8d6885d74b5d76e9fe07d3034d7b887cb7cd3603c58451d35542a2a72e65fe01e52511d0c607dedc3a6053ce655ea136af1a8b1daede59882b89e1c29ccba301e876d2e958ce6089a689bfb11a5592d00ff33d4a3bab6d883f522260c313b59b87e42ce6d5679c8b67178154d99a4a03cf36ebaebb1171403ac37ab45e166ffcab0624b2b69600617ca8be26764881e4f6c6eb0237b48148cd8e5aae3c09d22a6e4e527e13667a803f38aeae50bb8d973634048885a02190af2914add80ab4cf36ec411934987bfb2ec3da1e3619f249a6c694e88ae070ce0935340a6d8a67bd21db8dba4cbf04af35b15404d37f8479acd122d2bffa17e890c0b2448f3bee34cd46eaa0b5d7132dbaa2f8b25cad41f7a8184fbcd306f422fa9f0bf1b37f3789633d68b97ad4527bf36d5a2fac68c4316b74c098be94b6743a3dfc0e00a713a8e7b9dcd50c002a87b4207705c6f70dae2a0730613cd834f882c43f721d6401",
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
        assert_eq!(hex::encode(&cbor), "a464686173685820b3793f06e85809ae98f422cdcb5f508b4d5cd78f5a1732cd95d82a54f2b32037647479706566434344564141667075626c6963a1636b6579046776657273696f6e01");
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
                "b3793f06e85809ae98f422cdcb5f508b4d5cd78f5a1732cd95d82a54f2b32037",
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
            Nonce(super::Nonce([1u8; 32])),
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
            Nonce(super::Nonce([1u8; 32])),
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
            Nonce(super::Nonce([1u8; 32])),
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

    #[test]
    fn test_nonce_string_roundtrip() {
        let mut rng = StdRng::seed_from_u64(0);
        let nonce = Nonce(rng.gen());
        let string = nonce.to_string();
        let nonce_parsed: Nonce = string.parse().unwrap();
        assert_eq!(nonce_parsed, nonce);
    }

    #[test]
    fn test_nonce_json_roundtrip() {
        let mut rng = StdRng::seed_from_u64(0);
        let nonce = Nonce(rng.gen());
        let json = serde_json::to_string(&nonce).unwrap();
        let nonce_deserialized: Nonce = serde_json::from_str(&json).unwrap();
        assert_eq!(nonce_deserialized, nonce);
    }
}

#[cfg(test)]
#[allow(dead_code)] // todo ar remove again
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

    pub const NONCE: Nonce = Nonce([1u8; 32]);
    pub const VRA_BLOCK_HASH: LazyLock<hashes::BlockHash> =
        LazyLock::new(|| hashes::BlockHash::from([2u8; 32]));
    pub const VRA_TXN_HASH: LazyLock<hashes::TransactionHash> =
        LazyLock::new(|| hashes::TransactionHash::from([5u8; 32]));

    pub use crate::web3id::v1::fixtures::*;

    pub fn unfilled_context_fixture() -> UnfilledContextInformation {
        UnfilledContextInformationBuilder::new_simple(
            NONCE,
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
