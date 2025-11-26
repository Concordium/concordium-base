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
          "proofValue": "0000000000000006010098ad4f48bcd0cf5440853e520858603f16058ee0fc1afdc3efe98abe98771e23c000d19119c28d704a5916929f66f2a30200abb05a0ff79b3b06f912f0ec642268d3a1ad1cdf4f050ab7d55c795aa1ab771f4be29f29134e0d7709566f9b2468805f03009158599821c271588f24e92db7ca30197ec5b0c901efaadd34cca707e56b9aab1a7f14e329816e2acf4d07a7edf1bd6b0400af07a1ba7a22bcb1602114921a48fa966a821354cd0dd63a87ce018caccc50b56f2c9f55a062cdc423657aa5cec8a4c9050100097465737476616c75650602aef4be258f8baca0ee44affd36bc9ca6299cc811ac6cb77d10792ff546153d6a84c0c0e030b131ed29111911794174859966f6ba8cafaf228cb921351c2cbc84358c0fa946ca862f8e30d920e46397bf96b56f50b66ae9c93953dc24de2904640000000000000004a547c8619f3ff2670efbefb21281e459b7cc9766c4f377f78e9f97e2c50569a8dcb155f2a502e936d2cb6ef1a73e92af9916e6353b7127d55bb525cb18074b5ec130463e03a4eda583b05c2d63db40a08ab8bf05f930ec234cc2f788d5f5bfbeab3e4881918ce964ffd55483219edd435ac865286bfd313cd834aabfa8061d2ae173cbe4b59ab2bda78faa4c2c937afba80d7fba0822579ac0ef6915f4820f968a74f00ff5ab74e90b0a7bcb2b92093a5e94a54aea1d48ffd1e5bb3fb48069bc8686fc39256b42d9078c37efbea87c1fd885cc40b86c6b6842aeaad30238698800000005000000013c26f1e7570b8e3ad601d332bbb9c35831adb9df15067d5f237d446a2e8153b70ba3653e0fafbc842cd1e99db48a2e28bfe28a735da15c3689cfab8996b88e3d19def84044ea3ac4f735857236767a1d0ee12b4de9015534ef867bce670cc1f20000000233507984f62b349c5ce61a9bf04d3cf7b379773c6177817bbc625a3bf6b86a59589ce33c6f93efd633a9dc041b05cbf8af3572c63a2b50daa60e0dfc866087b5023f96284d7217fb62b277166a19e2adaee7c82f9d0dd42aeaded693720be7e5000000033583e65be2844c92f97eb3b7ea0a0b30e6b2c6e03ecfebb2f0f742115ab16c7931380522321ed887458603ed2dd6b3f4895e0f86b58688ebd1f57b53067cad3a32cfbaba3e4368b4eb662f6159b492e0799577f999dbdc0a3490c0b5649b0fd1000000042bb84fe8775902b247a49a581a92ece9486f4ea11d95812faf9df8b40bf4628f2a6d155cf7426f0e83a8a68e255b1fddbc68b6a4eb78eb28c608fecf4770f66e26201f17689c9cb9d6f5b62080152ee5befed2d8bf8911ae018c9648ffe2938800000005510ca234128a8adfd4321be100d1694ffde3492638da333347572d91f3f357b9468f520e552954f5130a40513cca4fe1f33f5222ad2353e9b3a7e9f59aba7a673a36152765fa2b13d9551a38c0738f13c01e1f2f254c222540aa06199e2ea42f48ca21e75e7218e80d73cfa9ebe7201df9290a453f08def04a62c605417635030000000c002bceb59abdabc30e3b70290ac19593074e9d7f961efeca01fee2ef20b57f02d555844560253d558a449ce90462d6b1e1c2e7a26048fce2e1e4c31903dd45a7cf026d703a25aa6c7d7fa7c01dafacbe8dfa2eb1687ea31f871065ce0b2d2415fd5701010102264a9a01ce2ca3e74b6c2f655962ca0f085e4e4bb2ef80a3ec063bbe1e42e525000d49e88a1dc318b16f4d9d5bcd14bd4bf2c42ddefcf76ba82bab7dbedc18b0fd194ff722105fe1becfe4d00fe4393a095bb16488eed6ac63d4e819b30c8f8c61005e46e26cd70fa7e980478bb030e670c4dfeef74d4432032ca2f84c38f7f3f46536dd55990d58db28c331391288bf92d66fd313b52837eec7046349d513e5ede0003297c35d8a68126638e98790eda7760155a8b7f60606bfb5bfed718aef68d2ca546f29035ccaa4844b807cba88f75692604fdbab294ee34230acecb332d0630200639f8ee330a373814e58ccc9dfbd6be0da6b8ba48c682c3a9ac0203f7180dd1e131351d06fdb63543b10163d1bbe98c059aa3af441741b96a8504c55a052daee0102002ca2eaf66f108739028e28aaf41cc51035724127467ef995bab1fe02c51231000000000000000502803596b4ba5ea05b1fea2b78e292f935d621453cffcd207e10f3072b2813ca3e963cebf05b19cd82da4bd5aad1dcc7fda1492d7ffc8f532bc4b37e9bf4753b7ae6b8f08e05a851052fc6ac7617ce68293678747d11f9a508bab6f7a60edde9c4b2b0c42b0f664e4bcf343ec942ad3a3f4a5ecb36839f56bff87c2426c4f0555555c8cfdfd332fb47efe94beea2bb1fc1a6d1d3a913881f6e526249330bf9a475a1e284544d68d2479cd5c225ee735aef5e5ace0d6b3b34c94c35352ae850d8d46ac2f9c6e79ce6649675df832606b5950f8fce0e2885b9d5803ad04192d29a290cabcb0e335535226b00486425d3be8c6e99a9bc3943179b26bcf1cbfd0cfb5629c4275cf8be413c044780587151c2e8b47d01c30caed3080fe25dd211f1ac8400000007a9ee8e6929639d7c7334458021546461c7074d514d4d233c3cb0a390c4ce8a6929865e02aa9e75cfc06330c369b999b3a0092e894284e919e928018bf6f9fc59e2efa0723e178f0554b2cfd03f7b84b41bc1f7fde0eb14bb0b64aeb2aaba5365aa90f01c2b87050e47cecc06e03c630d70c4b77afbde8684b2625f36db1aa4b32d55790329b8b071867e3243f05ecc1d951b6b46f48dde51e330c8c53aeed4d3a8b0e1efe15549160104a266c0ec380719c341c179b6c84ab729a870e47b4a2a85d3d1f7b65b0674eb5ea8e2031aca456f0c486978edc6303cf99712f0441aecaaebf0af4224afeb8b00daf9086c9438a0496a2022412308d90382360e62b136202da01b49fe8fe8f06184ec135ec74780ed1390515b1670a056679a6aa14e5e82076f1d1dfdd7eb4b15b05e61de916094e0b03d904ff4d278e1196d63fa3ff41b859bdff9812c2c8fa5d471337e5637b5e3d951973bdb84ebc34c77008a9a07834144ef2f1f43b6cf21a5ca2caf2a2d6e2a626a5232297878e063994943e55786137afa8b9ed43cb0193b2da7de8494310d179a29c214533285fb7f4626570e9154733292075ce80efa787df24eb3158dc4f9f2062cdd21b8bf602d7796b3efc85e49aba74d1b12b3e3d81ac9546c4644b136eb7c9284461dcfd64e86b817a89993e8380b1caa6705b873f874ec55e44734d03857715016a28d0fcdb4ae859b5e9459ff54f27c22a007e150eb951bdd87973e67517a5b3e858019d99c070cf15bd98394277aa86632769bb1f06f520777a5c3cf93fc3e9ed0aea1a25ee7b23f9991c99d0de14bf926378685662fb7d69f99d38954b433b45a09d500862369bdc4843ba94e0571f5c0fd4b1a45d7cdfc94bc4974626a3d306c0a0d0fe432f61e1735b8cd381ff71ae284ef761d80e151962a600fa1685e773cf2ef362d2844d73ceece02844bf20baa65aa79308e5d9b0ded37e246e1ace76438b1292ac7d78550729d68fd04a3bf974264785cf0fa2cf5e0f8bcca94a3771c466d0763e410b1039035240c33b7dec4981aa53e914f67ac932328b31f3fc4d0aac1c19a4da4dab1b525a63008d0e40b86076a1b7e9f0f219955c76798ae8d5131eee35e9900c5cdc8b58badd7022044521d7ad239a91bb2ae1a02fc61472f7d3629d14070641a1eb12db115593e2e2b5fc167962dfafe209fc006a112a42237794cfa2e915a90991364919ab89b3fd7b523fda624bf0b3da77b1964ab8c7f32ff2d305348bbec302152932228963226b197703be314b4fccd2c8c9e4384038e5bb7028e449e37cc3939b5302187fc21fd2918392f549f852c573f32b4fc55d84a27acbb8f910f6e660439b07f061a86c4197e4b70631edb869f5b4050767a8625ce1dbfd6127d04289a671b1bf343f5cba72d154bcd3c5c35cf06f92bccbd940c4651e344406a5b0000000288522a84e55bc513f4ca48849428ef9f956a26ce1f0eb739e49d1b57c97d57cf15af9116cfe49ee5196a533d487fcc5c98230612cb382cd1e49ae60d012d0f6c6985e77c0bfcd1687cd89ba2e66932768a628da4afe63c1378b490ef2551d0a187a1e01dce092b0c8acff2b1df84f75cd09539c5abd90642bfda99a648fb9551248131a0eb457743af0d58b958423836ad5dd1615920f8acf1f2c688c9316e7cdf6440cc41385cc0d862b83ffe0af503ab694152fb829871b31bebaac20bb0a1715d28c811c0a9769d5edf16f7d5a306dc18a006e5e6de36d5a65d575b975e69100cb92dc287cc9f96392dc333a2a835cf15898127da44ff241b278d16f190f20487cbd29bfc97194ed8868ed4e458c7b2bf8ab6f04efee532502cf588c4f26b9b2830baa635c56857be5fd6803fd35d508881bd7cf3b5872ff84640384e2576bd93d4d86fdafcba2df3f29036491573031ede2ddb09dd092ad890a68f07876aee8b7d4f3cd01356db57bfc20fb2fc248b8aa5b5c272947abb3848a0ff0b8c0a7ea9ca608c88abf84cec05736f29dac8f494c68c9ac9d2729b99558481db1844b8c59a0ae1b2c3c03ad9091867841fb547a648b03a29fc981d3b776836e55e96301ba62e26162eedbade649030ac2a9159dd34111ddae649f5f7de192a5fe647d138bcdecf6c3c8ed141f8de4456b6417e7d61ada423df9979eb379192788acabd2abda66af33ad18d39e14fcf9178421c9d96adefaf25c7767d812c2b5cd8e69400000002b1afe618ab0194e831229483914d84b7e3dafd2e23eb661ada31a871212ff99ed369bd418720f213725334ee0cd84f95b8335d2d2d436d54c1320bc90ccf9924607fc27f19704fa7818673da4bd0813c773b9e1edaee40ecce0958925b3f6b8b967e6072b376a6d3ce64d8fb95338304b46b914e474b7a4cfd59ee7706a9357a76ce92c2d00e711bbc524cee09c534ce814460d87b7470d03e25dd08bb0bbc825adcd9f66cf1b2138e741c1a022314a28cdc6ed9f4ad02658003e23c04fb42ac66ac5ad6470723b5a67e3e1926f45eb14b9af215b3bb28a190f665cd1fcb6fa64c3d631299695d9534be64cde4ae46d70a17bbb8b2aaa9c71b48025131ad3b3902b387e119ec10c4a8963ee52710d75c21710881bae7fb5a8595fd43a9156419f8080891e50139bd4af14f1ba25ebe0152b5e83d115be493372e147742d8bfe3a8269e8ecd27ec055a11055d5405192cda8c8db528f06b120fc2e3f47089897411a97c0d726fbfa85f94141abd5ba2077e7056928ced031005efda3b6ac53b75163fe6474e558d4248967488941dec796d8e02cccd22a907a34219254b2febe0e6a7e1b9ca1ceb47515a3c827020b682562a6360c9270243244b9805c00ef24464072e5d636ed9eb2e4c020256425b4860cd2bc0cb48ed3ba171bc0b3bcf2739f42b8999615ecbabcc61abd860fde30f279f88dcec4aeac2a3fbdb95d75f3f124c0195245ad176aad3ff0d6bb4d6357bd34c772c11a3b70e23bb74c18062a2144500000007977f36ad0224878709df8ab94ec4bb86e738816e72f29aab307be192de4351f2f8de29757395bcade5d5497dc8ebe18981bbe8c651d926007cd1df483e3e70e60706b092b091616f5624e6c0b44593c471e2ebebd239a814fcb3fbd16293241ea586fa3ec47029be2698a45c652dbc190a9bf1eb4b06b51dbea0755a0f8a6cb9c622ad9e03dc83e887694e87cccefa23ab070673cfa7b9ad54a4f7fa4343565da7e9575467283b9a8c82381418d2d4e426161b11f4714924f86916618b7b8251a1bf436578791d3beab78fe969a0b2504cb046dd9513bd23ee40797f49fad186964572c4fff0164783c40725667791d09376e2dc0ccb83954c8f16147f68350a2393dcbe707e87f740e5301171c152824cdab75110d13c29063caaaf4a155e41833f1be03275f2e677322861094eb5acb281e6af8665df37fa359e4a1d84ab5d5fff7e71d8f1d77f45b0f9412c117b3bae6d238024bf89ab60da2e7e7a467be2a7611d53dabb3c00e095d1732c787e05b861d10169c2828026023f35568b14fb9843b4b2bc40ee2dd0764b83d8107d3a9f35c93ec6e2f76293821d447e9e6486128eeb886f60b3ee3cec7c5bd5857540a3de5ba73d8cf08683efa9810b5ce5039de30155d3479cf475c0e6ab6e92dafa254e7c213ee15e214bcdf0408664c89986fa429f0647c71aed6c3bad7deaaa888503ad57d87d96e76a35442aab90dc396667e8cc66560a92f6084fbf9fb86ada861f13fbd25b5b3640698d7bd77d0128ab0cd675f396259761fe588c09d8819d7b2a72ef2225c20cbf9955f4840cafaa87e3e8a241e3b61e2e2d709a372f9ce749e29c591f8a42e29afc9e0ee7bdbb4319d452cdc62b349b7c3d776119c0de54837e43987a3645162e3d61aa5cae315e3e51407f4665ae2b0989ee607fb02c1a8425e955b4c9ed3315689a3750630fbc5aa63a24c5c3b1610276bd1eb2f4a99f53ee6fc354cb14a3a10a1d2dd307d7800be3f64977023e8b5cdd9d7a7588ffea391f4370b56032062f1d33c90f89a15d01",
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
        assert_eq!(hex::encode(&cbor), "a46468617368582081bd9a90e378357169599e5a70af14e1fd004383ea326738daf808c505600509647479706566434344564141667075626c6963a1636b6579046776657273696f6e01");
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
                "81bd9a90e378357169599e5a70af14e1fd004383ea326738daf808c505600509",
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
