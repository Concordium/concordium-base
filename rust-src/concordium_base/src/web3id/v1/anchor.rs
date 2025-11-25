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
          "proofValue": "0000000000000006010098ad4f48bcd0cf5440853e520858603f16058ee0fc1afdc3efe98abe98771e23c000d19119c28d704a5916929f66f2a30200abb05a0ff79b3b06f912f0ec642268d3a1ad1cdf4f050ab7d55c795aa1ab771f4be29f29134e0d7709566f9b2468805f03009158599821c271588f24e92db7ca30197ec5b0c901efaadd34cca707e56b9aab1a7f14e329816e2acf4d07a7edf1bd6b0400af07a1ba7a22bcb1602114921a48fa966a821354cd0dd63a87ce018caccc50b56f2c9f55a062cdc423657aa5cec8a4c9050100097465737476616c75650602aef4be258f8baca0ee44affd36bc9ca6299cc811ac6cb77d10792ff546153d6a84c0c0e030b131ed29111911794174859966f6ba8cafaf228cb921351c2cbc84358c0fa946ca862f8e30d920e46397bf96b56f50b66ae9c93953dc24de2904640000000000000004a547c8619f3ff2670efbefb21281e459b7cc9766c4f377f78e9f97e2c50569a8dcb155f2a502e936d2cb6ef1a73e92af9916e6353b7127d55bb525cb18074b5ec130463e03a4eda583b05c2d63db40a08ab8bf05f930ec234cc2f788d5f5bfbeab3e4881918ce964ffd55483219edd435ac865286bfd313cd834aabfa8061d2ae173cbe4b59ab2bda78faa4c2c937afba80d7fba0822579ac0ef6915f4820f968a74f00ff5ab74e90b0a7bcb2b92093a5e94a54aea1d48ffd1e5bb3fb48069bce918947b0401f828565db1e1e51aa857ef93e03fa5ababc60cd4786d7a09634900000005000000012ce448b95daa378716adf0848b6ea854a371f8a640a27aae907a65e1d165b4df09aa5ed12957cf03b1d3e63d08f678e42d4741932fb8a68be3de3dc42052c332352bea7c1bc835e9610dd6ecd8df1fb78c5c175cd2a88a5ad4b4731993c2755400000002630a1133b728c97b192006c497ecaa7b547069790aab33afdfc83f83ba195fb53f964ea79dab2d0045d6ed96ed44e37d36092cff72896093383b0be9ca5b4d4205888ac87fd63f140e6af46eaff4d6f7b97df993db959ddfea2da9de2c614eeb000000033f555cc9e29211d7b6e0157dc9012fef3d0d7d741832ae5b5a871cdf86a16d6b19bad51c715218a9fd1cbccfd36ffd31954b70b61f224223554884554e94fb2e020c07103d39461b8d0f72b260869977dae7258753cc39aae01f668abd2030cc000000044edf6719f081fb79fcf6ad84c8345eda80969194af7eaca4b93469edd70590f85f18123730e9c397d0ae12a21236af34e6fd1422f50ccfd43858df85b8048b9734d96018a5f60a96f993f0c27dbfca86bcac0e8d43b33354b27d7e5c7877a5ac000000050d792f44183c862b920029f6676493d2826142a0efc12909fb25cf9bf65c5a395c2dcb0d0c0d0de256d634ecefed391c5c6f6abd6930cbd9579a9c3e32c7dc902fbf3973d776db8645328ca8e64f7989208dea27eacf54ad1723194a2a040f905696c2bfe78b0ec413d57aa4d0553e77ded504b4fe62cc36c47d6d4a86b5cfa60000000c0027725a72d2e64a1173bf298dcf55c676e05b25fdb2029536950b87cdf3d4d8025127ea383a77dc8d7cebe9877096e55154a548c7dc00ae167aebb1b11b9b7cfc023ff02d4e04a94e3f4f52a5dcb0e0f4ff42ec4dd82fdbafae5bdcdabcab5731b60101010226defceebd8ea21e70659e0d47156e9aafa0e8433825732220ea7c0c64f05f80006ee634d79329135d6e7ba852ed6f11bd8346ddbebb96e0024681aae104e161516c9104b5e1f3f4ce09805d9a6ac56165fc6e06b64b1009842a54fc268d88efeb004f7ce2fffb38f7b85cbff4d83175b7192ef53e497ac21e7a02c76c55ad09cf2a481dc049ec4b6c844984801d62ab5d0c48b59ca891124a42762b91b47c3be4e90020d451af64b35661fbc1b2c4758dc3999a26452142d418cc17c03d0fd54b7bd070b3729b387669e5ba643cc52237f94ccd83513cdf360533c95c0e9ec95d3321006ef4b2f6ea5557fec7a9e2add74baeb3e4eee4033df5f5fe36e5ad141bf06d596f834f74b7285f35675046152d9ed31e55bff88704790c15d1376b9d367eae490102526050662f7ce80610a9537cb546c5d9f6d70c2cf1868ea5f03e5cf6deb0f796000000000000000502803596b4ba5ea05b1fea2b78e292f935d621453cffcd207e10f3072b2813ca3e963cebf05b19cd82da4bd5aad1dcc7fda1492d7ffc8f532bc4b37e9bf4753b7ae6b8f08e05a851052fc6ac7617ce68293678747d11f9a508bab6f7a60edde9c4832a0fe5be28e50fb11eeb45ada1c695c32f32ca6770c0cbde453d35f27aeccb42c859a479428fa37977e6495dba22d2a26bcebabbc8d4608efdfcababdc2e4023775a5b4a036bbdc54c700947eb10a13dc6638380093a2ae32fbcd187759ae57210fdb66984ff3cbf005e211ff658d558e48520db37620ea4ff00300af4204b62f4cd1fadff410104c96f90db4d00d04d33eea519333697ac76ba0b8f58cc4f40080ae28bc9f6f6a2bab31997b3d6eb369410dea819480d625751f8e410acfc00000007b8fa84c66b844c262f4d87c05e6953ecd8eb1c2dbcb39e29785806b6e724444cec1c4631fafe2d443608e9d80d47268483b5d81b6a029b9c9649fd1b1c2ae2a3952ffe0d742a871f0d1c616d01a25739ea46932297339cbe4ead8fb80dc568fc83a7d525f6142e7bc8103573ed78d254eba1ef2efa52b702e97e77167d0be1cef32561ce45c7c39312ff9e4e4b1d22dfb93d00ec817a88fe25810bdd6f4e8c01c70b71176106a6a6dd462136bc3a864428a49e679341707c593efae6cd7c4dabb22af142f11717364291ac39418bbae54a1cbf388bd64f906ed1406a822bd9c7db49462c04efe016e51a74745c64bc0185782f409611c2dd92f08e0d7dc1eb0dea1e9435b739085462454d18e738bdde1fe076a0ca39256fc1327f479257093585f5affff4e6025362e02017164f1637144310ead68ce9c3ac0314508f564e2940f6c0844d0dad7fbfa5656d3cedb122b6ebd8e7382d1650e1858b089efcb881b5dd1cb90b0a70d5dada079298bed1c4656ca730b8aae399b6fdcfbd48e1ca34a5ac1a6aa26707161e1f93f0e441dd1fae1043eed5cbb0c57f4b387ffa8cbce7b7c970c9ac42e8e2c65174b10f2ba1b484c9ea785cfe0ee8ddd39519c35e9743c38e53b484e7ac0484b7762e7bf6b1aaf4d8a3b6f018bc67b62480bd404eee1eb4343460d1aa1847d16786e2b7f514b1086e7ab2af51290b7c02baf61761ed5c74e78287bd57c703dd28be90692f3c6f8d5680406f7a937798a144131519d71f61ce807b2b08b57e0086f49509a0c138e838cb8f43c05992c87e4a63c8b0cc8d98de91d2fdb7136c1ae9f1aa20a38c2e26453407caacd5ea8bf948f927c4b440a71dd3573add57d748f701a4d2d49472b57b1b9ab5947833e7848a1fe600367f4517a2a897bd31f12cfa9740d2bc2d49d84b2bd244dd818658b2a20822308b071e35161216b4cb110a40d250d8d0a1a3c468081db7d7405f3ec73760fc1c50c16c9fae68090727f52ca4d7ed19d7571e91309fa71cda8e88471d61177b55f4e5039035240c33b7dec4981aa53e914f67ac932328b31f3fc4d0aac1c19a4da4dab1b525a63008d0e40b86076a1b7e9f0f219955c76798ae8d5131eee35e9900c5cdc8b58badd7022044521d7ad239a91bb2ae1a02fc61472f7d3629d14070641a1eb0ae78b9d434a8d58901dafdb10f2a64139185d098d2fcc635495c59746302c665f5cd233c7a2af83135dc4c9d68c4dc907a48ea71e14e5940a31afad31331273c0b9b1a5f9135f7c3ac7da281227ec16ef4a44d3ea368d80efe22709a378ed90959f6cab2611b7fb357a5b97645ea72b798e9f1e191f4090e72b41ae1aa6feb33bfe631a37c4aed94bda117d3efae9f2112a2e01f36e1a9247b5ea2f13735440ba3b4471d203585873a2632fcc12617398d6ed2e0dc3f131a810c4c074c2fb700000002ab6c28f1723d6169913f2fee10bdd5ca0c0beb23e2f8df58bb2c66ebe3b6376a84748885a152584c39f7d043f7bd95428578a6d20213df102ba313d04144aec52c4b99e33e79371b78bb19912359dbfbf99f0b4bb1b41c3f46f62ecf461cdd909643a10b66b79d6a682b02c6dc0f4562a200008884830ae274b3808d1c5eb7c5821686098723f9d9c08b7bab607d91bea7ba82eaf6fde9323d88abec3b81b9b2208f014d7b044b019ecdb735538fccaaa3c1aa0a9b412feea2d7b454c62592920833c9b9f8f222e59082492a73f5ff331a55b0f7abb7690db49e685570ab256830f006753b41f3c24b192e079ba9dd9bbbca82beea28ca13bd7f64ada89264390487cbd29bfc97194ed8868ed4e458c7b2bf8ab6f04efee532502cf588c4f26b9b2830baa635c56857be5fd6803fd35d508881bd7cf3b5872ff84640384e2576bd93d4d86fdafcba2df3f29036491573031ede2ddb09dd092ad890a68f07876aee853d3fec93bbfc61b872b43b5e0ccac5ecf166b0770708e8d7ca8078b19dfcf4d3feebf4f962e0c69833338255e2dc2b8a2fb5b617875c72f21c30c492945f922375140d0a03c9bdd7329fa8b6d2666ff7b9a6effc7d6659aba3f27f92b8bf6f0950bb10453a522bc6062133552608efecdc132037309e88a155f72665dc6c0b48bf27b3cd3d215470d14c6579d7dd32a85f75b2c5687d0d349061924d01af5c550fa76e21935a60acfcf31ef1b8c6a4180833b89bcdb11728cce06c3c19078600000002b67cac0bc5add116b86ac8cca6abbfd80c07582e86e90d76ba6c6aa41d01d11a4ca907a634ee339cb5ee830719379885a774cbf76d65d324ae890313a1688b0cc161f6e0b47dbd0db2157a92739a20d028c30b6da5ec4ebb76e00c8a69fae0d4a8fe97431f898f3e65b4c43c619f36818c5de5db53b358d65002b96880a1de467f812a8b841a758315b0cfac32b9cea2912a04dd0a87ec3c2fa8d7ba2d739eb5945d79366faea8f118df235e57a83a144a507a8d74e39e1479cd320332aa88a5518f62e781c524e28f40c701dee87e94e8c8315b003c71e1976ab072e0178a91196c01b9e0c00da3b620a28b0f1b498989e6ec966c7718c62efea0b25cc2665202b387e119ec10c4a8963ee52710d75c21710881bae7fb5a8595fd43a9156419f8080891e50139bd4af14f1ba25ebe0152b5e83d115be493372e147742d8bfe3a8269e8ecd27ec055a11055d5405192cda8c8db528f06b120fc2e3f47089897411b92d9655a6d0766ec82ea392c7b6d1c05b00ccacf5e0ce8ac3418db4ff5b7f2def38ca2480f2dc03dc3defdb5c2eddcbb7abb0385359202fab02ff010884811e5f513504c482f30a6a41cf1a5e1eae4ea5fd7e83c6006dfd1859ebcf7ef69b5f3102f68b98b020431c735540f0faa51d05e380ba8be244af5d9208b0a659b6c23b42da958e514c545107c454f1f82e18e4f718be1ad9254fc4ba1d87de6d625b684497e14c6654b2d547d58e152800deb8a1d1ca39287461bb183c0b8cc529bc00000007970c4e8eedd5fcb380f4bdaaac76bfa3fc52b9fd9a8a40f3782355bd7bdab4999a32ee6fccf1ebc6dd7e54b21dad79bf981f13d11a242716793cc47ec6f0e19296135609cfcaaf472afcc4870df46c9b6f9f69cf1bc234757fba97a74c1cee84912a32caf9b90d7787d46b1c675be9dc0fe10f078835f36fece20295c1c890df280293fb1b7a9b2825f90b235dec576c90a953eb9f0aad4255e399ab2a4d179f6a7f8884679078de8a8a352af00ceb3a104a9b2222cf26cf3c889455adb606d0b34c7723950f6e26ad096b74b1f62a52b3bb1b0c8c770495e57a760f3e69c69501f898df1dcff10d726adfb09a26c821a268a7531e43a52ba39c1e3ac1d83a0a539308e37237e6b9d11ed659da956e2e49e4b9e73579fca7fb446777c8f52f49863620612e3de9d270364451c2f775dcd678d4ad2c0cebb4eeda7b41d5418b0d347087e168386a8a883b4d9a72a06e5daebdd392b3a306e5813c3e00b4af12d83154ece98ce449f2f479d6b2446b61c45dac93262381a68e276f8b6bfbb1fcf3aa50b209fca5d003daf725b635ea24c45e624ee2e0a83399ec513edbf66fb41f6cab206e68c4e5f30519ba581c65d2b7873b10a486c96fcb3824dd94d7448e747f27443ac395271aa177c2ddd9b16d24d29a4b4c7c9eff295741919aa4ccc9bf8437f3cad8668726f9b012dda2b87d5a61ecbbad868115389bd20fa945a604fc7bc28feb58f7dc49ec36293a80494f3eb8964a49c534346040cd47fd6e498fb3c2153ea6f059b751f9d5548ecb3bf3e1e33ec52bc52acd2298bd7141a6fe3e199036c7fa3377a20a9688e2731d98e402c6334892c0d3c2ab82ff1c2bbd928ce3ef57afa80568c69e005949b384d48c189539e2278acbc4580aa93e1dacc72daf67b709bc0384d54f8c7399b318a584100031954e79999c51f37d9541d0602e116953f7fcbffec6c850499751f9767f1c4be6238566565390e7c5a3732c65b35a149fddd3c10d6231e342c1771c9e35688f18874cb25ecda9299ed9763237c51701",
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
        assert_eq!(hex::encode(&cbor), "a4646861736858202b89c72a01903e99004e7968cfea1ba5a00980c04e09f2f6d60590a3b49839ac647479706566434344564141667075626c6963a1636b6579046776657273696f6e01");
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
                "2b89c72a01903e99004e7968cfea1ba5a00980c04e09f2f6d60590a3b49839ac",
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
