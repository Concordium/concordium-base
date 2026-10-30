//! Implements verification of presentations against an anchored verification request and
//! defines the types verification request anchor (VRA) and verification audit anchor (VAA)
//!
//! The module defines a higher level verification flow that adds additional verifications
//! to the cryptographic verification.

use crate::common::{cbor, Serialize};
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

mod verify;

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

    /// Add the subject claims request to the verification request data.
    pub fn subject_claims(
        mut self,
        subject_claims: impl IntoIterator<Item = RequestedSubjectClaims>,
    ) -> Self {
        for claim in subject_claims {
            self.subject_claims.push(claim);
        }
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
    /// a connection ID for session tracking, and a rescource ID for tracking the connected website.
    /// It requests BlockHash to be provided by the presenter.
    ///
    /// # Parameters
    ///
    /// - `nonce` Cryptographic nonce for preventing replay attacks.
    /// - `connectionId` Identifier for the verification session (e.g. wallet-connect topic).
    /// - `rescourceId` Identifier for the rescource id (e.g. website URL or TLS fingerprint).
    pub fn new_simple(nonce: Nonce, connection_id: String, rescource_id: String) -> Self {
        Self::new()
            .given(LabeledContextProperty::Nonce(nonce))
            .given(LabeledContextProperty::ConnectionId(connection_id))
            .given(LabeledContextProperty::ResourceId(rescource_id))
            .requested(ContextLabel::BlockHash)
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum RequestedSubjectClaims {
    /// Claims based on the Concordium ID object.
    #[serde(rename = "identity")]
    Identity(RequestedIdentitySubjectClaims),
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
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

/// Identity based credential types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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

/// Statement that is requested to be proven.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, Eq, Serialize)]
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
        "label": "ResourceID",
        "context": "testrescource"
      },
      {
        "label": "ContextString",
        "context": "testcontext"
      }
    ],
    "requested": [
      "BlockHash"
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
          "label": "ResourceID",
          "context": "testrescource"
        },
        {
          "label": "ContextString",
          "context": "testcontext"
        }
      ],
      "requested": [
        "BlockHash"
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
          "label": "ResourceID",
          "context": "testrescource"
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
          "proofValue": "0000000000000006010098ad4f48bcd0cf5440853e520858603f16058ee0fc1afdc3efe98abe98771e23c000d19119c28d704a5916929f66f2a30200abb05a0ff79b3b06f912f0ec642268d3a1ad1cdf4f050ab7d55c795aa1ab771f4be29f29134e0d7709566f9b2468805f03009158599821c271588f24e92db7ca30197ec5b0c901efaadd34cca707e56b9aab1a7f14e329816e2acf4d07a7edf1bd6b0400af07a1ba7a22bcb1602114921a48fa966a821354cd0dd63a87ce018caccc50b56f2c9f55a062cdc423657aa5cec8a4c9050100097465737476616c75650602aef4be258f8baca0ee44affd36bc9ca6299cc811ac6cb77d10792ff546153d6a84c0c0e030b131ed29111911794174859966f6ba8cafaf228cb921351c2cbc84358c0fa946ca862f8e30d920e46397bf96b56f50b66ae9c93953dc24de2904640000000000000004a547c8619f3ff2670efbefb21281e459b7cc9766c4f377f78e9f97e2c50569a8dcb155f2a502e936d2cb6ef1a73e92af9916e6353b7127d55bb525cb18074b5ec130463e03a4eda583b05c2d63db40a08ab8bf05f930ec234cc2f788d5f5bfbeab3e4881918ce964ffd55483219edd435ac865286bfd313cd834aabfa8061d2ae173cbe4b59ab2bda78faa4c2c937afba80d7fba0822579ac0ef6915f4820f968a74f00ff5ab74e90b0a7bcb2b92093a5e94a54aea1d48ffd1e5bb3fb48069bcab06b213b4d0bab01d11f8b8dac7929fdeadd26ebb878533e2ad463f97c4074400000005000000013982d8634ba7b607d67fc2cec47760e39089e65dfd04728a11e330fb74aae64702902f6897ed9b0901d20a8e13c857e02ccd0b1699aeef7d990157222a28e3793ae12bd853dd9d555f5644614f3668ac1b939a5f759f2005755f109b344324f900000002299e3b83209194a5daba560539eb59cb2615403462bd4a982dfa4011c935048854c06b430bae0c0c7651bfae3a1b82b85fda6df5dc625ba1bea725470db40b6b6d08d1878f4a093f03e2e59c645043f578bd49d1494a1c17f8d35e2a268a853c000000035f7077067dcfd64b3cb6f1001413b00e02876849636f687cfb3439921703b2151fd8e4a1ce2b9e2119becdafe34471e2767814e931918f5154a1a868e9b167085881140ad3c00fb28b3004e10dd7be0122c5be14fb6b18395a395d520b491413000000045fe738215cadc14f6c1b9530ba2729df8e19056ba8d6a36a07b74b7a4d4f161214681d9e282bc66f651e6abd40fa2306cd7eebd4d8568d86dacd61fd68daa132589976383481036095ac682f76b28317a3a38a0248940e71bcb9ba97074705850000000546ef10550445ce704650cec7bcfcd3d12afa49e0b03ba489896e5c9926ba679a50578c0558aca331d52c043587cc9a39fea572aec5264ed649e319bc5702843f504d1db29033c662986854871549eb977afa029d2474ecfffd647536d87064e9401f7cd5cabb34a7928236e8974e624015725b86151d7086b61859416426950e0000000c006322cb2d9eedd02aa22891b347c5bdfad57923624537a9aa9dff62ec42b47df618eab39fdce1e55e781b79a4df6504cff605a2296f37668b83df8cd06a7b22ef0226be433784d8d73566cd1a66e72055946e239922473af17c7657fb18b1993e5801010102212792adb837956e7738952b66ff23da8238bd76ebc30f7471903687913b42db002a20e633165cf4100403446caea36bc6f935d5c133cddc5855c53ff8e70df21e264da93cfab5159c994285ea99b6bd8a77737632aa9fe9806ce45da49153e4ec00049a43991652d27caac2712722440aeb647fb1affa995d65842d21154dd71fc3545fdc094f8f6dc458f0e80500a3635e6a8794cc6c6bf473ffd440af2b0a7a1100471a435023d8d37987cfdab51c32d26c271dde080e07bb0a707f181d6d473ef83ef6e6952eadcd84e52ae8491735907b4783339ff5093c6b584a39ef5f058cfd000be7b86b16655c6f4c34c741acd581198a1456883634d8badb297a92ae275a652aebc2e6c7d95abba6bc1c1f4243aebcc49042aef2400737bd856bcd6365031101026ce7a87de12ab16de479952e1b14c83a60a3d1a653755e4d27119279c9729862000000000000000502803596b4ba5ea05b1fea2b78e292f935d621453cffcd207e10f3072b2813ca3e963cebf05b19cd82da4bd5aad1dcc7fda1492d7ffc8f532bc4b37e9bf4753b7ae6b8f08e05a851052fc6ac7617ce68293678747d11f9a508bab6f7a60edde9c48325374a989231f546585a242ff1c14c1aba6b12390829f771c3fecdf7850d9109f37f0b45a2ccfaf1d7e5884f897329abac9b66f10bb79b6de223f5446026a2539b2e6bab488f5a10559962134fe5b4e3b26a98b9257d97fa2d92dcff4119f96ec88a54de9a1707e8362041bcde1ab72af025e5b0f17fd17fb54590a2571d215fd2f77b7ede53aebf664bb6b4cc2a4f742fe3e69ae073d6ceaa5e1f9d44899854858aa9dd3ee5b92dab128775317bca2adba39a529aa77dff0a7de2ac159bf100000007a30f43762f1ea5cb9d928da6f13797e786206c6a60ce44ff4f51ee0f54f21c30b914559cd5407cc78c4f4da5afa4c8398baa5ef5f302fefb9a802eceb62ef30fd75ab312234d7eb9b42c79cb6001a2d38329f943e82d8b7b2170c969ac144786b03de383618809769bf937f298623190c9a4b99722235ee86959dfae28b8075aa52b5e449ea15f2bfac12557ca2317a98ace7da8c78e4f939b924a8f0a14595f85744ba1ee96f55a1675c6b87d54791cdd1f8250a51215c28e223fa9dbeef8e5a875c3e17062027a4a903ae22227ae894708048158587818c1ac1d6c7df4330766db017a73ce72e5febf60e7b1bc7d7cb173073e2bb5a39dc29a9df20c14532b002879f16c095ca692943d7e45568bce4f9eb3ef8b2bc7d13db72eb8c4caae45a990e75f030a9035b1ce8db1b1e4088ce3f5690535f9ee4a32b2f42ca6096285e45738a69ae38af9d15a3ef8d84cddf5903e7918466d3de2a4ee2d69acd443819921858991973a57942fcc99416c2ee38c5d574cae5f3f5e6c5701379e1d1d26957290b64ba7e5cb92a84c8178ff47a5676db348845f7d3448ac2f8bb7ccf43da8eeecba8a592bc0424def61cf7a5187b5582185aa5ffa309d1f5ab0b09c30e5cf2331a510f53afe6a1de3da75234a365b725c40d9b732829322f228f1a4f8b492b329a210d219f20a761b0eb0a40f883f2825e4b2436d4fc9f8517ab044f73657f4f931ce0b68cdbaeaa088cfd8087bb0c2a629748d53cf215dc909cb28ed538990917f7dd0771ccc3b5fb8143445f136593e86b93e0ce86db5b1ec72dc7ce390322134976d0c4cfa6c418914aa70a0ace0c608dba84a7730104524147a990c0783f9abe22eb8cd7cee765172a4d9bd8663018bbc843bdc878804bfa90801b41a0837c7768ede32122022d7e4bbe136f88b11979af840a84ffc0153ccbda13e37e469441c373dd41a09134427e07aa03ca4b3c2f45bb8f306924e6b752320da3c20156797bb3f0cbcea4baa65b2cf8f8ecc7db3a1cc661fe256a35b65c91d1b039035240c33b7dec4981aa53e914f67ac932328b31f3fc4d0aac1c19a4da4dab1b525a63008d0e40b86076a1b7e9f0f219955c76798ae8d5131eee35e9900c5cdc8b58badd7022044521d7ad239a91bb2ae1a02fc61472f7d3629d14070641a1eb2a100768d22eea4a37862e9f1a39db5e64d9a279101eab15b12b238c85222e325826898ca30342503451fc6630acb4b866370163b8bf2bc7f3c7e37b25e5d2c69e7dbff3ea31a0a47d1b23f35c6253d12689b4560f6585baf3835e439b47c916e2df6e045355f36b12d0fe12fae4034dfd1ce9640a531c11a71af7ea533cb9e24b0c91f803126862cdb43d09a57fb0b50ac4892ec88df7315eede5eda639f1e01a5bca4c57edfbace497473e52e0d34cce925d5458eff3f500a92cf1c2c811a00000002b0eec4950650f831ac97bcf95a49096df32dccd9cea1c191663a795d846141bc46b10fe1863abc4eb9cbdb6d9abb78adb4493c2c400c14a3bb78ca462141fcaad5266403843cb2f4c0efc1bc8b992d1f7cab7115f3facfd47b462dcc3c6341b7b15509de1b8941725938a8541fafdddcafb50397ab786fdb8de44072db0960f498ae2722d2382f8471dc60fc3d02a0e59041837fb3d8880a14fc33c616f217f335da9e31bd7982fd7ab9ca454b6f8abbcd283bba4b66502017b763bef1f4b7de3ea79879d242a1e924060c09ca767ee09b158c008e4a6694765ee08bb1c086d85bed12e14a865599412c755798c31ba05b99c5d56a44ed308e7c4257e123115d0487cbd29bfc97194ed8868ed4e458c7b2bf8ab6f04efee532502cf588c4f26b9b2830baa635c56857be5fd6803fd35d508881bd7cf3b5872ff84640384e2576bd93d4d86fdafcba2df3f29036491573031ede2ddb09dd092ad890a68f07876aeeaf8d66a9cb5548434878358c55ef19ff69d0fd5b1d1ef009fb65761f4747dbd27d41a5ac8e73328e0da1a3080f439e51963ed4dbd585778a4f12e550ce20bdb11033898d522f0b51a4cbfa7ec056cd74157be5315bd2671436d50dd4d66922df3823c927a3a0a296800f088e709ee2f58b2baabcb5b4cec5d39ab6fb1c79d9302b0d33cba89f014ac138f649b7b28c63b88754dcc2be4a50ed1ac4ba5e165a2f33e902d5b793dcbb20b8ded2d343463f873968e8c06e303a9a2d05614615db2a00000002b6a06b7dee944ca93c82d855194cb26beb806efb3efe29e246b2fc0d426a238208390f3006b21e32178eb41059721272938b7eeb86cda0e6c887a066b2391723110bcb278552a8614fe4af99da63171c2f886fae23575bb8d705da53e23a4a02a3493dbda03cb03ca7a6a8fd5a5627cd054a822953bacd2dd66133f27a8b52920e83dbd694dd7cb163bc5dfb2ca7e007b29d7b6915f0c18555026508bc5d95c802bfc02aec5efffd1f745ddae0d5f42cfab9f3845f674fd91f08bbe4f0767ea81d0393b20a3843fc193bfe687a02abf6837a83caa51407e1cc7ff2c486db72196f923b35bdcbbab61a53f7f20fcd8e3fbc7d130b4ee3f20c39583f69bf20260102b387e119ec10c4a8963ee52710d75c21710881bae7fb5a8595fd43a9156419f8080891e50139bd4af14f1ba25ebe0152b5e83d115be493372e147742d8bfe3a8269e8ecd27ec055a11055d5405192cda8c8db528f06b120fc2e3f4708989741184a96506d47f7ebddea7e469c18e90e23ba7bb3b9190f9e93b2d6e862ea1e95b30fbf812d790c68fc405b2fc3188a1818fb7e36b39030a01b01e72b4117fef1be719a56545ff11d846b41e21ba7fd404c1236c36649d0f3ed9db6f4f8f66bd6650bd3fc2c6e44efff53d18cbd558a02b518ee0d26f6b2b2e846fc60e355ceadd26f17d39c060ba090dbbc9a40ac12ec893682068a8154dfb4273efceba0b9d4767e8e85c2e806c167470501efecafede584457d17c3764c49ab027cd3a3dec5d00000007b04552093c3a3150e143efad56b5956c62e3a5f1bc19a85455156d0464788240650cfeea4bca064ab831ed2d3ed4e00e9921750672741966e22703444f367a66bd237d3090e3aa3eae6821712a0e9edc0b3a791d96708be1f12b31c3379f45e7977cfa7219649c16d36ef10a172e4efcb22041f85a9fa0a625411a3f0f11a7ff438664e850edfe6fcffa4c4e289ec467b79e029a934c5c466555c2408212bf3615eeb2e1cf29e043ad9309d4104a75161157a384074f9811f0fea98754f362e5a074bbd689239b37916a3580fba089332fdb1cc86d49ce2e34d81d9c7466a3bed5cf84fb35f7a958885e3bc78f23cd02a352f1af0de441a9851547742fbb883e5bd872e6ad7870c537bd2977c9dd2d162934569e46fb13acd1091327b70e0108a81d77554ac438413808f8f14cb8bc75517e1fa270ca65577b01f6d12d61801a493ac8274cdcecb9f81b1e616c6e38f6b916b53143f2332d3071655342fbc5f53bc43e17568dc70cecd9cbea5e22d457320805f2dbbd2b093a4b699f3745fa8895e1a6204c68eae4d39aeff9c07957bb0585922ebfb886275c3fbbf0bb5b1a01db2d61fa4edf12e22d96a64c20aaa0ce85245fc4fb1de5c893287fcf5fbd733ce99d2a9af20d1f3bdb659992339c37931b2250b13d44219f39371b6745c07227a76a6849a6e204eba9012efa331aec5367a6bd5f2fb6e85d69e5cde7dcaf55ed6e875bcc829eeb778e4a97b52a608db19165d905af3753f29cd2a16a58bdca17f6401733b4994af58177761c42ad8983e71354e2b52d6ee663476bd9c4e8c2e1a825fd2c0f5cac55fbcb77b655202fb3e59dfb014c184d97728da8e3303299a63d256e0df4f7b4bccb413d1b7eedf114a2282073d636b168403efb0a45aa913034421625491ea4d73edf6b3ea5aa772b7a34b5e298c22c0f5acc0ddde8394c510843808277d149fc6be19371f87120373aae4edd2840ff403fb22e206ab139003572d11eb079c5595f1dbbed0c07e813c54de8462c05141903e0cc584bf07d2201",
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

        let cbor = cbor::cbor_encode(&verification_request_anchor);

        assert_eq!(hex::encode(&cbor), "a4646861736858204bbaffb80ea1a9591ea9105152e64a9bb24c463fb923cb69686197c10ffac109647479706566434344565241667075626c6963a1636b6579046776657273696f6e01");

        let decoded: VerificationRequestAnchor = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(decoded, verification_request_anchor);
    }

    #[test]
    fn test_verification_audit_anchor_cbor_roundtrip() {
        let verification_audit_anchor_on_chain = fixtures::verification_audit_anchor_fixture();

        let cbor = cbor::cbor_encode(&verification_audit_anchor_on_chain);
        assert_eq!(hex::encode(&cbor), "a46468617368582048d2fc8fc2cb58431cf9433799e740959691d8f549b30fd99fdd282b3ca3b55f647479706566434344564141667075626c6963a1636b6579046776657273696f6e01");
        let decoded: VerificationAuditAnchor = cbor::cbor_decode(&cbor).unwrap();
        assert_eq!(decoded, verification_audit_anchor_on_chain);
    }

    #[test]
    fn test_compute_the_correct_verification_request_anchor() -> anyhow::Result<()> {
        let verification_request_anchor_hash = fixtures::verification_request_anchor_fixture().hash;

        let expected_verification_request_anchor_hash = Hash::new(
            <[u8; 32]>::from_hex(
                "4bbaffb80ea1a9591ea9105152e64a9bb24c463fb923cb69686197c10ffac109",
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
                "48d2fc8fc2cb58431cf9433799e740959691d8f549b30fd99fdd282b3ca3b55f",
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
            "testrescource".to_string(),
        )
        .given(LabeledContextProperty::ContextString(
            "testcontext".to_string(),
        ))
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
