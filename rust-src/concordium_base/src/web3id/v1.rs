//! Functionality related to constructing and verifying V1 Concordium Web3ID proofs.
//!
//! The main entrypoints in this module are the [`verify`](PresentationV1::verify)
//! function for verifying presentations in the context of given public
//! data, and the [`prove`](RequestV1::prove) function for constructing a proof.
//!
//! Terminology and model largely follows <https://www.w3.org/TR/vc-data-model-2.0/>
//!
//! The cryptographic protocol is described in the internal blue paper (v2.2.0) in
//! "15.4 Identity Presentations using Zero-Knowledge Proofs" and
//! "17 Web3 Verifiable Credentials"

/// Types defining the verification request anchor (VRA) and verification audit anchor (VAA)
/// These types are part of the higher level verification flow.
pub mod anchor;
mod proofs;

use crate::base::CredentialRegistrationID;
use crate::curve_arithmetic::{Curve, Pairing};
use crate::id::id_proof_types::{AtomicProof, AtomicStatement};
use crate::id::secret_sharing::Threshold;
use crate::id::types::{
    ArIdentity, ArInfos, Attribute, AttributeTag, ChainArData, CredentialValidity,
    HasIdentityObjectFields, IdObjectUseData, IdentityAttribute,
    IdentityAttributesCredentialsProofs, IdentityObjectV1, IpContextOnly, IpIdentity, IpInfo,
    YearMonth,
};
use crate::web3id::did;
use crate::web3id::did::Network;
use crate::{common, pedersen_commitment};
use anyhow::{bail, ensure, Context};
use itertools::Itertools;
use nom::AsBytes;
use serde::de::{DeserializeOwned, Error as _};
use serde::ser::{Error as _, SerializeMap};
use serde::Deserializer;
use std::collections::{BTreeMap, BTreeSet};

const CONCORDIUM_CONTEXT_INFORMATION_TYPE: &str = "ConcordiumContextInformationV1";

const VERIFIABLE_PRESENTATION_TYPE: &str = "VerifiablePresentation";
const CONCORDIUM_VERIFIABLE_PRESENTATION_TYPE: &str = "ConcordiumVerifiablePresentationV1";

const VERIFIABLE_CREDENTIAL_TYPE: &str = "VerifiableCredential";
const CONCORDIUM_VERIFIABLE_CREDENTIAL_V1_TYPE: &str = "ConcordiumVerifiableCredentialV1";
const CONCORDIUM_ACCOUNT_BASED_CREDENTIAL_TYPE: &str = "ConcordiumAccountBasedCredential";
const CONCORDIUM_IDENTITY_BASED_CREDENTIAL_TYPE: &str = "ConcordiumIdBasedCredential";

const CONCORDIUM_REQUEST_TYPE: &str = "ConcordiumVerifiablePresentationRequestV1";

const CONCORDIUM_SUBJECT_CLAIMS_V1_TYPE: &str = "ConcordiumSubjectClaimsV1";
const CONCORDIUM_ACCOUNT_BASED_SUBJECT_CLAIMS_TYPE: &str = "ConcordiumAccountBasedSubjectClaims";
const CONCORDIUM_IDENTITY_BASED_SUBJECT_CLAIMS_TYPE: &str = "ConcordiumIdBasedSubjectClaims";

/// Verification context information that serves as a distinguishing context when requesting
/// proofs.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, common::Serialize, Debug)]
pub struct ContextInformation {
    /// This part of the context is specified by the application requesting a verifiable presentation (e.g. merchant backend).
    pub given: Vec<ContextProperty>,
    /// This part of the context is filled in by the application creating the verifiable presentation (wallet or ID app).
    pub requested: Vec<ContextProperty>,
}

impl serde::Serialize for ContextInformation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("type", &CONCORDIUM_CONTEXT_INFORMATION_TYPE)?;
        map.serialize_entry("given", &self.given)?;
        map.serialize_entry("requested", &self.requested)?;
        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for ContextInformation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut value = serde_json::Value::deserialize(deserializer)?;

        let result = (|| -> anyhow::Result<Self> {
            let ty: String = take_field_de(&mut value, "type")?;
            ensure!(
                ty == CONCORDIUM_CONTEXT_INFORMATION_TYPE,
                "expected type {}",
                CONCORDIUM_CONTEXT_INFORMATION_TYPE
            );

            let given = take_field_de(&mut value, "given")?;
            let requested = take_field_de(&mut value, "requested")?;

            Ok(Self { given, requested })
        })();

        result.map_err(|err| D::Error::custom(format!("{:#}", err)))
    }
}

/// Property value used in [`ContextInformation`]
#[derive(
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    serde::Deserialize,
    serde::Serialize,
    common::Serialize,
    Debug,
)]
pub struct ContextProperty {
    pub label: String,
    pub context: String,
}

/// Claims about a single account based subject. Accounts are on-chain credentials
/// deployed from identity credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountBasedSubjectClaims<C: Curve, AttributeType: Attribute<C::Scalar>> {
    /// Network on which the account exists
    pub network: Network,
    /// Account registration id
    pub cred_id: CredentialRegistrationID,
    /// Attribute statements
    pub statements: Vec<AtomicStatement<C, AttributeTag, AttributeType>>,
}

/// Claims about a single identity based subject. Identity credentials
/// are issued by identity providers. The subject is not directly identified in this type,
/// only the identity provider that issued the identity credentials is identified. The corresponding
/// credentials will contain and ephemeral id [`IdentityCredentialEphemeralId`] that can be decrypted
/// by the privacy guardians to IdCredPub, which is an identifier for the identity credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityBasedSubjectClaims<C: Curve, AttributeType: Attribute<C::Scalar>> {
    /// Network to which the identity credentials are issued
    pub network: Network,
    /// Identity provider which issued the credentials
    pub issuer: IpIdentity,
    /// Attribute statements
    pub statements: Vec<AtomicStatement<C, AttributeTag, AttributeType>>,
}

/// Claims about a subject.
/// To prove the claims and create a credential, the corresponding private input [`CredentialProofPrivateInputs`] is needed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectClaims<C: Curve, AttributeType: Attribute<C::Scalar>> {
    /// Claims about an account based subject. Accounts are on-chain credentials
    /// deployed from identity credentials.
    Account(AccountBasedSubjectClaims<C, AttributeType>),
    /// Claims about an identity based subject.
    Identity(IdentityBasedSubjectClaims<C, AttributeType>),
}

impl<C: Curve, AttributeType: Attribute<C::Scalar> + serde::Serialize> serde::Serialize
    for SubjectClaims<C, AttributeType>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Account(AccountBasedSubjectClaims {
                network,
                cred_id,
                statements: statement,
            }) => {
                let mut map = serializer.serialize_map(None)?;
                map.serialize_entry(
                    "type",
                    &[
                        CONCORDIUM_SUBJECT_CLAIMS_V1_TYPE,
                        CONCORDIUM_ACCOUNT_BASED_SUBJECT_CLAIMS_TYPE,
                    ],
                )?;
                let id = did::Method::new_account_credential(*network, *cred_id);
                map.serialize_entry("id", &id)?;
                map.serialize_entry("statement", statement)?;
                map.end()
            }
            Self::Identity(IdentityBasedSubjectClaims {
                network,
                issuer,
                statements: statement,
            }) => {
                let mut map = serializer.serialize_map(None)?;
                map.serialize_entry(
                    "type",
                    &[
                        CONCORDIUM_SUBJECT_CLAIMS_V1_TYPE,
                        CONCORDIUM_IDENTITY_BASED_SUBJECT_CLAIMS_TYPE,
                    ],
                )?;
                let issuer = did::Method::new_idp(*network, *issuer);
                map.serialize_entry("issuer", &issuer)?;
                map.serialize_entry("statement", statement)?;
                map.end()
            }
        }
    }
}

impl<'de, C: Curve, AttributeType: Attribute<C::Scalar> + DeserializeOwned> serde::Deserialize<'de>
    for SubjectClaims<C, AttributeType>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut value = serde_json::Value::deserialize(deserializer)?;

        let result = (|| -> anyhow::Result<Self> {
            let types: BTreeSet<String> = take_field_de(&mut value, "type")?;

            Ok(
                if types
                    .iter()
                    .any(|ty| ty == CONCORDIUM_ACCOUNT_BASED_SUBJECT_CLAIMS_TYPE)
                {
                    let id: did::Method = take_field_de(&mut value, "id")?;
                    let did::IdentifierType::Credential { cred_id } = id.ty else {
                        bail!("expected account credential did, was {}", id);
                    };
                    let statement = take_field_de(&mut value, "statement")?;

                    Self::Account(AccountBasedSubjectClaims {
                        network: id.network,
                        cred_id,
                        statements: statement,
                    })
                } else if types
                    .iter()
                    .any(|ty| ty == CONCORDIUM_IDENTITY_BASED_SUBJECT_CLAIMS_TYPE)
                {
                    let issuer: did::Method = take_field_de(&mut value, "issuer")?;
                    let did::IdentifierType::Idp { idp_identity } = issuer.ty else {
                        bail!("expected issuer did, was {}", issuer);
                    };
                    let statement = take_field_de(&mut value, "statement")?;

                    Self::Identity(IdentityBasedSubjectClaims {
                        network: issuer.network,
                        issuer: idp_identity,
                        statements: statement,
                    })
                } else {
                    bail!("unknown subject claims types: {}", types.iter().format(","))
                },
            )
        })();

        result.map_err(|err| D::Error::custom(format!("{:#}", err)))
    }
}

/// Extract the value at the given key. This mutates the `value` replacing the
/// value at the provided key with `Null`.
fn take_field(value: &mut serde_json::Value, field: &str) -> anyhow::Result<serde_json::Value> {
    Ok(value
        .get_mut(field)
        .with_context(|| format!("field {field} is not present"))?
        .take())
}

/// Extract the value at the given key and deserializes it. This mutates the `value` replacing the
/// value at the provided key with `Null`.
fn take_field_de<T: DeserializeOwned>(
    value: &mut serde_json::Value,
    field: &str,
) -> anyhow::Result<T> {
    serde_json::from_value(take_field(value, field)?)
        .with_context(|| format!("deserialize {}", field))
}

/// Metadata of an account credential derived from an identity issued by an
/// identity provider.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AccountCredentialMetadataV1 {
    pub issuer: IpIdentity,
    pub cred_id: CredentialRegistrationID,
}

/// Metadata of an identity based credential.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct IdentityCredentialMetadataV1 {
    pub issuer: IpIdentity,
    pub validity: CredentialValidity,
}

/// Metadata of a credential [`CredentialV1`].
/// Contains the information needed to determine the validity of the
/// credential and resolve [`CredentialsInputs`](super::CredentialsInputs)
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CredentialMetadataTypeV1 {
    /// Metadata of an account credential, i.e., a credential derived from an
    /// identity object.
    Account(AccountCredentialMetadataV1),
    /// Metadata of an identity based credential.
    Identity(IdentityCredentialMetadataV1),
}

/// Metadata of a credential [`CredentialV1`].
/// The metadata consists of
///
/// * data that is part of the verification presentation and credentials but needs to be verified externally (network is an example of that)
/// * information about data that must be resolved externally to [`CredentialVerificationMaterial`] in order to verify
///   the presentation
///
/// Hence, proper handling of the metadata is required for verifying the presentation. An implementation of handling
/// the metadata may be found in the [Rust SDK `web3id` module](https://docs.rs/concordium-rust-sdk/latest/concordium_rust_sdk/web3id/index.html)
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CredentialMetadataV1 {
    /// Timestamp of when the proof was created.
    pub created: chrono::DateTime<chrono::Utc>,
    pub network: Network,
    /// Metadata specific to the type of credential
    pub cred_metadata: CredentialMetadataTypeV1,
}

/// Account based credentials. This contains almost
/// all the information needed to verify it, except the public commitments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountBasedCredentialV1<C: Curve, AttributeType: Attribute<C::Scalar>> {
    /// Issuer of this credential, the identity provider index on the
    /// relevant network.
    pub issuer: IpIdentity,
    /// Credential subject
    pub subject: AccountCredentialSubject<C, AttributeType>,
    /// Proofs of the credential
    pub proof: ConcordiumZKProof<AccountCredentialProofs<C, AttributeType>>,
}

/// Subject of account based credential
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountCredentialSubject<C: Curve, AttributeType: Attribute<C::Scalar>> {
    /// Network on which the account credentials exist
    pub network: Network,
    /// Account credentials registration id. Identifies the subject.
    pub cred_id: CredentialRegistrationID,
    /// Proven statements
    pub statements: Vec<AtomicStatement<C, AttributeTag, AttributeType>>,
}

impl<C: Curve, AttributeType: Attribute<C::Scalar> + serde::Serialize> serde::Serialize
    for AccountCredentialSubject<C, AttributeType>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        let id = did::Method::new_account_credential(self.network, self.cred_id);
        map.serialize_entry("id", &id)?;
        map.serialize_entry("statement", &self.statements)?;
        map.end()
    }
}

impl<'de, C: Curve, AttributeType: Attribute<C::Scalar> + DeserializeOwned> serde::Deserialize<'de>
    for AccountCredentialSubject<C, AttributeType>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut value = serde_json::Value::deserialize(deserializer)?;

        let result = (|| -> anyhow::Result<Self> {
            let id: did::Method = take_field_de(&mut value, "id")?;
            let did::IdentifierType::Credential { cred_id } = id.ty else {
                bail!("expected identity credential did, was {}", id);
            };
            let statement = take_field_de(&mut value, "statement")?;

            Ok(Self {
                network: id.network,
                cred_id,
                statements: statement,
            })
        })();

        result.map_err(|err| D::Error::custom(format!("{:#}", err)))
    }
}

/// Proof of account based credential
#[derive(Clone, Debug, Eq, PartialEq, common::Serialize)]
pub struct AccountCredentialProofs<C: Curve, AttributeType: Attribute<C::Scalar>> {
    /// Proofs of the atomic statements on attributes
    pub statement_proofs: Vec<AtomicProof<C, AttributeType>>,
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> AccountBasedCredentialV1<C, AttributeType> {
    /// Metadata for the credential
    pub fn metadata(&self) -> AccountCredentialMetadataV1 {
        let AccountBasedCredentialV1 {
            subject: AccountCredentialSubject { cred_id, .. },
            issuer,
            ..
        } = self;

        AccountCredentialMetadataV1 {
            issuer: *issuer,
            cred_id: *cred_id,
        }
    }

    /// Extract the subject claims from the credential.
    pub fn claims(&self) -> AccountBasedSubjectClaims<C, AttributeType> {
        let AccountBasedCredentialV1 {
            subject:
                AccountCredentialSubject {
                    network,
                    cred_id,
                    statements,
                },
            ..
        } = self;

        AccountBasedSubjectClaims {
            network: *network,
            cred_id: *cred_id,
            statements: statements.clone(),
        }
    }
}

/// Encrypted ephemeral id for an identity credential. It will have a new value for each time a credential is proven
/// derived from the identity credential (the encryption is a randomized function).
/// The id can be decrypted to IdCredPub by first converting the value to [`IdentityCredentialEphemeralIdData`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityCredentialEphemeralId(pub Vec<u8>);

/// Encrypted ephemeral id for an identity credential. The id can be decrypted to IdCredPub by the privacy guardians (anonymity revokers).
/// It will have a new value for each time credential is proven (the encryption is a randomized function).
#[derive(Debug, Clone, PartialEq, Eq, common::Serialize)]
pub struct IdentityCredentialEphemeralIdData<C: Curve> {
    /// Decryption threshold of the IdCredPub in [`IdentityCredentialEphemeralId`]
    pub threshold: Threshold,
    /// Anonymity revocation data. It is an encryption of shares of IdCredPub,
    /// each share encrypted for the privacy guardian (anonymity revoker)
    /// that is the key in the map.
    #[map_size_length = 2]
    pub ar_data: BTreeMap<ArIdentity, ChainArData<C>>,
}

impl<C: Curve> IdentityCredentialEphemeralIdData<C> {
    pub fn as_ref(&self) -> IdentityCredentialEphemeralIdDataRef<'_, C> {
        IdentityCredentialEphemeralIdDataRef {
            threshold: self.threshold,
            ar_data: &self.ar_data,
        }
    }
}

/// Encrypted ephemeral id for an identity credential. The id can be decrypted to IdCredPub by the privacy guardians (anonymity revokers).
/// It will have a new value for each time credential is proven (the encryption is a randomized function)
#[derive(Debug, Clone, PartialEq, Eq, common::Serial)]
pub struct IdentityCredentialEphemeralIdDataRef<'a, C: Curve> {
    /// Decryption threshold of the IdCredPub in [`IdentityCredentialEphemeralId`]
    pub threshold: Threshold,
    /// Anonymity revocation data. It is an encryption of shares of IdCredPub,
    /// each share encrypted for the privacy guardian (anonymity revoker)
    /// that is the key in the map.
    #[map_size_length = 2]
    pub ar_data: &'a BTreeMap<ArIdentity, ChainArData<C>>,
}

impl IdentityCredentialEphemeralId {
    /// Deserialized into id data
    pub fn try_to_data<C: Curve>(
        &self,
    ) -> common::ParseResult<IdentityCredentialEphemeralIdData<C>> {
        common::from_bytes(&mut self.0.as_bytes())
    }

    /// Serialize from id data
    pub fn from_data<C: Curve>(data_ref: IdentityCredentialEphemeralIdDataRef<'_, C>) -> Self {
        IdentityCredentialEphemeralId(common::to_bytes(&data_ref))
    }
}

/// Identity based credential. This type of credential is derived from identity credentials issued
/// by an identity provider. The type contains almost
/// all the information needed to verify it, except the identity provider and privacy guardian (anonymity revoker) public keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityBasedCredentialV1<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
> {
    /// Issuer of the underlying identity credential from which this credential is derived.
    pub issuer: IpIdentity,
    /// Temporal validity of the identity credential. Notice this is the validity period of
    /// the identity credential on which the present derived credential is based.
    pub validity: CredentialValidity,
    /// Credential subject
    pub subject: IdentityCredentialSubject<C, AttributeType>,
    /// Proof of the credential
    pub proof: ConcordiumZKProof<IdentityCredentialProofs<P, C, AttributeType>>,
}

/// Subject of identity based credential
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityCredentialSubject<C: Curve, AttributeType: Attribute<C::Scalar>> {
    /// Network to which the credentials are issued
    pub network: Network,
    /// Ephemeral encrypted id for the credential. This is the subject of the credential.
    ///
    /// Since the id is ephemeral, the identity derived credential is an [unlinkable disclosure](https://www.w3.org/TR/vc-data-model-2.0/#dfn-unlinkable-disclosure)
    pub cred_id: IdentityCredentialEphemeralId,
    /// Proven statements
    pub statements: Vec<AtomicStatement<C, AttributeTag, AttributeType>>,
}

impl<C: Curve, AttributeType: Attribute<C::Scalar> + serde::Serialize> serde::Serialize
    for IdentityCredentialSubject<C, AttributeType>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        let id = did::Method::new_identity_credential(self.network, self.cred_id.clone());
        map.serialize_entry("id", &id)?;
        map.serialize_entry("statement", &self.statements)?;
        map.end()
    }
}

impl<'de, C: Curve, AttributeType: Attribute<C::Scalar> + DeserializeOwned> serde::Deserialize<'de>
    for IdentityCredentialSubject<C, AttributeType>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut value = serde_json::Value::deserialize(deserializer)?;

        let result = (|| -> anyhow::Result<Self> {
            let id: did::Method = take_field_de(&mut value, "id")?;
            let did::IdentifierType::EncryptedIdentityCredentialId { cred_id } = id.ty else {
                bail!("expected identity credential did, was {}", id);
            };
            let statement = take_field_de(&mut value, "statement")?;

            Ok(Self {
                network: id.network,
                cred_id,
                statements: statement,
            })
        })();

        result.map_err(|err| D::Error::custom(format!("{:#}", err)))
    }
}

/// Proof of identity based credential
#[derive(Clone, Debug, Eq, PartialEq, common::Serialize)]
pub struct IdentityCredentialProofs<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
> {
    /// The attributes that are part of the underlying identity credential from which this credential is derived
    pub identity_attributes: BTreeMap<AttributeTag, IdentityAttribute<C, AttributeType>>,
    /// Proof of:
    /// * knowledge of a signature from the identity provider on the attributes
    ///   in `identity_attributes` and on [`IdentityBasedCredentialV1::validity`]
    /// * correctness of the encryption of IdCredPub in [`IdentityCredentialSubject::cred_id`]
    pub identity_attributes_proofs: IdentityAttributesCredentialsProofs<P, C>,
    /// Proofs for the atomic statements based on the attribute commitments
    /// and values in `identity_attributes`
    pub statement_proofs: Vec<AtomicProof<C, AttributeType>>,
}

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: Attribute<C::Scalar>>
    IdentityBasedCredentialV1<P, C, AttributeType>
{
    /// Metadata for the credential
    pub fn metadata(&self) -> IdentityCredentialMetadataV1 {
        let IdentityBasedCredentialV1 {
            issuer, validity, ..
        } = self;

        IdentityCredentialMetadataV1 {
            issuer: *issuer,
            validity: validity.clone(),
        }
    }

    /// Extract the subject claims from the credential.
    pub fn claims(&self) -> IdentityBasedSubjectClaims<C, AttributeType> {
        let IdentityBasedCredentialV1 {
            subject:
                IdentityCredentialSubject {
                    network,
                    statements,
                    ..
                },
            issuer,
            ..
        } = self;

        IdentityBasedSubjectClaims {
            network: *network,
            issuer: *issuer,
            statements: statements.clone(),
        }
    }
}

/// Version of proof
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ConcordiumZKProofVersion {
    #[serde(rename = "ConcordiumZKProofV4")]
    ConcordiumZKProofV4,
}

/// Credential proof. Wraps the actual credential specific proof.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(bound(serialize = "T: common::Serial", deserialize = "T: common::Deserial"))]
pub struct ConcordiumZKProof<T> {
    #[serde(rename = "created")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(
        rename = "proofValue",
        serialize_with = "common::base16_encode",
        deserialize_with = "common::base16_decode"
    )]
    pub proof_value: T,
    #[serde(rename = "type")]
    pub proof_type: ConcordiumZKProofVersion,
}

/// Verifiable credential. Embeds and proofs the claims from a [`SubjectClaims`].
/// To verify the credential, the corresponding public input [`CredentialsInputs`](super::CredentialsInputs) is needed.
/// Also, the data in [`CredentialMetadataV1`] returned by [`CredentialV1::metadata`] must be verified externally in
/// order to verify the credential.
// for some reason, version 1.82 clippy thinks the `Identity` variant is 0 bytes and hence gives this warning
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialV1<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
> {
    /// Credential based on an on-chain account
    Account(AccountBasedCredentialV1<C, AttributeType>),
    /// Identity based credential
    Identity(IdentityBasedCredentialV1<P, C, AttributeType>),
}

impl<
        P: Pairing,
        C: Curve<Scalar = P::ScalarField>,
        AttributeType: Attribute<C::Scalar> + serde::Serialize,
    > serde::Serialize for CredentialV1<P, C, AttributeType>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Account(AccountBasedCredentialV1 {
                subject,
                issuer,
                proof: proofs,
            }) => {
                let mut map = serializer.serialize_map(None)?;
                map.serialize_entry(
                    "type",
                    &[
                        VERIFIABLE_CREDENTIAL_TYPE,
                        CONCORDIUM_VERIFIABLE_CREDENTIAL_V1_TYPE,
                        CONCORDIUM_ACCOUNT_BASED_CREDENTIAL_TYPE,
                    ],
                )?;
                map.serialize_entry("credentialSubject", subject)?;
                let issuer = did::Method::new_idp(subject.network, *issuer);
                map.serialize_entry("issuer", &issuer)?;
                map.serialize_entry("proof", proofs)?;
                map.end()
            }
            Self::Identity(IdentityBasedCredentialV1 {
                issuer,
                validity,
                subject,
                proof: proofs,
            }) => {
                let mut map = serializer.serialize_map(None)?;
                map.serialize_entry(
                    "type",
                    &[
                        VERIFIABLE_CREDENTIAL_TYPE,
                        CONCORDIUM_VERIFIABLE_CREDENTIAL_V1_TYPE,
                        CONCORDIUM_IDENTITY_BASED_CREDENTIAL_TYPE,
                    ],
                )?;
                map.serialize_entry("credentialSubject", subject)?;
                map.serialize_entry(
                    "validFrom",
                    &validity
                        .created_at
                        .lower()
                        .ok_or(S::Error::custom("convert crated at to date time"))?,
                )?;
                map.serialize_entry(
                    "validUntil",
                    &validity
                        .valid_to
                        .upper_inclusive()
                        .ok_or(S::Error::custom("convert valid to to date time"))?,
                )?;
                let issuer = did::Method::new_idp(subject.network, *issuer);
                map.serialize_entry("issuer", &issuer)?;
                map.serialize_entry("proof", proofs)?;
                map.end()
            }
        }
    }
}

impl<
        'de,
        P: Pairing,
        C: Curve<Scalar = P::ScalarField>,
        AttributeType: Attribute<C::Scalar> + DeserializeOwned,
    > serde::Deserialize<'de> for CredentialV1<P, C, AttributeType>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut value = serde_json::Value::deserialize(deserializer)?;

        let result = (|| -> anyhow::Result<Self> {
            let types: BTreeSet<String> = take_field_de(&mut value, "type")?;

            Ok(
                if types
                    .iter()
                    .any(|ty| ty == CONCORDIUM_ACCOUNT_BASED_CREDENTIAL_TYPE)
                {
                    let subject: AccountCredentialSubject<C, AttributeType> =
                        take_field_de(&mut value, "credentialSubject")?;
                    let issuer: did::Method = take_field_de(&mut value, "issuer")?;
                    let did::IdentifierType::Idp { idp_identity } = issuer.ty else {
                        bail!("expected idp did, was {}", issuer);
                    };
                    ensure!(issuer.network == subject.network, "network not identical");
                    let proof: ConcordiumZKProof<AccountCredentialProofs<C, AttributeType>> =
                        take_field_de(&mut value, "proof")?;

                    Self::Account(AccountBasedCredentialV1 {
                        issuer: idp_identity,
                        subject,
                        proof,
                    })
                } else if types
                    .iter()
                    .any(|ty| ty == CONCORDIUM_IDENTITY_BASED_CREDENTIAL_TYPE)
                {
                    let subject: IdentityCredentialSubject<C, AttributeType> =
                        take_field_de(&mut value, "credentialSubject")?;
                    let valid_from: chrono::DateTime<chrono::Utc> =
                        take_field_de(&mut value, "validFrom")?;
                    let valid_until: chrono::DateTime<chrono::Utc> =
                        take_field_de(&mut value, "validUntil")?;
                    let validity = CredentialValidity {
                        created_at: YearMonth::from_timestamp(valid_from.timestamp())
                            .context("convert valid from to year and month")?,
                        valid_to: YearMonth::from_timestamp(valid_until.timestamp())
                            .context("convert valid until to year and month")?,
                    };
                    let issuer: did::Method = take_field_de(&mut value, "issuer")?;
                    let did::IdentifierType::Idp { idp_identity } = issuer.ty else {
                        bail!("expected idp did, was {}", issuer);
                    };
                    ensure!(issuer.network == subject.network, "network not identical");
                    let proof: ConcordiumZKProof<IdentityCredentialProofs<P, C, AttributeType>> =
                        take_field_de(&mut value, "proof")?;

                    Self::Identity(IdentityBasedCredentialV1 {
                        issuer: idp_identity,
                        validity,
                        subject,
                        proof,
                    })
                } else {
                    bail!("unknown credential types: {}", types.iter().format(","))
                },
            )
        })();

        result.map_err(|err| D::Error::custom(format!("{:#}", err)))
    }
}

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: Attribute<C::Scalar>>
    CredentialV1<P, C, AttributeType>
{
    /// Network on which the credentials are valid
    pub fn network(&self) -> Network {
        match self {
            CredentialV1::Account(acc) => acc.subject.network,
            CredentialV1::Identity(id) => id.subject.network,
        }
    }

    /// When credentials were created
    pub fn created(&self) -> chrono::DateTime<chrono::Utc> {
        match self {
            CredentialV1::Account(acc) => acc.proof.created_at,
            CredentialV1::Identity(id) => id.proof.created_at,
        }
    }

    /// Metadata about the credential. This contains data that must be externally verified
    /// and also data needed to look up [`CredentialVerificationMaterial`].
    pub fn metadata(&self) -> CredentialMetadataV1 {
        let cred_metadata = match self {
            CredentialV1::Account(cred_proof) => {
                CredentialMetadataTypeV1::Account(cred_proof.metadata())
            }
            CredentialV1::Identity(cred_proof) => {
                CredentialMetadataTypeV1::Identity(cred_proof.metadata())
            }
        };

        CredentialMetadataV1 {
            created: self.created(),
            network: self.network(),
            cred_metadata,
        }
    }

    /// Extract the subject claims from the credential
    pub fn claims(&self) -> SubjectClaims<C, AttributeType> {
        match self {
            CredentialV1::Account(cred_proof) => SubjectClaims::Account(cred_proof.claims()),
            CredentialV1::Identity(cred_proof) => SubjectClaims::Identity(cred_proof.claims()),
        }
    }
}

/// Version of proof
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ConcordiumLinkingProofVersion {
    #[serde(rename = "ConcordiumWeakLinkingProofV1")]
    ConcordiumWeakLinkingProofV1,
}

/// Proof that the credential holder has created the presentation. Currently
/// not used.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LinkingProofV1 {
    #[serde(rename = "created")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(
        rename = "proofValue",
        serialize_with = "common::base16_encode",
        deserialize_with = "common::base16_decode"
    )]
    pub proof_value: [u8; 0],
    #[serde(rename = "type")]
    pub proof_type: ConcordiumLinkingProofVersion,
}

/// Verifiable presentation. Is the response to proving a [`RequestV1`] with [`RequestV1::prove`]. It contains proofs for
/// the claims in the request. To verify the presentation, use [`PresentationV1::verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationV1<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
> {
    /// Context information for the presentation
    pub presentation_context: ContextInformation,
    /// The verifiable credentials in the presentation
    pub verifiable_credentials: Vec<CredentialV1<P, C, AttributeType>>,
    /// Proofs linking the credentials to a holder. Currently not used.
    pub linking_proof: LinkingProofV1,
}

impl<
        P: Pairing,
        C: Curve<Scalar = P::ScalarField>,
        AttributeType: Attribute<C::Scalar> + serde::Serialize,
    > serde::Serialize for PresentationV1<P, C, AttributeType>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry(
            "type",
            &[
                VERIFIABLE_PRESENTATION_TYPE,
                CONCORDIUM_VERIFIABLE_PRESENTATION_TYPE,
            ],
        )?;
        map.serialize_entry("presentationContext", &self.presentation_context)?;
        map.serialize_entry("verifiableCredential", &self.verifiable_credentials)?;
        map.serialize_entry("proof", &self.linking_proof)?;
        map.end()
    }
}

impl<
        'de,
        P: Pairing,
        C: Curve<Scalar = P::ScalarField>,
        AttributeType: Attribute<C::Scalar> + DeserializeOwned,
    > serde::Deserialize<'de> for PresentationV1<P, C, AttributeType>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut value = serde_json::Value::deserialize(deserializer)?;

        let result = (|| -> anyhow::Result<Self> {
            let types: BTreeSet<String> = take_field_de(&mut value, "type")?;
            ensure!(
                types.contains(CONCORDIUM_VERIFIABLE_PRESENTATION_TYPE),
                "expected type {}",
                CONCORDIUM_VERIFIABLE_PRESENTATION_TYPE
            );

            let presentation_context = take_field_de(&mut value, "presentationContext")?;
            let verifiable_credentials = take_field_de(&mut value, "verifiableCredential")?;
            let linking_proof = take_field_de(&mut value, "proof")?;

            Ok(Self {
                presentation_context,
                verifiable_credentials,
                linking_proof,
            })
        })();

        result.map_err(|err| D::Error::custom(format!("{:#}", err)))
    }
}

/// A request to prove a verifiable presentation [`PresentationV1`]
/// with [`RequestV1::prove`].
/// Contains subject claims and a context. The secret data to prove the claims
/// is input via [`CredentialProofPrivateInputs`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RequestV1<C: Curve, AttributeType: Attribute<C::Scalar>> {
    /// Context challenge for the proof
    pub challenge: ContextInformation,
    /// Claims to prove
    pub subject_claims: Vec<SubjectClaims<C, AttributeType>>,
}

impl<C: Curve, AttributeType: Attribute<C::Scalar> + serde::Serialize> serde::Serialize
    for RequestV1<C, AttributeType>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("type", &CONCORDIUM_REQUEST_TYPE)?;
        map.serialize_entry("context", &self.challenge)?;
        map.serialize_entry("subjectClaims", &self.subject_claims)?;
        map.end()
    }
}

impl<'de, C: Curve, AttributeType: Attribute<C::Scalar> + DeserializeOwned> serde::Deserialize<'de>
    for RequestV1<C, AttributeType>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut value = serde_json::Value::deserialize(deserializer)?;

        let result = (|| -> anyhow::Result<Self> {
            let ty: String = take_field_de(&mut value, "type")?;
            ensure!(
                ty == CONCORDIUM_REQUEST_TYPE,
                "expected type {}",
                CONCORDIUM_REQUEST_TYPE
            );

            let challenge = take_field_de(&mut value, "context")?;
            let credential_statements = take_field_de(&mut value, "subjectClaims")?;

            Ok(Self {
                challenge,
                subject_claims: credential_statements,
            })
        })();

        result.map_err(|err| D::Error::custom(format!("{:#}", err)))
    }
}

/// Private inputs for an account credential proof.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AccountCredentialProofPrivateInputs<'a, C: Curve, AttributeType> {
    /// Issuer of the identity credentials used to deploy the account credentials
    pub issuer: IpIdentity,
    /// The attribute values that are committed to in the account credentials
    pub attribute_values: &'a BTreeMap<AttributeTag, AttributeType>,
    /// The randomness of the attribute commitments in the account credentials
    pub attribute_randomness: &'a BTreeMap<AttributeTag, pedersen_commitment::Randomness<C>>,
}

/// Private inputs for an identity credential proof.
pub struct IdentityCredentialProofPrivateInputs<
    'a,
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType,
> {
    /// Information on the identity provider and the privacy guardians public keys
    pub ip_context: IpContextOnly<'a, P, C>,
    /// Identity object. Together with `id_object_use_data`, it constitutes the identity credentials
    pub id_object: &'a dyn HasIdentityObjectFields<P, C, AttributeType>,
    /// Identity credential
    pub id_object_use_data: &'a IdObjectUseData<P, C>,
}

/// The additional private inputs (mostly secrets), needed to prove the claims
/// in a [request](RequestV1).
pub enum CredentialProofPrivateInputs<
    'a,
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType,
> {
    /// Inputs are for an account credential derived from an identity issued by an
    /// identity provider.
    Account(AccountCredentialProofPrivateInputs<'a, C, AttributeType>),
    /// Inputs are for an identity credential issued by an identity provider.
    Identity(IdentityCredentialProofPrivateInputs<'a, P, C, AttributeType>),
}

/// An owned version of [`IdentityCredentialProofPrivateInputs`] that can be deserialized.
#[derive(Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(bound(
    serialize = "AttributeType: serde::Serialize",
    deserialize = "AttributeType: DeserializeOwned"
))]
#[serde(rename_all = "camelCase")]
pub struct OwnedIdentityCredentialProofPrivateInputs<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
> {
    /// Identity provider information
    pub ip_info: IpInfo<P>,
    /// Public information on the __supported__ anonymity revokers.
    /// Must include at least the anonymity revokers supported by the identity provider.
    /// This is used to create and validate credential.
    pub ars_infos: ArInfos<C>,
    /// Identity object. Together with `id_object_use_data`, it constitutes the identity credentials.
    pub id_object: IdentityObjectV1<P, C, AttributeType>,
    /// Parts of the identity credentials created locally and not by the identity provider
    pub id_object_use_data: IdObjectUseData<P, C>,
}

/// An owned version of [`AccountCredentialProofPrivateInputs`] that can be deserialized.
#[derive(Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(bound(
    serialize = "AttributeType: serde::Serialize",
    deserialize = "AttributeType: DeserializeOwned"
))]
#[serde(rename_all = "camelCase")]
pub struct OwnedAccountCredentialProofPrivateInputs<C: Curve, AttributeType: Attribute<C::Scalar>> {
    /// Issuer of the identity credentials used to deploy the account credentials
    pub issuer: IpIdentity,
    /// The attribute values that are committed to in the account credentials
    #[serde(rename = "values")]
    pub attribute_values: BTreeMap<AttributeTag, AttributeType>,
    /// The randomness of the attribute commitments in the account credentials
    #[serde(rename = "randomness")]
    pub attribute_randomness: BTreeMap<AttributeTag, pedersen_commitment::Randomness<C>>,
}

/// An owned version of [`CredentialProofPrivateInputs`] that can be deserialized.
#[derive(Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(bound(
    serialize = "AttributeType: serde::Serialize",
    deserialize = "AttributeType: DeserializeOwned"
))]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum OwnedCredentialProofPrivateInputs<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
> {
    /// Private inputs for account based credential
    Account(OwnedAccountCredentialProofPrivateInputs<C, AttributeType>),
    /// Private inputs for identity based credential
    Identity(Box<OwnedIdentityCredentialProofPrivateInputs<P, C, AttributeType>>),
}

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: Attribute<C::Scalar>>
    OwnedCredentialProofPrivateInputs<P, C, AttributeType>
{
    /// Borrow the private inputs
    pub fn borrow(&self) -> CredentialProofPrivateInputs<'_, P, C, AttributeType> {
        match self {
            OwnedCredentialProofPrivateInputs::Account(acc) => {
                CredentialProofPrivateInputs::Account(AccountCredentialProofPrivateInputs {
                    issuer: acc.issuer,
                    attribute_values: &acc.attribute_values,
                    attribute_randomness: &acc.attribute_randomness,
                })
            }
            OwnedCredentialProofPrivateInputs::Identity(id) => {
                CredentialProofPrivateInputs::Identity(IdentityCredentialProofPrivateInputs {
                    ip_context: IpContextOnly {
                        ip_info: &id.ip_info,
                        ars_infos: &id.ars_infos.anonymity_revokers,
                    },
                    id_object: &id.id_object,
                    id_object_use_data: &id.id_object_use_data,
                })
            }
        }
    }
}

/// Verification material for an account credential.
#[derive(Debug, PartialEq, Eq, Clone, serde::Deserialize, serde::Serialize)]
#[serde(bound(serialize = "", deserialize = ""))]
#[serde(rename_all = "camelCase")]
pub struct AccountCredentialVerificationMaterial<C: Curve> {
    // Commitments to attribute values. Are part of the on-chain account credentials.
    #[serde(rename = "commitments")]
    pub attribute_commitments: BTreeMap<AttributeTag, pedersen_commitment::Commitment<C>>,
}

/// Verification material for an identity credential.
#[derive(Debug, PartialEq, Eq, Clone, serde::Deserialize, serde::Serialize)]
#[serde(bound(serialize = "", deserialize = ""))]
#[serde(rename_all = "camelCase")]
pub struct IdentityCredentialVerificationMaterial<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// Public information on the chosen identity provider.
    pub ip_info: IpInfo<P>,
    /// Public information on the __supported__ anonymity revokers.
    /// This is used by the identity provider and the chain to
    /// validate the identity object requests, to validate credentials,
    /// as well as by the account holder to create a credential.
    pub ars_infos: ArInfos<C>,
}

/// The additional public inputs needed to verify
/// a [credential](CredentialV1).
#[derive(Debug, PartialEq, Eq, Clone, serde::Deserialize, serde::Serialize)]
#[serde(bound(serialize = "", deserialize = ""))]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum CredentialVerificationMaterial<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// Verification material for an account credential.
    Account(AccountCredentialVerificationMaterial<C>),
    /// Verification material for an identity credential.
    Identity(IdentityCredentialVerificationMaterial<P, C>),
}

/// Error proving claims in a request
#[derive(thiserror::Error, Debug)]
pub enum ProveError {
    #[error("failure to prove atomic statement")]
    AtomicStatementProof,
    #[error(
        "the number of private inputs or their type does not match the subject claims to prove"
    )]
    PrivateInputsMismatch,
    #[error("cannot prove identity attribute credentials: {0}")]
    IdentityAttributeCredentials(String),
}

/// Error verifying presentation
#[derive(Debug, Clone, Hash, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum VerifyError {
    #[error("the number of verification material inputs does not match the credentials to verify")]
    VeficationMaterialMismatch,
    #[error("the credential was not valid (index {0})")]
    InvalidCredential(usize),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elgamal::Cipher;
    use crate::id::constants::{ArCurve, AttributeKind, IpPairing};
    use crate::id::id_proof_types::{
        AtomicStatement, AttributeInRangeStatement, AttributeInSetStatement,
        AttributeNotInSetStatement, RevealAttributeStatement,
    };
    use crate::id::types::{AttributeTag, GlobalContext};
    use crate::web3id::did::Network;
    use crate::web3id::Web3IdAttribute;
    use std::marker::PhantomData;

    fn remove_whitespace(str: &str) -> String {
        str.chars().filter(|c| !c.is_whitespace()).collect()
    }

    fn identity_cred_id_fixture() -> IdentityCredentialEphemeralId {
        let mut ar_data = BTreeMap::new();
        ar_data.insert(
            ArIdentity::try_from(1).unwrap(),
            ChainArData {
                enc_id_cred_pub_share: Cipher::generate(&mut fixtures::seed(0)),
            },
        );
        ar_data.insert(
            ArIdentity::try_from(2).unwrap(),
            ChainArData {
                enc_id_cred_pub_share: Cipher::generate(&mut fixtures::seed(1)),
            },
        );
        ar_data.insert(
            ArIdentity::try_from(3).unwrap(),
            ChainArData {
                enc_id_cred_pub_share: Cipher::generate(&mut fixtures::seed(2)),
            },
        );

        IdentityCredentialEphemeralId::from_data(IdentityCredentialEphemeralIdDataRef::<ArCurve> {
            ar_data: &ar_data,
            threshold: Threshold(2),
        })
    }

    #[test]
    fn test_identity_credential_id_serialization() {
        let cred_id = identity_cred_id_fixture();
        let data = cred_id.try_to_data::<ArCurve>().unwrap();
        let cred_id_deserialized = IdentityCredentialEphemeralId::from_data(data.as_ref());
        assert_eq!(cred_id_deserialized, cred_id);
    }

    /// Tests JSON serialization and deserialization of request and presentation. Test
    /// uses account credentials.
    #[test]
    fn test_request_and_presentation_account_json() {
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

        let acc_cred_fixture = fixtures::account_credentials_fixture(
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

        let credential_statements = vec![SubjectClaims::Account(AccountBasedSubjectClaims {
            network: Network::Testnet,
            cred_id: acc_cred_fixture.cred_id,
            statements: vec![
                AtomicStatement::AttributeInRange {
                    statement: AttributeInRangeStatement {
                        attribute_tag: 3.into(),
                        lower: Web3IdAttribute::Numeric(80),
                        upper: Web3IdAttribute::Numeric(1237),
                        _phantom: PhantomData,
                    },
                },
                AtomicStatement::AttributeInSet {
                    statement: AttributeInSetStatement {
                        attribute_tag: 2.into(),
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
                AtomicStatement::AttributeNotInSet {
                    statement: AttributeNotInSetStatement {
                        attribute_tag: 1.into(),
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
                AtomicStatement::AttributeInRange {
                    statement: AttributeInRangeStatement {
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
                    },
                },
                AtomicStatement::RevealAttribute {
                    statement: RevealAttributeStatement {
                        attribute_tag: 5.into(),
                    },
                },
            ],
        })];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            challenge,
            subject_claims: credential_statements,
        };

        let request_json = serde_json::to_string_pretty(&request).unwrap();
        println!("request:\n{}", request_json);
        let expected_request_json = r#"
{
  "type": "ConcordiumVerifiablePresentationRequestV1",
  "context": {
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
  "subjectClaims": [
    {
      "type": [
        "ConcordiumSubjectClaimsV1",
        "ConcordiumAccountBasedSubjectClaims"
      ],
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
    }
  ]
}
"#;
        assert_eq!(
            remove_whitespace(&request_json),
            remove_whitespace(expected_request_json),
            "request json"
        );
        let request_deserialized: RequestV1<ArCurve, Web3IdAttribute> =
            serde_json::from_str(&request_json).unwrap();
        assert_eq!(request_deserialized, request);

        let private_inputs_json =
            serde_json::to_string_pretty(&acc_cred_fixture.private_inputs).unwrap();
        println!("private inputs:\n{}", private_inputs_json);
        let expected_private_inputs_json = r#"
{
  "type": "account",
  "issuer": 17,
  "values": {
    "lastName": "xkcd",
    "sex": "aa",
    "dob": 137,
    "countryOfResidence": {
      "type": "date-time",
      "timestamp": "2023-08-28T23:12:15Z"
    },
    "nationality": "testvalue",
    "idDocType": "bb"
  },
  "randomness": {
    "lastName": "699201275c7b728a133a3cd9135f218aa951a2274432c9381fedd8a6ed7e497a",
    "sex": "699201275c7b728a133a3cd9135f218aa951a2274432c9381fedd8a6ed7e497a",
    "dob": "699201275c7b728a133a3cd9135f218aa951a2274432c9381fedd8a6ed7e497a",
    "countryOfResidence": "699201275c7b728a133a3cd9135f218aa951a2274432c9381fedd8a6ed7e497a",
    "nationality": "699201275c7b728a133a3cd9135f218aa951a2274432c9381fedd8a6ed7e497a",
    "idDocType": "699201275c7b728a133a3cd9135f218aa951a2274432c9381fedd8a6ed7e497a"
  }
}
        "#;
        assert_eq!(
            remove_whitespace(&private_inputs_json),
            remove_whitespace(expected_private_inputs_json),
            "private inputs json"
        );
        let private_inputs_deserialized: OwnedCredentialProofPrivateInputs<
            IpPairing,
            ArCurve,
            Web3IdAttribute,
        > = serde_json::from_str(&private_inputs_json).unwrap();
        assert!(
            private_inputs_deserialized == acc_cred_fixture.private_inputs,
            "private inputs"
        );

        // the easiest way to construct a presentation, is just to run the prover on a request
        let now = chrono::DateTime::parse_from_rfc3339("2023-08-28T23:12:15Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let proof = request
            .clone()
            .prove_with_rng(
                &global_context,
                [acc_cred_fixture.private_inputs()].into_iter(),
                &mut fixtures::seed0(),
                now,
            )
            .expect("prove");

        let proof_json = serde_json::to_string_pretty(&proof).unwrap();
        println!("proof:\n{}", proof_json);
        let expected_proof_json = r#"
{
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

        assert_eq!(
            remove_whitespace(&proof_json),
            remove_whitespace(expected_proof_json),
            "proof json"
        );
        let proof_deserialized: PresentationV1<IpPairing, ArCurve, Web3IdAttribute> =
            serde_json::from_str(&proof_json).unwrap();
        assert_eq!(proof_deserialized, proof);

        let verification_material_json =
            serde_json::to_string_pretty(&acc_cred_fixture.verification_material).unwrap();
        println!("verification material:\n{}", verification_material_json);
        let expected_verification_material_json = r#"
{
  "type": "account",
  "commitments": {
    "lastName": "9443780e625e360547c5a6a948de645e92b84d91425f4d9c0455bcf6040ef06a741b6977da833a1552e081fb9c4c9318",
    "sex": "83a4e3bc337339a16a97dfa4bfb426f7e660c61168f3ed922dcf26d7711e083faa841d7e70d44a5f090a9a6a67eff5ad",
    "dob": "a26ce49a7a289e68eaa43a0c4c33b2055be159f044eabf7d0282d1d9f6a0109956d7fb7b6d08c9f0f2ac6a42d2c68a47",
    "countryOfResidence": "8e3c148518f00cd370cfeebdf0b09bec7376b859419e2585157adb38f4e87df35f70b087427fd22cac5d19d095dae8b2",
    "nationality": "8ae7a7fc631dc8566d0db1ce0258ae9b025ac5535bc7206db92775459ba291789ae6c40687763918c6c297b636b3991c",
    "idDocType": "aa3f03d85c333c66260a088ab10b778ab8796700f3def762ed881cdf5bfe37a72251bc329c7b553521fc49d5fac43ded"
  }
}
        "#;
        assert_eq!(
            remove_whitespace(&verification_material_json),
            remove_whitespace(expected_verification_material_json),
            "verification material json"
        );
        let verification_material_deserialized: CredentialVerificationMaterial<IpPairing, ArCurve> =
            serde_json::from_str(&verification_material_json).unwrap();
        assert!(
            verification_material_deserialized == acc_cred_fixture.verification_material,
            "verification material"
        );
    }

    /// Tests JSON serialization and deserialization of request and presentation.
    #[test]
    fn test_request_and_presentation_identity_json() {
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
                AtomicStatement::AttributeInRange {
                    statement: AttributeInRangeStatement {
                        attribute_tag: 3.into(),
                        lower: Web3IdAttribute::Numeric(80),
                        upper: Web3IdAttribute::Numeric(1237),
                        _phantom: PhantomData,
                    },
                },
                AtomicStatement::AttributeInSet {
                    statement: AttributeInSetStatement {
                        attribute_tag: 2.into(),
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
                AtomicStatement::AttributeNotInSet {
                    statement: AttributeNotInSetStatement {
                        attribute_tag: 1.into(),
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
                AtomicStatement::AttributeInRange {
                    statement: AttributeInRangeStatement {
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
                    },
                },
                AtomicStatement::RevealAttribute {
                    statement: RevealAttributeStatement {
                        attribute_tag: 5.into(),
                    },
                },
            ],
        })];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            challenge,
            subject_claims: credential_statements,
        };

        let request_json = serde_json::to_string_pretty(&request).unwrap();
        println!("request:\n{}", request_json);
        let expected_request_json = r#"
{
  "type": "ConcordiumVerifiablePresentationRequestV1",
  "context": {
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
  "subjectClaims": [
    {
      "type": [
        "ConcordiumSubjectClaimsV1",
        "ConcordiumIdBasedSubjectClaims"
      ],
      "issuer": "did:ccd:testnet:idp:0",
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
    }
  ]
}
    "#;
        assert_eq!(
            remove_whitespace(&request_json),
            remove_whitespace(expected_request_json),
            "request json"
        );
        let request_deserialized: RequestV1<ArCurve, Web3IdAttribute> =
            serde_json::from_str(&request_json).unwrap();
        assert_eq!(request_deserialized, request);

        let private_inputs_json =
            serde_json::to_string_pretty(&id_cred_fixture.private_inputs).unwrap();
        println!("private inputs:\n{}", private_inputs_json);
        let expected_private_inputs_json = r#"
{
  "type": "identity",
  "ipInfo": {
    "ipIdentity": 0,
    "ipDescription": {
      "name": "IP0",
      "url": "IP0.com",
      "description": "IP0"
    },
    "ipVerifyKey": "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb800000014b9ac0998207f2313a6108aa5b79ac1f43440390d173d8f155567e9d66e379f959b1625b21f0a90e9cb741a33f8f30f8b8cd5c323290ce730dc0d46036b0b17b9e67ee192926d2f6d43eeb6cd2b3ef2e01c3082d8ae79ac7b21e03fea2e3d8be6a994a4f67adaaa5f595809c1eb09e329d9217030e204203009acb39768f29d8ee7ea9cac577426e60a4b6092b06434edaa9453c337ccba9aed254158238fa981d8771f9828c35dc7536dff17d1aafa2596c91b5208ee4122f2f8834ffde44466b5f8e84a6df5094b7152e891d69cd65eae54e3ac1661c7f9f344b92cb5a8f81ab439b87a5779598299fc13999b9cfe4788ce41f0d0071988ab052828d5463e17afb402a5bd627b923541fc25b572b756052f574e14a328afed2d06cad3c717349862ba5b2fc1490bd02dd78bb98e5eb32e47913d167243c130422c196c4027f806621065be565b4338fe7b410bf3bf6386ccee2c114c4bdcc48ba355e7c85debc67c612268fbdc3739d9636b1502e356e92415dd56bc30e6128acf0759b80fcaaa554b2c97dd223164bea0301ed858473aeaade0848ca1ecac1185241115e5f27c4752dce5eb2bb77caa166f021cec9d89b4f1fafdadffdb1d33d0662976a6397b3e29c127e22e31d462422d28f205ba90c215b0debfff9a7e72089e29b677679130150226672d4b9922e4fc65ed2f5a714197c282968754ee8ba82692d0a02eced66617dcefb35fc4590a61089cdb6f81957624d37d5033289f4f049912ab3f065f8e5c6fb6e1c0350a1ffc9596c9d8983a91d3023283db5f1cf86f15bbb0bc94c76439dee9ec503fff630b56d4a23317dca826f881bb396acbcd9dac8197bed966cdaea2d9e39e9d0076c787eeb40fb52777ea2af213164698e43ea1602f52f02fe1d23ec12a74a2076fe9aac071cff13755c446e0827b9d13043a89a78e6d8020b943073aa8921f400272fa4956895a1c6ab9014a86cb0a975ee6ff78f9481644225baad638b58a680363861a96bc89bed7c42d80311dd500be28de1a9414aba5cb962b3cc30f8d4968d9a472056156cbcd688db43731b354b5d3a39a5932b77612d665885f0d65639f86a68e2f18b3a1ebb6bba682b201a8676417afb8067eb0b36547514166d12de0bcc337c519a77f234e59bed337fe86f458476c325fa44f4abf5730d58a27a0d58209b56d18c2cc03fa09e83337c0cc3b6733605bfa8145b4361816ddaa5444b9633f2a1fabb932719825e6470148f57259d172b326a9b6029bd0495cc3c06b85054a8dfcc883e46a093ee3edc77ddb858dbf037a40ee9611cab1eed5631d60f2f2650d2329ef989defc64b19978e6487bedbcd969800000014ab8b28bfbb362a4effde28779dd580e2f0f413be25c5eae1c4b791c823053a39576e75936e6bc478cf567ecec0d647c116cf205ef41016494f9d9e5cd42f8d43c14048450a175084e2d89de8371eab8356613efc2f59b541023e7e382bb01e4b8a151d3998bc783629fa35c1f90b27f506be14a5f3f10289612d0fc87407a1a776249b2f6fa8a97fd94d37cdec154f6e192fee739a8e8685289bca273713bc0d8defd5734bc36b84e6cd3ba1fccf7eb115c26510719859257e02381b93888ac382e5aaa6633064a32c42f2d2d0f92d15a846a9f3dbfb867cc1c2aa515193736306adc92f61bcd21d29304794f54c91c6078af67f16ff449e1b8c25a76f2ad48e08fdd0338dd4c1168caa6f0c868bf7930cf61176a52d2f1ca77bbdf78fc48a8ab65ddc3d69eb833f917eaf280aeae14327f89a9f7e240e2bf34385e59bc7e3e77ac67cea40c4908fbbed6b1f22be5497058effea4557a29c013f8c952e340c9fee45a003f354ee9377e5d83dc35e742af600eafa79aa08941f7d3f44bb1c2468ad50a3aba1a90893fe241477b1a8d73d568e8c46759f8f650fa8ffdff4b041a49ed94a618459c7a1bbf6ab03b647bbf50d32e37663684a3e72ab63b97da818001646b1bfc76ab0ade98438706d6ca52c63502b61d110d750c09c8c8e7d5ca782a26d349123e48d57c4ff9d377748e64c6bd5f92b2ba908f1f9b4fc0cad0f590ca612384550dbe3e33cd57253c7c38e870f63751b47bf2e308d74cd2204ea6c311f399d6d91c5a4a66f01dee587418692eed0949679a89227c3018d37f70b202bb44c5ee8a41edcde3053e33971a48523c728fd956216331654fcb2e87a32ef3e8c4032db5275c556b1eb6b9d0bfe0eac0f44b2667cf9cb4c45af4c530406c6862f67ee508ad6a3961aa472f5a5037fe7251f2897c90624a07742258f7b0cfdec9438e2950347e5536d54ba09b0af2545b4f24de31d91575ebb28119baab4b2b863791e5cee31dbb30e4164213d7d5c7c0f9eb8f2b81e7de271b7d9f4606565af36766c9324e75d1c4061d31c79939f9ab83986b98459bd80f16ef519859eceedb79b40be49c0fdcdda821091a7cc79d853858709eda69916a8ac0c2b845c0ae33e75c31f8e7bc6a0d2d9098914643d6b0136b28d072c9759bb2f79826cceb7ad5bc089c186b5ecc332d5931d43a7d35f11fdd4398f236b05cb46f5cc0f82c23f98e2d0a4e797bb087edf5e34abd4f13a52b5a9a4d45461c02412a71ac64d221e006911248a5114248b83cf93332db0e90c605d10174688454495d348aa0a8f7973e2c76a0b0f411087aa211194726fe458e5ef69e962b7a88c73d9b471ae74b5a20cb9c783b97a21dcd35f90bf1d4260e5f6f35e8812a47d98142bf9cacbfa6a55dc649d9a931195509430f6542ca2541751bb80ccd3f9678b08a89fd69f115b04e0bc2ab0a77ab7cf48291fdcdd16eb2603acd60cfcffbaf7406e5eeb4955c28ee6b3bf572831c5560ae5f04d8a7d5cdc1b3d213505cef4d3668e03a196cd95bed961e2fede8200ec6d4da38ca6593909e10691b5d67efbc7bc329576d1809190cbc28a2be9e2d0ed16a2b8346419e19346f7f786119f03b316d0b389e8e1ceb5c823da009c0095a92718da957eba9482a0a2120ece8cd375ee17fe6f06a1272712c95c182e3c4fd13d4b4ca84998d70ea9ce3a801b1fa3cace5eb38741b33c034d7c757b779675235d8816ff52d17a430d00f404086bce79bb28755db93d79aff5e56c8961c7aeb260bd4b10d46c9f266d76f4d0f72eec3f0b52e9f49c56f9df5305e1340579afec7be028b134fd50080a880db8d61c39b94640adc9e519823913a9fc25d185436f22ff25c766f5a4f611830f1ee00e2c7a6ab33519497d898c56ac9d0133d0c34e27c146dac04c69f84a623aea2c3483545206d300ddb59af081d2dc3182603591d61e0dce6d330f12f360b1597761d274995e8518ab2d254c437e635b62cb426255d496af2f2fdd55aa8f839bca8052e3009f88606b20d7987c5dd21ac801511862d0b591edf137b198043ffb8b4b67386d456e5673bd63fab29a58aaf79027279118c0c1abefe106f7e7e9b49c63f945e4ad012d449f19508fbacd35e4931c769e49cd5a81b71451fa4ea6f001f1436236f3540302d1a7a3e58b26378ef8a0987fcf629ccb9a11a16562f790c2f8e3d16aa05372a4834861886afc01ad8ca2d43e48b7d0b1e5f9067d720316f2f4f6b607d0405ae766b57193bf1114f7be1353c33e2f2caaf67afc218297914eb43b38395c937b7183a0adc2b0c6a4714bec6805e373c4be12ec36084c2c58a3126fdfc884a852fdbff82b15023462737eedf78fdd565c0566440c10c8ad2508ad61d2f3aa52b307e7552039a1f645b5bbc75e6f24fa3d3946c39507f522504b223a305093ac33a5c84f90517f4368a639f34500410ee6731eda080da4f1a75bf962f1aee4d5289327a00e2bf2d90dcbffa5400b33c66ecf25620bfc638aa216d13bdb5832985a8d6892e3a0bb6474a6b2d9b5f59908feb6974592f02a743fe5c6a3cf6d4aa1a54154fea9f125af029473dea702dabebada9c2542783a224cf36c9e5626fc9f3af4e5c28283b15a10879df9989ba31758b5b715195ae93dd222319933d62a45a8572db0c317b28ddc86fd40f625275f6e4ea987576f60563636e002973a986acf34b4deaebf77892292ca20404bbb9455a2c3afc186c84e57de3626d3ad964b8d172ee7220fb72d1ff5e8a219b751a0c0532af50ca2ee0b7d7212800da6587cb7f530ab145e39a12089174c3fe120a8b7ca7b758c8e34b84ce9b4812ac73a2a0a2380b8",
    "ipCdiVerifyKey": "cd73dfc58e9f095f91726019504f8274b48e6689258f90a6139056119ac1b337"
  },
  "arsInfos": {
    "1": {
      "arIdentity": 1,
      "arDescription": {
        "name": "AnonymityRevoker1",
        "url": "AnonymityRevoker1.com",
        "description": "AnonymityRevoker1"
      },
      "arPublicKey": "b14cbfe44a02c6b1f78711176d5f437295367aa4f2a8c2551ee10d25a03adc69d61a332a058971919dad7312e1fc94c5856793e4ba5d058cea0b5c3a1c8affb272efcf53bbab77ee28d3e2270d5041d220c1e1a9c6c8619c84e40ebd70fb583e"
    },
    "2": {
      "arIdentity": 2,
      "arDescription": {
        "name": "AnonymityRevoker2",
        "url": "AnonymityRevoker2.com",
        "description": "AnonymityRevoker2"
      },
      "arPublicKey": "b14cbfe44a02c6b1f78711176d5f437295367aa4f2a8c2551ee10d25a03adc69d61a332a058971919dad7312e1fc94c5adffda1428112cc19e05f32e63aec7d686ad0cb2abbe0b46b46e94927e007b1372114ffc7bd37b28d878f9afbb59dd0e"
    },
    "3": {
      "arIdentity": 3,
      "arDescription": {
        "name": "AnonymityRevoker3",
        "url": "AnonymityRevoker3.com",
        "description": "AnonymityRevoker3"
      },
      "arPublicKey": "b14cbfe44a02c6b1f78711176d5f437295367aa4f2a8c2551ee10d25a03adc69d61a332a058971919dad7312e1fc94c583ed439dbadc3de91ab451aa82203c1079ee7ca62eebf57f042e7993abd9512776a215be1eef3ca99f19346260b1651b"
    },
    "4": {
      "arIdentity": 4,
      "arDescription": {
        "name": "AnonymityRevoker4",
        "url": "AnonymityRevoker4.com",
        "description": "AnonymityRevoker4"
      },
      "arPublicKey": "b14cbfe44a02c6b1f78711176d5f437295367aa4f2a8c2551ee10d25a03adc69d61a332a058971919dad7312e1fc94c5a95e8adf80e1ecefda3594baa96507bfea76ef1d4176e00bd2ce295ba901d93e6a2ffdc4492707b3c79a54fb50bacc9d"
    },
    "5": {
      "arIdentity": 5,
      "arDescription": {
        "name": "AnonymityRevoker5",
        "url": "AnonymityRevoker5.com",
        "description": "AnonymityRevoker5"
      },
      "arPublicKey": "b14cbfe44a02c6b1f78711176d5f437295367aa4f2a8c2551ee10d25a03adc69d61a332a058971919dad7312e1fc94c582917ec5cf87f432d508e5e9441c42e963c6a976b38688a204c399674da3cd0d20f1771116756f55443bad87bdf90cb8"
    }
  },
  "idObject": {
    "preIdentityObject": {
      "idCredPub": "856793e4ba5d058cea0b5c3a1c8affb272efcf53bbab77ee28d3e2270d5041d220c1e1a9c6c8619c84e40ebd70fb583e",
      "ipArData": {
        "1": {
          "encPrfKeyShare": "a45064854acb7969f49e221ca4e57aaf5d3a7af2a012e667d9f123a96e7fab6f3c0458e59149062a37615fbaff4d412fb8e39f1455436332ba88d08ef4188a917c2b9759c74fdd92543cdfc7853a4b8d1365a778e39c1eb8364455ae86828fe7acb968eac3f7f940d80e2cc4dee7ef9256cb1d19fd61a8c2b6d8bf61cdbfb105975b4132cd73f9679567ad8501e698c2b9642b9736a8fc19992307ad9c31cb417cf55e266ee030324d47a942206bc70579d2fce85ba37b1d122756f8773f6d4c8b3287ab16051907adab6558c887faae7d41384462d58b569b45ff4549c23325e763ebf98bb7b68090c9c23d11ae0577937c415ef3956c1bd631ca1cb02c34cc74f75f16e5209c9902433b3d37f10b93fae5718ee548247298198e87aca38d75b5754b446925b3861025a250ab232c5a53da735d5cfb13250db74b37b28ef522242228ab0a3735825be48a37e18bbf7c86fb4315bb9514c39c60f82a4e56ad42048a6d897749082431728d4cc5abd4c55c978d3a79ffd33d720a6bd498c2226cb0e9cd5f084c79d1d7beb52f58182962aebe2fad91740537faa2d409d31dec9af504b7ac8dc15eae6738698d2dc1041099fff2ac228bbf41eb01ad00e04bf822337e51f0eae379ea97d453ad74bf25271c629e6e8d1a9f0b4ec216db9c264b9993c123a38dd9c43cba26e535bb7d204ce1616d4a3d4203ee7e9f6db171c6171624dc82820b4c21456296aed19e9a26938ea05e114cb4faed79a571dfd8a41262f1318e7734f08f285d4bc9eb6a61a129a61d5d73abeba5ca67491d93f5dfbb1695e15f7ab4b21d8e42d8745410b4952f08884a59265039f0ad1188ea2988e4b9a9dd7d5059534ceda7a8b68fd7b67ac8b0d629f97a5cbf33517cfe85e0c4d11a2c6f0b404c4cfdbf71bd3dbc7a300229ee7498916ef620b954a1425cd4f565958b962fb370b2cc9af9074b639813133cb5cb49cf7556bbbb825dc350231a32ec4fbe1ef7f9a461f0f85b8f8cbf5cf614a723c4f3d10420bb92282ed0619581e0f5cb28ca7d27e11bc0409b9c32b26336420ffb2cb7dc6b701c90f03c3889ebd6",
          "proofComEncEq": "6b701a973c1bb3d8cdc73751dd9ddfe9bff40d3889e29ea9c81fdd00df48b2aa06fd5013628ea9f6d7135763aa5abdeb3bb40ebf6f9bd02945f61360b03fecc562b2151e048ebcc483562ca8f0c1bf56ff8bb5a624d587ad3e70d0178af71daa"
        },
        "2": {
          "encPrfKeyShare": "98909caaab24d52096778013b3078a91bdd9d2ec3740dfc20d1d3d96a97cb960dec9f7e76506aedf221d3ee457f0a02f8eee3d602d9aa83d0646525a66b1389f48f4514e59dc370f9de526ff71994817ea661b4c2c4da550308e93f591998081951db505906dbd2484a2dcddcd750deb8518068708dba46098889d3c63b3b44d1cdb3a6ba18ab399349b686544276ef298df8f30679ec5db25e079ec9a59ea90c9630dbc511e70a566ce0c3b12ddc0a4781444c9a47829c7e0924b8319232a46a7067b6e6d9d679ffd2754855bd419fa58523a45149d8d3863ec6bc1a0a397b5468e5ed85ab6b9c096cab0c022e058c0b4408fe8bbc46975078b49e5fabf210c20fa8f2f880a41569d8085fd0302fe1430123a253590496f10fb2f66f9f41deb93cfa1e32858566240edbe848cc8ed0248a58c516617dcb366b04b4f667ab6af0cbff779ee60dcf1b92cf047234c05feaae11e4921a0ff2b8802951e782710431e35b56c92d06dd258260a6b0e2731f5a6dcab6dbf0bbda1a9f95eec83234a958887f05cd1c47d26a157bc17e8fa66373fe5f6c7d42f1f58fad50531fee128b76ab8dc6cb54055ce3a33ac5ef02998a490f26c6e25f375cd74b2b96df178932315b9fbad3403147dca9c956e46f02a552399391001e344c8033c6944aa486bda8bc78da606e9d7b2dea63f73d6fa660014bc52edfd1a6fc26831993a7c73e58a2a8442ff084f128a30c3444810d143b58de4aad744b7351319ca5c1b98eba38e438483987a7990742505658626efabc0714da5aa3af1352aed59703ac4496844a4afa7050804bbf2741656e9ccea169c735672cc2180d6a17ff01f4bd77a7eb767a21187f322dc54d6386cadfedfab7d98f606a3af119e50a0f8350b7d2df1080e52e05069c1a59248590f0546a7f1613eca006eec003c9fb84b32b4b594741d8964200f39e5f759fecfdd594772111e4b6a5c07fb6c6a80f684b2f896f49a2d164de5e2304b5e8aba14d5338f473cb8ab66c353797a47d848a9161636985729df97cecec22810fec545a357c3f50fc716e193b2120e17a55a3ce73eb6d9ab38",
          "proofComEncEq": "45e6b59529d503bd61ad6ba55f314921d4ed21ec4b202b55bdde74c752d8b20900473da0371569129f83b1ec26a2d03365636834fa25fd43fc90efb39472126557092e454f0e03ea20f4354c0ebbdbf898d55309710f56e83e21505ff76d4599"
        },
        "3": {
          "encPrfKeyShare": "a9f8dc51aa51f8c8ba99eb584d3e8edff117e6cbb794bd38d60196a7063c0519a7d210d44d6e706300575c3fafe26b0cab34e550b2305ec9ca11c07b088d7fd7984204cf90b00a653ae845b024226d1f1f3cc13254c53e21d708abb78815f557b73fd28b41303fd8f70980b6667c50dd301940ca13bfde50acef475b36ddd440174761bf16f802b2adf1b843d4cd2159993abb70ab12882dba0c70fc22093a7ef7d6fc6575f1fdb6b9cba4e0f6e1ca752acd41e8321ea6eb7bade6f723090901b51d05cbdd46e968dbb5dff3351f6fa94f09a27595912db1e515ec898c169771d4ac2e2baaf1cbcd48f074d99f4476baa872f5a37c8c01cf8a7903dafb31fe4924648dbc09f18a001375f649a766c1404c468375f3e77328be86f3a2e1996f65b34de4e29008fa4046e32127de9cbe16212482c903024753908d23445b96194b57a32be4d7c32c0239e93e79410786009587a2da52335f594e0cfc175b67819fab9fdd7316aba577a3754e8efcdb6897fdcd91a78b0c42ae6b93cbdca59697cf907edb3389985ce020cdb1f07fc1be159c1ca81a62c50e784295ac6d8570772d9de01a12fc417a79e036306c797bf931af0b868e63176d3506fd9a841e36d228fab96bb64c4dca17abf457e52b06bd9d5b9680e803a04d2a7beaecc490c0e329b3b1f661459aa42a4cd45d2fa5d596555cbca168c15f0e69fd16ef2fb85a2c59b563e8acbaf4026d6616b891fd8fc8c584adae7248d833fa5c95ebefeaa1046ad1e8d61c3f221ceea4364d3f91e2a836586003ff4ee4218816640ce5f93d26988b586da2bb1970b8bc3e1504ac697514efd3efd84d508d92e447e4d31de06ec2397738f9a93fbb8f0743abe2407f9c3aaf47eb302705dc7e1ee2433c93a97628a346cda205d87230817db0e59440584e28cb46e578f9dce6b347b1684f703302a8011c4ae5a4da0fad84a0e445a2e24265b168a013b1905b72c45c4125e5bce96037ba561245a98057559e7253655fecb6d28b96ee55717fd5d77a5420381746b78878b1c24abf0d26e8e1c770a76cc52fc9da433924cdf4a9f746cfbae7c2ea",
          "proofComEncEq": "5eac61d458ff0b96d602b7df800d1f5817a03deda17d9e0690831ebae31245731383f8ee51e4c354f96f73ccab8bcf30b02810d055ce6654a05a5e5c2f7d3eeb181a7bd597eb5423abdac860a044173d14ade08c9d3efd174052f574fb548f82"
        },
        "4": {
          "encPrfKeyShare": "97884f06927a71c5f3b359eec48ccc02896a5dc4bd015281c20f4dc24d90b37773e3cb23aec76c2cf1790751803e60b29031458b8d0f230b319aa692a3e8943e7af2d5b1b07f218a89d2023e7a0b1be2e60e59f0b429ed7a6353c3b531abe0fa9169e24e415fc542873ab749c573a965fecacaf4f82f50cffc770574b5bbf7acb2b5efd9bead89142b4f4925ad401e228199d841fd9fdd504030bc8b64f1e3b968bc34db66458188f51cf15bf5399e9666e777c5803b0bcdeaa5cc8276dbdcb39428998328f946e3abc620ac5771fff823df17cd811329531b1ce9b2ffbfb5d6e8c5cea0ef5b882118abf124758cfda8b807c27e69ef1917aa3cc7c34392a880d8c560f0630808f41d20dc6136512b0363a361cd295a7320873a25626ef16a0ba6b4a3ffa661cf841dc85e8fdbf106fb86a455a5eb922da5f7d91f4b8e136f5d7c1b9a2525af06b686004ac9c446416693f6d5f3a234df348ec2460b638267bfdb660b492062b98fb9273ac5beb78a3404ef3f1d635ecd45d8903f5a7a51bb02b3bcdd16b2636663f580711a5a478b3fc58a7e71253977f50a7feaebcaa7e16ea6243d4b1bfdf527a2648c9e4d251ea3ad9efcb3a03bb14faf4656a890943051f97322a59f5159c0e2e47e362ae5ffd26f9fb946167a49ca2cd0d123e32e130b956aca8fb8cfae00bc806532b978940ac3b618d6c45dca555ca6478f8e5f3a3dd692c73f5924526354f316edd04cf47aaf32d7e765e94a53671698e2a168cf27e3acc31f3e6f0b6acb8af0d0f107126a1b3bd027c5a7397b670862b3e8c4e9c6adef865738ad275b7ca8923492889890ec203006616d693f81b3941e68d66e7ba645cc408bf3c85369c3bd0e7f8ed8a6af4d195d1fce1b8fda71d8f5ce206849aaacee1ef63c991a2f7a8b17e4a9950c2b54c04163da053087f3f47ca3888803a4e94d76680a321279de6384661c0d8825d9df144486138cef004b7c52a15536bfce1e16ead5e9889b5024169c211bd3a60a4cb89a80283f2ebfbac9c881faada4d350dbb818d6573cd1a165ac31bd6ffc21302e66a5f8128cdfe495b783425a",
          "proofComEncEq": "4dffbda31447676257b12785798537001c8645de3b3bb6a03b2814caeb1c75154957246a7047c8e631846b17530b46206d45ecb393d2fb6d7f90ff2fd11fe193640acbe581b6d7ea8504c71360259c3e002601f4298e5057e71d7d49793fd3ff"
        },
        "5": {
          "encPrfKeyShare": "a1600daa9c6c0deb892bdcb26aadce1f8483b3de6c9adfe42d2e30063511e8deb040074e4215c8a7bf3b2b945dba292fb0c5eacb03185f390cdc9ee6a944aa668ae24464daa0c0544b2a501d713d96af42837a2935074588ea93c6d71a6a4db5b10d34a436f5e80373f8afcdd2c1fe22373ef511f0e2fcb0914176af04ec2ff721ed3add858e32b743fe12a19186e35c80a65a4e389f404450c56cf6ef3ea2bac2a81603faef1b661a472837019a733773949d429cd80680ae9a39af2dc8bf6db51f0dbf988869d1a1c4c64c8148d3249ed8a21e582ced33beedf7dad41dcece3f0c001252d6656075344e262e822cecb67700f5b3f001e50df5cc3816f265da68ccf93f9d53ef01f769878410236a06174ab27528bbbecea98bf9e4db997aaba23ee512ab29ff21f1b0b787c8aeabd1d4e8a1e440617017c945e43bde6e609572dd6007d51d5c33b3e88880892e7ce48c0e5d9d4b9c450b7044eba17bb9cf43aa7de68f1e5e69602e0ace089ffaf9ea6da7773296d54b7e4a1bb1538c0beb7fb65ef4e7d08cd21bb8b0feff88f63cd202e3081fc49650391d13a05634f65c9b88b80b0eea4213b7990029db107ed2fbb5527e4f9c970992adbbe695f75eaa1a788493fb65f435fde50c7eb1895fb4048ae722fb75a6ce1f486ca325605408408b51cfe8f8ee49ee4cf33c154cfab5d61714f6d6f6f72ac2008120adc7e1d813cfb1c8f82b8aded7d0f4c4cff136a04aac8a31d52f08e87cfea798fabb7c44913bd849dd47dc48672af47137faa2c381778f98cdcbb811d8d76162c40e0198118a9fa0a9c74ac05296c20d59aa24779612948c5467952cc525c3b14d66f33839b032edbeedd18e8023a1b8fec02b5b1d8a5c8ea7dd76e6e82bfb30d4f7d95c82f5c1a1ac66bde607f712240b2c8fe5a4cd080fcbaa0cb6452ca604d36deba20db86723cfcfcd4faaf3c52fbbcc5914e893d94d9d5cbb2e878e06ddc234f3c7e97d9b84982c55e58b87e6668fdf859b51a10aa31c4acdf554c88b6d60bc08f4f8ad8edd9859cd82342c9848b0fd4856ac5801a0e4549aeb75fbcdc3b309af107f",
          "proofComEncEq": "6d7816dd98ebf307043fd391bbe61eb111434efd769d11a3d732837e7c7f979f65579eae14d0ab65febb3b35eaabd52f8adec44ed4457e9f2b02d98a94fbb5a7444ed07e30fcf6633e65bdaf8861a9dfca60378e66593cf9869a3fcf8d216f67"
        }
      },
      "choiceArData": {
        "arIdentities": [
          1,
          2,
          3,
          4,
          5
        ],
        "threshold": 4
      },
      "idCredSecCommitment": "a5da68e5bafe04b8f9935caaee9e3cd4fffca4b98e4d009d2d668b4c0c97a6a1b87df55fdf788aa5a5e61acc815020ef",
      "prfKeyCommitmentWithIP": "8d70a7eae189f97426799818a1dc70fde23a3f954b8bfd745476b39d292cbbc5400910ad46eb738d6efa330ac42f9fe8",
      "prfKeySharingCoeffCommitments": [
        "a28ae2406d9d998d980157f1bea6897736db7b6a6d0113e38b7be2bc807e28652e8f1b68e7817b23f772004b77c347bc",
        "9916e6353b7127d55bb525cb18074b5ec130463e03a4eda583b05c2d63db40a08ab8bf05f930ec234cc2f788d5f5bfbe",
        "ab3e4881918ce964ffd55483219edd435ac865286bfd313cd834aabfa8061d2ae173cbe4b59ab2bda78faa4c2c937afb",
        "a80d7fba0822579ac0ef6915f4820f968a74f00ff5ab74e90b0a7bcb2b92093a5e94a54aea1d48ffd1e5bb3fb48069bc"
      ],
      "proofsOfKnowledge": "ef6ef15d2a74adf7069c8e7ee9fd746c939393de125176ee4c2892fb00e5b62241d218b0b454f46c36d7d03161a8a8c81878dd21d82c13b8ffc1b20d53114e841191f8046304baa71491c278d480859d6c26aaa954761a41c3c6669b0144cdca1d972bcd300f6f317af7a09e93bcd7f813b26403ede6a43933447bd50f9da36209d5da0128dc7fbccca4ad16d234108158330e225932e2d88da5273cb56d5fc72964888d74e849b131ac6b5ba1be040532f43c83398336545fc096157a0fba3d19df54491bd7392644f93d3a96400ce4d3677e4f98cfa796456e43b6d670ff7d00000000000000059267a9e5f3678d58d4425f794eff090acdcd10d874cbff1091293900d462e9c4c5002b5ac4e85a0c27e8b9012360ff9b8c7f00c5fd8a5293fbcbe6c517c36e1d0eb961e3a46b7cc1d9ce396bd9402942844e538c7d1eff6ec56ce77ffd020de9b886b42b1b3d4d6a2de0e7c8d53dfc74b3bb799d3b0d9b4d71cf61e69bd09975b0eada43761c2036e517c46b3e1d0140b285886e4f9c66fae7baca4607af7beadec245331287110e3faa0cea8ea778572c5b50d469143fd31fc869c5781490944cd98413ad189e269f6c24f2a1889855f675801b2c211ad4788515db406351223cbb5f89bae758cd092471f5ded6d5b0ba68e4e8f97d4cc5ab9b776c89c2c7313bb5a05851f4169be2331e18f6bab2048713000b9c07ed0ec035aecae28ed70200000008a353c3afcec1ab919dccfe73b3c09ce9b01adc34023dfdc4da1b2e11eeebe393e087f24e6e844ad5da0d03953bec936c8f1c18f6b8b8739e5448b9bab8ec60404e24f7585ab7abd2847e1bfecaba52e81b4aa244b092ae704b68dc543c0e8fc5a80348dd0b23ab986bfd7d8d2d74af619d2bf6ab9288290b380c0e08ee4397f1d9b7e39741cdb480e498d5e468102a248135d1685719009603c02e5f1eb3598e9580516d7ec3db37a1672bd294e13c1a25ba89bd3b123cc0e3628a85dd8be5ab937c4ee2002a43ea8dacd2e614751b3bb23a6f2753302186cec44c1f6bb91abe890c693914f48fe0699ddd1d7619387cb5ecdb9617fe07714953fe1dc608c12c5416438855c4db7580a7e60bd4332865f622a61064f11afbbe71a20cd7c4f2a4b5dc52c73587557df511bfc6d431775100c0c199dacc1e43887469b82116aeccd39996d1145460d3808f2c8533bb82faa688ee4b76e2370919d08721267e6b84a85a98cfbaa530e8897491f06070e402b9224c88c3cadec051373b515e6264a9a99c5270fb0d252c62bc4bd8679ab39d78ef4b7bbe8cee4ebc51537b3d283c5541177741f35646cbb80a593568440f3796f415a64f3bdb2dbd25ea43aab3ce466d6cff2c98a21bc1f16e3de9bbb3be0a39a76a4a6b68c2092645c48af523fa2cb7155b1121ff567fc792ccbcfdf8f5b516631a974020f543cb134205c59b50917fc6e23e2900a837f3b3befe02f49853a10d449972d5b3de883a01fe7d2e0bf823bf22e116247f9917f3c81829f4cdede4746e3cca9bc3cccc720315ffaab3eca15f3b8945631ced1cb1ac5f8773e7677160ce5ea3509a14a0b00ea1c0e41845a79f8a8efe861185530d9c858d9377ea90ebaade5b5f7e983643d4db788659ac9bc7bc14b96cd9a83fa37278a8c92728ccd69c96b17b5ef80b151547425bc250823fd4607bafcea98c26677f0a58c302e114bfc6f9e0d754aa6b62ad7114fb51c372e4216c1b4cecfe3806f5fb07502aa6a41cb00e2cd7d9c704aa34c99eace866e3f73c4729c4b74fa142c0c0563168d6957f2a3fa876b2e80b961368f8b8045ad0dc0e2298276b9da6658b19fc3f908bf004e319522b562f68fa2d33bd9b931af194a02b8c42b2b845db927dd4ab8688285c3a85d88d6a7b9f2b3135f48db2b862aace45ea608516a59f8cafb53036581c8c81c7020bde354ce9fcda466bdf2a39b3552ccfc1ed15ef447bcb8c27eda80219fa8d0601bb85abf45c1b498eae79aec57ab64a988118ad51f969317657bf2e50b6c80ce9d07dc8c4beea2d0968a1d7b6f8ab7f983dc4e115cd5e552c1d30e577374131bb81bdcb76c10a8df58618bd0163a65e303f7f5b38080c58b3fd885d3f8fbebb19393225143b29121170525a963aaa87252f3baabe0d64a008d58e57d163b27ffc26dc2a4aef0bd6d1bd21284016b41383538ffa0c9196c5cb87d1c34c3dd7850f9b59716c6816cc3ebd66718b0a60dbb7cb78a3d6affce07d69f6a57102908ae23c1c9f8d62e28c7dbf21b73110a2383f6a7ed42d699d83124e69d8b72908f6b696239744aea36c089900000008aeb167b235c1a30a39d797bb9f8c7775dc98fc00415fe6bc19cc3278196e26147ec3483c9ec90cb8401eb97ceb61b42ab5ff08897b7d3e5d7283af82c8c6d5d36ffa3ada4d47196a262566a2e6646cbee460eaa57970423022cdd68b3cd98044a709521027c2307a301a0f596091ac04e028bc8e847741a045645292647bc245c116b0dbc7a17f9bce0d55e024d5002e913caa0c95554753a6fb7548676c5b330bc9e5db479bb6897b1f16471b5025b466e23413c7933caba812a79afc14e1f1a1e72ae61bf874330d06c9762be893b681c5d70ef2099375842919715e158f1b52562348a3c86d06d9be8327bf9bbc3282a800d3eb233471510da7a3fa516b022953a6e5bbd398b46d6886d0d24c3aa36ec0bda3da010a4119d3ac7c9fd70597b9c14002fd5c50acf74110bfa42f2bc3166eac105e0ed20321b07f90fb07ded276ea4830173b5f4bed2da45d20e26238845e3b03b1d44eedc1fa413688f03555e894182c615dffcd8ef629db7959b204ced822c69ad723d179748f32caeb973a970f8f35724ad0933a87aa462cdf1cbd1f8f7ee01166061549a53dc9944eed062bfa996e90bcd4b942cd717e922ac214a497d8268aae2c64716d5b20f4d81e093e92767284bd650a1deaa5e1c84ed80ffed83b6a422428850e8c3b7fdf6fa8f699fdcd9ccbdb8b93e88ec4422545769cdca78112c9c346db1d1edf5220d58279fb8e3fd53ff26e2f265d8fa7ba00f1d888ab7d506704b34acd86c45b8aaacc037f1dce79ebbca77170c6b56dc20db36acdba2dca4b1be129903a95dcfdbca905aa2e3987a4f19b2890559a15ffe064185802fcdfa774fbee7dca45fb1320425932b435b2c9414a832fab8392186ba8c2a102d27af59a0c8b8d0fe66ef2c8b9281cc6d6d5937bc77e2d20f52158b7be26cc1f64f38a9b35e770a7fb83418fd241aaec4cc6f54da24a89d1a7a19b69069d9280acdfc876f20075499514bfb54338632dd47678efd130cb5d6c546f8a57aa98caee1bec37ce282965da8dc518f92c82bff4e6c41e899d5b0fc8d5cfc2d09565d0079be8d18a601d4302398b44c6f023ce17a17e7199c825dddb1798560d6de9d4f1b2be44d0bb214d84010b49cb86353cc067fa6074654f5984d9f1afe373c390aca560933e73404262179bca95fe817879f96e25b09f8bad57bf1759c22dcea3adedb29aaf56de3cb0195f3f9680a82b58ab0f4af19857407798f37bf3d3960eb4280efad4e4ad3c1ef492d1479e260916576ae76a2d7d891dc5fc61a87e5823566154a554809b8fc3e4383d0e4882ae2b6dde1db2dcc59304ed755d4f413e1d4a534d60656f4191fe4b1912ce1f12060f0c4d4761693b27398aa8faa355a08e721f7ed8dfb8c5dadefe15057b1aed973d5894846422ee531ac77e8fd0a909169b7449e6d6951bfab74b78c9a9cd30fbe5e2457049083dd50e49da810c065df8721b8e9b40820eacef8cf63f6b1d44b1b45e83d2b4a28ec53e6c0c67d87e972086ede24924ff9be666d441a61b234d3cd92d47e7eb3920161ac06beaaa65e6310afad71c307642cadbc1842afac4000000088ec22de4cb0925dcb0f4132c0b27c3cc905372547eec56cc048492b3e59272f5d895cb967b57e1c3b12d1d824141e4b697f8eece3e0b5b56e5ac09eff9e50faad9fc77e81fbcebfe925fa00adec5e6c910d6a892b2e5fbd0c5284d9a1bf3f689876f0d19ff6c433f067da03168981e5a2f769dc36dffed04e51c548658619cd6276c9ff3ad6b6d9767472d9aa7675f76af8fc10be1f7dd80f6fa6acf7074197b6345f132fecc72990257293b30614c96ceaf523ddf24bde55316493f8d2584c994b0dcfabb70e7d5560d3b00a4ca0071f19f339b8d92a2afc3897dd1c50234b5367cee850245064f78682d09b745cbc0b6f136dadf1cbeedd2f5d947be10c114117787c3716e5817615bcc127ea3f5e32a77e97663bab04c9e49ff6187f233499169738dc9b870d66a4a9664bb0e92706ff1e3b55e79a58aea9b0c399f67c54785517848a7c48ea059b78c55284813d396454fccb3e668df1771d9f3af426a4aaf7723f616c007482846d71b90c1a55d734bbbf04102447d2eb50bb3172ea640af1b8c38d220b98cfdc71552ec8e02dfbb50fc9c6a4b1d0125aff61c2062270a717be8443c2cced7bae3246fa64e1d95820c72dec92f82b3ab2e08642cb3b2487a80c2d694a8b08d904537c621d96ec42bada5af876b70e881294746900f43e0ab002b1380d6d5362adefc56e3f464adf2a32d34183964bfcffe81fda690b49370d44aa55c2b30b8ca85e5a0cc68ba64b3c79a4556009902a182790f93c6c9197a7f4cfb8cf348d93ef00a9e33cdfff2a8648d64683e6f2728a5b3c6ed1a3487afc362a60f1266da5fa86e2e9b071e429e35053fb211d605c6cc6e490549056dd207176fbc09cf67986e925de42708b2b6d1a51d781662b8740a588516d600d9bd27024710bd661360fb568e2924056f83c41b0d769848077507114d5b5763418f306294b31cdc2ca9eb08abcc74a3861226b21d7d56c4bc119e36c10d3e50ec5f33c345fa8d19b2ebbb86529732787b8f405203853aad8bbcf69ff85e7231a7fd0421f301353e789408028e16866c1efb60812af54ad7e58778b9552b652d1a21af65a3ae21df81a5cdaf3e8be1d8e0c63bd6855758863f00ba5afcb1fe8918500ae744289a5959c4b24596ad87f350065dc6b33165e503591971636714ac50a014d92ba6e8d706bac2e29a47a6262f705339a1a937467e5406a988d13f27f6b29c83524b27735df1cc5bc717b52a04a312543fea3de99435fb50d242c04474445f885669c9db05ae22a23c808405674ba5cb6f5481af969782cc5d7c742f4794e9c6c43772a7b86122a8db81d436ae5a80c92e96ff46d194236bfa5166a4c7a99ce6d879dbb7ab8bef8577518d6de7aca670ce1c0f61231ca9ad68cbb5510131c8c9c1917e22d0c1910c8698f3f8a5c6c0cb4d523a1a4b849ef31d578e385d35b09fd0bf9cbcf38f52abe1dd5e39632586d23443c7cba4d3cf20761ba5b93434fa373b4502502647e13c88e1502f71ce2a60ef7e3367b6da30aacf6d6eb713663d3b66883fd21d8589a1218360d8b9e583624b03993b4c5a307c4011045557000000088df5cf227397f2d124b91407b8069c785b58afe236f87926d836a1029b7f1ab6eef4ce326f4f49eaf1c7c0d179f07069aca3a52f8182dab9ff1a60fd06db272e5f9015ac0f98b204c95b12734e2f7e5f44aa209606cc7abaafe8085132046601b592b3e5d8ed9ca3f80816627dac18f6eb7735211505fd77729c5a7642f5b15491ec41846a50733ab4131e183106c660972beeecdd0778d97a19eac26711b88f2756c9c8af444aa7f92c8e0c12bdb869531e125e0cca9b3a88484043c28ef5c58dbb98c08f728bfb6800c3473dc08be76c7404c8c13fa305e5e0cfa7c0e3b2191a4d832cfe74d210df697f0878f334caa5a0b2d175235e43e26ea1877c65495e5dc739c1ea5a1b4b93c279dd80d053ff91b9e9424a8048d867d312f771d5732bacd46008ce68fafc06ecc4d081a2a899fe6ca3a3fe3b9baa65e505665d09eb34f0e4402c0f23ae81ce48f3d89f3d5247895f6f52d2fc028b3546362c3fd6bd490d011c0d2cd162cbb54292afda3b82382e96cc1e238b209e7866261ebfda78d9a2493a52179581243f1bf24264ea2f6012282ebdf265d09e20e74b0271443ea82e2c5a3172a5908ad011b9edb9f9f123b4654b4ce85465a831e9a9275bc3ce332a332c6a1b2198f04f0489cf6a4befa9da8067c424251f05265f0a47c2d84a78a53253a66caa6354336bbbb7aec7aad199e7d8d5b07b817e4f947c75843a19e16bdb82d4edd71abeb3a40cbe17a3192b80e3eb27443c07f021d53da3e2255f063660ddd704ba05a41d84ad4ecee098c1e772f3a4736644e56a2d012f01111463912d18441cb74a16e543bed146ca6e2c5cb77bd990ac87103779f6a54371fe006b242e670a83c64d5da9a97a784eb41194253176a445f1132595a6f9c483d720ccf24323c787de6e95dc956568986605ecf5f156d0b9789ea2bd96b28da54eaf80811dde2b6bd91f7e9ef909f3bd6ef64e00e638e79316f707f9cf199f821f75652954b403856478a0bcc0338d94286883f2bf76c81e138a9b51bbb94b71ee18c19d791e0e600f230f51d4aaa91780266895dd0429eec282c5e452d68ad7500f36fe65a05936837cff38f6eb66db91bbcf9d56ecccaa91dabd8ba7a4f21d4c343cbfcf9546fa5868fe5c164a380079458dfd2a3494225528af2e118406ea8a2886f0eb1cf5d1063294323746333be4cdd12c92f922ee7c05c35414776def3e7aaa4bf67b831fa751b4c731da61a2e34581d6f8fbf6d966c87b3ae162cb612d84e9cf29ef21ee6066cfbe8ee334ea216f2c14c2c87c8a3bfbe241d8421aceb1e68a7c4320dc3e1a79f78c587ae6c548f7c7158c14c0d93fe1672a1744552cc69902035ef91bfde309cfef46f163128bcaab3be6819860762dfab24bdfa63128c061ad1592ff51d041a5366b0115fbe35c39bebe37e6bda6a24d679bce217b1aba00409cc078614ba4dc7126ad599b1121a3904c8b730813a357ad34df26af0f3c279b3a3545398583763678eb5df9b528ad89dc45d9a37c37f8cafbadfd9eeb04445fece1b946f569919024d7ed3762328bd1dd4eca348122d569ff0c78a1ec3500000008aa3607bb4c55b92f292fb3cfd2631e19f76500fd05157444132e8db3157be772c4cc7eaad42ba08e4fe02633e6bf11e1943e3ce5a8db25627b5fcb604bdd04dc5d7168e6c77a9e70d42a8acbb1c1e7949f144f91e29c655894d48a8bb6cb5910b5eb3c8f08044d7a41eded085eef133348213a7b512ead0d6aee2fbef71f12e5a97ad5689b40daec748c33cd8ada2a498f470b8dd2c1b0b98f0eb6fbbe1462a54e9bd52866d7732111093cee565d2240a58ac0274eca36b3162867dee8f01c29a15074310f1e2118a8854ba79109292c345d5d7efb3359eca054dfb6003afab4356585170f6dd7dc2c162a72fdd3eadc8871a3a0fa8e8263795d8386294df0314dabbde031c1f58734ad34e114581909d5fa0cc8a48e2c6ccdafc5f520b8cbeeacca947effd6b1c0618a82351cbaec4813f3aaba6bf089a0ff655ec2513f1580f4b659d3eb471b2a3ab98b61322a9c2ca871e4a720d75d86d18f4e88be8a2a4c76d8b974e45654a47f6ae0d86eb100f0544ec2b5ecc160b190303447de84e91ca5b138fcb5c807b485b33df0c37ae97649530042397093fe95ebc90dc33f925544fca69e340308f02b206fd542479f0583dd51097c908bc6b175cc1d14f9a6a3896ae398004c98ede2bf0cb446194ef78ae89a26e8a264706dedfb99a8669b2697af4acb63e6258d033c448dc614cd5e9f5e85ffc51b0e8c236737b0f4d4021e5194cf415d2741758585754040c09552ae89ed8afb5b00f0ad8da5701cf7958554ad5741b46e7623542f75b9c8945e2a2b7329e436fa6a7a48bdbb8df28908b3a5ddb4dc34d758507fa242ad72ee015615bd186f5bfc929995eba7dcda852bdcb225315a13dd071bec48fb63863ba6e1a17d6595e2eeacc1794538d6e3d2a67ebfb226bdada7629190cb1d1e2252836eb661122c622318515dfbe1489c4ce0148012e98bd00333d0b4f03bcabb76a087d9223dbc04d1b0e3eaee6d1c139e83a565b0db19a813ba89f657632dcbd53ee5a511f8911ee131f06b80640290f6a3c9195587c840e1b5eb52f77f9119cae6e429bfa9ca5471df550d8c9189d1b36c4e3cfbef80d7c2d261bb02d5ca58e58f9a9e10c201e443a6e98f21d9a75e1a7cdf1fefb610a2444f824d5072089d93616710603b721e66bb415879443a45cf27ec"
    },
    "attributeList": {
      "validTo": "202205",
      "createdAt": "202005",
      "maxAccounts": 237,
      "chosenAttributes": {
        "lastName": "xkcd",
        "sex": "aa",
        "dob": 137,
        "countryOfResidence": {
          "type": "date-time",
          "timestamp": "2023-08-28T23:12:15Z"
        },
        "nationality": "testvalue",
        "idDocType": "bb"
      }
    },
    "signature": "b9ac0998207f2313a6108aa5b79ac1f43440390d173d8f155567e9d66e379f959b1625b21f0a90e9cb741a33f8f30f8bb31074c341079322145e4ee2309c63a38eee2722c078e26f8e022ceb67969ccdcacc7d6ffd2086b3670d995033a6b62a"
  },
  "idObjectUseData": {
    "aci": {
      "credentialHolderInformation": {
        "idCredSecret": "699201275c7b728a133a3cd9135f218aa951a2274432c9381fedd8a6ed7e497a"
      },
      "prfKey": "0ce1e0b9a86a747d521c2d355235ef4d52d3e4d1eb1650e43b04aadc0df8729c"
    },
    "randomness": "271ec716f37a0e2d0db0055f43164167f6b4f901ff80eb1824b3f14ebf3c11a0"
  }
}
        "#;
        assert_eq!(
            remove_whitespace(&private_inputs_json),
            remove_whitespace(expected_private_inputs_json),
            "private inputs json"
        );
        let private_inputs_deserialized: OwnedCredentialProofPrivateInputs<
            IpPairing,
            ArCurve,
            Web3IdAttribute,
        > = serde_json::from_str(&private_inputs_json).unwrap();
        assert!(
            private_inputs_deserialized == id_cred_fixture.private_inputs,
            "private inputs"
        );

        // the easiest way to construct a presentation, is just to run the prover on a request
        let now = chrono::DateTime::parse_from_rfc3339("2023-08-28T23:12:15Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let proof = request
            .clone()
            .prove_with_rng(
                &global_context,
                [id_cred_fixture.private_inputs()].into_iter(),
                &mut fixtures::seed0(),
                now,
            )
            .expect("prove");

        let proof_json = serde_json::to_string_pretty(&proof).unwrap();
        println!("proof:\n{}", proof_json);
        let expected_proof_json = r#"
{
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
            "type": "RevealAttribute",
            "attributeTag": "nationality"
          }
        ]
      },
      "validFrom": "2020-05-01T00:00:00Z",
      "validUntil": "2022-05-31T23:59:59Z",
      "issuer": "did:ccd:testnet:idp:0",
      "proof": {
        "created": "2023-08-28T23:12:15Z",
        "proofValue": "0000000000000006010098ad4f48bcd0cf5440853e520858603f16058ee0fc1afdc3efe98abe98771e23c000d19119c28d704a5916929f66f2a30200abb05a0ff79b3b06f912f0ec642268d3a1ad1cdf4f050ab7d55c795aa1ab771f4be29f29134e0d7709566f9b2468805f03009158599821c271588f24e92db7ca30197ec5b0c901efaadd34cca707e56b9aab1a7f14e329816e2acf4d07a7edf1bd6b0400af07a1ba7a22bcb1602114921a48fa966a821354cd0dd63a87ce018caccc50b56f2c9f55a062cdc423657aa5cec8a4c9050092e74b23368a65b53b31889206da71a1fead62a4f68e8753ace1de719063a49d3f0a6c0f17675db9a5652e7a8429edb50602a76a6838f8d93d6d8e9e946d6bcf98c33e287673804ed9ccdbe6b9620db5fc506f0c7bf26d0bd661579f0ae018ab12cb87fd224a72890dab2e238aa4bb364eeb57c7776cb062dfd32dabaaeab5e8291327ddf00bd6c2d0a367da63ee73a3684c0000000000000004a547c8619f3ff2670efbefb21281e459b7cc9766c4f377f78e9f97e2c50569a8dcb155f2a502e936d2cb6ef1a73e92af9916e6353b7127d55bb525cb18074b5ec130463e03a4eda583b05c2d63db40a08ab8bf05f930ec234cc2f788d5f5bfbeab3e4881918ce964ffd55483219edd435ac865286bfd313cd834aabfa8061d2ae173cbe4b59ab2bda78faa4c2c937afba80d7fba0822579ac0ef6915f4820f968a74f00ff5ab74e90b0a7bcb2b92093a5e94a54aea1d48ffd1e5bb3fb48069bc80a923e289f1fca6c77bd65b90546b0fe69262b316d5448cc73302434fe52b05000000050000000143763c5ae7fbc4afcac9eba89de1bc52eb8ab7493ae5792614d1e4eec3cdeca6514173ecf5cf92cab53fe2ebc8569f866e97641531319b2ef27acad5fcef8a9709d5bbe8cf8f7844c08111abd9868f051d1eee6d01216c653bc8aecaa3578cfe00000002738d2525cd94ecc5b0970ff4ec4230cc6dcca3da41a251bca193406ce6773a592171758a81d60b3a14986ebc40562938ca75284298093835c3774740119fa64e5cff3a2a5e05a5bed356375091a1590c66a92b30144de9f44c1eb539da24ca1a00000003106f64c53781e0d6dcd74fbf20b5fc93d92a4357d0c54e3b3c38d5846110ace967c1e84b4363c96202de715a57b4dcafdd931c3dda0d0300109363666f7762f55e54208872003b5d9221a1db5b39046b7c6f11f98995ddde8b2a4f63f0b4d3db0000000424a8cd2b5b7201cc31cbb2587ce79afba29d165a8bb75b030b504e7158e502dc1fa68efb1aa8cdd9a74d8356fe7f44b22d755ef7f7b0cfcf17a56a7b8d6bceca6f3a96cb97b6c10af673b3347e0e15b614f5032b5efc4ff4476f94367af79fb9000000055c1c96177b50d76e89abbe2954c433e461a54e54b1017fa49cbe98e48ea11b1a70bf31b0d789f5fa30eac8a582209c888aa8695549c7e5ad3b13ef3b81743f305180023c53bee13a20c7a0bbfab26ae5fdbcabc66e9267d61e6dd17a18abd0d83c02c90793cf2e1d354ca03c85af924a4501853357051e5f960faae2d94204a60000000c0027d9ca86d157f53f0854a230b1ced054028ac5dd5661963fd32403730fa9767e4cb8b670f2a34d3415172d8fc5a177727ff908ebd6cbdce5ed1b3581643b24fb023270a95114ca7cc3d2132a4ede62af17506ebd07b6e20120e9f3c599717928220101010235b9f0411d81717269bef6a00ba6b777b479874e8083fcc6f1e46105c9ad7ff20043661ace7f1e8ebfff542f8d6e87679be9b04759239228811aa4411181d4a5a646fe6e6b0a114818746c6cb604845be1ae385d3b038a329e5a1db87de481cf4500183a883591a3a38071180df35beae7d743df68fee24743d2c332b34809949fd16aea0d598d958823c784c93f4a9514aeebb556864a36e0036f5d3b53a46209cc0054ed2bf6410b8cd36b1e398931db850b2a00fa34949b823f6b933a1a0c72e7f52c0762b145b2f370f3834430f23190a599c3fe0ca331d17050dfd5e50ba2c5af0049e83ecf884ab4fa05812c6b0c41b8d7c3642830bedcaa880ffdd51262cbaa84531cd128952d9af61422f54da3550b29ba8c1a5b8535b6e3fe39ed5df70cb6d5004e228384ae1aa7b0bd7897808694b6682e0d1b81b8e6adb242ddf32d7453a48e71f9866fb30c0b849c3ebede8de053d8cc2e134e6a5a84bcdee26440bad59e68026294fc38a506ac3b980f6a42c5c91e16c2dd50f99c925cd70ac48a73ac83a63a000000000000000501b61331d68d01dd74bb7d3afdbc875a4a6c72526ff35b4103af1a4da7b44ec1551ea9d4c27076884b98000dce54a2e868877cd48fc801f8a6b246d94f03c4d69a23bb6aea23067ba5b49ea8048c5f00c138a159f63fc41e284bc974e3a82b24d0a8524e36801912a4b0066e78eaa27b873ac33ad22ae39de12e6e2e949812b72ff46a5c26c75750c4a0db8600d4845d6c90b27ebfbb06c796090c00d361eca4ddd944020f88bd5629c069e01f073a485b1b2b08e11a14faf75e17e2ce79a1e411382454becf7c3f3761b482ee3d0a46f2cc6c3fe95286270aa0174d37a58123652fc4b3749dd44a1ece8a69415c353e8e56047b97ae3774a68e8a88a72513152f13034c8c7022c8cd999b189acfea580f2618e864a84c1567e9047d0ba74d80540000000793e2781f8acaf610b03dc83f55e5a8eb213ef4d258c2e446c979ddbe20b663e3aa82177b1f4823e940b96ed71e51ca3489752a39921134a5f6fef9a0ca8796958ce38881d02fc5ec60cb10cd709cab0a169b46d5159773d97d4497e096657a6b897e603d276827ddca5b2fe7d3d652933371bc8d685d288ea3666d37e2dc8bfa60dc0ebfa97e229b333e998e632d92c9b28de3338bf8f443bba16c5b0130c919437e2daaa44ea561ea6dd6046d4bebf84d1dcb5b2439ea18f713446a63468101b82ccff503d3e5a0dee8f3aa6b5907bc5d3de132dfd448890eb1c8ed8d32b71bc009e1ae5ffcefc603a97aba73481bf2adc259d01e98c9e8e85f08481c1d2a5854dbacc099920dbbaf7f8a0b8e3a539d569d19ce33f05bbe81e8c39ad0e202dfb85efcd2b8c5c3700be3e250ae9308568c0b394b2d527c1f9219675b66bbc6c44a6015fb06ee337a3635cadc2270f665a0c890c61c7333a872d8f92097ffbdf13b400d39aba8a09c6f5e28ad51737a18dc29667c2a5eb7db63a36cb5dc2245ff8a709ef51d1d8e53c21c4b61e9c6fa6abcf4de546d029746e10afa6db89d9469e43414ad4d6de65d43bdde9d461adb6ba512e5e59e39140eceaa00f52cc95251b7a6a79f1e7399c953c4540a0fb7da31a625c3a28124917adeb72788438f592c81197bedeb0816883be53009255668d9759c9ae013041e13de1bf9a4cb80e52bb2dc62579dd5b2bdbfbc709d7ebaac6087defcc5964d5aa97a0c360b484d42f8717d359b0c36d55b44bc9e411de22105b82bbd2ea83f448690e838b1e0d1f4dba4f6e1f538231b3eb62967d28a350d37f3eef91e5b9a59154377ee38b871859eff3eede93b062151e3395bdb25e28565988c690e596820b137c9d3b7bf66111acf1694134f9fe937004fae3d128033cb14295e60731b4499a030b3367632015a3cef3e032e90baa07a04ccd0e8a89287ae3b159f12865850bfab25cd2a3a0e466d6d60fe49ef6eacfaed80238d67564d6bb14348b4603b82f84728a28a77701d02abc6020a9302be54227a66fb1625475d097e9f75c97f1224090da03bb1db2fac3e1e0527b101631f3086936c465fff978d34288b74de204979fb8f3f327645799d3889d40f5cbcc61ae0448874a1bb59904c8b910bbcdf77c09b15545d84e985b0036d2445c5209c9b91d4735132da89bdd4916ffca2ec6cd070dac7aa470e19c7177111205e1bb5ee00707da4723474819cadd811550537a49ff9a4f9330fb6ecaddc736379487aca9c5b5e15989fb7d78356b645681db9f712e755991c10600349272d61da3c12ab4c354fc5be8a8c17fac55795ac3fc983e7c4feb7ca18143a6290893cf99253a03ec5f6aeb503c7f5d67e54ee3c31392c57520c519705c339fca0414d34feec9bef1b5d15f1962b620e94105a9394e249b2bdb32a63eced00000002ae23a3a4d8e72583611092c9b99ec275ae816a7ca1b225f1d95af75d8e5f89f1a44205885259b384ff69c44180d5dca48b1b2086b112de26e72d1b120dc2afe4e2ed3c52281b91d854fcf6b07f690bcbc67661af91c60e4f300e4aad75a5a3e9845f499a4184413aadeea9f8e2d82ff9aad39b5329ec5fdcc67d1566939a71f79d815068f5092a8d40e254f25674728f8b8c17b5bcdd75c4236097510213f2d18d90b5160d6cd3fa52879d7ec5725708ea4bf5ff13302a5d088896961d92ebaa27d90d46278ba50e551449fa2bdceaf261a65ea2b444e02ade2ad8d800628f436609d3cb325e378a10ea27963e561dbb485964044768e17f26936fd26fda235e0383765378621a7ce73a07b8c51ae60b98031cdaf29466142c0d3b83c627245a55c11ffa525a3b96f59169dd106f313ad493969b422412f746bfd9b2ab48e6b74d26f9b290b2141f8a4070d0a30f1832c641b2380d49af6287d85fc90bc8829637a5c6ac060f1a0d8a88e95e6cf0d0cc6a0c0ffaad2c8bfa3446d9bc8ff090fb9b7415a7942accea5d5394f801c67f923db7e523a18db43c1c364e53ffa7a6835f72da85c577b5ee230c1d7b04dd75d8bd42434f006004d34784ba96911da7dfde63621b0d5674a21cdbb745e7d0d0f19383ea27de57a29bfac52906f25896b0b90644bc2496b6fcb428aded9d8cce6c7cbaae5d48b0dd611ad9e570c7a8590d7931bae041aaa4db42bb6866b9a3ed75a8bbfa42c44beeb7a786030230be4c831500000002a1800ac3c07bcec245b3ba44c5f6d49857fed47d79c6273f7b0a7f886a8a20e4ae3859cef8d34a2a339443b8cedd97e28611e968e0231f039114b0f56882aaf8cb46fc8e035bef97db58183cab34c4966906e585db194cf962c282412084a89bb8cae478b44fbfd9205c705f1109831fe8f38aa89511ccf0cf961f4231b4bda863a854a838396299ee3292a60c2bdea3b22740dfbe1ab164114fefdcfe9e78bc6267079c07ab5068f80d80cc7a1c8bd683cd0763c357215ea93d1353e727d8821cf59c1161593e418466695e062418cc3da2ba6c6f587c3ad4e8bfc83b142f83262cf8b17a6c5fb17bc9ac5472785176a5e4bff95e32d6f0b839ebeb43825bbd01b6b7bc5a9d3a706bf5c7d8e6c22ac024270a95234030c0b553a958667073b935798cb22e9e57b04d2996e74d70509abc87f930c212b75796978cf882834240f98a14bcb1de18e26a2702cb8a94643e2fc06d71593c0adbb1ea3f00c5b666ddffb86be034f357095862dee04772ead188f87c435340312aeaa9cb6376461ad775ff5a7b633e4b5c2ec261cebc499666b9b525b11434ed8dd0631aae0b00ae178722bd07e97875bc259ebf488b93f7f8e3e740fa5883c30fbc4a4f9942443894813af5a6aafd4f84228b2c731dfdf33228a1fcdab676e52df91640bb911f95793b6b353e05cdc4057c1243c3c1cbf1221beb849a14f755993fdad412768ff570522c0a9d05d671bf187803bc7dd1bb21a2b26ea2527cb1b5b92fc3fdebe3cce2a200000007ae07e22eda7b5de57befb8a3480ba62c6325b6f1adefda3cb64a8761eb9e7b408e9141d9ab0d26e9a6f612ce03fb1a9ab43be20029d962f2bd1a61acd95def136619bf42c8780d992c63fc5d8e63c6078e177d89d8a4100c4746fec41ad6d9a29901d998c7b70a35087de4af6ce3d2e3eb41c8ebd0e63e0dc79ed9c1fccee5c0b156f23ebab10bfbc8f823dfca2714fa9240a498da590e08d3be16e6c6622ede2c99ab5a8ffd066f9b02481f7540dc8d2a8af4cef1f0d009bfcee7e4ce25576f91408600d90eb9883dc78dcabaff66d32a67a04db577fceda834907a2b8b60ed146540c00500ad7a8783383840a70582b9c9ed83de75560a93d22d495a05753e63fa520d79c95b4ef71a678fbbebfb3446e3eda66a48b261e6a84b7ac89ceae79758f2e70b69967740322648bc4b85dce541e3a9f3d6ef98dbd254997c910e7f55059b031aaf01aaab48a56d89b4d6bb98b4daf414417cae94999e5f51d7afa4d6f988cc9c7b28effae8cc98132deb785826428cd895b0f588d4f72f1c07e9f0a033fdc6ce957e4bff66f4fc65e41e6c666c955ea756bb82d9d383d103dc545147db2a1be19cb873560c22b7a610503197dc2ddabb97a03cbf2321e957ff0045f67103aa5e744a7938818558cf53b239fded36ef7c4baaaea357a9307fa006bfa7ec9865427955e80a365bbf2b11ad75ecac33fd332ffbbba4bff30888be4cec6da03eb65675a7a0026bf9e5309a80cea0b6f4a554aea6f1ff021c39f34f9b3441a507861346d8f544e69993a3273db851f40dfbe4f8cd5f7ae061f983dcd53588d7fc85e51ea28313afe09c1545b29bf200a4f692094026778221451cfcd43071ab14421a7a68759197fe32cf2689d28754e201f336930e36bef575dcb24431803f133913eaa1ac004a27817cd35f51666a8e022872586c3c96a29eec0ae869706550a9c2d58d430b5601560b2ffa59b57ec48807754f113cb7f8e22be0405a73cf54b6a1c8ebbac687fe690ef6ccf50538ca09da7f3e82bec3d8f2bb29729d0000097465737476616c75653e5879cfb054cb908f54994d43a9e657a69b3b4565a1126e709b1b020634622b6b49d69d2dafde98b9df25d85aab294cfdc801eb336e9ea6666800ee298f796c",
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

        assert_eq!(
            remove_whitespace(&proof_json),
            remove_whitespace(expected_proof_json),
            "proof json"
        );
        let proof_deserialized: PresentationV1<IpPairing, ArCurve, Web3IdAttribute> =
            serde_json::from_str(&proof_json).unwrap();
        assert_eq!(proof_deserialized, proof);

        let verification_material_json =
            serde_json::to_string_pretty(&id_cred_fixture.verification_material).unwrap();
        println!("verification material:\n{}", verification_material_json);
        let expected_verification_material_json = r#"
{
  "type": "identity",
  "ipInfo": {
    "ipIdentity": 0,
    "ipDescription": {
      "name": "IP0",
      "url": "IP0.com",
      "description": "IP0"
    },
    "ipVerifyKey": "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb800000014b9ac0998207f2313a6108aa5b79ac1f43440390d173d8f155567e9d66e379f959b1625b21f0a90e9cb741a33f8f30f8b8cd5c323290ce730dc0d46036b0b17b9e67ee192926d2f6d43eeb6cd2b3ef2e01c3082d8ae79ac7b21e03fea2e3d8be6a994a4f67adaaa5f595809c1eb09e329d9217030e204203009acb39768f29d8ee7ea9cac577426e60a4b6092b06434edaa9453c337ccba9aed254158238fa981d8771f9828c35dc7536dff17d1aafa2596c91b5208ee4122f2f8834ffde44466b5f8e84a6df5094b7152e891d69cd65eae54e3ac1661c7f9f344b92cb5a8f81ab439b87a5779598299fc13999b9cfe4788ce41f0d0071988ab052828d5463e17afb402a5bd627b923541fc25b572b756052f574e14a328afed2d06cad3c717349862ba5b2fc1490bd02dd78bb98e5eb32e47913d167243c130422c196c4027f806621065be565b4338fe7b410bf3bf6386ccee2c114c4bdcc48ba355e7c85debc67c612268fbdc3739d9636b1502e356e92415dd56bc30e6128acf0759b80fcaaa554b2c97dd223164bea0301ed858473aeaade0848ca1ecac1185241115e5f27c4752dce5eb2bb77caa166f021cec9d89b4f1fafdadffdb1d33d0662976a6397b3e29c127e22e31d462422d28f205ba90c215b0debfff9a7e72089e29b677679130150226672d4b9922e4fc65ed2f5a714197c282968754ee8ba82692d0a02eced66617dcefb35fc4590a61089cdb6f81957624d37d5033289f4f049912ab3f065f8e5c6fb6e1c0350a1ffc9596c9d8983a91d3023283db5f1cf86f15bbb0bc94c76439dee9ec503fff630b56d4a23317dca826f881bb396acbcd9dac8197bed966cdaea2d9e39e9d0076c787eeb40fb52777ea2af213164698e43ea1602f52f02fe1d23ec12a74a2076fe9aac071cff13755c446e0827b9d13043a89a78e6d8020b943073aa8921f400272fa4956895a1c6ab9014a86cb0a975ee6ff78f9481644225baad638b58a680363861a96bc89bed7c42d80311dd500be28de1a9414aba5cb962b3cc30f8d4968d9a472056156cbcd688db43731b354b5d3a39a5932b77612d665885f0d65639f86a68e2f18b3a1ebb6bba682b201a8676417afb8067eb0b36547514166d12de0bcc337c519a77f234e59bed337fe86f458476c325fa44f4abf5730d58a27a0d58209b56d18c2cc03fa09e83337c0cc3b6733605bfa8145b4361816ddaa5444b9633f2a1fabb932719825e6470148f57259d172b326a9b6029bd0495cc3c06b85054a8dfcc883e46a093ee3edc77ddb858dbf037a40ee9611cab1eed5631d60f2f2650d2329ef989defc64b19978e6487bedbcd969800000014ab8b28bfbb362a4effde28779dd580e2f0f413be25c5eae1c4b791c823053a39576e75936e6bc478cf567ecec0d647c116cf205ef41016494f9d9e5cd42f8d43c14048450a175084e2d89de8371eab8356613efc2f59b541023e7e382bb01e4b8a151d3998bc783629fa35c1f90b27f506be14a5f3f10289612d0fc87407a1a776249b2f6fa8a97fd94d37cdec154f6e192fee739a8e8685289bca273713bc0d8defd5734bc36b84e6cd3ba1fccf7eb115c26510719859257e02381b93888ac382e5aaa6633064a32c42f2d2d0f92d15a846a9f3dbfb867cc1c2aa515193736306adc92f61bcd21d29304794f54c91c6078af67f16ff449e1b8c25a76f2ad48e08fdd0338dd4c1168caa6f0c868bf7930cf61176a52d2f1ca77bbdf78fc48a8ab65ddc3d69eb833f917eaf280aeae14327f89a9f7e240e2bf34385e59bc7e3e77ac67cea40c4908fbbed6b1f22be5497058effea4557a29c013f8c952e340c9fee45a003f354ee9377e5d83dc35e742af600eafa79aa08941f7d3f44bb1c2468ad50a3aba1a90893fe241477b1a8d73d568e8c46759f8f650fa8ffdff4b041a49ed94a618459c7a1bbf6ab03b647bbf50d32e37663684a3e72ab63b97da818001646b1bfc76ab0ade98438706d6ca52c63502b61d110d750c09c8c8e7d5ca782a26d349123e48d57c4ff9d377748e64c6bd5f92b2ba908f1f9b4fc0cad0f590ca612384550dbe3e33cd57253c7c38e870f63751b47bf2e308d74cd2204ea6c311f399d6d91c5a4a66f01dee587418692eed0949679a89227c3018d37f70b202bb44c5ee8a41edcde3053e33971a48523c728fd956216331654fcb2e87a32ef3e8c4032db5275c556b1eb6b9d0bfe0eac0f44b2667cf9cb4c45af4c530406c6862f67ee508ad6a3961aa472f5a5037fe7251f2897c90624a07742258f7b0cfdec9438e2950347e5536d54ba09b0af2545b4f24de31d91575ebb28119baab4b2b863791e5cee31dbb30e4164213d7d5c7c0f9eb8f2b81e7de271b7d9f4606565af36766c9324e75d1c4061d31c79939f9ab83986b98459bd80f16ef519859eceedb79b40be49c0fdcdda821091a7cc79d853858709eda69916a8ac0c2b845c0ae33e75c31f8e7bc6a0d2d9098914643d6b0136b28d072c9759bb2f79826cceb7ad5bc089c186b5ecc332d5931d43a7d35f11fdd4398f236b05cb46f5cc0f82c23f98e2d0a4e797bb087edf5e34abd4f13a52b5a9a4d45461c02412a71ac64d221e006911248a5114248b83cf93332db0e90c605d10174688454495d348aa0a8f7973e2c76a0b0f411087aa211194726fe458e5ef69e962b7a88c73d9b471ae74b5a20cb9c783b97a21dcd35f90bf1d4260e5f6f35e8812a47d98142bf9cacbfa6a55dc649d9a931195509430f6542ca2541751bb80ccd3f9678b08a89fd69f115b04e0bc2ab0a77ab7cf48291fdcdd16eb2603acd60cfcffbaf7406e5eeb4955c28ee6b3bf572831c5560ae5f04d8a7d5cdc1b3d213505cef4d3668e03a196cd95bed961e2fede8200ec6d4da38ca6593909e10691b5d67efbc7bc329576d1809190cbc28a2be9e2d0ed16a2b8346419e19346f7f786119f03b316d0b389e8e1ceb5c823da009c0095a92718da957eba9482a0a2120ece8cd375ee17fe6f06a1272712c95c182e3c4fd13d4b4ca84998d70ea9ce3a801b1fa3cace5eb38741b33c034d7c757b779675235d8816ff52d17a430d00f404086bce79bb28755db93d79aff5e56c8961c7aeb260bd4b10d46c9f266d76f4d0f72eec3f0b52e9f49c56f9df5305e1340579afec7be028b134fd50080a880db8d61c39b94640adc9e519823913a9fc25d185436f22ff25c766f5a4f611830f1ee00e2c7a6ab33519497d898c56ac9d0133d0c34e27c146dac04c69f84a623aea2c3483545206d300ddb59af081d2dc3182603591d61e0dce6d330f12f360b1597761d274995e8518ab2d254c437e635b62cb426255d496af2f2fdd55aa8f839bca8052e3009f88606b20d7987c5dd21ac801511862d0b591edf137b198043ffb8b4b67386d456e5673bd63fab29a58aaf79027279118c0c1abefe106f7e7e9b49c63f945e4ad012d449f19508fbacd35e4931c769e49cd5a81b71451fa4ea6f001f1436236f3540302d1a7a3e58b26378ef8a0987fcf629ccb9a11a16562f790c2f8e3d16aa05372a4834861886afc01ad8ca2d43e48b7d0b1e5f9067d720316f2f4f6b607d0405ae766b57193bf1114f7be1353c33e2f2caaf67afc218297914eb43b38395c937b7183a0adc2b0c6a4714bec6805e373c4be12ec36084c2c58a3126fdfc884a852fdbff82b15023462737eedf78fdd565c0566440c10c8ad2508ad61d2f3aa52b307e7552039a1f645b5bbc75e6f24fa3d3946c39507f522504b223a305093ac33a5c84f90517f4368a639f34500410ee6731eda080da4f1a75bf962f1aee4d5289327a00e2bf2d90dcbffa5400b33c66ecf25620bfc638aa216d13bdb5832985a8d6892e3a0bb6474a6b2d9b5f59908feb6974592f02a743fe5c6a3cf6d4aa1a54154fea9f125af029473dea702dabebada9c2542783a224cf36c9e5626fc9f3af4e5c28283b15a10879df9989ba31758b5b715195ae93dd222319933d62a45a8572db0c317b28ddc86fd40f625275f6e4ea987576f60563636e002973a986acf34b4deaebf77892292ca20404bbb9455a2c3afc186c84e57de3626d3ad964b8d172ee7220fb72d1ff5e8a219b751a0c0532af50ca2ee0b7d7212800da6587cb7f530ab145e39a12089174c3fe120a8b7ca7b758c8e34b84ce9b4812ac73a2a0a2380b8",
    "ipCdiVerifyKey": "cd73dfc58e9f095f91726019504f8274b48e6689258f90a6139056119ac1b337"
  },
  "arsInfos": {
    "1": {
      "arIdentity": 1,
      "arDescription": {
        "name": "AnonymityRevoker1",
        "url": "AnonymityRevoker1.com",
        "description": "AnonymityRevoker1"
      },
      "arPublicKey": "b14cbfe44a02c6b1f78711176d5f437295367aa4f2a8c2551ee10d25a03adc69d61a332a058971919dad7312e1fc94c5856793e4ba5d058cea0b5c3a1c8affb272efcf53bbab77ee28d3e2270d5041d220c1e1a9c6c8619c84e40ebd70fb583e"
    },
    "2": {
      "arIdentity": 2,
      "arDescription": {
        "name": "AnonymityRevoker2",
        "url": "AnonymityRevoker2.com",
        "description": "AnonymityRevoker2"
      },
      "arPublicKey": "b14cbfe44a02c6b1f78711176d5f437295367aa4f2a8c2551ee10d25a03adc69d61a332a058971919dad7312e1fc94c5adffda1428112cc19e05f32e63aec7d686ad0cb2abbe0b46b46e94927e007b1372114ffc7bd37b28d878f9afbb59dd0e"
    },
    "3": {
      "arIdentity": 3,
      "arDescription": {
        "name": "AnonymityRevoker3",
        "url": "AnonymityRevoker3.com",
        "description": "AnonymityRevoker3"
      },
      "arPublicKey": "b14cbfe44a02c6b1f78711176d5f437295367aa4f2a8c2551ee10d25a03adc69d61a332a058971919dad7312e1fc94c583ed439dbadc3de91ab451aa82203c1079ee7ca62eebf57f042e7993abd9512776a215be1eef3ca99f19346260b1651b"
    },
    "4": {
      "arIdentity": 4,
      "arDescription": {
        "name": "AnonymityRevoker4",
        "url": "AnonymityRevoker4.com",
        "description": "AnonymityRevoker4"
      },
      "arPublicKey": "b14cbfe44a02c6b1f78711176d5f437295367aa4f2a8c2551ee10d25a03adc69d61a332a058971919dad7312e1fc94c5a95e8adf80e1ecefda3594baa96507bfea76ef1d4176e00bd2ce295ba901d93e6a2ffdc4492707b3c79a54fb50bacc9d"
    },
    "5": {
      "arIdentity": 5,
      "arDescription": {
        "name": "AnonymityRevoker5",
        "url": "AnonymityRevoker5.com",
        "description": "AnonymityRevoker5"
      },
      "arPublicKey": "b14cbfe44a02c6b1f78711176d5f437295367aa4f2a8c2551ee10d25a03adc69d61a332a058971919dad7312e1fc94c582917ec5cf87f432d508e5e9441c42e963c6a976b38688a204c399674da3cd0d20f1771116756f55443bad87bdf90cb8"
    }
  }
}
        "#;
        assert_eq!(
            remove_whitespace(&verification_material_json),
            remove_whitespace(expected_verification_material_json),
            "verification material json"
        );
        let verification_material_deserialized: CredentialVerificationMaterial<IpPairing, ArCurve> =
            serde_json::from_str(&verification_material_json).unwrap();
        assert!(
            verification_material_deserialized == id_cred_fixture.verification_material,
            "verification material"
        );
    }
}

#[cfg(test)]
mod fixtures {
    use super::*;
    use crate::base::CredentialRegistrationID;
    use crate::common;
    use crate::curve_arithmetic::Value;
    use crate::id::constants::{ArCurve, AttributeKind, IpPairing};
    use crate::id::id_proof_types::{
        AttributeInRangeStatement, AttributeInSetStatement, AttributeNotInSetStatement,
        RevealAttributeStatement,
    };
    use crate::id::types::{
        ArInfos, AttributeList, AttributeTag, GlobalContext, IdentityObjectV1, IpData, IpIdentity,
        YearMonth,
    };
    use crate::id::{identity_provider, test};
    use crate::web3id::Web3IdAttribute;
    use rand::SeedableRng;
    use std::fmt::Debug;
    use std::marker::PhantomData;
    use std::str::FromStr;

    pub struct IdentityCredentialsFixture<AttributeType: Attribute<<ArCurve as Curve>::Scalar>> {
        pub private_inputs: OwnedCredentialProofPrivateInputs<IpPairing, ArCurve, AttributeType>,
        pub verification_material: CredentialVerificationMaterial<IpPairing, ArCurve>,
        pub issuer: IpIdentity,
    }

    impl<AttributeType: Attribute<<ArCurve as Curve>::Scalar>>
        IdentityCredentialsFixture<AttributeType>
    {
        pub fn private_inputs(
            &self,
        ) -> CredentialProofPrivateInputs<'_, IpPairing, ArCurve, AttributeType> {
            self.private_inputs.borrow()
        }
    }

    /// Statements and attributes that make the statements true
    pub fn statements_and_attributes<TagType: FromStr + common::Serialize + Ord>() -> (
        Vec<AtomicStatement<ArCurve, TagType, Web3IdAttribute>>,
        BTreeMap<TagType, Web3IdAttribute>,
    )
    where
        <TagType as FromStr>::Err: Debug,
    {
        let statements = vec![
            AtomicStatement::AttributeInSet {
                statement: AttributeInSetStatement {
                    attribute_tag: AttributeTag(1).to_string().parse().unwrap(),
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
            AtomicStatement::AttributeNotInSet {
                statement: AttributeNotInSetStatement {
                    attribute_tag: AttributeTag(2).to_string().parse().unwrap(),
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
            AtomicStatement::AttributeInRange {
                statement: AttributeInRangeStatement {
                    attribute_tag: AttributeTag(3).to_string().parse().unwrap(),
                    lower: Web3IdAttribute::Numeric(80),
                    upper: Web3IdAttribute::Numeric(1237),
                    _phantom: PhantomData,
                },
            },
            AtomicStatement::AttributeInRange {
                statement: AttributeInRangeStatement {
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
                },
            },
            AtomicStatement::RevealAttribute {
                statement: RevealAttributeStatement {
                    attribute_tag: AttributeTag(5).to_string().parse().unwrap(),
                },
            },
        ];

        let attributes = [
            (
                AttributeTag(1).to_string().parse().unwrap(),
                Web3IdAttribute::String(AttributeKind::try_new("aa".into()).unwrap()),
            ),
            (
                AttributeTag(2).to_string().parse().unwrap(),
                Web3IdAttribute::String(AttributeKind::try_new("xkcd".into()).unwrap()),
            ),
            (
                AttributeTag(3).to_string().parse().unwrap(),
                Web3IdAttribute::Numeric(137),
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
            (
                AttributeTag(5).to_string().parse().unwrap(),
                Web3IdAttribute::String(AttributeKind::try_new("testvalue".into()).unwrap()),
            ),
            (
                AttributeTag(6).to_string().parse().unwrap(),
                Web3IdAttribute::String(AttributeKind::try_new("bb".into()).unwrap()),
            ),
        ]
        .into_iter()
        .collect();

        (statements, attributes)
    }

    fn create_attribute_list<AttributeType: Attribute<<ArCurve as Curve>::Scalar>>(
        alist: BTreeMap<AttributeTag, AttributeType>,
    ) -> AttributeList<<ArCurve as Curve>::Scalar, AttributeType> {
        let valid_to = YearMonth::new(2022, 5).unwrap();
        let created_at = YearMonth::new(2020, 5).unwrap();
        AttributeList {
            valid_to,
            created_at,
            max_accounts: 237,
            alist,
            _phantom: Default::default(),
        }
    }

    pub fn identity_credentials_fixture<AttributeType: Attribute<<ArCurve as Curve>::Scalar>>(
        attrs: BTreeMap<AttributeTag, AttributeType>,
        global_context: &GlobalContext<ArCurve>,
    ) -> IdentityCredentialsFixture<AttributeType> {
        let max_attrs = 10;
        let num_ars = 5;
        let IpData {
            public_ip_info: ip_info,
            ip_secret_key,
            ..
        } = test::test_create_ip_info(&mut seed0(), num_ars, max_attrs);

        let (ars_infos, _ars_secret) = test::test_create_ars(
            &global_context.on_chain_commitment_key.g,
            num_ars,
            &mut seed0(),
        );
        let ars_infos = ArInfos {
            anonymity_revokers: ars_infos,
        };

        let id_object_use_data = test::test_create_id_use_data(&mut seed0());
        let (context, pio, _randomness) = test::test_create_pio_v1(
            &id_object_use_data,
            &ip_info,
            &ars_infos.anonymity_revokers,
            &global_context,
            num_ars,
            &mut seed0(),
        );
        let alist = create_attribute_list(attrs);
        let ip_sig = identity_provider::sign_identity_object_v1_with_rng(
            &pio,
            context.ip_info,
            &alist,
            &ip_secret_key,
            &mut seed0(),
        )
        .expect("sign credentials");

        let id_object = IdentityObjectV1 {
            pre_identity_object: pio,
            alist: alist.clone(),
            signature: ip_sig,
        };

        let commitment_inputs = OwnedCredentialProofPrivateInputs::Identity(Box::new(
            OwnedIdentityCredentialProofPrivateInputs {
                ip_info: ip_info.clone(),
                ars_infos: ars_infos.clone(),
                id_object,
                id_object_use_data,
            },
        ));

        let credential_inputs =
            CredentialVerificationMaterial::Identity(IdentityCredentialVerificationMaterial {
                ip_info: ip_info.clone(),
                ars_infos,
            });

        IdentityCredentialsFixture {
            private_inputs: commitment_inputs,
            verification_material: credential_inputs,
            issuer: ip_info.ip_identity,
        }
    }

    pub struct AccountCredentialsFixture<AttributeType: Attribute<<ArCurve as Curve>::Scalar>> {
        pub private_inputs: OwnedCredentialProofPrivateInputs<IpPairing, ArCurve, AttributeType>,
        pub verification_material: CredentialVerificationMaterial<IpPairing, ArCurve>,
        pub cred_id: CredentialRegistrationID,
    }

    impl<AttributeType: Attribute<<ArCurve as Curve>::Scalar>>
        AccountCredentialsFixture<AttributeType>
    {
        pub fn private_inputs(
            &self,
        ) -> CredentialProofPrivateInputs<'_, IpPairing, ArCurve, AttributeType> {
            self.private_inputs.borrow()
        }
    }

    pub fn account_credentials_fixture<AttributeType: Attribute<<ArCurve as Curve>::Scalar>>(
        attrs: BTreeMap<AttributeTag, AttributeType>,
        global_context: &GlobalContext<ArCurve>,
    ) -> AccountCredentialsFixture<AttributeType> {
        let cred_id_exp = ArCurve::generate_scalar(&mut seed0());
        let cred_id = CredentialRegistrationID::from_exponent(&global_context, cred_id_exp);

        let mut attr_rand = BTreeMap::new();
        let mut attr_cmm = BTreeMap::new();
        for (tag, attr) in &attrs {
            let attr_scalar = Value::<ArCurve>::new(attr.to_field_element());
            let (cmm, cmm_rand) = global_context
                .on_chain_commitment_key
                .commit(&attr_scalar, &mut seed0());
            attr_rand.insert(*tag, cmm_rand);
            attr_cmm.insert(*tag, cmm);
        }

        let commitment_inputs =
            OwnedCredentialProofPrivateInputs::Account(OwnedAccountCredentialProofPrivateInputs {
                attribute_values: attrs,
                attribute_randomness: attr_rand,
                issuer: IpIdentity::from(17u32),
            });

        let credential_inputs =
            CredentialVerificationMaterial::Account(AccountCredentialVerificationMaterial {
                attribute_commitments: attr_cmm,
            });

        AccountCredentialsFixture {
            private_inputs: commitment_inputs,
            verification_material: credential_inputs,
            cred_id,
        }
    }

    pub fn seed0() -> rand::rngs::StdRng {
        seed(0)
    }

    pub fn seed(seed: u64) -> rand::rngs::StdRng {
        rand::rngs::StdRng::seed_from_u64(seed)
    }
}
