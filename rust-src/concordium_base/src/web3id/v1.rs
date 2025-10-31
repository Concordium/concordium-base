//! Concordium Verifiable Presentations V1.
//!
//! Terminology and model largely follows <https://www.w3.org/TR/vc-data-model-2.0/>

mod proofs;

use crate::base::CredentialRegistrationID;
use crate::common;
use crate::curve_arithmetic::{Curve, Pairing};
use crate::id::id_proof_types::{AtomicProof, AtomicStatement};
use crate::id::secret_sharing::Threshold;
use crate::id::types::{
    ArIdentity, Attribute, AttributeTag, ChainArData, CredentialValidity, IdentityAttribute,
    IdentityAttributesCredentialsProofs, IpIdentity,
};
use crate::web3id::did::Network;
use crate::web3id::{did, AccountCredentialMetadata, IdentityCredentialMetadata, LinkingProof};
use anyhow::{bail, ensure, Context};
use itertools::Itertools;

use serde::de::{DeserializeOwned, Error};
use serde::ser::SerializeMap;
use serde::Deserializer;
use std::collections::{BTreeMap, BTreeSet};

const CONCORDIUM_CONTEXT_INFORMATION_TYPE: &'static str = "ConcordiumContextInformationV1";

const VERIFIABLE_PRESENTATION_TYPE: &'static str = "VerifiablePresentation";
const CONCORDIUM_VERIFIABLE_PRESENTATION_TYPE: &'static str = "ConcordiumVerifiablePresentationV1";

const VERIFIABLE_CREDENTIAL_TYPE: &'static str = "VerifiableCredential";
const CONCORDIUM_VERIFIABLE_CREDENTIAL_V1_TYPE: &'static str = "ConcordiumVerifiableCredentialV1";
const CONCORDIUM_ACCOUNT_BASED_CREDENTIAL_TYPE: &'static str = "ConcordiumAccountBasedCredential";
const CONCORDIUM_IDENTITY_BASED_CREDENTIAL_TYPE: &'static str = "ConcordiumIdBasedCredential";

const CONCORDIUM_REQUEST_TYPE: &'static str = "ConcordiumVerifiablePresentationRequestV1";

const CONCORDIUM_STATEMENT_V1_TYPE: &'static str = "ConcordiumStatementV1";
const CONCORDIUM_ACCOUNT_BASED_STATEMENT_TYPE: &'static str = "ConcordiumAccountBasedStatement";
const CONCORDIUM_IDENTITY_BASED_STATEMENT_TYPE: &'static str = "ConcordiumIdBasedStatement";

/// Context challenge that serves as a distinguishing context when requesting
/// proofs.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, common::Serialize, Debug)]
pub struct ContextChallenge {
    /// This part of the challenge is supposed to be provided by the dapp backend (e.g. merchant backend).
    pub given: Vec<ContextProperty>,
    /// This part of the challenge is supposed to be provided by the wallet or ID app.
    pub requested: Vec<ContextProperty>,
}

impl serde::Serialize for ContextChallenge {
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

impl<'de> serde::Deserialize<'de> for ContextChallenge {
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

/// A statement about a single account based credential
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountCredentialStatementV1<C: Curve, AttributeType: Attribute<C::Scalar>> {
    pub network: Network,
    pub cred_id: CredentialRegistrationID,
    pub statements: Vec<AtomicStatement<C, AttributeTag, AttributeType>>,
}

/// A statement about a single identity based credential
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityCredentialStatementV1<C: Curve, AttributeType: Attribute<C::Scalar>> {
    pub network: Network,
    // todo ar should the identity provider be here? document what is here and what is not
    pub issuer: IpIdentity,
    /// Attribute statements
    pub statements: Vec<AtomicStatement<C, AttributeTag, AttributeType>>,
}

/// A statement about a credential. The credential
/// is derived from an underlying credential, represented via the different variants:
/// account credentials and identity credentials.
/// To prove the statement, the corresponding private input [`CommitmentInputs`](super::CommitmentInputs) is needed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialStatementV1<C: Curve, AttributeType: Attribute<C::Scalar>> {
    /// Statement about an account credential derived from an identity issued by an
    /// identity provider.
    Account(AccountCredentialStatementV1<C, AttributeType>),
    /// Statement about an identity based credential derived from an identity credential issued by an
    /// identity provider.
    Identity(IdentityCredentialStatementV1<C, AttributeType>),
}

impl<C: Curve, AttributeType: Attribute<C::Scalar> + serde::Serialize> serde::Serialize
    for CredentialStatementV1<C, AttributeType>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Account(AccountCredentialStatementV1 {
                network,
                cred_id,
                statements: statement,
            }) => {
                let mut map = serializer.serialize_map(None)?;
                map.serialize_entry(
                    "type",
                    &[
                        CONCORDIUM_STATEMENT_V1_TYPE,
                        CONCORDIUM_ACCOUNT_BASED_STATEMENT_TYPE,
                    ],
                )?;
                let id = did::Method::<C>::new_account_credential(*network, *cred_id);
                map.serialize_entry("id", &id)?;
                map.serialize_entry("statement", statement)?;
                map.end()
            }
            Self::Identity(IdentityCredentialStatementV1 {
                network,
                issuer,
                statements: statement,
            }) => {
                let mut map = serializer.serialize_map(None)?;
                map.serialize_entry(
                    "type",
                    &[
                        CONCORDIUM_STATEMENT_V1_TYPE,
                        CONCORDIUM_IDENTITY_BASED_STATEMENT_TYPE,
                    ],
                )?;
                let issuer = did::Method::<C>::new_idp(*network, *issuer);
                map.serialize_entry("issuer", &issuer)?;
                map.serialize_entry("statement", statement)?;
                map.end()
            }
        }
    }
}

impl<'de, C: Curve, AttributeType: Attribute<C::Scalar> + DeserializeOwned> serde::Deserialize<'de>
    for CredentialStatementV1<C, AttributeType>
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
                    .any(|ty| ty == CONCORDIUM_ACCOUNT_BASED_STATEMENT_TYPE)
                {
                    let id: did::Method<C> = take_field_de(&mut value, "id")?;
                    let did::IdentifierType::AccountCredential { cred_id } = id.ty else {
                        bail!("expected account credential did, was {}", id);
                    };
                    let statement = take_field_de(&mut value, "statement")?;

                    Self::Account(AccountCredentialStatementV1 {
                        network: id.network,
                        cred_id,
                        statements: statement,
                    })
                } else if types
                    .iter()
                    .any(|ty| ty == CONCORDIUM_IDENTITY_BASED_STATEMENT_TYPE)
                {
                    let issuer: did::Method<C> = take_field_de(&mut value, "issuer")?;
                    let did::IdentifierType::Idp { idp_identity } = issuer.ty else {
                        bail!("expected issuer did, was {}", issuer);
                    };
                    let statement = take_field_de(&mut value, "statement")?;

                    Self::Identity(IdentityCredentialStatementV1 {
                        network: issuer.network,
                        issuer: idp_identity,
                        statements: statement,
                    })
                } else {
                    bail!("unknown credential types: {}", types.iter().format(","))
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

/// Metadata of a credential [`CredentialV1`].
/// Contains the information needed to determine the validity of the
/// credential and resolve [`CredentialsInputs`](super::CredentialsInputs)
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CredentialMetadataTypeV1 {
    /// Metadata of an account credential, i.e., a credential derived from an
    /// identity object.
    Account(AccountCredentialMetadata),
    /// Metadata of an identity based credential.
    Identity(IdentityCredentialMetadata),
}

/// Metadata of a credential [`CredentialV1`].
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
    pub proofs: ConcordiumZKProof<AccountCredentialProofs<C, AttributeType>>,
}

/// Subject of account based credential
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountCredentialSubject<C: Curve, AttributeType: Attribute<C::Scalar>> {
    pub network: Network,
    /// Reference to the credential to which this statement applies.
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
        let id = did::Method::<C>::new_account_credential(self.network, self.cred_id);
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
            let id: did::Method<C> = take_field_de(&mut value, "id")?;
            let did::IdentifierType::AccountCredential { cred_id } = id.ty else {
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
    pub fn metadata(&self) -> AccountCredentialMetadata {
        let AccountBasedCredentialV1 {
            subject: AccountCredentialSubject { cred_id, .. },
            issuer,
            ..
        } = self;

        AccountCredentialMetadata {
            issuer: *issuer,
            cred_id: *cred_id,
        }
    }

    /// Extract the statement from the proof.
    pub fn statement(&self) -> AccountCredentialStatementV1<C, AttributeType> {
        let AccountBasedCredentialV1 {
            subject:
                AccountCredentialSubject {
                    network,
                    cred_id,
                    statements,
                },
            proofs,
            ..
        } = self;

        AccountCredentialStatementV1 {
            network: *network,
            cred_id: *cred_id,
            statements: statements.clone(),
        }
    }
}

/// Ephemeral id for identity credentials. The id can be decrypted to IdCredPub.
/// It will have a new value for each time credential is proven (the encryption is a randomized function)
#[derive(Debug, Clone, PartialEq, Eq, common::Serialize)]
pub struct IdentityCredentialId<C: Curve> {
    // todo ar make non-generic?
    /// Anonymity revocation data. It is an encryption of shares of IdCredSec,
    /// each share encrypted for the privacy guardian (anonymity revoker)
    /// that is the key in the map.
    #[map_size_length = 2]
    pub ar_data: BTreeMap<ArIdentity, ChainArData<C>>,
}

/// Identity based credentials. This type of credential is derived from identity credentials issued
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
    /// Decryption threshold of the IdCredPub in [`IdentityCredentialId`]
    pub threshold: Threshold,
    /// Temporal validity of the credential
    // #[serde(rename = "validity")]
    pub validity: CredentialValidity,
    /// The attributes that are part of the underlying identity credential from which this credential is derived
    // #[map_size_length = 2]
    // #[serde(rename = "attributes")]
    pub attributes: BTreeMap<AttributeTag, IdentityAttribute<C, AttributeType>>,
    /// Credential subject
    pub subject: IdentityCredentialSubject<C, AttributeType>,
    /// Proofs of the credential
    pub proofs: ConcordiumZKProof<IdentityCredentialProofs<P, C, AttributeType>>,
}

/// Subject of identity based credential
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityCredentialSubject<C: Curve, AttributeType: Attribute<C::Scalar>> {
    pub network: Network,
    /// Ephemeral id for the credential
    pub cred_id: IdentityCredentialId<C>,
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
            let id: did::Method<C> = take_field_de(&mut value, "id")?;
            let did::IdentifierType::IdentityCredential { cred_id } = id.ty else {
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
    /// Proof that the attributes and the other values in [`IdentityBasedCredentialV1`] are correct
    pub identity_attributes_proofs: IdentityAttributesCredentialsProofs<P, C>,
    /// Proofs of the atomic statements on attributes
    pub statement_proofs: Vec<AtomicProof<C, AttributeType>>,
}

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: Attribute<C::Scalar>>
    IdentityBasedCredentialV1<P, C, AttributeType>
{
    pub fn metadata(&self) -> IdentityCredentialMetadata {
        let IdentityBasedCredentialV1 {
            issuer, validity, ..
        } = self;

        IdentityCredentialMetadata {
            issuer: issuer.clone(),
            validity: validity.clone(),
        }
    }

    /// Extract the statement from the proof.
    pub fn statement(&self) -> IdentityCredentialStatementV1<C, AttributeType> {
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

        IdentityCredentialStatementV1 {
            network: *network,
            issuer: *issuer,
            statements: statements.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ConcordiumProofType {
    #[serde(rename = "ConcordiumZKProofV4")]
    ConcordiumZKProofV4,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(bound(serialize = "T: common::Serial", deserialize = "T: common::Deserial"))]
pub struct ConcordiumZKProof<T> {
    #[serde(rename = "createdAt")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(
        rename = "proof",
        serialize_with = "common::base16_encode",
        deserialize_with = "common::base16_decode"
    )]
    pub proof: T,
    #[serde(rename = "type")]
    pub proof_type: ConcordiumProofType,
}

/// Verifiable credential. Embeds and proofs the statements from a [`CredentialStatementV1`]. The credential
/// is derived from an underlying credential, represented via the different variants:
/// account credentials and identity credentials.
/// To verify the credential, the corresponding public input [`CredentialsInputs`](super::CredentialsInputs) is needed.
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
                proofs,
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
                map.serialize_entry("proof", proofs)?;
                let issuer = did::Method::<C>::new_idp(subject.network, *issuer);
                map.serialize_entry("issuer", &issuer)?;
                map.end()
            }
            Self::Identity(IdentityBasedCredentialV1 {
                issuer,
                threshold,
                validity,
                attributes,
                subject,
                proofs,
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
                map.serialize_entry("validFrom", &validity.created_at)?;
                map.serialize_entry("validUntil", &validity.valid_to)?;
                map.serialize_entry("proof", proofs)?;
                let issuer = did::Method::<C>::new_idp(subject.network, *issuer);
                map.serialize_entry("issuer", &issuer)?;
                map.serialize_entry("attributes", &attributes)?;
                map.serialize_entry("threshold", &threshold)?;
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
        // todo ar impl deser
        todo!()
    }
}

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: Attribute<C::Scalar>>
    CredentialV1<P, C, AttributeType>
{
    pub fn network(&self) -> Network {
        match self {
            CredentialV1::Account(acc) => acc.subject.network,
            CredentialV1::Identity(id) => id.subject.network,
        }
    }

    pub fn created(&self) -> chrono::DateTime<chrono::Utc> {
        match self {
            CredentialV1::Account(acc) => acc.proofs.created_at,
            CredentialV1::Identity(id) => id.proofs.created_at,
        }
    }

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

    /// The statement of the credential.
    pub fn statement(&self) -> CredentialStatementV1<C, AttributeType> {
        match self {
            CredentialV1::Account(cred_proof) => {
                CredentialStatementV1::Account(cred_proof.statement())
            }
            CredentialV1::Identity(cred_proof) => {
                CredentialStatementV1::Identity(cred_proof.statement())
            }
        }
    }
}

/// Verifiable presentation. Is the response to a [`RequestV1`]. It contains proofs for
/// statements. To verify the proofs, public [`CredentialsInputs`](super::CredentialsInputs) is needed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentationV1<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
> {
    pub presentation_context: ContextChallenge,
    pub verifiable_credentials: Vec<CredentialV1<P, C, AttributeType>>,
    /// Signatures from keys of Web3 credentials (not from ID credentials).
    /// The order is the same as that in the `credential_proofs` field.
    pub linking_proof: LinkingProof,
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
                VERIFIABLE_CREDENTIAL_TYPE,
                CONCORDIUM_VERIFIABLE_PRESENTATION_TYPE,
            ],
        )?;
        map.serialize_entry("presentationContext", &self.presentation_context)?;
        map.serialize_entry("proof", &self.linking_proof)?;
        map.serialize_entry("verifiableCredential", &self.verifiable_credentials)?;
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

            let presentation_context = take_field_de(&mut value, "context")?;
            let verifiable_credentials = take_field_de(&mut value, "verifiableCredentials")?;
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

/// A request for a verifiable presentation [`PresentationV1`].
/// Contains statements and a context. The secret data to prove the statements
/// is input via [`CommitmentInputs`](super::CommitmentInputs).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RequestV1<C: Curve, AttributeType: Attribute<C::Scalar>> {
    pub challenge: ContextChallenge,
    pub credential_statements: Vec<CredentialStatementV1<C, AttributeType>>,
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
        map.serialize_entry("credentialStatements", &self.credential_statements)?;
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
            let credential_statements = take_field_de(&mut value, "credentialStatements")?;

            Ok(Self {
                challenge,
                credential_statements,
            })
        })();

        result.map_err(|err| D::Error::custom(format!("{:#}", err)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::constants::{ArCurve, AttributeKind, IpPairing};
    use crate::id::id_proof_types::{
        AtomicStatement, AttributeInRangeStatement, AttributeInSetStatement,
        AttributeNotInSetStatement, RevealAttributeStatement,
    };
    use crate::id::types::{AttributeTag, GlobalContext};
    use crate::web3id::did::Network;
    use crate::web3id::{fixtures, Web3IdAttribute};
    use std::marker::PhantomData;

    fn remove_whitespace(str: &str) -> String {
        str.chars().filter(|c| !c.is_whitespace()).collect()
    }

    /// Tests JSON serialization and deserialization of request and presentation. Test
    /// uses account credentials.
    #[test]
    fn test_request_and_presentation_account_json() {
        let challenge = ContextChallenge {
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

        let credential_statements = vec![CredentialStatementV1::Account(
            AccountCredentialStatementV1 {
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
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("ff".into()).unwrap(),
                                ),
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("aa".into()).unwrap(),
                                ),
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("zz".into()).unwrap(),
                                ),
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
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("ff".into()).unwrap(),
                                ),
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("aa".into()).unwrap(),
                                ),
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("zz".into()).unwrap(),
                                ),
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
            },
        )];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            challenge,
            credential_statements,
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
  "credentialStatements": [
    {
      "type": [
        "ConcordiumStatementV1",
        "ConcordiumAccountBasedStatement"
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

        // the easiest way to construct a presentation, is just to run the prover on a request
        let now = chrono::DateTime::parse_from_rfc3339("2023-08-28T23:12:15Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let proof = request
            .clone()
            .prove_with_rng(
                &global_context,
                [acc_cred_fixture.commitment_inputs()].into_iter(),
                &mut fixtures::seed0(),
                now,
            )
            .expect("prove");

        let proof_json = serde_json::to_string_pretty(&proof).unwrap();
        println!("proof:\n{}", proof_json);
        let expected_proof_json = r#"
{
  "type": [
    "VerifiableCredential",
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
  "proof": {
    "created": "2023-08-28T23:12:15Z",
    "proofValue": [],
    "type": "ConcordiumWeakLinkingProofV1"
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
      "proof": {
        "createdAt": "2023-08-28T23:12:15Z",
        "proof": "000000000000000501b12365d42dbcdda54216b524d94eda74809018b8179d90c747829da5d24df4b2d835d7f77879cf52d5b1809564c5ec49990998db469e5c04553de3f787a3998d660204fe2dd1033a310bfc06ab8a9e5426ff90fdaf554ac11e96bbf18b1e1da898425e0f42bb5b91f650cffc83890c5c3634217e1ca6df0150d100aedc6c49b36b548e9e853f9180b3b994f2b9e6e302840ce0d443ca529eba7fb3b15cd10987be5a40a2e5cf825467588a00584b228bea646482954922ae2bffad62c65eebb71a4ca5367d4ac3e3b4cb0e56190e95f6af1c47d0b45991d39e58ee3a25c32de75c9d91cabd2cc5bc4325a4699b8a1c2e486059d472917ba1c5e4a2b66f77dbcf08a2aa21cbd0ec8f78061aa92cc1b126e06e1fc0da0d03c30e444721fbe07a1100000007ae9f2dffa4e4102b834e7930e7bb9476b00b8f0077e5fb48bc953f44571a9f9f8bcf46ea1cc3e93ca6e635d85ee5a63fa2a1c92e0bf7fba3e61a37f858f8fa52f40644f59e1fb65b6fb34eaaa75a907e85e2c8efd664a0c6a9d40cbe3e96fd7ab0ff06a4a1e66fd3950cf1af6c8a7d30197ae6aec4ecf463c368f3b587b5b65b93a6b77167e112e724a5fe6e7b3ce16b8402d736cb9b207e0e3833bb47d0e3ddc581790c9539ecd3190bdee690120c9b8e322e3fb2799ada40f5e7d9b66a8774aa662ab85c9e330410a19d0c1311c13cf59c798fa021d24afd85fabfe151802cbde37dafc0046920345961db062e5fb9b2fe0334debe1670ef88142a625e6acd1b7ded9f63b68d7b938b108dbf4cca60257bdf32fed399b2d0f11a10c59a4089937a28cbeefc28a93e533722d6060856baf26ccd9470a9c50229acc54753534888e1c8f8c612b5e6af0705dceeac85a5ac3d641b3033c5d3af066f33147256b86b1fffaaceea3bf9e4fd98f7a5371e4a882dd3c7cbe5d9b34e933d6ac224d7198cc4c8d3e5f0cef03fad810ca36499dc3a5e157d435843d60eb6a3fc3c3624d9fef8b5f2f2335af0a8ecca5cf71a9ffab6651d7c899d560264a6c9e361ee10a17dcb18522acdc0a19ab004f15ba1e23fa2aa3bb75f3767678d12c6dc35b2a04bb5239ce2cf35649a42525f42f91d6b80266af0fbd86645611332203ac555250fc29f6bb1b50932c7e48418bbadf57db4931789a0dd44e9b70d437af1ae686ede83e6965108a655caf34bd7b0b587eef0a29350020abae08bd2d979752316f749ab4686da684dcae5b571213c7bfb914cb70965e9b643862f71bab5d22b7dbf7d3f84636ba514ef2cf0c87ecf225e3bdc99e15368b3d814fb1e257ac1fc0b9114cbb8ed594ce50688c88d8ea9d0e97f55e89fbddd282e13d7303d3604e969bc0e699388c2f6fbb310aa82f18af896019d79f26f72fbe3a5dfc6fd30c34ac8d57d499e49664ecfa76094c6fba2372dba87a2b55dd9dc30877af0d6fdd2b2ea54be02b39554bf77b9ad30ef725df82bdb6c5456adf9ac3187ffbeaab1b4ce68782829850f10182deb13eaa94edd3640768224a178b8bac224d12711c7d3bec925db4da9bd1424db872757a1f2e10c9dac40483a69972504e5d69163a9f13c5dc8fc60a1634554a5009d948704f92e701eeb0a5b2cbfdcf62fd7b8cc0db65b2ba52dd1bbe2e46eddeff70f5fb3686917587b82a9cf1e1c8a7b6cf44dbe57bbf83d541bfbfccac677a377ef4e1a5ced1e7e5147bde759150f531780bcfc5658b099787d68277d3d41d992022be434194d8307d2a90a518705017affec5796354ff2432f57f525cf014bdcf0b9fd84b9501d3938259c433b4e6181e2630b56826c4a0c7d03cc0a8768ce7226703cf97ee83d6bc1c0c044a2e0d4439780d1c7351ea8ece10000000298ff27cb9f1c4afb38c535cee5dbde71599f727976298c540cdb7ff0b10a439f1599c9bf879e35746e2fd04dda05368d966efc49f07a5c48baaca5853de36dd2f0c7fab8106f1158f34ece1d0fd8576eb727d834cb0c380c150086e2222ba38283d8c26a9af828584cbd90801cc0c3e1855b9a26f81efd3931000b8a2109ac9cd5070b98963d700560fd6c6de1df8202ac21dfbdf141bdf58ee96d7a72cb2dfba962159a2c9d0fe1d312aca7a56ce97716d7d16e47b7c59e651ee8fe8dbbf56c3048a31df649d9da46f669b80d5cb31c3ee70c5e6a05de8be814833934befaef06757e390f83ce84b4fd84fb9d86eb30a897faa4718d7b5a12c086255a0a21cc038b69df7282cd3234e4423e85d15c09d49fc2005e869a4876fec01369c3b0ec0ae6f710797b4e5294a7fdf72c05341b6887da98066400436af27e739c140e3a481df2845cd78df942a2c0fb01429d5b04cd96b18c0b2bbf764b533a6f095edbea844cbc0d196b4e423c7fd409c1ceb6572812707c9048ec5a373c29e3cefbbd128e1ebe72b84be67ae22e3dfee5b47f57b289755b558624daeb22ce521c432fbf2cab96826ec670f18a194b151ec0f49c31237f35caae1296715571520e22caff2912531b1ee43d555dee29e7105161dfe86f133b3fb7c194e72c12b1eaac010160a3e8a44cad0b1c1ef89d492014997603a37b26e9461572edcf93a011d639550e0505ad8932c2a205c688d70d6414717c7a31868b5d01c37993085cf28d1c670000000295c326f59171824b2fc3e09816b73c6f75a03fb50f611559855d295e0a565ff6d2505f970464ca12e81031d286866dd5b73c285de994b592f8d8c2e64227bcc5ae2058339d11af025cfcb126c2b3c9a7839b87c8d218f93b0f30a0876076eb9598e1ec92a57f4ce785b1a05c01e8db34b4cefe8e518a859aa6d9530bbe72a033af7e87a95433de67b86f389e178b1aaaa53eddcdf1be990d96ba7e7f18ffa83d60385e1a1130dbf245e1b4bac2e8bceb2c1184380e6e0f7876157d7ae074d1fb013266272083b5420b3fc654141046e5bee9e3ffe50497f372d55b3f0aec05873c7409c8a1507c38f6c87b726e9355d5d326658e1e7e67b349ef1a65185ec51801b2a44460fcbf28d7ce0fce6c677113a88b88ec272d3cfac24d33afc47b6fa15259af84fa6543ef673cbd18a44d47420c8c53d7eaf9272dfa62fadd8d118c2055480b6494a67b0346c9fa0b2ba2cba9c0591224a2ed7b399ea35b89111a53059cb410c51ffb45d0aab4b642087698fcb67d55d33a711db3f84a125f970705b68c5ae5b8ea2394c891911d7f1032ec08ec8df792bcbcb1a953214317be0085b4b7b23a45d52a83f77cade01752c7ae6fe1d81bb5dc3b6a74e3d2f4130178263b9e633914559cf75d5902b5fc696198bff1d25812b05ade020d0aadcae022336b3c49639dd8dd90381bb59828ca9a82d87610d1e01b4ee4827f30d11ac72fa911f4439ca4fbfe164dc370e5c96dcc329bbf9972d71e811d17f5dd2ffb760ac0e31400000007b9e19ad95babc1c31bf657ae20a5420cf05bbf024ae2ffe13b363d5404c5a0ef360c54d49e8725210a5bba290d29cb58a2607e5134fdb367631e10d8e159396e39bbc09bd7084038f6b5cebd5386da5cd18cfe3ce9dbf75b51f4d7de00e00c5993a3b4d05fb3f4edb2a8d05cece2da96d7d87081c1610eb949caed95520479c662d623ad1464fee46bc3486521d44427ad8d76db0cc6ab51cb69d1dfd59c1938b68b80a8813c9dad15f9466941e377836693dfdcfc96e12a296699ef77ab274293a917b64e48f413ee2908b574ad8875951ce40dceadaf104145a2a937bce6707a962355a61efbf9379a1da606f98915a21a9255eaf105b04651d789fc90ddab8a402d11fd8e5befece4956d1d0c9c47987c7d282cb045c053fc860e8c07365b9937aae7fa435190992a02a24e388bd0b0836775d0e01c7faba3e92c5d3e8975fcad16cce9e9b01f378a572ab4039e0b8582d4d3a47c3b3fb587483cd1a760e628d0f3d63ac9e8b10cefa8b94d02cade0ab47005ad368f4f9e5b766a5c353a6eb1a7fd5bed46fbd1554c4ec47d8b6d3b38dcc66db969c646a34928eeb40147adc94878a1b237fcbe21f779e723e8a4f6a6cec0cb57205789e8d781bf465a833608b5181ad27d420e0e1f7383c0222df32259ace41dc092dfc745bbfc4bd371cd99e5a1c73baeb8ad15c34e060af529a8babad63c3a131ca089053f498170afb30b26e0f2794b0d1f417d870af7daf37694430db13f00b7af5101723d656d334c72b5e0bbe13478722e954935e6701ecf3cc725d61e42edbb896b6d4dff5b51f48e194337fb086908d50edcb61a295dcf57f54b6b41d5a760f5ff8992a6e45acfec08157dc3640fa1878cdb5ce41cb27ab9096beb3ded0b7cd57c1c4a850abc08ac822a3be26b4deb5a3cd11914ae5ac2c29430fe91be97fea012981dbb389da64d4a794017f91fb40e3188bd7190025a5b39c323a90f5a8496d5f64e200093072f1379728f1f0e741b51db5e4967d1e5437ca1d531ed742fe9ad2708ba06b3f80000097465737476616c75656d9f6e451166c885818931efbf878b5d041b211441fa707013ebe73e41ca25da68cebf07b67ef99e5fef798d5bdff3378d766b8116e710384d1530280b79e945",
        "type": "ConcordiumZKProofV4"
      },
      "issuer": "did:ccd:testnet:idp:17"
    }
  ]
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
    }

    /// Tests JSON serialization and deserialization of request and presentation.
    #[test]
    fn test_request_and_presentation_identity_json() {
        let challenge = ContextChallenge {
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

        let credential_statements = vec![CredentialStatementV1::Identity(
            IdentityCredentialStatementV1 {
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
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("ff".into()).unwrap(),
                                ),
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("aa".into()).unwrap(),
                                ),
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("zz".into()).unwrap(),
                                ),
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
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("ff".into()).unwrap(),
                                ),
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("aa".into()).unwrap(),
                                ),
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("zz".into()).unwrap(),
                                ),
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
            },
        )];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            challenge,
            credential_statements,
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
  "credentialStatements": [
    {
      "type": [
        "ConcordiumStatementV1",
        "ConcordiumIdBasedStatement"
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

        // the easiest way to construct a presentation, is just to run the prover on a request
        let now = chrono::DateTime::parse_from_rfc3339("2023-08-28T23:12:15Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let proof = request
            .clone()
            .prove_with_rng(
                &global_context,
                [id_cred_fixture.commitment_inputs()].into_iter(),
                &mut fixtures::seed0(),
                now,
            )
            .expect("prove");

        let proof_json = serde_json::to_string_pretty(&proof).unwrap();
        println!("proof:\n{}", proof_json);
        let expected_proof_json = r#"
{
  "type": [
    "VerifiableCredential",
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
  "proof": {
    "created": "2023-08-28T23:12:15Z",
    "proofValue": [],
    "type": "ConcordiumWeakLinkingProofV1"
  },
  "verifiableCredential": [
    {
      "type": [
        "VerifiableCredential",
        "ConcordiumVerifiableCredentialV1",
        "ConcordiumIdBasedCredential"
      ],
      "credentialSubject": {
        "id": "did:ccd:testnet:idcred:00050000000182d494c9b14d956c7114f7c4fd69ec1fca4018339e47c1feab138d8024287cfeaa0d21d4aa67ab9a97f5d05120a8e40bb85c7fa0ab43eb449f75f430376030fbccd14fd344d3261a297da74e43de07538b0facf6c25fac5dc30ecc51462192bc00000002b3e89bfa78279af73254f1d077495291f927a928b35ead4267c6dad33e2e01ae8e730b08bf6232c7194c857856bada9eb8429685e3b0b10bea5d7f55d0f7421e583740cc2566c822524e3d7f8b3eb13f4cb4bf50f84cbb92e74afcd39d96ca5200000003b9a5d4e1afe50d07bc6e58ccba17a89820b80b2d53493b86dae6f3bf75b05dd706fc5a9987963bb1cdc976bb3c6b48768b6fe00ddccbeb1e598e1363a569c8c0ba4ef7c293fd5ced0d169c4a23a39774057ae2830ff897d8f6f3f07cc80259f200000004973a177a5bd0ab3f3839d3d5475820b091181edb23505daff55860da0874d76ed48a1498b2b354d95c54c44e1a2173c2999ee2ebf4f732222cea944c6f6356994076ece3a3879d01ab4bd9bb4312323ab3cec99e2bc2ca01d17542f05881ac7a00000005b5a150156a40ee4171591f511015190c0854db3f6253cdfe62e663b3fbdcac236cdedb3ec3fb72f2460d9d59536bfb40b6deedb5eadbf733ca0f9b0a29e7a2ea9aac9604d9773ad2274f8edf4d55ac64c26895609a4a0145aa6254968552df5a",
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
      "validFrom": "202005",
      "validUntil": "202205",
      "proof": {
        "createdAt": "2023-08-28T23:12:15Z",
        "proof": "8d3f6cdc1c3119424c2fedcfa35874680d8300621545b83c2f7355780ee7a4ec62f4aa845aebd388a8031cd59b7ee674a3a431d6f97b7854c01cbf51995f8b6965e1a7e0c71fa625b26dd03680237892e183664861a67d69a8fbd979ced8de820000000000000004a6572c9d2160200762cd26ce1f0f5b9fbad87d7ab67f603bb09804f75e039e37a708a575f258369f3d432438265f2e3e99de25c3124d69f3ccb8ced84375e9cbbe4d19e4ccce5de3613542dc40ac5d8f3ed54e2dacf3a93e1a35063516d3cc61a643ee2c1f2b86defee6c6ff8b46353d899f96ae91ab271ee6fc38af13a343d593efb3ea8e8ca0c3686bba05533c33228bb82c5cdbcff8f3a92ab4c094786a872226b802bbe8898c27654dd3ff026ae92940f501438e7a2e7e7c5d24c6c0cf91a12ccc9b0d68f4ba755ce7e818afe1206d10a696bdcdcca4afc8198ac3ddd8db0000000500000001262c1a31a2999aa32ee1de70de43e32e123929d99612f158fe8e35effc478f2d2b90a6e155b50c60c8155f3739e06d94da6bffb27a16b17ff15456d21f1531b45ae65217242c6621b8b489443313986c9c7b9781fe4bfc205d0e7c871d1ee5dd000000020761c590322974631f1ef224b1e47d919d12e9fee1b206df6c5fd9b07a4e9d8b3589b8c3c5a3d80d8cf79664a1f7e5e74057a9e1164f4820b52fdc3269600aca18b6b2ccb16213307b74a9c2e0005dbfe258f43a0277dc7fca5b21d2d282057100000003521880219ec9237a24c182330856ccb08000c4240b3fe8dc818ea775becac5b11abbce000462d845b415980174d979f7b95416ba96a62b17b028cab73dac6fb0413bd8fe820787be887bbe6313ee3842b39a25156415012615df7c6f3ac2b09c000000041172599b3593703dd07e69cdccd185052010f3b0fe6646af6d42107d128ed8b842ff21e1cd6a1b1ae934fe297e31cbce124275c881e13fc731e8f7f49e4154a82cfef87769f0d39c5b1c207cc2275817af91ff0d710add81f0eb33179c18a6f9000000053a15bd3f2ff364c211261bf3c6b1dca4275a0a4053c15b1ec6122652427e72397085c18d8ea6882913f49dbad9c6b090501c7ef3e451371820a388489532506971d8f0e99270812f0fff382b5e899496609c957fee50ed3dfb687291a8b0bae833699c84a84739fcbda73a88e012bbfd7606b8061bc851b1412b00d094ee673b0000000b007225dfc2f59c91dd258e52cbdff44590a95e8a1f10a056e8dcd368878ca7dd9b54ba80865f57418f13f53b7193edddd91a9db7ac21ff2f1578661bed4d10aa30020fb70978f1be0898629c193c596604b8aff79bdbaeea9baeafc6f08d85ffeb4d0101010248cd267e1bc16405d99e76c9179a2026381b149e22e315e3423a772f89975491005861aa5fd2b9e0a89dac6b01b8136e7988129b8fe7c4dc199f2fd6e56f9fe70e6c2002b721bf30b8d5be3e5233f8ff178a49d6af6f8def26ca50bd49d6d5e2f1001a9114317d0016ad4da992cbc890d151695c5b3fdb8438fffead2f9ea1afc441689d366faff941b6c01eb3334223234b9cd8871253d457d27a93f9097d31f08e00188ace30bf28af5658b1d8dc2d8f6af1d1288cb969a30d1dca9d1fce3a145b7a237e69ea4468f634ef76641baa426b9b712300084ce591c754da61fb5004961a001b8b494fd84d455094e59c7c0ea9870850bd85385a994bb9160afdf0aa336e3b66684bb4a8e841cf48986aba1000d5e651a1185f024bde4c726216bf653d7c6e006138b2046110e04e75048cc2a51b7b2bbfb027f63604ed387240f7ca4dbd58b4064078d156e0698a3a89955ac8e5130abe47512e20f01215e385f780be800e31000000000000000501b12365d42dbcdda54216b524d94eda74809018b8179d90c747829da5d24df4b2d835d7f77879cf52d5b1809564c5ec49990998db469e5c04553de3f787a3998d660204fe2dd1033a310bfc06ab8a9e5426ff90fdaf554ac11e96bbf18b1e1da88328ab59c1841db88980eca8e795575319831cefdfea3db5e1ac009c1eccee8c616c9061728d962b0eb6e046c9de7103af58b125ceaed80196a59fcc0eeb443a81f28d92d85805b8655d1d5c6f83d3e10698435044b965a915451f3a716b88e34ccc9d15d748bb6303b0a70036f943a70b9944f0f23460b2464361c8cc02a12b3c80f32ec41ef79ff06ce460380c2a6c3c1db79ad10f8e60b01b38a2db9d016a45f15777f6d050d6ee896549a6413551611fda1bfd10a00753eb6c7425a498e100000007afcd89b352b23892c8f90049b328d625aea428cdb6b824f3fe06c1404a9f028709c4b45c35d5cadfbb6c421b95a488d29366c01d3a4e10f94198c67319fe058a7a4cf3dde04fe75fa12b0967620b0b8fb7dfa327d79b1d9c12ebd9c0aa7dbe178e1aa3c1a43e6342f4496c7ea6bc9f8747015d6ab365b64b701bf3a7d71c6e922b197c0ddb73ed463f8ee565eb691540997ad2f06d8b1e05a1ac1d638f8b71d3256f72de4e47cddbd052c53c8605b64c8b7e7d8e93e7b5489b2aeaa091f837c88ebc134677dbddf662615f37f5a6405357bc8562ba907cf086749fd093194b9f99f8eaed17830d8dbc3c9896c66fc0f4a4fc1f4e11c354878c440ae82b578ed129cc596240e1d072e7d9bd562634c1c6b1b3c8bf1649b5491245b0fe447c1ffdaa56ded90458ddbec7ff3c80328e19070fd412a791e89ef00a09cab0f3152e5222e663e4c204ef77b28a39392bc95d9da5f22d90ba4877c9d229ff6dcd142e73093518812b4c5a872d90971f7d8034be48d19039402f707283ed415af287ba86b84d83ea9fe6ae09857779dbb41b14e645cd653208861e19f5d98e3bf3b5b634866630856190ee461ea2569d268126c1b99f72f8e1c0972db5a865e337aa20332528dacea8319e08bb26cf6e4c4316f84e5ef66bce6bd6df279f53c3ef765c8093474a481fef99ccc1010f6b04c31e6286fe0bb640db64ae54502d03ccbd9db4c6a17ffb94c42d3e432e282b946e1d16a440a136b81a4e04d4e3fc04f82f07eda251373352f65a4718b0e9015e42e8e0825312db354fd4517c8ae959947f64898240cf2fadab0cab532a9ebea35a127db0b895d34a1f37b82321245ac763f59237c50396c2bff2392985e8027e5f9c85a651e57edbb212a6b82db3f00e8e36dc32231ef6f6b2e77579805e06f15c72933dfc83f2e4ef2c80e69ebbbce50e17c04294209b8d131f96071d69ae706c9a89fecdc1fbf05ce904b12539952a470107028974c01f828916c7d4f65af75c4f4cec7aec9fc2778011338d0ee6ffb46be302b39554bf77b9ad30ef725df82bdb6c5456adf9ac3187ffbeaab1b4ce68782829850f10182deb13eaa94edd3640768224a178b8bac224d12711c7d3bec925db4da9bd1424db872757a1f2e10c9dac40483a69972504e5d69163a9f13c5dc8fc609652472623e81f66723fdd7b8ab14b75970a645449111841565b8797fea350c3bf64d0264a2d4868d0b9b6c5b089fe7685399b18ec61a2b67904d299d9decdb64cb61a43e400a5fa908274c573cfa2102e9fd31b7974c3167649f65dc47e197f46824456234921e24ce52faa44d10562846670166e67e55e370ae6b9aa9587371c6b66ac4bccc97b2a02d46d1875d60a53dcc6d4a1cc2f86ed5dc5f2fc59ffe636be514f7241c8f4c5a178566516ffd0ef2e93ad4d764e49333536e538a65567000000028500d047e9c719cac92621060f8787a27bd5b98307584b3b49da3c8a3f1225a7ca7190c36a8a6a3f85919cb82862ed8fb93e44c2806a248688f42494b40c57ad5b1002bd41360115bfbd35c7d521ab28a2a1a8c9f039b6623c71357e3795044d8d2a9eb19fafec6ffd173598c971f2549729427787c8107574c9db8f187289e05253898f0b447b1cdc5353b3bf9a1f7e831d92a50191a7d4e8def01385dad540d76cbd7598f51341737856569542720319e2f5413303b06118658561860d03e95fbd131c94610859cdb0b03f3e27d09c4a110d1930f3d1a5b9b2b9f3d3b056525731c6072bcac2a9ef6cf9750738af5987f19941ac79be734a4d30f7ad66c838038b69df7282cd3234e4423e85d15c09d49fc2005e869a4876fec01369c3b0ec0ae6f710797b4e5294a7fdf72c05341b6887da98066400436af27e739c140e3a481df2845cd78df942a2c0fb01429d5b04cd96b18c0b2bbf764b533a6f095edbea89eb636b296f1cb711da46f26406dd51acdac9d9543401b1bfbe91650f1d839cd9300bad606fa3d8a5bf1a5bee38fca58772271680824a2508ea501d8b1483a652400e51e65e3ede13ff88e2d15b1c9d1db8904d2443569817d04ffaae55f22e0d19b2f65399641c65ab1b874f50bda64110f97fd85dab16c2f60eeb2f816a1d31ae95cb4e954bc966de9aa414390af7b27cfd8ef32cdf4229090aacfd599d9d1f709bf97acc370d358ee0561fdafb19ecc5caf6bc39b081601a9272144709560000000282aa17d5da54dd8a01c0c92c058020ce536be3db04787a2981ee41037d302da2f72714c63b79c53a0e63125bba8475d58d8e94f3d568155cf02e2d61d65fabcab4c981a21aeb1a62737ec3e8dbd4d598a74942c68e415ffcb1f5d283ddf64daa846bd8f0d21e5295874a4e529238cb943e2020cd0f6b59c53a5df3ff4e1175033aebdcc2ebcf8822c3f9cd0fabc5d25289d22b7a44ad214fbee33447673cf6c4898faadd1b116cf056403adedac6a0b7764f9cf570e13662ebc9966b9c648ce769efc33b8b608877bb224757e4905637d4b2d8575c8d7ffc83e0a9d50d3031494d8a5eac2986ff03fe1ea37d0fdaa2120f36d6f39ccae892905ab9a59032824401b2a44460fcbf28d7ce0fce6c677113a88b88ec272d3cfac24d33afc47b6fa15259af84fa6543ef673cbd18a44d47420c8c53d7eaf9272dfa62fadd8d118c2055480b6494a67b0346c9fa0b2ba2cba9c0591224a2ed7b399ea35b89111a53059ca7360a1ed7a5cc62e26d1ba8023548d8691df406b10b85e7ca36a0064682db381abedb01a3649867c754c5a599105fdc82229c1d9fa684f7004448fa0809738877f6bc87d97adf5dd5db6002dc5ac6c8c1a79df4fc758c9aaac8f38a98cc8c2b6ae6204881de6bf7c6fa66b323738ec21af9093184627cd5b1be07067cbe95fa0cc76f6b0b83476fc4af68ebd8a6fa7e9477e656970f824bbfa649c37f49a48b520baa419830e5e6bffadc76dd1121d4fab1062be7288c9973ce7011f6d60a2000000007a69dd9e8a1de3a6ae369878e9eaf1f2c5c994d7c69e51e6619943e34536e380b20fc84fccf1ed1e79f3f3f2ddaa9d4e1b73386a0a12d15d6a0ec8f77b986034687c65356d94530677c3db5276c4544038b182268e7bb9be7a22690cedffdbd9cb11d0ff07f5111ac51933f0321954f150c0f8a16ccc285a3b37274bfeeae37779e31d86b886d1ac5f783f1414beb2568afe31c858f0d800edf1d2e4e14a509c9745fed22c5e119595267f67002da47eff5eb6f0c402c24ed929973422ef3dd32acf03f0ef958914b20f6e67df1eff16490f7924e475c40c6cd45d12b68bf4138670ef1cfe3acfe9ed4dab8cbad6c8a70888294c44991c14b087157d731bfb2af094765e3d281419a41e3585d3c808459c21f96d517dd45bf50b56e3e08bd409fa59d87b07de9d011d42c847feedded53cdf4aaa20c88268728ae79daf8ea1abe32c19100230124e5becd6f43471872eeac7dfb4313f892248c4fbb0211e014ff3d94c433eb5acf82ed553f918bd282a4f63158a4497e133049bfea6048dbd74390c61811d6c0c9c3ecc0f440e0332713e3dfb6181bc1d6fa96c0d079872edb2a87dc1da3225bef42c3142b82e35d06b5a54874f51ddcfd5ad82f24ccf5a59338651703ed57f338ab7730486abf26e0e60445205d688e9be8294493dbc114b0b2899bdf62047149a4b651eeb74df92f2f4c96120a6ee7d54eb075fd3aca2d43e3ea2ae9b604b47cdfedd84d85c3aa28418d62c1f701c37782d179624de3a2ec98cfcb081f747cbb73e1859ed8354143831939ea29db81fb00af129729a1062e4488d24f4bec553d6a5a272f295f9f24917ba6dd28febe0331859dd0ea8f9d01fee95c1fb8170c11981cec4e1365c857c7aef0934faae3686dd741503653d9683e9cb4f86eb34185535dbf106a21ce334b988fc3f1d11fcf922cf5afd596e6f28403de9f17d8d1808b5cdfb591551c8b3aec6a6d5e4940c194b5cf5ba5dabace166a19abc60588efc973a15386ec6393ab6dedbdb01d33dcd6cb191afab8d9e42c0000097465737476616c75656013dc1febbeb115c9de3ba1484bc465ea1435250212cc431a204d2af1af5bc43c7bc79d89bf1d97e7a230577cde10eb98f22e9c721f7552986501aa3fc02088",
        "type": "ConcordiumZKProofV4"
      },
      "issuer": "did:ccd:testnet:idp:0",
      "attributes": {
        "lastName": {
          "repr": "committed",
          "value": "8f0142e3d0ace53c83ddf765dc2e9d9147a815a8c1a28bdf4ad0272c7b7569069fbfb28103a2eb49d219557eba89266b"
        },
        "sex": {
          "repr": "committed",
          "value": "8c36e020c72b47ca84e8b6224d48135efc5c467739a2af85a1d37feddd0cc1de13173fde14f5adc7af7048db047ccbd6"
        },
        "dob": {
          "repr": "committed",
          "value": "9249cbfa9b1bd0371c847a0e55d070103a9a52ee851d974d212a7cb1f3177dc41a9512ae1cb3f9f7200130bde1cdef37"
        },
        "countryOfResidence": {
          "repr": "committed",
          "value": "97d9cfa3955e7fd0bf8d81d712f9cbbe55721e900f53a3c3cdedceb7469c28eb65e4857d8dac9bac81671da0096148be"
        },
        "nationality": {
          "repr": "committed",
          "value": "8a5c0d88e2dc71d6fcaee2db5344ed7f9447127f6aa64461b4c6ef2b3958cb6ab067800ecd8613d99f14b99bdcb5b209"
        }
      },
      "threshold": 4
    }
  ]
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
    }
}
