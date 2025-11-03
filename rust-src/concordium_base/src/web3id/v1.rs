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
    IdentityAttributesCredentialsProofs, IpIdentity, YearMonth,
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

/// Property value used in [`ContextChallenge`]
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
    // todo ar issuer also here?
    pub statements: Vec<AtomicStatement<C, AttributeTag, AttributeType>>,
}

/// A statement about a single identity based credential
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityCredentialStatementV1<C: Curve, AttributeType: Attribute<C::Scalar>> {
    pub network: Network,
    // todo ar should the identity provider be here? document what is here and what is not (maybe fail in prover also)
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

// todo ar describe credential metadata
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
    pub proof: ConcordiumZKProof<AccountCredentialProofs<C, AttributeType>>,
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
    // todo ar make non-generic, create IdentityCredentialIdData
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
    /// Proof of the credential
    pub proof: ConcordiumZKProof<IdentityCredentialProofs<P, C, AttributeType>>,
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
                let issuer = did::Method::<C>::new_idp(subject.network, *issuer);
                map.serialize_entry("issuer", &issuer)?;
                map.serialize_entry("proof", proofs)?;
                map.end()
            }
            Self::Identity(IdentityBasedCredentialV1 {
                issuer,
                threshold,
                validity,
                attributes,
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
                map.serialize_entry("validFrom", &validity.created_at)?;
                map.serialize_entry("validUntil", &validity.valid_to)?;
                let issuer = did::Method::<C>::new_idp(subject.network, *issuer);
                map.serialize_entry("issuer", &issuer)?;
                map.serialize_entry("attributes", &attributes)?;
                map.serialize_entry("threshold", &threshold)?;
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
                    let issuer: did::Method<C> = take_field_de(&mut value, "issuer")?;
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
                    let created_at: YearMonth = take_field_de(&mut value, "validFrom")?;
                    let valid_to: YearMonth = take_field_de(&mut value, "validUntil")?;
                    let validity = CredentialValidity {
                        created_at,
                        valid_to,
                    };
                    let issuer: did::Method<C> = take_field_de(&mut value, "issuer")?;
                    let did::IdentifierType::Idp { idp_identity } = issuer.ty else {
                        bail!("expected idp did, was {}", issuer);
                    };
                    ensure!(issuer.network == subject.network, "network not identical");
                    let attributes: BTreeMap<AttributeTag, IdentityAttribute<C, AttributeType>> =
                        take_field_de(&mut value, "attributes")?;
                    let threshold: Threshold = take_field_de(&mut value, "threshold")?;
                    let proof: ConcordiumZKProof<IdentityCredentialProofs<P, C, AttributeType>> =
                        take_field_de(&mut value, "proof")?;

                    Self::Identity(IdentityBasedCredentialV1 {
                        issuer: idp_identity,
                        threshold,
                        validity,
                        attributes,
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
    pub fn network(&self) -> Network {
        match self {
            CredentialV1::Account(acc) => acc.subject.network,
            CredentialV1::Identity(id) => id.subject.network,
        }
    }

    pub fn created(&self) -> chrono::DateTime<chrono::Utc> {
        match self {
            CredentialV1::Account(acc) => acc.proof.created_at,
            CredentialV1::Identity(id) => id.proof.created_at,
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
      "proof": {
        "createdAt": "2023-08-28T23:12:15Z",
        "proof": "000000000000000501b12365d42dbcdda54216b524d94eda74809018b8179d90c747829da5d24df4b2d835d7f77879cf52d5b1809564c5ec49990998db469e5c04553de3f787a3998d660204fe2dd1033a310bfc06ab8a9e5426ff90fdaf554ac11e96bbf18b1e1da898425e0f42bb5b91f650cffc83890c5c3634217e1ca6df0150d100aedc6c49b36b548e9e853f9180b3b994f2b9e6e302840ce0d443ca529eba7fb3b15cd10987be5a40a2e5cf825467588a00584b228bea646482954922ae2bffad62c65eebb71a4ca5367d4ac3e3b4cb0e56190e95f6af1c47d0b45991d39e58ee3a25c32de75c9d91cabd2cc5bc4325a4699b8a1c2e486059d472917ba1c5e4a2b66f77dbcf08a2aa21cbd0ec8f78061aa92cc1b126e06e1fc0da0d03c30e444721fbe07a1100000007ae9f2dffa4e4102b834e7930e7bb9476b00b8f0077e5fb48bc953f44571a9f9f8bcf46ea1cc3e93ca6e635d85ee5a63fa2a1c92e0bf7fba3e61a37f858f8fa52f40644f59e1fb65b6fb34eaaa75a907e85e2c8efd664a0c6a9d40cbe3e96fd7ab0ff06a4a1e66fd3950cf1af6c8a7d30197ae6aec4ecf463c368f3b587b5b65b93a6b77167e112e724a5fe6e7b3ce16b8402d736cb9b207e0e3833bb47d0e3ddc581790c9539ecd3190bdee690120c9b8e322e3fb2799ada40f5e7d9b66a8774aa662ab85c9e330410a19d0c1311c13cf59c798fa021d24afd85fabfe151802cbde37dafc0046920345961db062e5fb9b2fe0334debe1670ef88142a625e6acd1b7ded9f63b68d7b938b108dbf4cca60257bdf32fed399b2d0f11a10c59a4089937a28cbeefc28a93e533722d6060856baf26ccd9470a9c50229acc54753534888e1c8f8c612b5e6af0705dceeac85a5ac3d641b3033c5d3af066f33147256b86b1fffaaceea3bf9e4fd98f7a5371e4a882dd3c7cbe5d9b34e933d6ac224d7198cc4c8d3e5f0cef03fad810ca36499dc3a5e157d435843d60eb6a3fc3c3624d9fef8b5f2f2335af0a8ecca5cf71a9ffab6651d7c899d560264a6c9e361ee10a17dcb18522acdc0a19ab004f15ba1e23fa2aa3bb75f3767678d12c6dc35b2a04bb5239ce2cf35649a42525f42f91d6b80266af0fbd86645611332203ac555250fc29f6bb1b50932c7e48418bbadf57db4931789a0dd44e9b70d437af1ae686ede83e6965108a655caf34bd7b0b587eef0a29350020abae08bd2d979752316f749ab4686da684dcae5b571213c7bfb914cb70965e9b643862f71bab5d22b7dbf7d3f84636ba514ef2cf0c87ecf225e3bdc99e15368b3d814fb1e257ac1fc0b9114cbb8ed594ce50688c88d8ea9d0e97f55e89fbddd282e13d7303d3604e969bc0e699388c2f6fbb310aa82f18af896019d79f26f72fbe3a5dfc6fd30c34ac8d57d499e49664ecfa76094c6fba2372dba87a2b55dd9dc30877af0d6fdd2b2ea54be02b39554bf77b9ad30ef725df82bdb6c5456adf9ac3187ffbeaab1b4ce68782829850f10182deb13eaa94edd3640768224a178b8bac224d12711c7d3bec925db4da9bd1424db872757a1f2e10c9dac40483a69972504e5d69163a9f13c5dc8fc60a1634554a5009d948704f92e701eeb0a5b2cbfdcf62fd7b8cc0db65b2ba52dd1bbe2e46eddeff70f5fb3686917587b82a9cf1e1c8a7b6cf44dbe57bbf83d541bfbfccac677a377ef4e1a5ced1e7e5147bde759150f531780bcfc5658b099787d68277d3d41d992022be434194d8307d2a90a518705017affec5796354ff2432f57f525cf014bdcf0b9fd84b9501d3938259c433b4e6181e2630b56826c4a0c7d03cc0a8768ce7226703cf97ee83d6bc1c0c044a2e0d4439780d1c7351ea8ece10000000298ff27cb9f1c4afb38c535cee5dbde71599f727976298c540cdb7ff0b10a439f1599c9bf879e35746e2fd04dda05368d966efc49f07a5c48baaca5853de36dd2f0c7fab8106f1158f34ece1d0fd8576eb727d834cb0c380c150086e2222ba38283d8c26a9af828584cbd90801cc0c3e1855b9a26f81efd3931000b8a2109ac9cd5070b98963d700560fd6c6de1df8202ac21dfbdf141bdf58ee96d7a72cb2dfba962159a2c9d0fe1d312aca7a56ce97716d7d16e47b7c59e651ee8fe8dbbf56c3048a31df649d9da46f669b80d5cb31c3ee70c5e6a05de8be814833934befaef06757e390f83ce84b4fd84fb9d86eb30a897faa4718d7b5a12c086255a0a21cc038b69df7282cd3234e4423e85d15c09d49fc2005e869a4876fec01369c3b0ec0ae6f710797b4e5294a7fdf72c05341b6887da98066400436af27e739c140e3a481df2845cd78df942a2c0fb01429d5b04cd96b18c0b2bbf764b533a6f095edbea844cbc0d196b4e423c7fd409c1ceb6572812707c9048ec5a373c29e3cefbbd128e1ebe72b84be67ae22e3dfee5b47f57b289755b558624daeb22ce521c432fbf2cab96826ec670f18a194b151ec0f49c31237f35caae1296715571520e22caff2912531b1ee43d555dee29e7105161dfe86f133b3fb7c194e72c12b1eaac010160a3e8a44cad0b1c1ef89d492014997603a37b26e9461572edcf93a011d639550e0505ad8932c2a205c688d70d6414717c7a31868b5d01c37993085cf28d1c670000000295c326f59171824b2fc3e09816b73c6f75a03fb50f611559855d295e0a565ff6d2505f970464ca12e81031d286866dd5b73c285de994b592f8d8c2e64227bcc5ae2058339d11af025cfcb126c2b3c9a7839b87c8d218f93b0f30a0876076eb9598e1ec92a57f4ce785b1a05c01e8db34b4cefe8e518a859aa6d9530bbe72a033af7e87a95433de67b86f389e178b1aaaa53eddcdf1be990d96ba7e7f18ffa83d60385e1a1130dbf245e1b4bac2e8bceb2c1184380e6e0f7876157d7ae074d1fb013266272083b5420b3fc654141046e5bee9e3ffe50497f372d55b3f0aec05873c7409c8a1507c38f6c87b726e9355d5d326658e1e7e67b349ef1a65185ec51801b2a44460fcbf28d7ce0fce6c677113a88b88ec272d3cfac24d33afc47b6fa15259af84fa6543ef673cbd18a44d47420c8c53d7eaf9272dfa62fadd8d118c2055480b6494a67b0346c9fa0b2ba2cba9c0591224a2ed7b399ea35b89111a53059cb410c51ffb45d0aab4b642087698fcb67d55d33a711db3f84a125f970705b68c5ae5b8ea2394c891911d7f1032ec08ec8df792bcbcb1a953214317be0085b4b7b23a45d52a83f77cade01752c7ae6fe1d81bb5dc3b6a74e3d2f4130178263b9e633914559cf75d5902b5fc696198bff1d25812b05ade020d0aadcae022336b3c49639dd8dd90381bb59828ca9a82d87610d1e01b4ee4827f30d11ac72fa911f4439ca4fbfe164dc370e5c96dcc329bbf9972d71e811d17f5dd2ffb760ac0e31400000007b9e19ad95babc1c31bf657ae20a5420cf05bbf024ae2ffe13b363d5404c5a0ef360c54d49e8725210a5bba290d29cb58a2607e5134fdb367631e10d8e159396e39bbc09bd7084038f6b5cebd5386da5cd18cfe3ce9dbf75b51f4d7de00e00c5993a3b4d05fb3f4edb2a8d05cece2da96d7d87081c1610eb949caed95520479c662d623ad1464fee46bc3486521d44427ad8d76db0cc6ab51cb69d1dfd59c1938b68b80a8813c9dad15f9466941e377836693dfdcfc96e12a296699ef77ab274293a917b64e48f413ee2908b574ad8875951ce40dceadaf104145a2a937bce6707a962355a61efbf9379a1da606f98915a21a9255eaf105b04651d789fc90ddab8a402d11fd8e5befece4956d1d0c9c47987c7d282cb045c053fc860e8c07365b9937aae7fa435190992a02a24e388bd0b0836775d0e01c7faba3e92c5d3e8975fcad16cce9e9b01f378a572ab4039e0b8582d4d3a47c3b3fb587483cd1a760e628d0f3d63ac9e8b10cefa8b94d02cade0ab47005ad368f4f9e5b766a5c353a6eb1a7fd5bed46fbd1554c4ec47d8b6d3b38dcc66db969c646a34928eeb40147adc94878a1b237fcbe21f779e723e8a4f6a6cec0cb57205789e8d781bf465a833608b5181ad27d420e0e1f7383c0222df32259ace41dc092dfc745bbfc4bd371cd99e5a1c73baeb8ad15c34e060af529a8babad63c3a131ca089053f498170afb30b26e0f2794b0d1f417d870af7daf37694430db13f00b7af5101723d656d334c72b5e0bbe13478722e954935e6701ecf3cc725d61e42edbb896b6d4dff5b51f48e194337fb086908d50edcb61a295dcf57f54b6b41d5a760f5ff8992a6e45acfec08157dc3640fa1878cdb5ce41cb27ab9096beb3ded0b7cd57c1c4a850abc08ac822a3be26b4deb5a3cd11914ae5ac2c29430fe91be97fea012981dbb389da64d4a794017f91fb40e3188bd7190025a5b39c323a90f5a8496d5f64e200093072f1379728f1f0e741b51db5e4967d1e5437ca1d531ed742fe9ad2708ba06b3f80000097465737476616c75656d9f6e451166c885818931efbf878b5d041b211441fa707013ebe73e41ca25da68cebf07b67ef99e5fef798d5bdff3378d766b8116e710384d1530280b79e945",
        "type": "ConcordiumZKProofV4"
      },
      "issuer": "did:ccd:testnet:idp:17"
    }
  ],
  "proof": {
    "created": "2023-08-28T23:12:15Z",
    "proofValue": [],
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
        "id": "did:ccd:testnet:idcred:000500000001a45064854acb7969f49e221ca4e57aaf5d3a7af2a012e667d9f123a96e7fab6f3c0458e59149062a37615fbaff4d412f959d6060a0b98ae6c2d1f08ab3e173f02ceb959c69c30eb55017c74af4179470adb3b3b7b5e382bc8fd3dc173d7bc6b400000002acb968eac3f7f940d80e2cc4dee7ef9256cb1d19fd61a8c2b6d8bf61cdbfb105975b4132cd73f9679567ad8501e698c280e2dc5cac96c5e428adcc4cd9de19b7704df058a5c938c894bf03a94298fc5f741930c575f8f0dd1af64052dcaf4f00000000038b3287ab16051907adab6558c887faae7d41384462d58b569b45ff4549c23325e763ebf98bb7b68090c9c23d11ae057787793917a120aaf73f3caeec5adfc74d43f7ab4d920d89940a8e1cf5e73df89ff49cf95ac38dbc127587259fcdd8baec00000004b5754b446925b3861025a250ab232c5a53da735d5cfb13250db74b37b28ef522242228ab0a3735825be48a37e18bbf7c962776f4a4698f6e30c4ed4d4aca5583296fd05ca86234abe88d347b506073c32d8b87b88f03e9e888aa8a6d76050b2200000005b0e9cd5f084c79d1d7beb52f58182962aebe2fad91740537faa2d409d31dec9af504b7ac8dc15eae6738698d2dc10410930a5f6bc26b8b3b65c82748119af60f17f1e114c62afa62f7783b20a455cd4747d6cda058f381e40185bb9e6618f4e4",
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
      "issuer": "did:ccd:testnet:idp:0",
      "attributes": {
        "lastName": {
          "repr": "committed",
          "value": "98ad4f48bcd0cf5440853e520858603f16058ee0fc1afdc3efe98abe98771e23c000d19119c28d704a5916929f66f2a3"
        },
        "sex": {
          "repr": "committed",
          "value": "abb05a0ff79b3b06f912f0ec642268d3a1ad1cdf4f050ab7d55c795aa1ab771f4be29f29134e0d7709566f9b2468805f"
        },
        "dob": {
          "repr": "committed",
          "value": "9158599821c271588f24e92db7ca30197ec5b0c901efaadd34cca707e56b9aab1a7f14e329816e2acf4d07a7edf1bd6b"
        },
        "countryOfResidence": {
          "repr": "committed",
          "value": "af07a1ba7a22bcb1602114921a48fa966a821354cd0dd63a87ce018caccc50b56f2c9f55a062cdc423657aa5cec8a4c9"
        },
        "nationality": {
          "repr": "committed",
          "value": "92e74b23368a65b53b31889206da71a1fead62a4f68e8753ace1de719063a49d3f0a6c0f17675db9a5652e7a8429edb5"
        },
        "idDocType": {
          "repr": "known"
        }
      },
      "threshold": 4,
      "proof": {
        "createdAt": "2023-08-28T23:12:15Z",
        "proof": "8173d8e37a94d18ce07f949dc39817ea2f155734552344981e4ce81af9a2caa6d3d2594e1df9e27c4c2c57077950e804b3626ea8d37a61703a59d59f01e8848b2796de8d2612788e1a01c4c08660e46a702f1f2a35a2ad3241cc4484170780550000000000000004a547c8619f3ff2670efbefb21281e459b7cc9766c4f377f78e9f97e2c50569a8dcb155f2a502e936d2cb6ef1a73e92af9916e6353b7127d55bb525cb18074b5ec130463e03a4eda583b05c2d63db40a08ab8bf05f930ec234cc2f788d5f5bfbeab3e4881918ce964ffd55483219edd435ac865286bfd313cd834aabfa8061d2ae173cbe4b59ab2bda78faa4c2c937afba80d7fba0822579ac0ef6915f4820f968a74f00ff5ab74e90b0a7bcb2b92093a5e94a54aea1d48ffd1e5bb3fb48069bcb5ab73f515d1b6f0738b8e35c5a9e16a0c339ac6ad71d799782d6bae9c4599eb000000050000000116875813697a02d01468fc7c96ce6c9a5fb310c99b3eef5916521d9583a10f4c6be26400b387a8f065db91a09efbca512db7febb8e0c70f6f2721a01e8636aee4b746441998a3cf009774258ea5b68ec544fffe2671ebda47335f101b8fc88030000000258a56b356a7a4d0ade83836a4d8ab3d4892425651c97bacac0a2865f9e2f1d5a0080221d15a70eca660d87bdda784e4ffa54861c27a3123089e5f91714a2325502b094f495488132a244d7c6fbd49882be74c5cc184165d9dc37087c539d82bb000000032595369b792fd2fa7393e2dff2c7fa35d801f9ee2363a1ebbd2c798c6e43e59560f3fc019c7fa50273eaefd1a140afc685928e068e3aa172fc5e12c00128959e643b5ae32e494d3d93f8dbb082d348f9df9d8debb959ee61b48c5ca971f727e10000000471829340b30b56601669e1949825d07f708723378a83af93a44e80fc1f6ca6d9491194cd83eaa4856ddf4fc96178beb2d5556c3ec912b2d78c54a49d45d088be080f1702f05c2bc53d66381227ce63aca3d7cfb38931f59fd65a49b5d3a03e37000000050d92e9833f8e05a65e63c54770f15eee7fd3fae89044b8066a12734a278ca36b2ceaed97cdd8a5ba06e5e0ecdd01238fe6cb2c7937cbf141a0d433da197646ce120cfb0f82fd37008adf92988f7b1381585dcb49a295bdc16ac062a243fe3a32240c0b98b9ee6e5d5e693c388984d78c195509cef164c2138b6baf339f45056b0000000c002b8779c6f944d5b9793144551f88bf4330736f336b89b04466e4985f39c9c05e506665b11a902dae85f3cfb4335b6661ade1b241ebf3f6ea80dbca6d8e5b6edb024a1f05dcf762547540760873ed1c7ecc0eb8bc570b52c94a2a96271dbd50d5e40101010268ce6b3e84ebf1d0a7dda93e3a191d99df72424df09bddf7b0d06c08e89b7530005c68ba40a4de9faa184455a7b6ac9ec137525cd0998fa9df027a9603f42e22d106abd155a73cfc0c6dc55dd6a8c0b6c27f9e48d0c343cf2914426992919325f000034af7d96c1c1a2903b359e6b7289e2c2c1a862a5de7288cd1453cceacc6838e657b01b509da3b12abfe589b834a13217cc4d7aa1edd27eec3880a20813d3fea00252b0c26168cf2c428d366199a89c973f003357310d14adef71a97f6b6a1b9c51ae7aac06c667831690bb1205cdd963a9698c604689ebd30dbebb06756319c21003ae50f7c77b62c10fd84ce37d0b93c3818301610ba1f6345842d91f7fca90c3b6b08df78796e985ccfc376f9b07100bef6c618a2f3fb58bbdfafacd92ea061d4001ddee9c392c500fe4e436df281fa3ebe00e38fb25c3f3d48df1ee645da1af13d24100eb2f67ad86235ceb86a623a4efd5d5b89b482d4b306d1b48d0223b592530237c04cc07c67111e8cb03d3708ebc7aea744591585df1146153da805ec635317000000000000000501b61331d68d01dd74bb7d3afdbc875a4a6c72526ff35b4103af1a4da7b44ec1551ea9d4c27076884b98000dce54a2e868877cd48fc801f8a6b246d94f03c4d69a23bb6aea23067ba5b49ea8048c5f00c138a159f63fc41e284bc974e3a82b24d08ec9f4202874cb0d3e50b1596de2a6fc4d2d30fca8249bb3f603a7b0aa662fad7810653e173af087275d38eedc02e7a7a710fa44ab549eb963641027203ffd202fe1a98dc3189777cd26b877bb5a2940a1a31e77795cd9cc63215b2c2dc7deff255c2670c5e9cb30a13a7e76e19b6821e4dd63728b02f7f60e6ca8acc42fbddb44bb741f2f1618105f951991ef75142fbfc8325d8c0e070e98d86fdf79cdefb019127db8f08cc4f8511d682e7d4f39db6472fa1a46db1e7cf9bdc8405c860f8500000007a3d31532689a4e14027d8d5ac1bea2dae3d8578115f82f7095e1362ae454ac081cd40a093e736ed8d54b6b093b242c71b1d79f2f06cd50f613ec495e039a65286f9d35ab5b8b07afc105beb991c1e5126f58eb41cf7682dc0d55effb8d15ddcd966214fcd9b03198ed4bde5e2a026c579d26225cbd8b8a45c1a0e89566c65be2fbc58f25c0ef4ed8ba89c91f15f68e27a96cf7add41d3f5483fc195d072a78cfbf402c942814fc4fdd33f4106f95c6027ed223f1af15512dd448d6f8572543fba491f4029d714773b89d2b8d45470df0cee1ba3b6e4f6dfc9a1305cb6c39e8e77e0143e01c2f4bda62da4716179f2fd0a5eeaba8d324cf0c8ebca7bde7fb96c3535b65c9b67a3c3b8e23e9e40e7de9f48c0959214c28e0dfe88af86e6f518eb690418223a4c88eb60cfbf46da318ff41000f6d892e3605cda78f008c5162d3b3f0c5188ad67969420f60ee18ff3d47999095eaa3f7378680126465b7ba3edcbb3444d44659d573ad13cbd3c721975bf82606168580b0871841d93e91c6a7594ea7c13b9cd657daa0907daddc2216351c00dd7b4e177f3a13a443b1b739a69706443f62da3b861f4e8f065d26dffe5cf1b9e624eae96d77d7f21fa866da686405e13bcc1e3b08b7c10f828b6f48a78e9f65635e1d32133f7945e15574ce2313a38085992bbfcc253ae483af26cf4bae1c400ec7cac77bc13d889cc7e5aab5a34da2d462a688ba0391ba7a96b41031a245b16c64ea695b6d43b7bbbca9b019e9452023550d6558d2a497c7a15bc8992a491f9c0c1d302e4c10fbe8a3bb7c06e8829985c006e436d174694e5902702ae9603244327fe5d126037cdc932bdb3642d44b26ec70e85dd7aeddb05f66a25f9a5f92ac8392ad01fdcfec28ddf80b3a9c3ccab9a0a0b72b9362e98e3dc16220b577fd28ce1a88b9a3fc887896270cea83eb1d60123d6172082bab944c1bd0eb5979a47fd52fd310a4cebcf935a606a4a4e148c3d011056172b28f8ba2a82495fce423d69daf6c3ea5595b36aa248c79e18c02abc6020a9302be54227a66fb1625475d097e9f75c97f1224090da03bb1db2fac3e1e0527b101631f3086936c465fff978d34288b74de204979fb8f3f327645799d3889d40f5cbcc61ae0448874a1bb59904c8b910bbcdf77c09b15545d84e985b5f5367efb331a344b5f30bb2d84074001f165c3e70119b4501f73e4a6a7dd494a45d81189c0f6afac159fe8625137ad8d37923b3c4faab1b2a9ec0989c2086dd1e5d51550a33b3e6c696c40317c3d34836afb32c09a82120f0453e3c119ea016d9da4aae97477b04982d44504d2cfc48a329faa8b7b12f0e874ab7ba86dab274792ea28e71431306f4d95ca8412b7692d0a5b99bf70f5294a234e8951dc7e8a6441ba56e8ad9ccd9d2cb6790924f05d0278b2fa9548dcb1512336148a90626500000002a13803d7e1121d45033c3d135353a6fbde59ead5faf0648d0c5b7c7321c2fce48b87a0440db9f5d33867b9ad2e054e18ab0b993de8ed1359bfe6c0113af59535d40a18768cb379218bf9803946c39542e0323a294d11cf3f74d2131b5cd32ec8ac081eba3bcba391d1c1e7bdcea58cf5ca82b2215021ff07c77a701072e911c7f1bb700fe1da879be52227d3d3621b178718f10fc8d16338f6e3c5f8dd4940c4c991942f17ad2885d0222eb5b8bc44a24482f973069297017395126f61882fad406357ec4af94830126050bd7c93c4274850473ce39dd75bced9a27b4a5ca0f74bf6fbe1ae6055594e739d818218583850bda8ace6b50647b2742d1370a01cd60383765378621a7ce73a07b8c51ae60b98031cdaf29466142c0d3b83c627245a55c11ffa525a3b96f59169dd106f313ad493969b422412f746bfd9b2ab48e6b74d26f9b290b2141f8a4070d0a30f1832c641b2380d49af6287d85fc90bc882963790811af6e779a03eeb22ddfaa1d1d402afdedfc341992dc3b1052c08d7cb9ac9f34ae8a4d4ffe9d1f756c2e2cae01e3980fbe15a6cf0cfbc20db5995c93412ec2bd05e01fa5c20edb1fcd272706259383833d8f8946f2b20d82ff54550db527d049aa5bc43f7ba9b2f8e4492aacf8e46c5f1b751193022ae6ba9910c5841a01054735bd8d3bed59fb1e691eaa54a23e1515e6d8c57854f60e8903c1c97fc1aa10b264bf8adea7225beff481a2a8b8464746100d1bbfffc852b88bcec3f9a3c7300000002ab1e22b5ff506d9f97230cbe76d7f09fbe0e4063b352f8247b957b97e75e2bed10b7774c7050e1ceeb17dd145d66235b94b980380ed7da6c72e45ef2c2636a6fbb48a6a7b1790e774778d527b163ed054d2796bbfc8d85095d9f215ea9ac322aa465314096c517a56c927ab262ee513ba6d6aae1257f6459c8e6a3a37f52444a7a76829a9d41a8d543bcc41f96dea649b9a16e803c3f9ab93c2d0876a4f07dca29c255a8c47867ef0645fbc60d827f1aade61ab9fe09008d9e289b830086825e2a8cda17903cdcbc1f46d962bf94018a103b1c8dfef71d2aa13c17b45fba70632fd17dfa3d21672a07efd92e20a9a63df8e899b8de3c91cacb722e557b652e9d01b6b7bc5a9d3a706bf5c7d8e6c22ac024270a95234030c0b553a958667073b935798cb22e9e57b04d2996e74d70509abc87f930c212b75796978cf882834240f98a14bcb1de18e26a2702cb8a94643e2fc06d71593c0adbb1ea3f00c5b666ddffb2c397cada47c5f77890d214785d8b413c3b3f6f66a7e6f28c30cc5887676bd4536de8f2697ba1f0ad7ebd2a24a334a8a6412d69fc00e2a4fe979849b4b706077163bf6540122babbb52323d3ac48a8ee6e67212ab33513182c00152e13391620048381525ce0ee6010c9eb6d26d88dcd92c86d03ecf406b0864a2c6153e3a501ed1012111caa174cf97c8cbb2d4db08a04c7d084ccaaf79c0441273392adba553e432b830a197dabdbf523147ee979b5e6caac2b017965da62878fd916311e500000007b02fa2072b53827ea36ad8c12707b0b85c7043c3972d6c42d9ac0b056af0e21099c567122eefa3ada253f686cc3e5d038f2d17f7e5fbfe101254d345c40b0dadbac2cd6c4f474311a1e4e63e2a503947821ed5f2bda8b1673298b33c4083d6e9a330f0a23ae2f8706379818242f3ea39f6a73eed2e3b5cbad49297c87509673e4032e7e438a742c76ccd61e91c6ec51c88a3650dcb01fd86df447e6daf2bc5c1ae49ec37e976e6b6901d79a5258ec15b25f94849119988595c0e048ac1a02d448c6d66a4a08567946a429b19606bd80b3606614e0f159e3061b419bb53d195c4e6df32ba0691a77b4f91ae2d79884b56813e557cba192178e7a615c99744aa12db70343392d4844bff1f41c5a85b1550d9586f32ac752bed613e5ad3d4bc85afb6e04dd464f5b50ee7ce6b81c76b788b50478ef3a0473f24191f2162c744e2306e18bc1f5b440351c48cf6406d0fc3e189d29b8b1b3f590b0bf7a67d4c15f43ace1c170a907b3f79f9ac4dd193ebce269c58a6c9d41fa969e9a5243aa6791345913d801dbdc13004a634a65696dcd58c739b9a79902c7a28a24caeaa58a65e9342eae8e434c071d6c3f935747e7a285db2cef668e9a1f12e89a2b2b0643b1bbb6d435522bf2b5a330eafd2c5cc81f799e2c5034be63c09c2b1e4e6d6be98f4efaf7438df37b5db5921fa9aefa5a3147ded7ecc9f366f79200a457e88993ecc9978453ebfa7f050a116017924fc94c1aca83b0493ad90113c6b9e06287ce7eca692c01861413d1cefdbb9a1828f66ec93292d5bac82ed8634f4fe814e93c658c2a265abfee8ea95e3914576677db42cc25ad27182c1ebbd8707bc3c2474f3e44578cc1a46b126d802d6d409bd717296c3a8fa09a21070184fde5cee27c2a1c208ef33c49ee1260f39f10ab761625371b931bfb17f84d4c08b10cea5c1e2db452a62a952e2e4e17214a239e223fb2332a346416a498d833f163f99a618b8b5116a08d92db50d2ad15615e053be73754c28f740739a9121cd46fd834244c26c71390000097465737476616c7565b5dcab00052cefe7df07e5a7bb441829203240342288350b17559078297519b429ddca008278bf71e31c0b3d3b3cfa787fb37f6205f8b5144d249a4db2826c81",
        "type": "ConcordiumZKProofV4"
      }
    }
  ],
  "proof": {
    "created": "2023-08-28T23:12:15Z",
    "proofValue": [],
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
    }
}
