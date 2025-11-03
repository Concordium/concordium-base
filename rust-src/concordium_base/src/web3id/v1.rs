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
    ArIdentity, Attribute, AttributeTag, ChainArData,
    CredentialValidity, IdentityAttribute, IdentityAttributesCredentialsProofs, IpIdentity,
    YearMonth,
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
            proof: proofs,
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
        "id": "did:ccd:testnet:idcred:000500000001822c07eba2b19631b0260e1fcd1f2f3d34d15a86439ce690d461f0b604f9fd66e898a37e3767dccc52037cc0d16f5f2db9d1f0495c09a4e1b96de2abe8c4c50c32e58c4d9f42d561d323c8a8fa98284bd808b963366bd7d0d9abe66e2560c55900000002a1c7252516d1f900335e2b5e95153b828fac094b1f095a0dd938960daddd6abd2de4c958115c584e0ea7fc2d20f4298882465b46dd09bafcfb687f61385c8dbd654081ecda8b412e974cbcd2917446078974461610c701c70c5392c19794c0460000000395c935342c44f3cb2c2dc28f1d4b41908ff2cc5be942cace1333fd6ce51c7c2e3003f574454bdc53625f3a91ab0720ea94c51d970c84023ce26da5dcace7c0b9d58091e02041142fa676d87d09e401069292352eb2616a6066ebca323b42944900000004b09f55ecd741a2493820b76b9edc59e668d1229611aa8f9ffee25256bd23bd35c2b9216ebe4799a39edb4d844c264619b20fc14990d1b930cd858d78ed016bc61837118e1eadee8402d7cfca0bdcb54871cd836c1f7a049aaf449f942ab6781e000000058bfc154b8b3160881dfeb5b8d387f13af35507371e3692e51daff7fe4dd1730cd9e33d37a047868ef90363771497d0c28c1a42fa841c1df1e0df488571b2365387ad81bdf72cb58f6b50a1f247b1abdd6408325b4594b758902816f23c033db9",
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
          "value": "869a0f6cb2500a479fe4bd6fd64145fc61a66583c7133644fdb73bc1cc2e8ba9dda53d1af5306c7ae9c78396487d17e8"
        },
        "sex": {
          "repr": "committed",
          "value": "a9998b370e959c1a0fe2229b2e45869812c01e49712cb0b9a6554d9d093f53b2d00eea9af51a115ffe2dca82a5d02024"
        },
        "dob": {
          "repr": "committed",
          "value": "af4170b2037bf7855645c50de927be744a132b663f56312a6088bd477df28b1a5257eb15824bd008dd252d0a712f18b7"
        },
        "countryOfResidence": {
          "repr": "committed",
          "value": "97fd6b45699ef8bbc1a8ec2b4179f20870aa16f6f1df3d5170be58aad418f50683f8b6839fd93d7cd9de25d776df79d5"
        },
        "nationality": {
          "repr": "committed",
          "value": "ad2e8f306c09c1e5161c041df22760c6763a54dcbe724626ddf8284848841df94f2f897da9a6dd8d6d7dc51bbfb15d37"
        },
        "idDocType": {
          "repr": "known"
        }
      },
      "threshold": 4,
      "proof": {
        "createdAt": "2023-08-28T23:12:15Z",
        "proof": "95c8e8b22a5a13166763afadeb631c02d0c2c1fdcf493860beb5970d0249877c09e8e23148495d9cc28cc572442259879299458558d4105bd6a96b8b6621c663997fd4ce9ba098d9abf11adc17871e058e506e790dc9fbe0abf4da0937e2c7bb0000000000000004a2eaf2eb41947c19de06713ccccd248ad30e70afbb8d6263ce8760a8fd31877eea77adb4b24f727db1ee08354f19688281dfd0cc3ff2fdea558d37e95b8b7607b3824d3cc17fdd13916245423c538a9684e00a06937e7e327d0e6fafcfd96caba33c785115a44d3fd5596986e8e4aae3cb166768b56a066670e2b9fb2890d85aac8ad24d0a61b217a6723124649bed7eab9b369335a4eb78f03f085fcc751f08848ea3884f1ad8ad82d86b159155cf4521f62614255e86e10d4c92b3dccd959cb8bd96f793cc54c532772f4589587144165c2a3b5089eefeceb9a55f45c5ab1500000005000000011f8ac9beaff008a7aaae63b14a08a382ad65503cced05964f067f89553ebb0e269e2e6c49ce52d72e7f967f72b58174de5318773113f307337d6ea566fa3c3f81b35d07af457d7f51b2cd0c03b9a18708fa5768f66645ed0f0b11a812ba78bbc000000024506b97f279a87f7abb47c220288a1461a27261774b2b7b46e0c17842126b9c319be01ce55644ff8d972c7efa7a41b5891ad33aa9edd152ddd2d08076a765a4833efc6b99876a8fcfbb5eb553e42658fb64cfc7772e6d9998b0c46de0605b9a0000000033b5fbceed29f2f7d0ce3d8ccbbee76131d248e5ecf0c9870f40ee8f91861a3c007381a116b925beb99bf07e020f1936ee7f1d35014c72eeba3a410e92f8f4f685e220a2b9456932ab0a8c137f50c872bc256b6a9929a93352d1c0d98b5e32b260000000402c728119ec85168ff17fc9259c1f6dd6181ba371879d453515e1cacf41168680d31a53b3adcab2942226a46bdad873af4a7657ea2085e756e7b5a0ae1aa9833477370c714fc3c9c78678020ce5c3f500ee477f96501a641ddc5e70ebaf1394100000005155bf24d84e0b85767328b05f60ff9865c7407f80a1fb40af22cbafdb36a15325152d2fa05b993a0ef98a091f1e8d2b7f2e7435b8df39a203cbee34374218be60c4ccc81c4f3c98edd97f714a9976a0aca5f38c3a8bf2405a7b0d52d9835ed7717ccc17ddb83a7d901174dca2d90326428db446042369486dab5ce41bfbf6f850000000c006e4adee0b9319f9b532b0add9e08e0b6bde3103c6c85888a02d507470bd10aa101af9fb87c9f6d7cb33a13e72c725421447c8abe3b676bc1dff4cd7874f1482f02252606fdaa0f2394bfb5751cffbe55e36f0cd9638820769f7fdfb4990dc26bbe0101010230127456736304d7b8d9a80786ec99f17c1c6e21af5e2e63f054e112b62691c80002ac8267e9109041e5f42e6b7c26dcc4df357f71ca235a5c7d73131f285c364103c748b39f4903da2ecca234abd5b829d96c5da79ac866f53ae716dcd2b229b50053620a84638895b5d800faab4eca09b01491765da6449155aa8046ce449b7aa602294a0d7a7b14e5a006f3cdca9a6952f479cb6833d81e387cf5cb77100fb42b0006fec8a790275b6dbddf6610876caa0238657897c557a9cd37ac5fd61885f04b3f5030a66f04c938b546715ddd806cfa13513c66a0915c6ba8e70171258a460f0033126d0ec9f3ccefd4c1438b098608f7051d612cdd2754091bcdefba69c882cf37288ff1c59dc127950449a8367df9f4efb6f88436c806ad937866d2c8ba2a320043c4f173e160acfd003c7377d92f84ac653aa441d6eee52fe19c56b8db13094f688c6f69eadf14f0696d46ede89f7fa61f321e13ce721d3d64ff24753de249bf022f1993b6992d746256daee754fe32a482d1d93864daaf839c479aee5c6aaabea000000000000000501b12365d42dbcdda54216b524d94eda74809018b8179d90c747829da5d24df4b2d835d7f77879cf52d5b1809564c5ec49990998db469e5c04553de3f787a3998d660204fe2dd1033a310bfc06ab8a9e5426ff90fdaf554ac11e96bbf18b1e1da881bcd5a48f69e61843585354bd3985ebc7c2b9bb05d8837b035c935baa91190f2d46389dd5be7178ed3e6f1e6249b160a8dc723973fb8c56bc5183c19a8b7dc8e189a938b3908334785ee248dc553b66cdef8f55f82d5b8b7b885c771deb27be3b64766773ad0ec736cfe23663d619dba90b98053a1c23d3c47a813bd0a171ae1d5ce02eef19fc3e8a49bde3bff0fbbc1a4dcf2dad179b0a2fb84c6125d8e49836ef708fd29d372ddbbeaadc9bbee6c4b214b508ed1b9fa396a6ae2ec7ceec9800000007a789a4f017c7039237b115df77f874462437621b3e342a6d5516cb3bff8c04d9a7249f7397dad627fcb0aa561ec3046696c8e709c2ee96a059ea22c1dc8ad4b69d2db5902f97746f858eb8f7fef354759ba305585e08b848e8acdf9aeaaaf2dca0e898d7d35872ed0ad0840a0f61e1135ec40df55aefbdb072c1b79b55958295c0ed6f952e7cdcb769468f5ffb5989ce94e072bfb3c48cdc23ede92d29f9d1e2e4fdff4303d23f173586157c4763490d2505b39e95135c95fc61b9b31b116161b701b163a7d2c95da584d9279aadea78bdd3d5ac2321bc4b0bf6b951ee582c40f27995b9043d144fa6b012d11815fc9ea0af26fd6ff4d8cc846ecb3e5192b9b752c4cdc0fd8838a485eddc52b66e6cc4c248593270217a350249b0e058388e9ea03e105bef7a0956fd3cc488d65f49cacf6928aa809e5b37415d1e153f8d4eff3053e7c6eda3090fa9cc36968ac26ca787034bd6c635182df52f9f88dce5c7dd51f2f6e43438d21b4cad628731e212de44296c9aee0f79a39284f5bf28c2dbc1a7f44f8532b5e8dcf6aab35ba67d970decb196c7e1804c530ecf6f98247cff7f14d75c83596b15390ecee40ddedf3753966d4aefb50b7b3635b42a1fc624e354a1d9ad0783390e1bf82d2835b105761a1df60bfa6d72f5b148a8a25c8a219edf91be5a93b67d7589e38ae54d6746dfad357e9a85d1e43c30b2f0579a77ef7e9b6052b325f0e5504ddd9a4bb1891891e2a5d669e5d50c17b952a6ffc570f8e280e554fcb417a5e5a1ad6650bd4cd1186e2ace7c13de44191b4a5e4c73a7df483395b84931a05a3050ed9473f3dada830291b1f8da5a3ee05a18901f97f07a8723c786ce996648aed6bde640a60a3eae6193dd0b5a2b4420373aec9234dcae0a57f13d5eb7b364e19246e3a5a4feac2f332bc0b89f7d154fd5c992f0e2a7afd7bc5989a43a63f3c5c4b7b725d4a5b5a3327dcb66ac15ecf2dfe45d199c084ad9362ba3c4fcf7a69337b831ed1dd7b26528339320ae7593b1693b8ed440a680a66d02b39554bf77b9ad30ef725df82bdb6c5456adf9ac3187ffbeaab1b4ce68782829850f10182deb13eaa94edd3640768224a178b8bac224d12711c7d3bec925db4da9bd1424db872757a1f2e10c9dac40483a69972504e5d69163a9f13c5dc8fc60974981f719133d51f2df44137528c28692366ab5e45e506cf0584796b9560306010ad1f713846cd27ae2c07682f92b6bb63fff70521f91c9f3796b86ebc97ddebbb6a728dc3ca2098737e3dc2a9a8c14c949bc5215ae38ed0e0ae044b0ded8657227824425e26aab5688c59ca948332f603d134186776662519da0fdc01bf31b185a9e346b2737bad64e8e371ff589ab654ade8217e2711e70fd472613b9f4c84480bfb97333f52661ea01567301b914fba26ca5dad0914eef139d29867048b200000002a21c6708dab8013a266472d2355ca80bf7acbb74d00dadc856ea1be7eb39bc94056f18b1205a02b288409f26a65b765fb18c3fb59f0e7f8f30cd403b42a617d216f875edc6e62902a83df11e6c4e43c1006eb99c5ef87993f17e3d1d114013c0800bc0509d5df34dde0deafb7a1a38ebff7bfb6fc086216dbab489199552c4e0b4304b4b5404a7c0bf8c889c6cf119c6ae03b4ebcd4f25edf4fca2a9fde11d1ff846f13171532fbca4e3e0fe5684c495204acad0cbaa14dea3247e0d18e5e8481a38283bd210925e1df156c46094908ef1b7c5ae37f65c33cb8b2918dcc780ed008078fc0533f4cf04e2904a035950b46e3bb1a20cef864a87488d30d503aa63038b69df7282cd3234e4423e85d15c09d49fc2005e869a4876fec01369c3b0ec0ae6f710797b4e5294a7fdf72c05341b6887da98066400436af27e739c140e3a481df2845cd78df942a2c0fb01429d5b04cd96b18c0b2bbf764b533a6f095edbea963c929f48434a98f66208ac0dc6afebeb26442c8c92f912a3c0b731ef08bc39d6f9977baa29cf6c8ad6fd7297c6d9e7a69b07d6a92a161ed720fa4daf147acac523446a27054d7ef311b572f54468f8b478c272ac53afd7c451be9e502b61f45c669ac5a0685501d1f023ed784e7d642810c4e5186d99f1c79ee9333330c469066f9c3347b268c82c1ec5e335231405b9fec5df6e29ef6a0e8d20ba0654ae7a069271dbe47ed3ec40ff92690721c6d1d9e9c1bb0dd80ac1f2ea34a748fd4f6000000002a17c7530d64eda675005bf960377f4a1c291a251578327d7a3b1ba43b252a74f350b164caac15f679df133443ca3ad29b6d552b4f7b152379f03f47de348505227c8c4ccc830ad7c15f485a1412067cd702d5c1da656ff6d11ad62d4f365914aab944f73a4fa2204f8e8e54bd34bd30d3e20c3c93c032a66d4dfe689e470183ca437bca696d1ce90a5a96897a51fc9a9952a9b266971bbd45bafed9c619fef2118b086e6337e3c918eba771566fa7f8e44eb64b5fe0caf04b03ac6a64aeec3ca43ff57c804f021d12fd787e3d1f16301690916eac95b00c8fd841e52a60604c45852a1ce784b46505e88bc11f1afcae3766806d885fb19b95138b9f768639fe701b2a44460fcbf28d7ce0fce6c677113a88b88ec272d3cfac24d33afc47b6fa15259af84fa6543ef673cbd18a44d47420c8c53d7eaf9272dfa62fadd8d118c2055480b6494a67b0346c9fa0b2ba2cba9c0591224a2ed7b399ea35b89111a53059cb69f228eafb2f146a71a9d00e4c1246412f9b81cd703622adb4d033b65e970737a9db997c934888784dae3e6fc1fbefa91858d497d32296c43652cdece6162918637d2b9fc7882a255cba0700163b46732343f1dfb191362e1537016c91ae7bd38afc478d0a6a38fdaf2d47f730524f5301aea6cd1d0fa1a776abbbda3f68c4507c6023747b56885e9ee9e981dc34523b2d49aea664d7043fadba0d354f7bf013827348f99d3d8fd4426758cc99d0ca7b90ae2a79425ed73bae17bdb3af3429600000007b0ae69262b263730fe9e0c430592ab4d1bdceb2a01c392cf2a9d2066d05a4aadc04d796f2e31fef66cb093224a0a3226a0e81fef95035f999542770817633aad940f9237192c50b08ad78d724c8344d82d294b7b19133498b8f4d940ac0448daa515e7076e9b8199aebcc9365e8ac7596a3b68d7e495118149f452d5f0e92ca46227ae6b01c4c44472bff596849175b28935926e3324b9b0848e578a8034d5706253b1a179f592ef743bc8112e169623e682e4779153144b97e8e1883ca2ebbda9f38a41e52ed5dd579f1d5c7aacb0bcb52c761228837fab1a137d01fcd10b333d069deeef5f84caec5f40d1f28e6662adc0364ef27df1fa55667c14ca365b7b9e14061faf16d9cc56b6c413b61bd1d924ee6bbe752e51557f7ce1b997eb2995869e94a88d23e5ac19b1c16346fd3d465d035141b9cf4cb1a89a1b5713bbccce34792b9e2c4df03ff6f217820cf4dbfcb770c72967204e940dce7c697e314641b5f67654b2b4fa60ce8f218388b128ea39d73a34c1f253a753367c1130ecf38582c7cb57500d60612d27cc28dfff2c01a50ab915f40277d8bc9ebd6922bf736f30bff52f3d7d4a91fc89117b7b234ddc88327b794e0a0bff57183174932caf48010b30b0098628f824618566bfc72dde6c93d896e295fb83eafacf0f98a3b709a43865764edd117aa77e91add7caffbd7c4ba3f209e7a7d0c98564ce56aed4f01ca4b35b51c47c802558f024780ef356a046dda570f1b84c1848d8921aa730670cb2ce2ab9d0bc0e79a41c51951b837ba0e150288350607b164d7b100c734a88b7dbc6ddabef7d72acbc002e886bcc877413dbce2b1472b9930fbbcd3a9757dfc52d08ca0dc2614b916cc8ea28c9308faf9bd381e838b684658fe51416ad9484ec0634deef479f6822d515f42d4ae04868b245a7abc5dbc63b27c180a83d540e347c960d806fb65b335311988968039affbc4c672a6f1c4be79b4a34f0bc8b2e57298429a0c36d3f40901e692bfc677aad91e2734d41b521a64ab4370ef0c2d30000097465737476616c75659e31cea08d50f7e556c6b8f1268d86619504f75f508a8f2c9bbaf1db6bf350e23c4f5ab2321aae6dc22e39b980238040ce5c1ce4579d8bc338cb1015a5f0f0ac",
        "type": "ConcordiumZKProofV4"
      }
    }
  ],
  "proof": {
    "created": "2023-08-28T23:12:15Z",
    "proofValue": [],
    "type": "ConcordiumWeakLinkingProofV1"
  },
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
