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

use serde::de::{DeserializeOwned, Error as _};
use serde::ser::{Error as _, SerializeMap};
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
      "issuer": "did:ccd:testnet:idp:17",
      "proof": {
        "createdAt": "2023-08-28T23:12:15Z",
        "proof": "000000000000000501b12365d42dbcdda54216b524d94eda74809018b8179d90c747829da5d24df4b2d835d7f77879cf52d5b1809564c5ec49990998db469e5c04553de3f787a3998d660204fe2dd1033a310bfc06ab8a9e5426ff90fdaf554ac11e96bbf18b1e1da898425e0f42bb5b91f650cffc83890c5c3634217e1ca6df0150d100aedc6c49b36b548e9e853f9180b3b994f2b9e6e302840ce0d443ca529eba7fb3b15cd10987be5a40a2e5cf825467588a00584b228bea646482954922ae2bffad62c65eebb71a4ca5367d4ac3e3b4cb0e56190e95f6af1c47d0b45991d39e58ee3a25c32de75c9d91cabd2cc5bc4325a4699b8a1c2e486059d472917ba1c5e4a2b66f77dbcf08a2aa21cbd0ec8f78061aa92cc1b126e06e1fc0da0d03c30e444721fbe07a1100000007ae9f2dffa4e4102b834e7930e7bb9476b00b8f0077e5fb48bc953f44571a9f9f8bcf46ea1cc3e93ca6e635d85ee5a63fa2a1c92e0bf7fba3e61a37f858f8fa52f40644f59e1fb65b6fb34eaaa75a907e85e2c8efd664a0c6a9d40cbe3e96fd7ab0ff06a4a1e66fd3950cf1af6c8a7d30197ae6aec4ecf463c368f3b587b5b65b93a6b77167e112e724a5fe6e7b3ce16b8402d736cb9b207e0e3833bb47d0e3ddc581790c9539ecd3190bdee690120c9b8e322e3fb2799ada40f5e7d9b66a8774aa662ab85c9e330410a19d0c1311c13cf59c798fa021d24afd85fabfe151802cbde37dafc0046920345961db062e5fb9b2fe0334debe1670ef88142a625e6acd1b7ded9f63b68d7b938b108dbf4cca60257bdf32fed399b2d0f11a10c59a4089937a28cbeefc28a93e533722d6060856baf26ccd9470a9c50229acc54753534888e1c8f8c612b5e6af0705dceeac85a5ac3d641b3033c5d3af066f33147256b86b1fffaaceea3bf9e4fd98f7a5371e4a882dd3c7cbe5d9b34e933d6ac224d7198cc4c8d3e5f0cef03fad810ca36499dc3a5e157d435843d60eb6a3fc3c3624d9fef8b5f2f2335af0a8ecca5cf71a9ffab6651d7c899d560264a6c9e361ee10a17dcb18522acdc0a19ab004f15ba1e23fa2aa3bb75f3767678d12c6dc35b2a04bb5239ce2cf35649a42525f42f91d6b80266af0fbd86645611332203ac555250fc29f6bb1b50932c7e48418bbadf57db4931789a0dd44e9b70d437af1ae686ede83e6965108a655caf34bd7b0b587eef0a29350020abae08bd2d979752316f749ab4686da684dcae5b571213c7bfb914cb70965e9b643862f71bab5d22b7dbf7d3f84636ba514ef2cf0c87ecf225e3bdc99e15368b3d814fb1e257ac1fc0b9114cbb8ed594ce50688c88d8ea9d0e97f55e89fbddd282e13d7303d3604e969bc0e699388c2f6fbb310aa82f18af896019d79f26f72fbe3a5dfc6fd30c34ac8d57d499e49664ecfa76094c6fba2372dba87a2b55dd9dc30877af0d6fdd2b2ea54be02b39554bf77b9ad30ef725df82bdb6c5456adf9ac3187ffbeaab1b4ce68782829850f10182deb13eaa94edd3640768224a178b8bac224d12711c7d3bec925db4da9bd1424db872757a1f2e10c9dac40483a69972504e5d69163a9f13c5dc8fc60a1634554a5009d948704f92e701eeb0a5b2cbfdcf62fd7b8cc0db65b2ba52dd1bbe2e46eddeff70f5fb3686917587b82a9cf1e1c8a7b6cf44dbe57bbf83d541bfbfccac677a377ef4e1a5ced1e7e5147bde759150f531780bcfc5658b099787d68277d3d41d992022be434194d8307d2a90a518705017affec5796354ff2432f57f525cf014bdcf0b9fd84b9501d3938259c433b4e6181e2630b56826c4a0c7d03cc0a8768ce7226703cf97ee83d6bc1c0c044a2e0d4439780d1c7351ea8ece10000000298ff27cb9f1c4afb38c535cee5dbde71599f727976298c540cdb7ff0b10a439f1599c9bf879e35746e2fd04dda05368d966efc49f07a5c48baaca5853de36dd2f0c7fab8106f1158f34ece1d0fd8576eb727d834cb0c380c150086e2222ba38283d8c26a9af828584cbd90801cc0c3e1855b9a26f81efd3931000b8a2109ac9cd5070b98963d700560fd6c6de1df8202ac21dfbdf141bdf58ee96d7a72cb2dfba962159a2c9d0fe1d312aca7a56ce97716d7d16e47b7c59e651ee8fe8dbbf56c3048a31df649d9da46f669b80d5cb31c3ee70c5e6a05de8be814833934befaef06757e390f83ce84b4fd84fb9d86eb30a897faa4718d7b5a12c086255a0a21cc038b69df7282cd3234e4423e85d15c09d49fc2005e869a4876fec01369c3b0ec0ae6f710797b4e5294a7fdf72c05341b6887da98066400436af27e739c140e3a481df2845cd78df942a2c0fb01429d5b04cd96b18c0b2bbf764b533a6f095edbea844cbc0d196b4e423c7fd409c1ceb6572812707c9048ec5a373c29e3cefbbd128e1ebe72b84be67ae22e3dfee5b47f57b289755b558624daeb22ce521c432fbf2cab96826ec670f18a194b151ec0f49c31237f35caae1296715571520e22caff2912531b1ee43d555dee29e7105161dfe86f133b3fb7c194e72c12b1eaac010160a3e8a44cad0b1c1ef89d492014997603a37b26e9461572edcf93a011d639550e0505ad8932c2a205c688d70d6414717c7a31868b5d01c37993085cf28d1c670000000295c326f59171824b2fc3e09816b73c6f75a03fb50f611559855d295e0a565ff6d2505f970464ca12e81031d286866dd5b73c285de994b592f8d8c2e64227bcc5ae2058339d11af025cfcb126c2b3c9a7839b87c8d218f93b0f30a0876076eb9598e1ec92a57f4ce785b1a05c01e8db34b4cefe8e518a859aa6d9530bbe72a033af7e87a95433de67b86f389e178b1aaaa53eddcdf1be990d96ba7e7f18ffa83d60385e1a1130dbf245e1b4bac2e8bceb2c1184380e6e0f7876157d7ae074d1fb013266272083b5420b3fc654141046e5bee9e3ffe50497f372d55b3f0aec05873c7409c8a1507c38f6c87b726e9355d5d326658e1e7e67b349ef1a65185ec51801b2a44460fcbf28d7ce0fce6c677113a88b88ec272d3cfac24d33afc47b6fa15259af84fa6543ef673cbd18a44d47420c8c53d7eaf9272dfa62fadd8d118c2055480b6494a67b0346c9fa0b2ba2cba9c0591224a2ed7b399ea35b89111a53059cb410c51ffb45d0aab4b642087698fcb67d55d33a711db3f84a125f970705b68c5ae5b8ea2394c891911d7f1032ec08ec8df792bcbcb1a953214317be0085b4b7b23a45d52a83f77cade01752c7ae6fe1d81bb5dc3b6a74e3d2f4130178263b9e633914559cf75d5902b5fc696198bff1d25812b05ade020d0aadcae022336b3c49639dd8dd90381bb59828ca9a82d87610d1e01b4ee4827f30d11ac72fa911f4439ca4fbfe164dc370e5c96dcc329bbf9972d71e811d17f5dd2ffb760ac0e31400000007b9e19ad95babc1c31bf657ae20a5420cf05bbf024ae2ffe13b363d5404c5a0ef360c54d49e8725210a5bba290d29cb58a2607e5134fdb367631e10d8e159396e39bbc09bd7084038f6b5cebd5386da5cd18cfe3ce9dbf75b51f4d7de00e00c5993a3b4d05fb3f4edb2a8d05cece2da96d7d87081c1610eb949caed95520479c662d623ad1464fee46bc3486521d44427ad8d76db0cc6ab51cb69d1dfd59c1938b68b80a8813c9dad15f9466941e377836693dfdcfc96e12a296699ef77ab274293a917b64e48f413ee2908b574ad8875951ce40dceadaf104145a2a937bce6707a962355a61efbf9379a1da606f98915a21a9255eaf105b04651d789fc90ddab8a402d11fd8e5befece4956d1d0c9c47987c7d282cb045c053fc860e8c07365b9937aae7fa435190992a02a24e388bd0b0836775d0e01c7faba3e92c5d3e8975fcad16cce9e9b01f378a572ab4039e0b8582d4d3a47c3b3fb587483cd1a760e628d0f3d63ac9e8b10cefa8b94d02cade0ab47005ad368f4f9e5b766a5c353a6eb1a7fd5bed46fbd1554c4ec47d8b6d3b38dcc66db969c646a34928eeb40147adc94878a1b237fcbe21f779e723e8a4f6a6cec0cb57205789e8d781bf465a833608b5181ad27d420e0e1f7383c0222df32259ace41dc092dfc745bbfc4bd371cd99e5a1c73baeb8ad15c34e060af529a8babad63c3a131ca089053f498170afb30b26e0f2794b0d1f417d870af7daf37694430db13f00b7af5101723d656d334c72b5e0bbe13478722e954935e6701ecf3cc725d61e42edbb896b6d4dff5b51f48e194337fb086908d50edcb61a295dcf57f54b6b41d5a760f5ff8992a6e45acfec08157dc3640fa1878cdb5ce41cb27ab9096beb3ded0b7cd57c1c4a850abc08ac822a3be26b4deb5a3cd11914ae5ac2c29430fe91be97fea012981dbb389da64d4a794017f91fb40e3188bd7190025a5b39c323a90f5a8496d5f64e200093072f1379728f1f0e741b51db5e4967d1e5437ca1d531ed742fe9ad2708ba06b3f80000097465737476616c75656d9f6e451166c885818931efbf878b5d041b211441fa707013ebe73e41ca25da68cebf07b67ef99e5fef798d5bdff3378d766b8116e710384d1530280b79e945",
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
      "validFrom": "2020-05-01T00:00:00Z",
      "validUntil": "2022-05-31T23:59:59Z",
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
        "proof": "a76a6838f8d93d6d8e9e946d6bcf98c33e287673804ed9ccdbe6b9620db5fc506f0c7bf26d0bd661579f0ae018ab12cb87fd224a72890dab2e238aa4bb364eeb57c7776cb062dfd32dabaaeab5e8291327ddf00bd6c2d0a367da63ee73a3684c0000000000000004a547c8619f3ff2670efbefb21281e459b7cc9766c4f377f78e9f97e2c50569a8dcb155f2a502e936d2cb6ef1a73e92af9916e6353b7127d55bb525cb18074b5ec130463e03a4eda583b05c2d63db40a08ab8bf05f930ec234cc2f788d5f5bfbeab3e4881918ce964ffd55483219edd435ac865286bfd313cd834aabfa8061d2ae173cbe4b59ab2bda78faa4c2c937afba80d7fba0822579ac0ef6915f4820f968a74f00ff5ab74e90b0a7bcb2b92093a5e94a54aea1d48ffd1e5bb3fb48069bc80a923e289f1fca6c77bd65b90546b0fe69262b316d5448cc73302434fe52b05000000050000000143763c5ae7fbc4afcac9eba89de1bc52eb8ab7493ae5792614d1e4eec3cdeca6514173ecf5cf92cab53fe2ebc8569f866e97641531319b2ef27acad5fcef8a9709d5bbe8cf8f7844c08111abd9868f051d1eee6d01216c653bc8aecaa3578cfe00000002738d2525cd94ecc5b0970ff4ec4230cc6dcca3da41a251bca193406ce6773a592171758a81d60b3a14986ebc40562938ca75284298093835c3774740119fa64e5cff3a2a5e05a5bed356375091a1590c66a92b30144de9f44c1eb539da24ca1a00000003106f64c53781e0d6dcd74fbf20b5fc93d92a4357d0c54e3b3c38d5846110ace967c1e84b4363c96202de715a57b4dcafdd931c3dda0d0300109363666f7762f55e54208872003b5d9221a1db5b39046b7c6f11f98995ddde8b2a4f63f0b4d3db0000000424a8cd2b5b7201cc31cbb2587ce79afba29d165a8bb75b030b504e7158e502dc1fa68efb1aa8cdd9a74d8356fe7f44b22d755ef7f7b0cfcf17a56a7b8d6bceca6f3a96cb97b6c10af673b3347e0e15b614f5032b5efc4ff4476f94367af79fb9000000055c1c96177b50d76e89abbe2954c433e461a54e54b1017fa49cbe98e48ea11b1a70bf31b0d789f5fa30eac8a582209c888aa8695549c7e5ad3b13ef3b81743f305180023c53bee13a20c7a0bbfab26ae5fdbcabc66e9267d61e6dd17a18abd0d83c02c90793cf2e1d354ca03c85af924a4501853357051e5f960faae2d94204a60000000c0027d9ca86d157f53f0854a230b1ced054028ac5dd5661963fd32403730fa9767e4cb8b670f2a34d3415172d8fc5a177727ff908ebd6cbdce5ed1b3581643b24fb023270a95114ca7cc3d2132a4ede62af17506ebd07b6e20120e9f3c599717928220101010235b9f0411d81717269bef6a00ba6b777b479874e8083fcc6f1e46105c9ad7ff20043661ace7f1e8ebfff542f8d6e87679be9b04759239228811aa4411181d4a5a646fe6e6b0a114818746c6cb604845be1ae385d3b038a329e5a1db87de481cf4500183a883591a3a38071180df35beae7d743df68fee24743d2c332b34809949fd16aea0d598d958823c784c93f4a9514aeebb556864a36e0036f5d3b53a46209cc0054ed2bf6410b8cd36b1e398931db850b2a00fa34949b823f6b933a1a0c72e7f52c0762b145b2f370f3834430f23190a599c3fe0ca331d17050dfd5e50ba2c5af0049e83ecf884ab4fa05812c6b0c41b8d7c3642830bedcaa880ffdd51262cbaa84531cd128952d9af61422f54da3550b29ba8c1a5b8535b6e3fe39ed5df70cb6d5004e228384ae1aa7b0bd7897808694b6682e0d1b81b8e6adb242ddf32d7453a48e71f9866fb30c0b849c3ebede8de053d8cc2e134e6a5a84bcdee26440bad59e68026294fc38a506ac3b980f6a42c5c91e16c2dd50f99c925cd70ac48a73ac83a63a000000000000000501b61331d68d01dd74bb7d3afdbc875a4a6c72526ff35b4103af1a4da7b44ec1551ea9d4c27076884b98000dce54a2e868877cd48fc801f8a6b246d94f03c4d69a23bb6aea23067ba5b49ea8048c5f00c138a159f63fc41e284bc974e3a82b24d0a8524e36801912a4b0066e78eaa27b873ac33ad22ae39de12e6e2e949812b72ff46a5c26c75750c4a0db8600d4845d6c90b27ebfbb06c796090c00d361eca4ddd944020f88bd5629c069e01f073a485b1b2b08e11a14faf75e17e2ce79a1e411382454becf7c3f3761b482ee3d0a46f2cc6c3fe95286270aa0174d37a58123652fc4b3749dd44a1ece8a69415c353e8e56047b97ae3774a68e8a88a72513152f13034c8c7022c8cd999b189acfea580f2618e864a84c1567e9047d0ba74d80540000000793e2781f8acaf610b03dc83f55e5a8eb213ef4d258c2e446c979ddbe20b663e3aa82177b1f4823e940b96ed71e51ca3489752a39921134a5f6fef9a0ca8796958ce38881d02fc5ec60cb10cd709cab0a169b46d5159773d97d4497e096657a6b897e603d276827ddca5b2fe7d3d652933371bc8d685d288ea3666d37e2dc8bfa60dc0ebfa97e229b333e998e632d92c9b28de3338bf8f443bba16c5b0130c919437e2daaa44ea561ea6dd6046d4bebf84d1dcb5b2439ea18f713446a63468101b82ccff503d3e5a0dee8f3aa6b5907bc5d3de132dfd448890eb1c8ed8d32b71bc009e1ae5ffcefc603a97aba73481bf2adc259d01e98c9e8e85f08481c1d2a5854dbacc099920dbbaf7f8a0b8e3a539d569d19ce33f05bbe81e8c39ad0e202dfb85efcd2b8c5c3700be3e250ae9308568c0b394b2d527c1f9219675b66bbc6c44a6015fb06ee337a3635cadc2270f665a0c890c61c7333a872d8f92097ffbdf13b400d39aba8a09c6f5e28ad51737a18dc29667c2a5eb7db63a36cb5dc2245ff8a709ef51d1d8e53c21c4b61e9c6fa6abcf4de546d029746e10afa6db89d9469e43414ad4d6de65d43bdde9d461adb6ba512e5e59e39140eceaa00f52cc95251b7a6a79f1e7399c953c4540a0fb7da31a625c3a28124917adeb72788438f592c81197bedeb0816883be53009255668d9759c9ae013041e13de1bf9a4cb80e52bb2dc62579dd5b2bdbfbc709d7ebaac6087defcc5964d5aa97a0c360b484d42f8717d359b0c36d55b44bc9e411de22105b82bbd2ea83f448690e838b1e0d1f4dba4f6e1f538231b3eb62967d28a350d37f3eef91e5b9a59154377ee38b871859eff3eede93b062151e3395bdb25e28565988c690e596820b137c9d3b7bf66111acf1694134f9fe937004fae3d128033cb14295e60731b4499a030b3367632015a3cef3e032e90baa07a04ccd0e8a89287ae3b159f12865850bfab25cd2a3a0e466d6d60fe49ef6eacfaed80238d67564d6bb14348b4603b82f84728a28a77701d02abc6020a9302be54227a66fb1625475d097e9f75c97f1224090da03bb1db2fac3e1e0527b101631f3086936c465fff978d34288b74de204979fb8f3f327645799d3889d40f5cbcc61ae0448874a1bb59904c8b910bbcdf77c09b15545d84e985b0036d2445c5209c9b91d4735132da89bdd4916ffca2ec6cd070dac7aa470e19c7177111205e1bb5ee00707da4723474819cadd811550537a49ff9a4f9330fb6ecaddc736379487aca9c5b5e15989fb7d78356b645681db9f712e755991c10600349272d61da3c12ab4c354fc5be8a8c17fac55795ac3fc983e7c4feb7ca18143a6290893cf99253a03ec5f6aeb503c7f5d67e54ee3c31392c57520c519705c339fca0414d34feec9bef1b5d15f1962b620e94105a9394e249b2bdb32a63eced00000002ae23a3a4d8e72583611092c9b99ec275ae816a7ca1b225f1d95af75d8e5f89f1a44205885259b384ff69c44180d5dca48b1b2086b112de26e72d1b120dc2afe4e2ed3c52281b91d854fcf6b07f690bcbc67661af91c60e4f300e4aad75a5a3e9845f499a4184413aadeea9f8e2d82ff9aad39b5329ec5fdcc67d1566939a71f79d815068f5092a8d40e254f25674728f8b8c17b5bcdd75c4236097510213f2d18d90b5160d6cd3fa52879d7ec5725708ea4bf5ff13302a5d088896961d92ebaa27d90d46278ba50e551449fa2bdceaf261a65ea2b444e02ade2ad8d800628f436609d3cb325e378a10ea27963e561dbb485964044768e17f26936fd26fda235e0383765378621a7ce73a07b8c51ae60b98031cdaf29466142c0d3b83c627245a55c11ffa525a3b96f59169dd106f313ad493969b422412f746bfd9b2ab48e6b74d26f9b290b2141f8a4070d0a30f1832c641b2380d49af6287d85fc90bc8829637a5c6ac060f1a0d8a88e95e6cf0d0cc6a0c0ffaad2c8bfa3446d9bc8ff090fb9b7415a7942accea5d5394f801c67f923db7e523a18db43c1c364e53ffa7a6835f72da85c577b5ee230c1d7b04dd75d8bd42434f006004d34784ba96911da7dfde63621b0d5674a21cdbb745e7d0d0f19383ea27de57a29bfac52906f25896b0b90644bc2496b6fcb428aded9d8cce6c7cbaae5d48b0dd611ad9e570c7a8590d7931bae041aaa4db42bb6866b9a3ed75a8bbfa42c44beeb7a786030230be4c831500000002a1800ac3c07bcec245b3ba44c5f6d49857fed47d79c6273f7b0a7f886a8a20e4ae3859cef8d34a2a339443b8cedd97e28611e968e0231f039114b0f56882aaf8cb46fc8e035bef97db58183cab34c4966906e585db194cf962c282412084a89bb8cae478b44fbfd9205c705f1109831fe8f38aa89511ccf0cf961f4231b4bda863a854a838396299ee3292a60c2bdea3b22740dfbe1ab164114fefdcfe9e78bc6267079c07ab5068f80d80cc7a1c8bd683cd0763c357215ea93d1353e727d8821cf59c1161593e418466695e062418cc3da2ba6c6f587c3ad4e8bfc83b142f83262cf8b17a6c5fb17bc9ac5472785176a5e4bff95e32d6f0b839ebeb43825bbd01b6b7bc5a9d3a706bf5c7d8e6c22ac024270a95234030c0b553a958667073b935798cb22e9e57b04d2996e74d70509abc87f930c212b75796978cf882834240f98a14bcb1de18e26a2702cb8a94643e2fc06d71593c0adbb1ea3f00c5b666ddffb86be034f357095862dee04772ead188f87c435340312aeaa9cb6376461ad775ff5a7b633e4b5c2ec261cebc499666b9b525b11434ed8dd0631aae0b00ae178722bd07e97875bc259ebf488b93f7f8e3e740fa5883c30fbc4a4f9942443894813af5a6aafd4f84228b2c731dfdf33228a1fcdab676e52df91640bb911f95793b6b353e05cdc4057c1243c3c1cbf1221beb849a14f755993fdad412768ff570522c0a9d05d671bf187803bc7dd1bb21a2b26ea2527cb1b5b92fc3fdebe3cce2a200000007ae07e22eda7b5de57befb8a3480ba62c6325b6f1adefda3cb64a8761eb9e7b408e9141d9ab0d26e9a6f612ce03fb1a9ab43be20029d962f2bd1a61acd95def136619bf42c8780d992c63fc5d8e63c6078e177d89d8a4100c4746fec41ad6d9a29901d998c7b70a35087de4af6ce3d2e3eb41c8ebd0e63e0dc79ed9c1fccee5c0b156f23ebab10bfbc8f823dfca2714fa9240a498da590e08d3be16e6c6622ede2c99ab5a8ffd066f9b02481f7540dc8d2a8af4cef1f0d009bfcee7e4ce25576f91408600d90eb9883dc78dcabaff66d32a67a04db577fceda834907a2b8b60ed146540c00500ad7a8783383840a70582b9c9ed83de75560a93d22d495a05753e63fa520d79c95b4ef71a678fbbebfb3446e3eda66a48b261e6a84b7ac89ceae79758f2e70b69967740322648bc4b85dce541e3a9f3d6ef98dbd254997c910e7f55059b031aaf01aaab48a56d89b4d6bb98b4daf414417cae94999e5f51d7afa4d6f988cc9c7b28effae8cc98132deb785826428cd895b0f588d4f72f1c07e9f0a033fdc6ce957e4bff66f4fc65e41e6c666c955ea756bb82d9d383d103dc545147db2a1be19cb873560c22b7a610503197dc2ddabb97a03cbf2321e957ff0045f67103aa5e744a7938818558cf53b239fded36ef7c4baaaea357a9307fa006bfa7ec9865427955e80a365bbf2b11ad75ecac33fd332ffbbba4bff30888be4cec6da03eb65675a7a0026bf9e5309a80cea0b6f4a554aea6f1ff021c39f34f9b3441a507861346d8f544e69993a3273db851f40dfbe4f8cd5f7ae061f983dcd53588d7fc85e51ea28313afe09c1545b29bf200a4f692094026778221451cfcd43071ab14421a7a68759197fe32cf2689d28754e201f336930e36bef575dcb24431803f133913eaa1ac004a27817cd35f51666a8e022872586c3c96a29eec0ae869706550a9c2d58d430b5601560b2ffa59b57ec48807754f113cb7f8e22be0405a73cf54b6a1c8ebbac687fe690ef6ccf50538ca09da7f3e82bec3d8f2bb29729d0000097465737476616c75653e5879cfb054cb908f54994d43a9e657a69b3b4565a1126e709b1b020634622b6b49d69d2dafde98b9df25d85aab294cfdc801eb336e9ea6666800ee298f796c",
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
