//! Functionality related to constructing and verifying V1 Concordium verifiable presentations.
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

pub mod anchor;
mod proofs;

use crate::base::CredentialRegistrationID;
use crate::bulletproofs::set_membership_proof::SetMembershipProof;
use crate::bulletproofs::set_non_membership_proof::SetNonMembershipProof;
use crate::common::{Buffer, Get, ParseResult, Put};
use crate::curve_arithmetic::{Curve, Pairing};
use crate::id::id_proof_types::{
    AttributeInRangeStatement, AttributeInSetStatement, AttributeNotInSetStatement,
    AttributeValueProof, AttributeValueStatement,
};
use crate::id::range_proof::RangeProof;
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
use byteorder::ReadBytesExt;
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
#[derive(Debug, Clone, PartialEq, Eq, common::Serialize)]
pub struct AccountBasedSubjectClaims<
    C: Curve,
    AttributeType: Attribute<C::Scalar> + common::Serialize,
> {
    /// Network on which the account exists
    pub network: Network,
    /// Identity provider which issued the credentials
    pub issuer: IpIdentity,
    /// Account registration id
    pub cred_id: CredentialRegistrationID,
    /// Attribute statements
    pub statements: Vec<AtomicStatementV1<C, AttributeTag, AttributeType>>,
}

/// Claims about a single identity based subject. Identity credentials
/// are issued by identity providers. The subject is not directly identified in this type,
/// only the identity provider that issued the identity credentials is identified. The corresponding
/// credentials will contain and ephemeral id [`IdentityCredentialEphemeralId`] that can be decrypted
/// by the privacy guardians to IdCredPub, which is an identifier for the identity credentials.
#[derive(Debug, Clone, PartialEq, Eq, common::Serialize)]
pub struct IdentityBasedSubjectClaims<
    C: Curve,
    AttributeType: Attribute<C::Scalar> + common::Serialize,
> {
    /// Network to which the identity credentials are issued
    pub network: Network,
    /// Identity provider which issued the credentials
    pub issuer: IpIdentity,
    /// Attribute statements
    pub statements: Vec<AtomicStatementV1<C, AttributeTag, AttributeType>>,
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

impl<C: Curve, AttributeType: Attribute<C::Scalar> + common::Serial> common::Serial
    for SubjectClaims<C, AttributeType>
{
    fn serial<B: Buffer>(&self, out: &mut B) {
        match self {
            Self::Account(claims) => {
                out.put(&0u8);
                out.put(claims);
            }
            Self::Identity(claims) => {
                out.put(&1u8);
                out.put(claims);
            }
        }
    }
}

impl<C: Curve, AttributeType: Attribute<C::Scalar> + common::Deserial> common::Deserial
    for SubjectClaims<C, AttributeType>
{
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let tag: u8 = source.get()?;
        Ok(match tag {
            0 => {
                let claims = source.get()?;
                Self::Account(claims)
            }
            1 => {
                let claims = source.get()?;
                Self::Identity(claims)
            }
            _ => bail!("unsupported SubjectClaims: {}", tag),
        })
    }
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
                issuer,
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
                let issuer = did::Method::new_idp(*network, *issuer);
                map.serialize_entry("issuer", &issuer)?;
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
                    let issuer: did::Method = take_field_de(&mut value, "issuer")?;
                    let did::IdentifierType::Idp { idp_identity } = issuer.ty else {
                        bail!("expected issuer did, was {}", issuer);
                    };
                    ensure!(
                        issuer.network == id.network,
                        "issuer and account registration id network not identical"
                    );
                    let statement = take_field_de(&mut value, "statement")?;

                    Self::Account(AccountBasedSubjectClaims {
                        network: id.network,
                        issuer: idp_identity,
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
    /// Account credential registration id for the credential.
    /// Must be used to look up the account credential on chain.
    pub cred_id: CredentialRegistrationID,
}

/// Metadata of an identity based credential.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct IdentityCredentialMetadataV1 {
    /// Issuer of the identity credentials. Must be used to look
    /// up the identity provider keys on chain.
    pub issuer: IpIdentity,
    /// Validity of the credential.
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
/// * data that is part of the verification presentation and credentials but needs to be verified externally: network, credential validity period
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
#[derive(Clone, Debug, Eq, PartialEq, common::Serialize)]
pub struct AccountBasedCredentialV1<C: Curve, AttributeType: Attribute<C::Scalar>> {
    /// Issuer of this credential, the identity provider index on the
    /// relevant network.
    pub issuer: IpIdentity,
    /// Credential subject
    pub subject: AccountCredentialSubject<C, AttributeType>,
    /// Proofs of the credential
    pub proof: ConcordiumZKProof<AccountCredentialProofs<C>>,
}

/// Subject of account based credential
#[derive(Clone, Debug, Eq, PartialEq, common::Serialize)]
pub struct AccountCredentialSubject<C: Curve, AttributeType: Attribute<C::Scalar>> {
    /// Network on which the account credentials exist
    pub network: Network,
    /// Account credentials registration id. Identifies the subject.
    pub cred_id: CredentialRegistrationID,
    /// Proven statements
    pub statements: Vec<AtomicStatementV1<C, AttributeTag, AttributeType>>,
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
pub struct AccountCredentialProofs<C: Curve> {
    /// Proofs of the atomic statements on attributes
    pub statement_proofs: Vec<AtomicProofV1<C>>,
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> AccountBasedCredentialV1<C, AttributeType> {
    /// Metadata for the credential
    pub fn metadata(&self) -> AccountCredentialMetadataV1 {
        let AccountBasedCredentialV1 {
            subject: AccountCredentialSubject { cred_id, .. },
            ..
        } = self;

        AccountCredentialMetadataV1 { cred_id: *cred_id }
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
            issuer,
            ..
        } = self;

        AccountBasedSubjectClaims {
            network: *network,
            issuer: *issuer,
            cred_id: *cred_id,
            statements: statements.clone(),
        }
    }
}

/// Encrypted, ephemeral id for an identity credential. It will have a new value for each time a credential is proven
/// derived from the identity credential (the encryption is a randomized function).
/// The id can be decrypted to IdCredPub by first converting the value to [`IdentityCredentialEphemeralIdData`].
#[derive(Debug, Clone, PartialEq, Eq, common::Serialize)]
pub struct IdentityCredentialEphemeralId(pub Vec<u8>);

/// Encrypted, ephemeral id for an identity credential. The id can be decrypted to IdCredPub by the privacy guardians (anonymity revokers).
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

/// Encrypted, ephemeral id for an identity credential. The id can be decrypted to IdCredPub by the privacy guardians (anonymity revokers).
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
#[derive(Clone, Debug, Eq, PartialEq, common::Serialize)]
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
#[derive(Clone, Debug, Eq, PartialEq, common::Serialize)]
pub struct IdentityCredentialSubject<C: Curve, AttributeType: Attribute<C::Scalar>> {
    /// Network to which the credentials are issued
    pub network: Network,
    /// Ephemeral encrypted id for the credential. This is the subject of the credential.
    ///
    /// Since the id is ephemeral, the identity derived credential is an [unlinkable disclosure](https://www.w3.org/TR/vc-data-model-2.0/#dfn-unlinkable-disclosure)
    pub cred_id: IdentityCredentialEphemeralId,
    /// Proven statements
    pub statements: Vec<AtomicStatementV1<C, AttributeTag, AttributeType>>,
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
    ///
    /// * knowledge of a signature from the identity provider on the attributes
    ///   in `identity_attributes` and on [`IdentityBasedCredentialV1::validity`]
    /// * correctness of the encryption of IdCredPub in [`IdentityCredentialSubject::cred_id`]
    pub identity_attributes_proofs: IdentityAttributesCredentialsProofs<P, C>,
    /// Proofs for the atomic statements based on the attribute commitments
    /// and values in `identity_attributes`
    pub statement_proofs: Vec<AtomicProofV1<C>>,
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
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ConcordiumZKProofVersion {
    #[serde(rename = "ConcordiumZKProofV4")]
    ConcordiumZKProofV4,
}

impl common::Serial for ConcordiumZKProofVersion {
    fn serial<B: Buffer>(&self, out: &mut B) {
        match self {
            Self::ConcordiumZKProofV4 => {
                out.put(&0u8);
            }
        }
    }
}

impl common::Deserial for ConcordiumZKProofVersion {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let tag: u8 = source.get()?;
        Ok(match tag {
            0 => Self::ConcordiumZKProofV4,
            _ => bail!("unsupported ConcordiumZKProofVersion: {}", tag),
        })
    }
}

/// Credential proof. Wraps the actual credential specific proof.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, common::Serialize)]
#[serde(bound(serialize = "T: common::Serial", deserialize = "T: common::Deserial"))]
pub struct ConcordiumZKProof<T: common::Serialize> {
    /// When proof was created
    #[serde(rename = "created")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// The actual proof
    #[serde(
        rename = "proofValue",
        serialize_with = "common::base16_encode",
        deserialize_with = "common::base16_decode"
    )]
    pub proof_value: T,
    /// Version/type of proof
    #[serde(rename = "type")]
    pub proof_version: ConcordiumZKProofVersion,
}

/// Verifiable credential that contains subject claims and proofs of the claims.
/// The subject and claims can be retrieved by calling [`CredentialV1::claims`].
/// To verify the credential, the corresponding public input [`CredentialVerificationMaterial`] is needed.
/// Also, some of the data in [`CredentialMetadataV1`] returned by [`CredentialV1::metadata`] must be verified externally in
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

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: Attribute<C::Scalar>>
    common::Serial for CredentialV1<P, C, AttributeType>
{
    fn serial<B: Buffer>(&self, out: &mut B) {
        match self {
            Self::Account(cred) => {
                out.put(&0u8);
                out.put(cred)
            }
            Self::Identity(cred) => {
                out.put(&1u8);
                out.put(cred)
            }
        }
    }
}

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: Attribute<C::Scalar>>
    common::Deserial for CredentialV1<P, C, AttributeType>
{
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let tag: u8 = source.get()?;
        Ok(match tag {
            0 => {
                let cred = source.get()?;
                Self::Account(cred)
            }
            1 => {
                let cred = source.get()?;
                Self::Identity(cred)
            }
            _ => bail!("unsupported CredentialV1: {}", tag),
        })
    }
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
                    ensure!(
                        issuer.network == subject.network,
                        "issuer and account registration id network not identical"
                    );
                    let proof: ConcordiumZKProof<AccountCredentialProofs<C>> =
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

    /// When credentials were created
    pub fn proof_version(&self) -> ConcordiumZKProofVersion {
        match self {
            CredentialV1::Account(acc) => acc.proof.proof_version,
            CredentialV1::Identity(id) => id.proof.proof_version,
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
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ConcordiumLinkingProofVersion {
    #[serde(rename = "ConcordiumWeakLinkingProofV1")]
    ConcordiumWeakLinkingProofV1,
}

impl common::Serial for ConcordiumLinkingProofVersion {
    fn serial<B: Buffer>(&self, out: &mut B) {
        match self {
            Self::ConcordiumWeakLinkingProofV1 => {
                out.put(&0u8);
            }
        }
    }
}

impl common::Deserial for ConcordiumLinkingProofVersion {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let tag: u8 = source.get()?;
        Ok(match tag {
            0 => Self::ConcordiumWeakLinkingProofV1,
            _ => bail!("unsupported ConcordiumLinkingProofVersion: {}", tag),
        })
    }
}

/// Proof that the credential holder has created the presentation. Currently
/// not used.
#[derive(Clone, Debug, Eq, PartialEq, common::Serialize, serde::Serialize, serde::Deserialize)]
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

/// Verifiable presentation that contains verifiable credentials each
/// consisting of subject claims and proofs of them.
/// It is the response to proving a [`RequestV1`] with [`RequestV1::prove`].
/// To verify the presentation, use [`PresentationV1::verify`].
#[derive(Debug, Clone, PartialEq, Eq, common::Serialize)]
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
    pub context: ContextInformation,
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
        map.serialize_entry("context", &self.context)?;
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

            let context = take_field_de(&mut value, "context")?;
            let credential_statements = take_field_de(&mut value, "subjectClaims")?;

            Ok(Self {
                context,
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
    /// Issuer of the credential
    pub issuer: IpIdentity,
    /// Commitments to attribute values. Are part of the on-chain account credentials.
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
    VerificationMaterialMismatch,
    #[error("the credential was not valid (index {0})")]
    InvalidCredential(usize),
}

/// The types of statements that can be used in subject claims
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize, Eq)]
#[serde(bound(
    serialize = "C: Curve, AttributeType: Attribute<C::Scalar> + serde::Serialize, TagType: \
                 serde::Serialize",
    deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + serde::Deserialize<'de>, \
                   TagType: serde::Deserialize<'de>"
))]
#[serde(tag = "type")]
pub enum AtomicStatementV1<
    C: Curve,
    TagType: common::Serialize,
    AttributeType: Attribute<C::Scalar>,
> {
    /// The atomic statement stating that an attribute is equal to a public value
    AttributeValue(AttributeValueStatement<C, TagType, AttributeType>),
    /// The atomic statement stating that an attribute is in a range.
    AttributeInRange(AttributeInRangeStatement<C, TagType, AttributeType>),
    /// The atomic statement stating that an attribute is in a set.
    AttributeInSet(AttributeInSetStatement<C, TagType, AttributeType>),
    /// The atomic statement stating that an attribute is not in a set.
    AttributeNotInSet(AttributeNotInSetStatement<C, TagType, AttributeType>),
}

impl<C: Curve, TagType: common::Serialize + Copy, AttributeType: Attribute<C::Scalar>>
    AtomicStatementV1<C, TagType, AttributeType>
{
    /// Attribute to which this statement applies.
    pub fn attribute(&self) -> TagType {
        match self {
            Self::AttributeValue(statement) => statement.attribute_tag,
            Self::AttributeInRange(statement) => statement.attribute_tag,
            Self::AttributeInSet(statement) => statement.attribute_tag,
            Self::AttributeNotInSet(statement) => statement.attribute_tag,
        }
    }
}

impl<C: Curve, TagType: common::Serialize, AttributeType: Attribute<C::Scalar>> common::Serial
    for AtomicStatementV1<C, TagType, AttributeType>
{
    fn serial<B: Buffer>(&self, out: &mut B) {
        match self {
            Self::AttributeValue(statement) => {
                0u8.serial(out);
                statement.serial(out);
            }
            Self::AttributeInRange(statement) => {
                1u8.serial(out);
                statement.serial(out);
            }
            Self::AttributeInSet(statement) => {
                2u8.serial(out);
                statement.serial(out);
            }
            Self::AttributeNotInSet(statement) => {
                3u8.serial(out);
                statement.serial(out);
            }
        }
    }
}

impl<C: Curve, TagType: common::Serialize, AttributeType: Attribute<C::Scalar>> common::Deserial
    for AtomicStatementV1<C, TagType, AttributeType>
{
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        match u8::deserial(source)? {
            0u8 => {
                let statement = source.get()?;
                Ok(Self::AttributeValue(statement))
            }
            1u8 => {
                let statement = source.get()?;
                Ok(Self::AttributeInRange(statement))
            }
            2u8 => {
                let statement = source.get()?;
                Ok(Self::AttributeInSet(statement))
            }
            3u8 => {
                let statement = source.get()?;
                Ok(Self::AttributeNotInSet(statement))
            }
            n => anyhow::bail!("Unknown statement tag: {}.", n),
        }
    }
}

/// Proof of a [`AtomicStatementV1`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum AtomicProofV1<C: Curve> {
    /// A proof that an attribute is equal to a public value
    AttributeValue(AttributeValueProof<C>),
    /// A proof that an attribute is equal to a public value but where
    /// the value is already revealed as part of composed proofs
    AttributeValueAlreadyRevealed,
    /// A proof that an attribute is in a range
    AttributeInRange(RangeProof<C>),
    /// A proof that an attribute is in a set
    AttributeInSet(SetMembershipProof<C>),
    /// A proof that an attribute is not in a set
    AttributeNotInSet(SetNonMembershipProof<C>),
}

impl<C: Curve> common::Serial for AtomicProofV1<C> {
    fn serial<B: Buffer>(&self, out: &mut B) {
        match self {
            Self::AttributeValue(proof) => {
                0u8.serial(out);
                proof.serial(out);
            }
            Self::AttributeValueAlreadyRevealed => {
                1u8.serial(out);
            }
            Self::AttributeInRange(proof) => {
                2u8.serial(out);
                proof.serial(out);
            }
            Self::AttributeInSet(proof) => {
                3u8.serial(out);
                proof.serial(out);
            }
            Self::AttributeNotInSet(proof) => {
                4u8.serial(out);
                proof.serial(out);
            }
        }
    }
}

impl<C: Curve> common::Deserial for AtomicProofV1<C> {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        match u8::deserial(source)? {
            0u8 => {
                let proof = source.get()?;
                Ok(Self::AttributeValue(proof))
            }
            1u8 => Ok(Self::AttributeValueAlreadyRevealed),
            2u8 => {
                let proof = source.get()?;
                Ok(Self::AttributeInRange(proof))
            }
            3u8 => {
                let proof = source.get()?;
                Ok(Self::AttributeInSet(proof))
            }
            4u8 => {
                let proof = source.get()?;
                Ok(Self::AttributeNotInSet(proof))
            }
            n => anyhow::bail!("Unknown proof type tag: {}", n),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elgamal::Cipher;
    use crate::id::constants::{ArCurve, AttributeKind, IpPairing};
    use crate::id::id_proof_types::{
        AttributeInRangeStatement, AttributeInSetStatement, AttributeNotInSetStatement,
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
            issuer: acc_cred_fixture.issuer,
            statements: vec![
                AtomicStatementV1::AttributeInRange(AttributeInRangeStatement {
                    attribute_tag: 3.into(),
                    lower: Web3IdAttribute::Numeric(80),
                    upper: Web3IdAttribute::Numeric(1237),
                    _phantom: PhantomData,
                }),
                AtomicStatementV1::AttributeInSet(AttributeInSetStatement {
                    attribute_tag: 2.into(),
                    set: [
                        Web3IdAttribute::String(AttributeKind::try_new("ff".into()).unwrap()),
                        Web3IdAttribute::String(AttributeKind::try_new("aa".into()).unwrap()),
                        Web3IdAttribute::String(AttributeKind::try_new("zz".into()).unwrap()),
                    ]
                    .into_iter()
                    .collect(),
                    _phantom: PhantomData,
                }),
                AtomicStatementV1::AttributeNotInSet(AttributeNotInSetStatement {
                    attribute_tag: 1.into(),
                    set: [
                        Web3IdAttribute::String(AttributeKind::try_new("ff".into()).unwrap()),
                        Web3IdAttribute::String(AttributeKind::try_new("aa".into()).unwrap()),
                        Web3IdAttribute::String(AttributeKind::try_new("zz".into()).unwrap()),
                    ]
                    .into_iter()
                    .collect(),
                    _phantom: PhantomData,
                }),
                AtomicStatementV1::AttributeInRange(AttributeInRangeStatement {
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
                AtomicStatementV1::AttributeValue(AttributeValueStatement {
                    attribute_tag: AttributeTag(5).to_string().parse().unwrap(),
                    attribute_value: Web3IdAttribute::String(
                        AttributeKind::try_new("testvalue".into()).unwrap(),
                    ),
                    _phantom: Default::default(),
                }),
            ],
        })];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            context: challenge,
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
      "issuer": "did:ccd:testnet:idp:17",
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
            "type": "AttributeValue",
            "attributeTag": "nationality",
            "attributeValue": "testvalue"
          }
        ]
      },
      "issuer": "did:ccd:testnet:idp:17",
      "proof": {
        "created": "2023-08-28T23:12:15Z",
        "proofValue": "000000000000000502b12365d42dbcdda54216b524d94eda74809018b8179d90c747829da5d24df4b2d835d7f77879cf52d5b1809564c5ec49990998db469e5c04553de3f787a3998d660204fe2dd1033a310bfc06ab8a9e5426ff90fdaf554ac11e96bbf18b1e1da88db85b1fecf20f66e9a4cca89ca261430d9a775de164636011003d72d1d522dae8488fb5ff2b348e8f4f4f68d7bc33e38a29abf47db4d15f9d1b703efff0ed234a668d779cad8e592041828446206bb98c48e23e06684405903c6cd14e06f4c4389c1954fd8c8be55052680025ff77e060416cea8d8a9cd512da8d6a4d3651092557b7ec885d994d32e775174bebb4f61630fdd1192dfa1cd0fe0b76cbdbc167571a3b82445887427d46f406f2e8139e93bd8950368cb74d9219fcf3cc195b7400000007a6bbc0b7dedae5d3c9b4096410d050e926f6aaa65b63d6e903bdf533762b3f0eab62286575e4261a5adcaf800aef0a3394b567034287af3f6fa990315e29ab084ccefeca9ef5a185a64170b169fd3c90d3f70ce1f0df4b1f2a8a88efefcf2ac9831d560dd6c8328b470d21163a8fc3174a2456e76bb0672b85fd8d14ee08b257e6b54df0c9bd2142ce9a176af53c3b6794aeacbdb1b40f22c4ae645b10b218a5cc6d50dbf7b374e706de7b6ec9faf72d89e6e91b3383b1ab3b6d2d5be95af2d192eddb29452b78545944d23b578dc4a364cd626e57fffc2e4e284e67c4c58d4a58029ad2fe82a74c4f79ef643e3d417493b5a25ffc04b8968cf6ad43a6ff2e0bdad32cd83fc26f958177add5a5dc61dfda8e3c95f17ebef3d0d364c2ba4f55eeb7e5f7beff294a7df714d83a5cbbf665b711877e4497941d5eb99b4ee4ddbcb0b22d04df8a2290d1c29a4d2b559f28308ff961fad1c524478e5fce35f2b05b64e3d36ddf55af7b269436ae1e06cb2b106af4d3465e171f8b2f8d5c7de50cb9068b186360d490384d75fedb0bdc6e7349ff43f86b6ac6a3578281aca11c1c15ee191da64f61e9a28cad750167ad86b781b7d204a1f241d65006c6ba2de1bbbe35d00d55893780c487e5e772c5a12f20b61ec355d75fedb5969096200f7d1afc5b805db4b2b001629af1cb3f6aaa3abef758c282261264b36525e7d16a76ecc09070e9a0ec300b679bd773137b81335fb792609ae55831fb97c96449e29a438ec9f60e9c6ffdebe8f3b168e33b51e3cec726067ddd143537f21713968f8dbb04c796b66f80e11f416c7db00b43d7272f824ea5e5059579e746c032310cbe801ecb5f04b23346926141ee8b79e2e4d522bd93d263844569fdb5a5f29e522c31868408a82b29d6b0392c1ff173431155190c630145f1c9ad989060c456e7979b32b46ea6e831a80f9d4bdd4b3bb5dfa32cac82415a5258a1d3528eddf116378d51c449b7071b1902c289f468d5212aabb6fea40a3d4e9cddd9444e00b1b36369bb6c03b39554bf77b9ad30ef725df82bdb6c5456adf9ac3187ffbeaab1b4ce68782829850f10182deb13eaa94edd3640768224a178b8bac224d12711c7d3bec925db4da9bd1424db872757a1f2e10c9dac40483a69972504e5d69163a9f13c5dc8fc60b1ae7e6d38e19aa6374b3db2d0ed6918fac19a79981df368bb842f5b3e88ed9f88af521c771e336233d35dab81a3ef02b12475047f017ddc597aa597f49dadc9cbb0c72cb50b08c7e3a155f35b7879d64ea48923d6a550399e33a167dc783c7f6ced1b69d4180cca76304febb32c320703294b174da590c3607aa1651f0a88573997ddc59deb816d401a5130517c7a81f1e92cd4e5511bbdc15dd8762a9d285616c3a0b58c0ed867cc74128f52006aeb802f1a07237c66d8c4feef00fd2b1ae400000002a83a469f8f002dc2bf11e8c1b65e2a17b1f398c6806744425e444bffeafc34128320d8a061e226b6d7541ee0e0466327b14b41d7d8142aa18f5b3e734ca8b07cbe0d024a0f648e4db512ee56f4e7ef71d08b1fe3985db75d0beb6e1cc9b8c428971e9c0858baed4e935768dd2201aa82cfbf1692770dc92c7558f23fd46f5d050cd11a1cb476380011fca121f1ce23b9b43e16948af3b3fe4c8a15d4ff935476b23a67f14b0d2ee19a9c48ab89228be2772d63a50fe87fb9ce56dbf43f261b8a0de90b8f7cf375db6016b9b3fa0af14594312df176ea4070eae321a8b22f573c7183f0d3655b15dda99339fd9caa66e9134861e6504c7cc8188c19d1756383ec048b69df7282cd3234e4423e85d15c09d49fc2005e869a4876fec01369c3b0ec0ae6f710797b4e5294a7fdf72c05341b6887da98066400436af27e739c140e3a481df2845cd78df942a2c0fb01429d5b04cd96b18c0b2bbf764b533a6f095edbeaa506a369ea1e6bf58a89075f51344b7db1e4899a12383642a04091aaaef9fcf49281d22d23faca75c7de65be46fb3ae787822af473431d3b611a1aa63051cf37c2a5cae78b26e6e66e8994d62a5b1098bf61306a3418422199a614e4b09269953ec7d6cd85b83e0d4bb6d5370506f505e0e255e3fc86321938647e5638d47a3f711431d0e050a141c2d7a9ff7473515d24fcf7d49df7c62c7a311de1ba74e1eb017f29dec74a0c4b6c1033754c4cec0c45c85e99c62e654d0b6ed8087e811b560000000286384013b18b78f466a96c266b36cd1b3ae84b6746e1cddb521d5248c62eac29c1f7faddfe5094ce8fd5b457d65f0fc18c018bcac96884e2907c390ee2ecbe057336d4c1bd0c6edeba8340910f5ed88b1169283ff98cfecb016af2476595f835806f969e3a7b594d41af1abf47619d929ca35323890888d58febdb488ce9a2a170dcdc0222a6b33d1ce367702a5e6f6e84bb20150993878b7e5023bf51c427b7bf8cfb7b504e5e0258b25c7fe094a79dd4051c2807f480a36bf6d38795526a4f02ee00fa5456eac9e78022d1593bba9d6f4b09c064558cc5d433b81346c7b4f60c731be525a641825de736e0ea4776de5cbbe0c4d8c5b9c080b8160a39f868e702b2a44460fcbf28d7ce0fce6c677113a88b88ec272d3cfac24d33afc47b6fa15259af84fa6543ef673cbd18a44d47420c8c53d7eaf9272dfa62fadd8d118c2055480b6494a67b0346c9fa0b2ba2cba9c0591224a2ed7b399ea35b89111a53059c862afeedd50d8b65c822e69a213b0fc8f2e4188289ebbc5828ff043f0365453989208210c97536a7e9ee865af8872688935b3a9616c8802e3482a4074d0b759e11d052195453ef95945cd0557916d80a9eda70f61ffc653ce99d66caf1cdf7f0688f3bd5adc04f23552b0ef780e6c804f2738b60c3e812cc36c9c02484a47b831c0ff050e1513f54ba97372b1b8b48a278a56d5088ef09d2f24a6c9b95697c1406e4718f3bc71070191eaff6f89ce06c9aa5fedaeb0dabbbd4da46eb22a74ae200000007a5df6c977b2cceed7dc03296768edbe510f0674341d6732cd366a56b13469408ca9a94c1bd50f77074e351ebd8ec6a9485fa5193e1d6574ed673a8ea871fcf9621b0a67f370f56f882c062360c0f4038c1afb1d25dfb554f03b7757a71e61f21ab3baa7c7ac3d30ef2d5328fff37fb6658052001b90bf00000d1b553d8fe988342bee11e6cd1423131c019a9766272069248846381908bbefcf3129f8dbc3cf848ce7fa2e8e7d90c51e03634cf23574ecf51b9efb3b5c244bbbaf8f136c2e917874397a528529aa95cd3076f0ad4fe1751d25e5351dc4fbe28efabae297827a47f902d822b561304db940dfec34db5778e00039f96cb100e76c29cd3b71733f139054e8a39df0d5644285ac93486a2374ecea315f961f59a9c9f6d18fce437e286e11cc988e03ba537773e37fee3bd4a222bcc4361743621916bfd8e982b5957ce2f1dedc3e5fdedea8ae8574ef10e2ab24f53383813f54832fc7b3e79bc7a82c46b4b66ff5aa24086a59041ca4d9db7bff59c37820129d9f3df31007c17d1e48e63b20c1b9ca5106b3baac41a29318810fa8fed1e954c2cd4793db870fed9b17350aeea535ed51ff96fff8c1d7b67518a913efebe3dc3eaac543787be142064eb2fa0559b9f4e570d297ecf1d09bb704595217a5643016e52df4e1c20c0be398ef9832c8343626967d7f81eadd5d81d27a208ed586ef24d69ce7101e4a8384fc5a3cd25716c550c73a4b079d297b507a4ca1d6099346c31b4ade498589f40a04d072e6e9a664e07c9165eb8bb2d1f7568c00c09e4421cf5da5a466684df2e3987f692dff494949916f3bde458fd16f3ef4ddf09563b93b239ea442430d449c27a21215b5dba2930237640088c5d176cb3e5941d5f0a56982b2b05f35503cfc007b730475f28f4241ac28c5f955723f9d92124ab4aab89d198444db0de63fc100df9dab06a3e0591a5096877b581e7304278af7fe8778c13df4f0bc72e0801e663f075db89c119b8639b836a3d6026ec7610ed05fc405228c03e2bec4d60d61b00fee62d95135d4f7f9b06628d14597d9045d70e3d27d9ab7847b71e968b3639f70b5faf58f07543f340c7b5a6a12542209795ae19544a3e32bd966df630815b60",
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
  "issuer": 17,
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
                AtomicStatementV1::AttributeInRange(AttributeInRangeStatement {
                    attribute_tag: 3.into(),
                    lower: Web3IdAttribute::Numeric(80),
                    upper: Web3IdAttribute::Numeric(1237),
                    _phantom: PhantomData,
                }),
                AtomicStatementV1::AttributeInSet(AttributeInSetStatement {
                    attribute_tag: 2.into(),
                    set: [
                        Web3IdAttribute::String(AttributeKind::try_new("ff".into()).unwrap()),
                        Web3IdAttribute::String(AttributeKind::try_new("aa".into()).unwrap()),
                        Web3IdAttribute::String(AttributeKind::try_new("zz".into()).unwrap()),
                    ]
                    .into_iter()
                    .collect(),
                    _phantom: PhantomData,
                }),
                AtomicStatementV1::AttributeNotInSet(AttributeNotInSetStatement {
                    attribute_tag: 1.into(),
                    set: [
                        Web3IdAttribute::String(AttributeKind::try_new("ff".into()).unwrap()),
                        Web3IdAttribute::String(AttributeKind::try_new("aa".into()).unwrap()),
                        Web3IdAttribute::String(AttributeKind::try_new("zz".into()).unwrap()),
                    ]
                    .into_iter()
                    .collect(),
                    _phantom: PhantomData,
                }),
                AtomicStatementV1::AttributeInRange(AttributeInRangeStatement {
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
                AtomicStatementV1::AttributeValue(AttributeValueStatement {
                    attribute_tag: AttributeTag(5).to_string().parse().unwrap(),
                    attribute_value: Web3IdAttribute::String(
                        AttributeKind::try_new("testvalue".into()).unwrap(),
                    ),
                    _phantom: Default::default(),
                }),
            ],
        })];

        let request = RequestV1::<ArCurve, Web3IdAttribute> {
            context: challenge,
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
          "type": "AttributeValue",
          "attributeTag": "nationality",
          "attributeValue": "testvalue"
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
        "proofValue": "0000000000000006010098ad4f48bcd0cf5440853e520858603f16058ee0fc1afdc3efe98abe98771e23c000d19119c28d704a5916929f66f2a30200abb05a0ff79b3b06f912f0ec642268d3a1ad1cdf4f050ab7d55c795aa1ab771f4be29f29134e0d7709566f9b2468805f03009158599821c271588f24e92db7ca30197ec5b0c901efaadd34cca707e56b9aab1a7f14e329816e2acf4d07a7edf1bd6b0400af07a1ba7a22bcb1602114921a48fa966a821354cd0dd63a87ce018caccc50b56f2c9f55a062cdc423657aa5cec8a4c9050100097465737476616c75650602aef4be258f8baca0ee44affd36bc9ca6299cc811ac6cb77d10792ff546153d6a84c0c0e030b131ed29111911794174859966f6ba8cafaf228cb921351c2cbc84358c0fa946ca862f8e30d920e46397bf96b56f50b66ae9c93953dc24de2904640000000000000004a547c8619f3ff2670efbefb21281e459b7cc9766c4f377f78e9f97e2c50569a8dcb155f2a502e936d2cb6ef1a73e92af9916e6353b7127d55bb525cb18074b5ec130463e03a4eda583b05c2d63db40a08ab8bf05f930ec234cc2f788d5f5bfbeab3e4881918ce964ffd55483219edd435ac865286bfd313cd834aabfa8061d2ae173cbe4b59ab2bda78faa4c2c937afba80d7fba0822579ac0ef6915f4820f968a74f00ff5ab74e90b0a7bcb2b92093a5e94a54aea1d48ffd1e5bb3fb48069bc022d40f10bd9f0db027ee76e5d78722b22605a1f420c0d8923f384fd2e9df4d500000005000000014996e6a8d95d738baf684228c059ffda43b6a801240c467ff648b24c1e32a8fa25e6348ea46cfe7a6134f6754367715ab1fa97f963720164fd4af47882ea5f5c68917936ca63783c8e7252b3add6d60427580f639caec877eaf62af847e260b0000000022edfd6a9b5f6cb325c2ddafc2f37328768062360b94ff89b795eefc2bdd8b8c7566f982f3189e2158c9932e6c2236beae9c4a1767de64235066fc668c43590a466a5e08b9552ff74c7850795edfb41de40a8183b3ae27e25e14a851192492649000000035477e4693d1f65ba2c6d911de408be4b4164ae853b9d944859a7125c7f80c8b6737b58adf891170ac056de0907671899121fede2fd7cbcd6c266fef9d011baf65e6529fb326268ad4394ac4bdcd594901d2d649c9633ed273d47472550a6ed1d00000004636f324e0c8d9958f960f621ba0bdb0a12c2fdac465fab6f3d6b0219edf20bda34bcc475e9e940e5f2c166aab81bb46a24fe84a7c150f60f19b25a9aa26b02960fb8204657da982ecc80099255157f127037fc1d01bae5e751dfd1b568d5d3b2000000055252326e4bd286ff449e1e4191ad5bfd3834498357850252b2efdf71e5a195801b0b139f690a241db78ffae798e90adf5468ed485dd47c396dafdbf95846ab3f1dfc26f4044279839a74ef3d99d3e683ddfd948707a841052beed7fa59d3cfe10a85e4f590f94aeec5694aa34ce7809e6409635c3dcc06c48e2b6eb7c88e805b0000000c0044de5e492f26cdc8d9dd7353c8f4561776db5cf1e9e56765f8a27325bea23c7c6e93ee0e96b86044e30a334d6a3574f1eb257fbc13e38045de829d08e668e1760233b357f18e2fb13b681affb3100a76389289b0a672fb4c018b496086e907a8d9010101024a3c3d379c549361b01f1da35dc354171e8b08e37cde8b26708a7d0a74a1c475001607576a587bc3724829d37a211c4e7ac685f5d2ff8d183878c47761fa207a2772c92a29d9723c60fcf02a5f3ee44f16c8d719ef0ff7306017e8abcca0ac43da002c1306c3df6c321d1827b482e5bdd43d9ae0ebda13ee87f8ffce45b9280974d30da67ed93028333a98441ec283b84ef993ba16ee3f63abeb6913cb84c6087e520031d913edbe710a6ef608a7496ddb24b62af6dc53b0c400515094a102dc34ba7e5101b14654477c70600fc619c536a55689a34483d87a607c616b8e4a7f588b1c0020de9f2cbea7cb077e1dc06c4f2f3286792ff9ab865d04a264699b063387d3565a810470a1a3f0b94ed0a313bf2558035cb562112fe9d4ce3db05035da60dfb401023ecf78fe04bea07742a2b68c1dfc848ced58d50cc72e3aa9417456c137f07042000000000000000502803596b4ba5ea05b1fea2b78e292f935d621453cffcd207e10f3072b2813ca3e963cebf05b19cd82da4bd5aad1dcc7fda1492d7ffc8f532bc4b37e9bf4753b7ae6b8f08e05a851052fc6ac7617ce68293678747d11f9a508bab6f7a60edde9c4975a76ced40574074001091721440b1d62252454c2b26494f5014ef4b5f0adaab23eea032dabcf7fc274915ed26a38ea985468e8f27f81f378870fdf0c9fa880b75d301d54dead22ebe69d98305b8bcb1825f77084a3fe794ef69ae07ca2f40c327c3b8055a8dc2823524df825d4748e84c743856120bf5bc77826884412154e26cf2b601c2b869084806c5e670919b8cb8d6ea8f7a8fd14096f7dc9765bcd0d5a04e5770764de9318b0f4f5fd1343b30f0954656423cbb994da605956acc5e30000000792698ceb941b32e6ff12451a75d1eb465ca0710879a4d67ecf75ff5e614605b7284f07109a658007dd94b499322649a68af4e7b7ad848fbc3e2dfe248fe846d0836279a0a8045909516fa2de9ce9d456e68278372af302a891a3c138596bb369abb626f0e5ccd6ceb9d6f7f0bd979a37afdeff02c294ad7db9ad1335f0d532027bf7fc78c7fe3d1025bbd9b754e8ce068ef1e251727d48cb25040091f05b327ac2ec733c1cb349f6aa20c00f644a3f9c84df72112b4f4b247126df77eb27933db078a098bc904d01ce5de1be0fdb9d8796b3d427c7a89d7ace44209339c5577416dff5094858771314c6dcb8562f7d17a30c84630530510bff914ff0398b4616171386c23145d4cff3e4a0f698715bd68dbe2233b851ee49c17c0b7dc9b6f5f4ae461de98c4d582c8be6f490e75a0c2b1a61dfca366e86ca6ed131b93d43c93292f6182cf3d86e98d0baf613630e7a34a54dcba10f680b641579909c138223182443f71f110d7eb97d0bc99c795d95f28611ddf484208c3aa9763b517024d32faaea07a4343e4fa9b72ffb951fddd5e811def887a8d92e89c574d7820ed46df10da13e63ec1223d2bf1ee4b8f6cd353eae032fd8b3f6f886d5feb3032ac2c6cef1f03513e04646ffdbd0be6597f674bfcbce9f16127b43aa49f4e6853c56e2cd96c75aab089f07d04515e52a097c1b08c75ddb30315af1d65aebd00585c3818e7587baa5b11b80a0fd5fd2e0b7b473c9ad112a3168aadaf83ba4d94ad7e6b47c639684d634fe5ae59fc1f9e6741e924bdc8ed49c2a72bf1e7869fff80d17a7a0adacbf2123fbed51683d0897fd76310f3896381f47c675764b6475a027f92a0b89d863218dce9b3ac48524b3d1def4f0877aeab34415a27e33d305e9ae39dc8c918125498ab16932378e9f739bd2e0c4866265ff9f98c7b562000c762254336c3ac576cdfd96936c3f32ded9523594401d0ad2f2232a01b9c8443395180f1ec80a119e63e0bf631cb93a9db4ee6a2a29e06f520835f7af238e1c8cd873bef1e4039035240c33b7dec4981aa53e914f67ac932328b31f3fc4d0aac1c19a4da4dab1b525a63008d0e40b86076a1b7e9f0f219955c76798ae8d5131eee35e9900c5cdc8b58badd7022044521d7ad239a91bb2ae1a02fc61472f7d3629d14070641a1e86c2ef60ae3a42de23a15550c75b135a7be766fc38a2554377afc4892fef23e54ad59b72bfa590493d3a0e6d0c3692f9b12c28a4c2fcbfc8331381867935bdbdbe83220fe2330b5024ffdaeb37eb9a4f8dc8505ff846ce16a24ad0f36b8145591838c8cd056b4fa56d76e3f0d3c04cd58a13fc953ac12f292817ad4c1b46d62e372b5a5f8c7f3a4dcb29beb03b75d7b9d0a4a463e37f00da224c7fde6d34c3d53f34ac41a47b698e9b381d0debc448c465c594d9cf9c42e8cbce7e0e03091000000000028f08b690d86821cdcd517648214e22b5b0b73e2c7f82a3ccae933d61bc0e28fc69b047aba5cc6b8e9e6f4578e02924db920fdd2cbc3f1171c98169f4fd5676b77f210f9ae5e949afab54b2e52137538906ea05c5fc5e0ca989eb081a3ba9285ea611a9d69bbefb08d3142a7523a3ca91961b4f6deaa87286a4fe776607572b5db7e6ea488c5b9007731663b4537b584983937bfa8ec12bc8f6b1ec8185cb2863f7dc15f82f50978301f7441901d2921799af71fbf5f3a83162ddaed844b5647970b4bf4cb7d8bae88457f65c2e5f09b71b6585303e4783642c20949423fba406002407e6a58cd57836650e76df878926d0b6315f4c4329385566667701fe7f820487cbd29bfc97194ed8868ed4e458c7b2bf8ab6f04efee532502cf588c4f26b9b2830baa635c56857be5fd6803fd35d508881bd7cf3b5872ff84640384e2576bd93d4d86fdafcba2df3f29036491573031ede2ddb09dd092ad890a68f07876aeeb5ed24f1e21e96aa8f81d1b57f7963fdb0d617a6c302365781dcbe1628103ba3e9fb7c05ec5064aa5f518a2dd54deb3bb6547660749326b8e7c23931f938d1f94b2b199330c7cf4e21caaf3586b5ce3f56d5a1a06a78729f9e8b7838eef1f95828f2e1f46ccd7642fae51f13d2b0d6c55b328e0d6bae6355d412db989f82a3fa47b167da18c385588da0d8b2715d09c06cb2e03a1bccf8e112893d054c79b8d850d3c90fc8866865a2f85a8b3f64d9dfad1381b1bc0653335ac741925dccaac600000002895dca7ed412bae0cb70d758773dcfbb2254c95be80f230ceb3a73883bd6b6220cff45b7e9d058da58071acb8a32767b99a869379b6095f4e2b7ddecbd8a4d17a094f9681a4345c35c87dd86cba4074e56dae9e1ddadb7edfa248058f12f8f0c965d922130d696027a12fdfd06b1c39c7fba1875b39f751be361ccf330dfcdfa68623eb78747bc06f9ac45b812d5d313abfbfabdb4411220d1e78b5384749bb890b3f220139e0200315d516b3fb2e156b2a5c1c2a081a3e67eb6e8fc97be9bb4439a9eaadaab8e29db023baa98322d0d0e7f06efd708b5c7f8846e799e8607a20242d81c399a6571f8ea9c203a534ebfc6bf416540b8ad6a2c82e66dd9d2c0c502b387e119ec10c4a8963ee52710d75c21710881bae7fb5a8595fd43a9156419f8080891e50139bd4af14f1ba25ebe0152b5e83d115be493372e147742d8bfe3a8269e8ecd27ec055a11055d5405192cda8c8db528f06b120fc2e3f47089897411aaae9e0b0179b2e09afee8e5d56ea05b85694d71186f6d6dba1465c19cfc41f55751c1c7e3e071f0a97733f2ad4a8d7eb5038bb97411c01f77d451d483611c939f1910f388110198c69a2efdce02ad2334a1c39958bd66abb940ef1f42143a65010e383128f291e962c579ec7cb9f24f373554e84ce1a21f459d5ea4ab1a41ec733322f9b95611de75450bf415e60dc15f8d33fdb61f14d9c73c92cd6ace0943403768e8947e8122b2cbbc663a5373940daf22b914730c980c66e87e444db56f000000078c1751517b7f76514a5ea7af097099c03cc64d9416494d5a9f448c2615903650ab7c8c2358619073d84f04034ba7f768b62b4825d8a12f4c0378b2b271eb05f8b3cff514ebdae3b6de637539305437c2bc0bc6c2649961a1d22295035d07f460863a3d0467f01e79c4199bf3dd73a57a58315be6b4e465e43fe66e82dc933ee622598672fbd0c5bae12d8e187c7a6dc8a2c4b3dc57040a759e23594760d76c8d6655c0860e4a1187e89d7451b1507bc5e0ff3eeb28577af943a44afb61d96eca898cb8417551edffc189fe2d24e83f554206c397b80153044e45be32aef5b46deff4625d1d316338bf3521ee32ef50388a067b5c0972ca68797b98b337c09589c307d5adfac00a524ccca6d8d5450a0eea765673fbea3956aa0edf0dc0a2c7318dd61540865a408715c148e406489f7e56d953af3df90585b2dd12e99a4a6878009001b62f9fa0a023041fd77f41be2da2ed746a07bb3fa3864ab5e76be4f98d480fd97280735eb9f44c6bb0b1b02e2ee8c9d1c71c68de3325e6d14f44ef98b68b50ddef96b312c9a17296ecf837591659252f25670d9744c7334abca978eab4d7c40276b876ca682c2c06ba2809082d842c021fadb934bff19025c4dc1d80f6a9fac3cf59a7209c1d73113b87b8d34a8d618a5534db6fbc4492cfb6439a2c088cbbd44febb15f56e1d119bbf1e2bd108325711d56938eeffce12ecc900059822448666fd380701afb94887ff3a73d5ab6e3a9614ec319bb579d02de414db8a02d54f80928255dafc2b7833159aab87daffd5e143e7e939ec2c05496573f7de1aa46492cc29053e0ab0d7a2b524b3cade5e2ee0fbb0aa8f0b340cf139321230da9d50df0e36794ff03927ebdfaeb5b4c88612f9a7cb6660d8a088433ec92cd24ad06e4bb75885b0b7103d524f4f6b080be40484b9138278d95feb40af1c52cbb29f7623675d081c0930866586fee0476a9f21bffe406e3265413f792e0d464e9476becd32bb6af4856aaf4dfdbd6f1a2fea4cbe6df332e324f091fa74e7d9cdf01",
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
        Vec<AtomicStatementV1<ArCurve, TagType, Web3IdAttribute>>,
        BTreeMap<TagType, Web3IdAttribute>,
    )
    where
        <TagType as FromStr>::Err: Debug,
    {
        let statements = vec![
            AtomicStatementV1::AttributeInSet(AttributeInSetStatement {
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
            AtomicStatementV1::AttributeNotInSet(AttributeNotInSetStatement {
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
            AtomicStatementV1::AttributeInRange(AttributeInRangeStatement {
                attribute_tag: AttributeTag(3).to_string().parse().unwrap(),
                lower: Web3IdAttribute::Numeric(80),
                upper: Web3IdAttribute::Numeric(1237),
                _phantom: PhantomData,
            }),
            AtomicStatementV1::AttributeInRange(AttributeInRangeStatement {
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
            AtomicStatementV1::AttributeValue(AttributeValueStatement {
                attribute_tag: AttributeTag(5).to_string().parse().unwrap(),
                attribute_value: Web3IdAttribute::String(
                    AttributeKind::try_new("testvalue".into()).unwrap(),
                ),
                _phantom: Default::default(),
            }),
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
        pub issuer: IpIdentity,
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

        let issuer = IpIdentity::from(17u32);

        let commitment_inputs =
            OwnedCredentialProofPrivateInputs::Account(OwnedAccountCredentialProofPrivateInputs {
                attribute_values: attrs,
                attribute_randomness: attr_rand,
                issuer,
            });

        let credential_inputs =
            CredentialVerificationMaterial::Account(AccountCredentialVerificationMaterial {
                issuer,
                attribute_commitments: attr_cmm,
            });

        AccountCredentialsFixture {
            private_inputs: commitment_inputs,
            issuer,
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
