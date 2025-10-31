//! Functionality related to constructing and verifying Web3ID proofs.
//!
//! The main entrypoints in this module are the [`verify`](Presentation::verify)
//! function for verifying [`Presentation`]s in the context of given public
//! data, and the [`prove`](Request::prove) function for constructing a proof.

pub mod did;
mod proofs;
pub mod v1;

#[cfg(test)]
mod test;

use crate::id::types::{
    ArInfos, CredentialValidity, HasIdentityObjectFields, IdObjectUseData, IdentityObjectV1,
    IpContextOnly, IpInfo,
};
use crate::{
    base::CredentialRegistrationID,
    cis4_types::IssuerKey,
    common,
    common::{base16_decode_string, base16_encode_string},
    curve_arithmetic::Curve,
    id::{
        constants::{ArCurve, AttributeKind},
        id_proof_types::{AtomicProof, AtomicStatement},
        types::{Attribute, AttributeTag, GlobalContext, IpIdentity},
    },
    pedersen_commitment,
};
use concordium_contracts_common::{
    hashes::HashBytes, ContractAddress, OwnedEntrypointName, OwnedParameter, Timestamp,
};

use crate::web3id::did::{IdentifierType, Method, Network};

use crate::common::{SerdeDeserialize, SerdeSerialize};
use crate::curve_arithmetic::Pairing;
use serde::de::DeserializeOwned;
use serde::{Deserializer, Serializer};
use std::{
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
    str::FromStr,
};

/// Domain separation string used when the issuer signs the commitments.
pub const COMMITMENT_SIGNATURE_DOMAIN_STRING: &[u8] = b"WEB3ID:COMMITMENTS";

/// Domain separation string used when signing the revoke transaction
/// using the credential secret key.
pub const REVOKE_DOMAIN_STRING: &[u8] = b"WEB3ID:REVOKE";

/// Domain separation string used when signing the linking proof using
/// the credential secret key.
pub const LINKING_DOMAIN_STRING: &[u8] = b"WEB3ID:LINKING";

/// A statement about a single account based credential
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountCredentialStatement<C: Curve, AttributeType: Attribute<C::Scalar>> {
    pub network: Network,
    pub cred_id: CredentialRegistrationID,
    pub statements: Vec<AtomicStatement<C, AttributeTag, AttributeType>>,
}

/// A statement about a single Web3 based credential
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Web3IdCredentialStatement<C: Curve, AttributeType: Attribute<C::Scalar>> {
    /// The credential type. This is chosen by the provider to provide
    /// some information about what the credential is about.
    pub ty: BTreeSet<String>,
    pub network: Network,
    /// Reference to a specific smart contract instance that issued the
    /// credential.
    pub contract: ContractAddress,
    /// Credential identifier inside the contract.
    pub credential: CredentialHolderId,
    pub statements: Vec<AtomicStatement<C, String, AttributeType>>,
}

/// A statement about a single credential, either an account credential or a
/// Web3 credential.
#[derive(Debug, Clone, serde::Deserialize, PartialEq, Eq)]
#[serde(
    try_from = "serde_json::Value",
    bound(deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + DeserializeOwned")
)]
pub enum CredentialStatement<C: Curve, AttributeType: Attribute<C::Scalar>> {
    /// Statement about an account credential derived from an identity issued by an
    /// identity provider.
    Account(AccountCredentialStatement<C, AttributeType>),
    /// Statement about a credential issued by a Web3 identity provider, a smart
    /// contract.
    Web3Id(Web3IdCredentialStatement<C, AttributeType>),
}

impl<C: Curve, AttributeType: Attribute<C::Scalar> + DeserializeOwned> TryFrom<serde_json::Value>
    for CredentialStatement<C, AttributeType>
{
    type Error = anyhow::Error;

    fn try_from(mut value: serde_json::Value) -> Result<Self, Self::Error> {
        let id_value = get_field(&mut value, "id")?;
        let Some(Ok((_, id))) = id_value.as_str().map(did::parse_did) else {
            anyhow::bail!("id field is not a valid DID");
        };
        match id.ty {
            IdentifierType::AccountCredential { cred_id } => {
                let statement = get_field(&mut value, "statement")?;
                Ok(Self::Account(AccountCredentialStatement {
                    network: id.network,
                    cred_id,
                    statements: serde_json::from_value(statement)?,
                }))
            }
            IdentifierType::ContractData {
                address,
                entrypoint,
                parameter,
            } => {
                let statement = get_field(&mut value, "statement")?;
                let ty = get_field(&mut value, "type")?;
                anyhow::ensure!(entrypoint == "credentialEntry", "Invalid entrypoint.");
                Ok(Self::Web3Id(Web3IdCredentialStatement {
                    ty: serde_json::from_value(ty)?,
                    network: id.network,
                    contract: address,
                    credential: CredentialHolderId::new(ed25519_dalek::VerifyingKey::from_bytes(
                        &parameter.as_ref().try_into()?,
                    )?),
                    statements: serde_json::from_value(statement)?,
                }))
            }
            _ => {
                anyhow::bail!("Only ID credentials and Web3 credentials are supported.")
            }
        }
    }
}

impl<C: Curve, AttributeType: Attribute<C::Scalar> + serde::Serialize> serde::Serialize
    for CredentialStatement<C, AttributeType>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            CredentialStatement::Account(AccountCredentialStatement {
                network,
                cred_id,
                statements: statement,
            }) => {
                let json = serde_json::json!({
                    "id": format!("did:ccd:{network}:cred:{cred_id}"),
                    "statement": statement,
                });
                json.serialize(serializer)
            }
            CredentialStatement::Web3Id(Web3IdCredentialStatement {
                network,
                contract,
                credential,
                statements: statement,
                ty,
            }) => {
                let json = serde_json::json!({
                    "type": ty,
                    "id": format!("did:ccd:{network}:sci:{}:{}/credentialEntry/{}", contract.index, contract.subindex, credential),
                    "statement": statement,
                });
                json.serialize(serializer)
            }
        }
    }
}

/// A pair of a statement and a proof.
pub type StatementWithProof<C, TagType, AttributeType> = (
    AtomicStatement<C, TagType, AttributeType>,
    AtomicProof<C, AttributeType>,
);

/// Metadata of an account credentials derived from an identity issued by an
/// identity provider.
pub struct AccountCredentialMetadata {
    pub issuer: IpIdentity,
    pub cred_id: CredentialRegistrationID,
}

/// Metadata of an identity based credential.
pub struct IdentityCredentialMetadata {
    pub issuer: IpIdentity,
    pub validity: CredentialValidity,
}

/// Metadata of a Web3Id credential.
pub struct Web3idCredentialMetadata {
    pub contract: ContractAddress,
    pub holder: CredentialHolderId,
}

/// Metadata of a single credential.
pub enum CredentialMetadata {
    /// Metadata of an account credential, i.e., a credential derived from an
    /// identity object.
    Account(AccountCredentialMetadata),
    /// Metadata of a Web3Id credential.
    Web3Id(Web3idCredentialMetadata),
}

/// Metadata about a single [`CredentialProof`].
pub struct ProofMetadata {
    /// Timestamp of when the proof was created.
    pub created: chrono::DateTime<chrono::Utc>,
    pub network: Network,
    /// The DID of the credential the proof is about.
    pub cred_metadata: CredentialMetadata,
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> CredentialProof<C, AttributeType> {
    pub fn network(&self) -> Network {
        match self {
            CredentialProof::Account(acc) => acc.network,
            CredentialProof::Web3Id(web3) => web3.network,
        }
    }

    pub fn created(&self) -> chrono::DateTime<chrono::Utc> {
        match self {
            CredentialProof::Account(acc) => acc.created,
            CredentialProof::Web3Id(web3) => web3.created,
        }
    }

    pub fn metadata(&self) -> ProofMetadata {
        let cred_metadata = match self {
            CredentialProof::Account(cred_proof) => {
                CredentialMetadata::Account(cred_proof.metadata())
            }
            CredentialProof::Web3Id(cred_proof) => {
                CredentialMetadata::Web3Id(cred_proof.metadata())
            }
        };

        ProofMetadata {
            created: self.created(),
            network: self.network(),
            cred_metadata,
        }
    }

    /// Extract the statement from the proof.
    pub fn statement(&self) -> CredentialStatement<C, AttributeType> {
        match self {
            CredentialProof::Account(cred_proof) => {
                CredentialStatement::Account(cred_proof.statement())
            }
            CredentialProof::Web3Id(cred_proof) => {
                CredentialStatement::Web3Id(cred_proof.statement())
            }
        }
    }
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> AccountBasedCredential<C, AttributeType> {
    pub fn metadata(&self) -> AccountCredentialMetadata {
        let AccountBasedCredential {
            cred_id, issuer, ..
        } = self;

        AccountCredentialMetadata {
            issuer: *issuer,
            cred_id: *cred_id,
        }
    }

    /// Extract the statement from the proof.
    pub fn statement(&self) -> AccountCredentialStatement<C, AttributeType> {
        let AccountBasedCredential {
            network,
            cred_id,
            proofs,
            ..
        } = self;

        AccountCredentialStatement {
            network: *network,
            cred_id: *cred_id,
            statements: proofs.iter().map(|(x, _)| x.clone()).collect(),
        }
    }
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> Web3IdBasedCredential<C, AttributeType> {
    pub fn metadata(&self) -> Web3idCredentialMetadata {
        let Web3IdBasedCredential {
            holder, contract, ..
        } = self;

        Web3idCredentialMetadata {
            contract: *contract,
            holder: *holder,
        }
    }

    /// Extract the statement from the proof.
    pub fn statement(&self) -> Web3IdCredentialStatement<C, AttributeType> {
        let Web3IdBasedCredential {
            holder,
            network,
            contract,
            ty,
            proofs,
            ..
        } = self;

        Web3IdCredentialStatement {
            ty: ty.clone(),
            network: *network,
            contract: *contract,
            credential: *holder,
            statements: proofs.iter().map(|(x, _)| x.clone()).collect(),
        }
    }
}

/// Account based credentials. This contains almost
/// all the information needed to verify it, except the public commitments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountBasedCredential<C: Curve, AttributeType: Attribute<C::Scalar>> {
    /// Creation timestamp of the proof.
    pub created: chrono::DateTime<chrono::Utc>,
    pub network: Network,
    /// Reference to the credential to which this statement applies.
    pub cred_id: CredentialRegistrationID,
    /// Issuer of this credential, the identity provider index on the
    /// relevant network.
    pub issuer: IpIdentity,
    pub proofs: Vec<StatementWithProof<C, AttributeTag, AttributeType>>,
}

/// A proof of Web3 credentials. This contains almost
/// all the information needed to verify it, except the issuer's public key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Web3IdBasedCredential<C: Curve, AttributeType: Attribute<C::Scalar>> {
    /// Creation timestamp of the proof.
    pub created: chrono::DateTime<chrono::Utc>,
    /// Owner of the credential, a public key.
    pub holder: CredentialHolderId,
    pub network: Network,
    /// Reference to a specific smart contract instance.
    pub contract: ContractAddress,
    /// The credential type. This is chosen by the provider to provide
    /// some information about what the credential is about.
    pub ty: BTreeSet<String>,
    /// Commitments that the user has. These are all the commitments that
    /// are part of the credential, indexed by the attribute tag.
    pub commitments: SignedCommitments<C>,
    /// Individual proofs for statements.
    pub proofs: Vec<StatementWithProof<C, String, AttributeType>>,
}

/// A proof corresponding to one [`CredentialStatement`]. This contains almost
/// all the information needed to verify it, except the issuer's public key in
/// case of the `Web3Id` proof, and the public commitments in case of the
/// `Account` proof.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(bound(deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + DeserializeOwned"))]
#[serde(try_from = "serde_json::Value")]
pub enum CredentialProof<C: Curve, AttributeType: Attribute<C::Scalar>> {
    Account(AccountBasedCredential<C, AttributeType>),
    Web3Id(Web3IdBasedCredential<C, AttributeType>),
}

/// Commitments signed by the issuer.
#[derive(
    serde::Serialize, serde::Deserialize, Clone, Eq, PartialEq, Debug, crate::common::Serialize,
)]
#[serde(bound = "C: Curve")]
pub struct SignedCommitments<C: Curve> {
    #[serde(
        serialize_with = "crate::common::base16_encode",
        deserialize_with = "crate::common::base16_decode"
    )]
    pub signature: ed25519_dalek::Signature,
    pub commitments: BTreeMap<String, pedersen_commitment::Commitment<C>>,
}

impl<C: Curve> SignedCommitments<C> {
    /// Sign commitments for the owner.
    pub fn from_commitments(
        commitments: BTreeMap<String, pedersen_commitment::Commitment<C>>,
        holder: &CredentialHolderId,
        signer: &impl Web3IdSigner,
        issuer_contract: ContractAddress,
    ) -> Self {
        use crate::common::Serial;
        let mut data = COMMITMENT_SIGNATURE_DOMAIN_STRING.to_vec();
        holder.serial(&mut data);
        issuer_contract.serial(&mut data);
        commitments.serial(&mut data);
        Self {
            signature: signer.sign(&data),
            commitments,
        }
    }

    pub fn from_secrets<AttributeType: Attribute<C::Scalar>>(
        global: &GlobalContext<C>,
        values: &BTreeMap<String, AttributeType>,
        randomness: &BTreeMap<String, pedersen_commitment::Randomness<C>>,
        holder: &CredentialHolderId,
        signer: &impl Web3IdSigner,
        issuer_contract: ContractAddress,
    ) -> Option<Self> {
        // TODO: This is a bit inefficient. We don't need the intermediate map, we can
        // just serialize directly.

        let cmm_key = &global.on_chain_commitment_key;
        let mut commitments = BTreeMap::new();
        for ((vi, value), (ri, randomness)) in values.iter().zip(randomness.iter()) {
            if vi != ri {
                return None;
            }
            commitments.insert(
                ri.clone(),
                cmm_key.hide(
                    &pedersen_commitment::Value::<C>::new(value.to_field_element()),
                    randomness,
                ),
            );
        }
        Some(Self::from_commitments(
            commitments,
            holder,
            signer,
            issuer_contract,
        ))
    }
}

impl<C: Curve, AttributeType: Attribute<C::Scalar> + serde::Serialize> serde::Serialize
    for CredentialProof<C, AttributeType>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            CredentialProof::Account(AccountBasedCredential {
                created,
                network,
                cred_id,
                issuer,
                proofs,
            }) => {
                let json = serde_json::json!({
                    "type": ["VerifiableCredential", "ConcordiumVerifiableCredential"],
                    "issuer": format!("did:ccd:{network}:idp:{issuer}"),
                    "credentialSubject": {
                        "id": format!("did:ccd:{network}:cred:{cred_id}"),
                        "statement": proofs.iter().map(|x| &x.0).collect::<Vec<_>>(),
                        "proof": {
                            "type": "ConcordiumZKProofV3",
                            "created": created,
                            "proofValue": proofs.iter().map(|x| &x.1).collect::<Vec<_>>(),
                        }
                    }
                });
                json.serialize(serializer)
            }
            CredentialProof::Web3Id(Web3IdBasedCredential {
                created,
                network,
                contract,
                ty,
                commitments,
                proofs,
                holder,
            }) => {
                let json = serde_json::json!({
                    "type": ty,
                    "issuer": format!("did:ccd:{network}:sci:{}:{}/issuer", contract.index, contract.subindex),
                    "credentialSubject": {
                        "id": format!("did:ccd:{network}:pkc:{}", holder),
                        "statement": proofs.iter().map(|x| &x.0).collect::<Vec<_>>(),
                        "proof": {
                            "type": "ConcordiumZKProofV3",
                            "created": created,
                            "commitments": commitments,
                            "proofValue": proofs.iter().map(|x| &x.1).collect::<Vec<_>>(),
                        }
                    }
                });
                json.serialize(serializer)
            }
        }
    }
}

/// Extract the value at the given key. This mutates the `value` replacing the
/// value at the provided key with `Null`.
fn get_field(
    value: &mut serde_json::Value,
    field: &'static str,
) -> anyhow::Result<serde_json::Value> {
    match value.get_mut(field) {
        Some(v) => Ok(v.take()),
        None => anyhow::bail!("Field {field} is not present."),
    }
}

/// Extract an optional value at the given key. This mutates the `value`
/// replacing the value at the provided key with `Null`.
fn get_optional_field(
    value: &mut serde_json::Value,
    field: &'static str,
) -> anyhow::Result<serde_json::Value> {
    match value.get_mut(field) {
        Some(v) => Ok(v.take()),
        None => Ok(serde_json::Value::Null),
    }
}

impl<C: Curve, AttributeType: Attribute<C::Scalar> + serde::de::DeserializeOwned>
    TryFrom<serde_json::Value> for CredentialProof<C, AttributeType>
{
    type Error = anyhow::Error;

    fn try_from(mut value: serde_json::Value) -> Result<Self, Self::Error> {
        let issuer: String = serde_json::from_value(get_field(&mut value, "issuer")?)?;
        let ty: BTreeSet<String> = serde_json::from_value(get_field(&mut value, "type")?)?;
        anyhow::ensure!(
            ty.contains("VerifiableCredential") && ty.contains("ConcordiumVerifiableCredential")
        );
        let mut credential_subject = get_field(&mut value, "credentialSubject")?;
        let issuer = did::parse_did(&issuer)
            .map_err(|e| anyhow::anyhow!("Unable to parse issuer: {e}"))?
            .1;
        match issuer.ty {
            IdentifierType::Idp { idp_identity } => {
                let id = get_field(&mut credential_subject, "id")?;
                let Some(Ok(id)) = id.as_str().map(did::parse_did) else {
                    anyhow::bail!("Credential ID invalid.")
                };
                let IdentifierType::AccountCredential { cred_id } = id.1.ty else {
                    anyhow::bail!("Credential identifier must be a public key.")
                };
                anyhow::ensure!(issuer.network == id.1.network);
                let statement: Vec<AtomicStatement<_, _, _>> =
                    serde_json::from_value(get_field(&mut credential_subject, "statement")?)?;

                let mut proof = get_field(&mut credential_subject, "proof")?;

                anyhow::ensure!(
                    get_field(&mut proof, "type")?.as_str() == Some("ConcordiumZKProofV3")
                );
                let created = serde_json::from_value::<chrono::DateTime<chrono::Utc>>(get_field(
                    &mut proof, "created",
                )?)?;

                let proof_value: Vec<_> =
                    serde_json::from_value(get_field(&mut proof, "proofValue")?)?;

                anyhow::ensure!(proof_value.len() == statement.len());
                let proofs = statement.into_iter().zip(proof_value).collect();
                Ok(Self::Account(AccountBasedCredential {
                    created,
                    network: issuer.network,
                    cred_id,
                    issuer: idp_identity,
                    proofs,
                }))
            }
            IdentifierType::ContractData {
                address,
                entrypoint,
                parameter,
            } => {
                anyhow::ensure!(entrypoint == "issuer", "Invalid issuer DID.");
                anyhow::ensure!(
                    parameter.as_ref().is_empty(),
                    "Issuer must have an empty parameter."
                );
                let id = get_field(&mut credential_subject, "id")?;
                let Some(Ok(id)) = id.as_str().map(did::parse_did) else {
                    anyhow::bail!("Credential ID invalid.")
                };
                let IdentifierType::PublicKey { key } = id.1.ty else {
                    anyhow::bail!("Credential identifier must be a public key.")
                };
                anyhow::ensure!(issuer.network == id.1.network);
                // Make sure that the id's point to the same credential.
                let statement: Vec<AtomicStatement<_, _, _>> =
                    serde_json::from_value(get_field(&mut credential_subject, "statement")?)?;

                let mut proof = get_field(&mut credential_subject, "proof")?;

                anyhow::ensure!(
                    get_field(&mut proof, "type")?.as_str() == Some("ConcordiumZKProofV3")
                );
                let created = serde_json::from_value::<chrono::DateTime<chrono::Utc>>(get_field(
                    &mut proof, "created",
                )?)?;

                let commitments = serde_json::from_value(get_field(&mut proof, "commitments")?)?;

                let proof_value: Vec<_> =
                    serde_json::from_value(get_field(&mut proof, "proofValue")?)?;

                anyhow::ensure!(proof_value.len() == statement.len());
                let proofs = statement.into_iter().zip(proof_value).collect();

                Ok(Self::Web3Id(Web3IdBasedCredential {
                    created,
                    holder: CredentialHolderId::new(key),
                    network: issuer.network,
                    contract: address,
                    commitments,
                    proofs,
                    ty,
                }))
            }
            _ => anyhow::bail!("Only IDPs and smart contracts can be issuers."),
        }
    }
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> crate::common::Serial
    for CredentialProof<C, AttributeType>
{
    fn serial<B: crate::common::Buffer>(&self, out: &mut B) {
        // todo ar proof ser
        match self {
            CredentialProof::Account(AccountBasedCredential {
                created,
                network,
                cred_id,
                proofs,
                issuer,
            }) => {
                0u8.serial(out);
                created.timestamp_millis().serial(out);
                network.serial(out);
                cred_id.serial(out);
                issuer.serial(out);
                proofs.serial(out)
            }
            CredentialProof::Web3Id(Web3IdBasedCredential {
                created,
                network,
                contract,
                commitments,
                proofs,
                holder,
                ty,
            }) => {
                1u8.serial(out);
                created.timestamp_millis().serial(out);
                let len = ty.len() as u8;
                len.serial(out);
                for s in ty {
                    (s.len() as u16).serial(out);
                    out.write_all(s.as_bytes())
                        .expect("Writing to buffer succeeds.");
                }
                network.serial(out);
                contract.serial(out);
                holder.serial(out);
                commitments.serial(out);
                proofs.serial(out)
            }
        }
    }
}

#[doc(hidden)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
/// Used as a phantom type to indicate a Web3ID challenge.
pub enum Web3IdChallengeMarker {}

/// Sha256 challenge string that serves as a distinguishing context when requesting
/// proofs.
pub type Sha256Challenge = HashBytes<Web3IdChallengeMarker>;

/// A request for a proof. This type is an enumeration over the supported request
/// versions.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum VersionedRequest<C: Curve, AttributeType: Attribute<C::Scalar>> {
    V0(Request<C, AttributeType>),
    V1(v1::RequestV1<C, AttributeType>),
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> SerdeSerialize
    for VersionedRequest<C, AttributeType>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        todo!()
    }
}

impl<'de, C: Curve, AttributeType: Attribute<C::Scalar>> SerdeDeserialize<'de>
    for VersionedRequest<C, AttributeType>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        todo!()
    }
}

/// A request for a proof. This is the statement and challenge. The secret data
/// comes separately.
#[derive(Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
#[serde(bound(
    serialize = "C: Curve, AttributeType: Attribute<C::Scalar> + serde::Serialize",
    deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + DeserializeOwned"
))]
pub struct Request<C: Curve, AttributeType: Attribute<C::Scalar>> {
    pub challenge: Sha256Challenge,
    pub credential_statements: Vec<CredentialStatement<C, AttributeType>>,
}

#[repr(transparent)]
#[doc(hidden)]
/// An ed25519 public key tagged with a phantom type parameter based on its
/// role, e.g., an owner of a credential or a revocation key.
pub struct Ed25519PublicKey<Role> {
    pub public_key: ed25519_dalek::VerifyingKey,
    phantom: PhantomData<Role>,
}

impl<Role> From<ed25519_dalek::VerifyingKey> for Ed25519PublicKey<Role> {
    fn from(value: ed25519_dalek::VerifyingKey) -> Self {
        Self::new(value)
    }
}

impl<Role> serde::Serialize for Ed25519PublicKey<Role> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = self.to_string();
        s.serialize(serializer)
    }
}

impl<'de, Role> serde::Deserialize<'de> for Ed25519PublicKey<Role> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let s: String = String::deserialize(deserializer)?;
        s.try_into().map_err(D::Error::custom)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Ed25519PublicKeyFromStrError {
    #[error("Not a valid hex string: {0}")]
    InvalidHex(#[from] hex::FromHexError),
    #[error("Not a valid representation of a public key: {0}")]
    InvalidBytes(#[from] ed25519_dalek::SignatureError),
}

impl<Role> TryFrom<String> for Ed25519PublicKey<Role> {
    type Error = Ed25519PublicKeyFromStrError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl<Role> FromStr for Ed25519PublicKey<Role> {
    type Err = Ed25519PublicKeyFromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl<Role> TryFrom<&str> for Ed25519PublicKey<Role> {
    type Error = Ed25519PublicKeyFromStrError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = hex::decode(value)?.try_into().map_err(|_| {
            Self::Error::InvalidBytes(ed25519_dalek::SignatureError::from_source(
                "Incorrect public key length.",
            ))
        })?;
        Ok(Self::new(ed25519_dalek::VerifyingKey::from_bytes(&bytes)?))
    }
}

impl<Role> Ed25519PublicKey<Role> {
    pub fn new(public_key: ed25519_dalek::VerifyingKey) -> Self {
        Self {
            public_key,
            phantom: PhantomData,
        }
    }
}

impl<Role> std::fmt::Debug for Ed25519PublicKey<Role> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.public_key.as_bytes() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl<Role> std::fmt::Display for Ed25519PublicKey<Role> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.public_key.as_bytes() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

// Manual trait implementations to avoid bounds on the `Role` parameter.
impl<Role> Eq for Ed25519PublicKey<Role> {}

impl<Role> PartialEq for Ed25519PublicKey<Role> {
    fn eq(&self, other: &Self) -> bool {
        self.public_key.eq(&other.public_key)
    }
}

impl<Role> Clone for Ed25519PublicKey<Role> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<Role> Copy for Ed25519PublicKey<Role> {}

impl<Role> crate::contracts_common::Serial for Ed25519PublicKey<Role> {
    fn serial<W: crate::contracts_common::Write>(&self, out: &mut W) -> Result<(), W::Err> {
        out.write_all(self.public_key.as_bytes())
    }
}

impl<Role> crate::contracts_common::Deserial for Ed25519PublicKey<Role> {
    fn deserial<R: crate::contracts_common::Read>(
        source: &mut R,
    ) -> crate::contracts_common::ParseResult<Self> {
        let public_key_bytes = <[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]>::deserial(source)?;
        let public_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes)
            .map_err(|_| crate::contracts_common::ParseError {})?;
        Ok(Self {
            public_key,
            phantom: PhantomData,
        })
    }
}

impl<Role> crate::common::Serial for Ed25519PublicKey<Role> {
    fn serial<W: crate::common::Buffer>(&self, out: &mut W) {
        out.write_all(self.public_key.as_bytes())
            .expect("Writing to buffer always succeeds.");
    }
}

impl<Role> crate::common::Deserial for Ed25519PublicKey<Role> {
    fn deserial<R: std::io::Read>(source: &mut R) -> crate::common::ParseResult<Self> {
        use anyhow::Context;
        let public_key_bytes = <[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]>::deserial(source)?;
        let public_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes)
            .context("Invalid public key.")?;
        Ok(Self {
            public_key,
            phantom: PhantomData,
        })
    }
}

#[doc(hidden)]
pub enum CredentialHolderIdRole {}

/// The owner of a Web3Id credential.
pub type CredentialHolderId = Ed25519PublicKey<CredentialHolderIdRole>;

/// A presentation is the response to a [`VersionedRequest`]. This type is an enumeration
/// over the supported presentation versions.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum VersionedPresentation<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
> {
    V0(Presentation<C, AttributeType>),
    V1(v1::PresentationV1<P, C, AttributeType>),
}

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: Attribute<C::Scalar>>
    SerdeSerialize for VersionedPresentation<P, C, AttributeType>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        todo!()
    }
}

impl<'de, P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: Attribute<C::Scalar>>
    SerdeDeserialize<'de> for VersionedPresentation<P, C, AttributeType>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        todo!()
    }
}

/// A presentation is the response to a [`Request`]. It contains proofs for
/// statements, ownership proof for all Web3 credentials, and a context. The
/// only missing part to verify the proof are the public commitments.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(bound(deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + DeserializeOwned"))]
#[serde(try_from = "serde_json::Value")]
pub struct Presentation<C: Curve, AttributeType: Attribute<C::Scalar>> {
    pub presentation_context: Sha256Challenge,
    pub verifiable_credential: Vec<CredentialProof<C, AttributeType>>,
    /// Signatures from keys of Web3 credentials (not from ID credentials).
    /// The order is the same as that in the `credential_proofs` field.
    pub linking_proof: LinkingProof,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, thiserror::Error)]
#[non_exhaustive]
pub enum PresentationVerificationError {
    #[error("The linking proof was incomplete.")]
    MissingLinkingProof,
    #[error("The linking proof had extra signatures.")]
    ExcessiveLinkingProof,
    #[error("The linking proof was not valid.")]
    InvalidLinkinProof,
    #[error("The public data did not match the credentials.")]
    InconsistentPublicData,
    #[error("The credential was not valid.")]
    InvalidCredential,
}

impl<C: Curve, AttributeType: Attribute<C::Scalar> + DeserializeOwned> TryFrom<serde_json::Value>
    for Presentation<C, AttributeType>
{
    type Error = anyhow::Error;

    fn try_from(mut value: serde_json::Value) -> Result<Self, Self::Error> {
        let ty: String = serde_json::from_value(get_field(&mut value, "type")?)?;
        anyhow::ensure!(ty == "VerifiablePresentation");
        let presentation_context =
            serde_json::from_value(get_field(&mut value, "presentationContext")?)?;
        let verifiable_credential =
            serde_json::from_value(get_field(&mut value, "verifiableCredential")?)?;
        let linking_proof = serde_json::from_value(get_field(&mut value, "proof")?)?;
        Ok(Self {
            presentation_context,
            verifiable_credential,
            linking_proof,
        })
    }
}

impl<C: Curve, AttributeType: Attribute<C::Scalar> + serde::Serialize> serde::Serialize
    for Presentation<C, AttributeType>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let json = serde_json::json!({
            "type": "VerifiablePresentation",
            "presentationContext": self.presentation_context,
            "verifiableCredential": &self.verifiable_credential,
            "proof": &self.linking_proof
        });
        json.serialize(serializer)
    }
}

#[derive(
    Debug, Clone, Eq, PartialEq, crate::common::SerdeBase16Serialize, crate::common::Serialize,
)]
/// A proof that establishes that the owner of the credential itself produced
/// the proof. Technically this means that there is a signature on the entire
/// rest of the presentation using the public key that is associated with the
/// Web3 credential. The identity credentials do not have linking proofs since
/// the owner of those credentials retains full control of their secret
/// material.
struct WeakLinkingProof {
    signature: ed25519_dalek::Signature,
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Deserialize)]
#[serde(try_from = "serde_json::Value")]
/// A proof that establishes that the owner of the credential has indeed created
/// the presentation. At present this is a list of signatures.
pub struct LinkingProof {
    pub created: chrono::DateTime<chrono::Utc>,
    proof_value: Vec<WeakLinkingProof>,
}

impl crate::common::Serial for LinkingProof {
    fn serial<B: crate::common::Buffer>(&self, out: &mut B) {
        self.created.timestamp_millis().serial(out);
        self.proof_value.serial(out)
    }
}

impl serde::Serialize for LinkingProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let json = serde_json::json!({
            "type": "ConcordiumWeakLinkingProofV1",
            "created": self.created,
            "proofValue": self.proof_value,
        });
        json.serialize(serializer)
    }
}

impl TryFrom<serde_json::Value> for LinkingProof {
    type Error = anyhow::Error;

    fn try_from(mut value: serde_json::Value) -> Result<Self, Self::Error> {
        use anyhow::Context;
        let ty = value
            .get_mut("type")
            .context("No type field present.")?
            .take();
        if ty.as_str() != Some("ConcordiumWeakLinkingProofV1") {
            anyhow::bail!("Unrecognized proof type.");
        }
        let created = serde_json::from_value(
            value
                .get_mut("created")
                .context("No created field present.")?
                .take(),
        )?;
        let proof_value = serde_json::from_value(
            value
                .get_mut("proofValue")
                .context("No proofValue field present.")?
                .take(),
        )?;
        Ok(Self {
            created,
            proof_value,
        })
    }
}

/// An auxiliary trait that provides access to the owner of the Web3 verifiable
/// credential. The intention is that this is implemented by ed25519 keypairs
/// or hardware wallets.
pub trait Web3IdSigner {
    fn id(&self) -> ed25519_dalek::VerifyingKey;
    fn sign(&self, msg: &impl AsRef<[u8]>) -> ed25519_dalek::Signature;
}

impl Web3IdSigner for ed25519_dalek::SigningKey {
    fn id(&self) -> ed25519_dalek::VerifyingKey {
        self.verifying_key()
    }

    fn sign(&self, msg: &impl AsRef<[u8]>) -> ed25519_dalek::Signature {
        ed25519_dalek::Signer::sign(self, msg.as_ref())
    }
}

impl Web3IdSigner for crate::common::types::KeyPair {
    fn id(&self) -> ed25519_dalek::VerifyingKey {
        self.public()
    }

    fn sign(&self, msg: &impl AsRef<[u8]>) -> ed25519_dalek::Signature {
        self.sign(msg.as_ref())
    }
}

impl Web3IdSigner for ed25519_dalek::SecretKey {
    fn id(&self) -> ed25519_dalek::VerifyingKey {
        ed25519_dalek::SigningKey::from(self).verifying_key()
    }

    fn sign(&self, msg: &impl AsRef<[u8]>) -> ed25519_dalek::Signature {
        let expanded: ed25519_dalek::SigningKey = self.into();
        ed25519_dalek::Signer::sign(&expanded, msg.as_ref())
    }
}

/// The additional private inputs (mostly secrets), needed to prove the statements
/// in a [request](VersionedRequest).
pub enum CommitmentInputs<
    'a,
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType,
    Web3IdSigner,
> {
    /// Inputs are for an account credential derived from an identity issued by an
    /// identity provider.
    Account {
        issuer: IpIdentity,
        /// The values that are committed to and are required in the proofs.
        values: &'a BTreeMap<AttributeTag, AttributeType>,
        /// The randomness to go along with commitments in `values`.
        randomness: &'a BTreeMap<AttributeTag, pedersen_commitment::Randomness<C>>,
    },
    /// Inputs are for an identity credential issued by an identity provider.
    Identity {
        /// Context with identity provider data
        ip_context: IpContextOnly<'a, P, C>,
        /// Identity object. Together with `id_object_use_data`, it constitutes the identity credentials
        id_object: &'a dyn HasIdentityObjectFields<P, C, AttributeType>,
        /// Identity credentials
        id_object_use_data: &'a IdObjectUseData<P, C>,
    },
    /// Inputs are for a credential issued by Web3ID issuer.
    Web3Issuer {
        signature: ed25519_dalek::Signature,
        /// The signer that will sign the presentation.
        signer: &'a Web3IdSigner,
        /// All the values the user has and are required in the proofs.
        values: &'a BTreeMap<String, AttributeType>,
        /// The randomness to go along with commitments in `values`. This has to
        /// have the same keys as the `values` field, but it is more
        /// convenient if it is a separate map itself.
        randomness: &'a BTreeMap<String, pedersen_commitment::Randomness<C>>,
    },
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(bound(
    deserialize = "AttributeType: DeserializeOwned, C: Curve",
    serialize = "AttributeType: Clone + serde::Serialize, C: Curve"
))]
#[serde(try_from = "serde_json::Value", into = "serde_json::Value")]
/// The full credential, including secrets.
pub struct Web3IdCredential<C: Curve, AttributeType> {
    /// The credential holder's public key.
    pub holder_id: CredentialHolderId,
    /// The network to which the credential applies.
    pub network: Network,
    /// The address of the credential registry where the credential is tracked.
    pub registry: ContractAddress,
    /// Credential type describing what kind of a credential it is.
    pub credential_type: BTreeSet<String>,
    /// Link to the credential schema.
    pub credential_schema: String,
    /// The issuer's public key.
    pub issuer_key: IssuerKey,
    /// Start of the validity of the credential.
    pub valid_from: chrono::DateTime<chrono::Utc>,
    /// After this date, the credential becomes expired. `None` corresponds to a
    /// credential that cannot expire.
    pub valid_until: Option<chrono::DateTime<chrono::Utc>>,
    /// The values of different attributes, indexed by attribute tags.
    pub values: BTreeMap<String, AttributeType>,
    /// The randomness to go along with commitments in `values`. This has to
    /// have the same keys as the `values` field, but it is more
    /// convenient if it is a separate map itself.
    pub randomness: BTreeMap<String, pedersen_commitment::Randomness<C>>,
    /// The signature on the holder's public key, the contract address of the
    /// issuer, and the commitments from the issuer.
    pub signature: ed25519_dalek::Signature,
}

impl<C: Curve, AttributeType: serde::Serialize> From<Web3IdCredential<C, AttributeType>>
    for serde_json::Value
{
    fn from(value: Web3IdCredential<C, AttributeType>) -> Self {
        let id = Method {
            network: value.network,
            ty: IdentifierType::ContractData {
                address: value.registry,
                entrypoint: OwnedEntrypointName::new_unchecked("credentialEntry".into()),
                parameter: OwnedParameter::from_serial(&value.holder_id).unwrap(),
            },
        };
        let verification_method = Method {
            network: value.network,
            ty: IdentifierType::PublicKey {
                key: value.issuer_key.public_key,
            },
        };
        let cred_id = Method {
            network: value.network,
            ty: IdentifierType::PublicKey {
                key: value.holder_id.public_key,
            },
        };
        let issuer = Method {
            network: value.network,
            ty: IdentifierType::ContractData {
                address: value.registry,
                entrypoint: OwnedEntrypointName::new_unchecked("issuer".into()),
                parameter: OwnedParameter::empty(),
            },
        };

        let subject = serde_json::json!({
            "id": cred_id,
            "attributes": value.values,
        });
        let proof = serde_json::json!({
            "type": "Ed25519Signature2020",
            "verificationMethod": verification_method,
            "proofPurpose": "assertionMethod",
            "proofValue": base16_encode_string(&value.signature),
        });

        serde_json::json!({
            "id": id,
            "type": value.credential_type,
            "issuer": issuer,
            "validFrom": value.valid_from,
            "validUntil": value.valid_until,
            "credentialSubject": subject,
            "credentialSchema": {
                "type": "JsonSchema2023",
                "id": value.credential_schema
            },
            "randomness": value.randomness,
            "proof": proof,
        })
    }
}

impl<C: Curve, AttributeType: DeserializeOwned> TryFrom<serde_json::Value>
    for Web3IdCredential<C, AttributeType>
{
    type Error = anyhow::Error;

    fn try_from(mut value: serde_json::Value) -> Result<Self, Self::Error> {
        use anyhow::Context;

        let id_value = get_field(&mut value, "id")?;
        let Some(Ok((_, id))) = id_value.as_str().map(did::parse_did) else {
            anyhow::bail!("id field is not a valid DID");
        };
        let IdentifierType::ContractData {
            address,
            entrypoint,
            parameter,
        } = id.ty
        else {
            anyhow::bail!("Only Web3 credentials are supported.")
        };
        anyhow::ensure!(entrypoint == "credentialEntry", "Incorrect entrypoint.");
        let holder_id = CredentialHolderId::new(ed25519_dalek::VerifyingKey::from_bytes(
            parameter.as_ref().try_into()?,
        )?);

        // Just validate the issuer field.
        {
            let issuer_value = get_field(&mut value, "issuer")?;
            let Some(Ok((_, id))) = issuer_value.as_str().map(did::parse_did) else {
                anyhow::bail!("issuer field is not a valid DID");
            };
            let IdentifierType::ContractData {
                address: issuer_address,
                entrypoint: issuer_entrypoint,
                parameter: issuer_parameter,
            } = id.ty
            else {
                anyhow::bail!("Only Web3 credentials are supported.")
            };
            anyhow::ensure!(address == issuer_address, "Inconsistent issuer addresses.");
            anyhow::ensure!(issuer_entrypoint == "issuer", "Invalid issuer entrypoint.");
            anyhow::ensure!(
                issuer_parameter == OwnedParameter::empty(),
                "Issuer parameter should be empty."
            )
        }

        let valid_from = get_field(&mut value, "validFrom")?;
        let valid_until = get_optional_field(&mut value, "validUntil")?;

        let randomness_value = get_field(&mut value, "randomness")?;
        let randomness = serde_json::from_value::<
            BTreeMap<String, pedersen_commitment::Randomness<C>>,
        >(randomness_value)?;

        let values = {
            let mut subject = get_field(&mut value, "credentialSubject")?;

            let cred_id = get_field(&mut subject, "id")?;
            let Some(Ok((_, cred_id))) = cred_id.as_str().map(did::parse_did) else {
                anyhow::bail!("credentialSubject/id field is not a valid DID");
            };
            let IdentifierType::PublicKey { key } = cred_id.ty else {
                anyhow::bail!("Credential subject id must be a public key.")
            };
            anyhow::ensure!(
                holder_id.public_key == key,
                "Inconsistent data. Holder id and credential id do not match."
            );
            anyhow::ensure!(cred_id.network == id.network, "Inconsistent networks.");

            serde_json::from_value(get_field(&mut subject, "attributes")?)?
        };

        let (issuer_key, signature) = {
            let mut proof = get_field(&mut value, "proof")?;
            let ty = get_field(&mut proof, "type")?;
            anyhow::ensure!(
                ty == "Ed25519Signature2020",
                "Only `Ed25519Signature2020` type is supported."
            );
            let purpose = get_field(&mut proof, "proofPurpose")?;
            anyhow::ensure!(
                purpose == "assertionMethod",
                "Only `assertionMethod` purpose is supported."
            );
            let method = get_field(&mut proof, "verificationMethod")?;
            let Some(Ok((_, method))) = method.as_str().map(did::parse_did) else {
                anyhow::bail!("verificationMethod field is not a valid DID");
            };
            let IdentifierType::PublicKey { key } = method.ty else {
                anyhow::bail!("Verification method must be a public key.")
            };
            anyhow::ensure!(method.network == id.network, "Inconsistent networks.");
            let sig = get_field(&mut proof, "proofValue")?;
            let signature =
                base16_decode_string(sig.as_str().context("proofValue must be a string.")?)?;
            (key.into(), signature)
        };

        let credential_schema = {
            let mut schema = get_field(&mut value, "credentialSchema")?;
            let ty = get_field(&mut schema, "type")?;
            anyhow::ensure!(
                ty == "JsonSchema2023",
                "Only `JsonSchema2023` type is supported."
            );
            let id = get_field(&mut schema, "id")?;
            let serde_json::Value::String(id) = id else {
                anyhow::bail!("The id should be a string.")
            };
            id
        };

        let credential_type = serde_json::from_value(get_field(&mut value, "type")?)?;

        Ok(Self {
            holder_id,
            network: id.network,
            registry: address,
            credential_type,
            issuer_key,
            values,
            randomness,
            signature,
            valid_from: serde_json::from_value(valid_from)?,
            valid_until: serde_json::from_value(valid_until)?,
            credential_schema,
        })
    }
}

impl<C: Curve, AttributeType> Web3IdCredential<C, AttributeType> {
    /// Convert the credential into inputs for a proof.
    pub fn into_inputs<'a, P: Pairing<ScalarField = C::Scalar>, S: Web3IdSigner>(
        &'a self,
        signer: &'a S,
    ) -> CommitmentInputs<'a, P, C, AttributeType, S> {
        CommitmentInputs::Web3Issuer {
            signature: self.signature,
            signer,
            values: &self.values,
            randomness: &self.randomness,
        }
    }
}

/// An owned version of [`CommitmentInputs`] that can be deserialized.
#[derive(serde::Deserialize)]
#[serde(bound(deserialize = "AttributeType: DeserializeOwned"))]
#[serde(rename_all = "camelCase")]
pub struct OwnedIdentityCommitmentInputs<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
> {
    /// Identity provider information
    pub ip_info: IpInfo<P>,
    /// Public information on the __supported__ anonymity revokers.
    /// Must include at least the anonymity revokers supported by the identity provider.
    /// This is used to create and validate credential.
    pub ar_infos: ArInfos<C>,
    /// Identity object. Together with `id_object_use_data`, it constitutes the identity credentials
    pub id_object: IdentityObjectV1<P, C, AttributeType>,
    /// Identity credentials
    pub id_object_use_data: IdObjectUseData<P, C>,
}

#[serde_with::serde_as]
#[derive(serde::Deserialize)]
#[serde(bound(deserialize = "AttributeType: DeserializeOwned, Web3IdSigner: DeserializeOwned"))]
#[serde(rename_all = "camelCase", tag = "type")]
/// An owned version of [`CommitmentInputs`] that can be deserialized.
pub enum OwnedCommitmentInputs<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
    Web3IdSigner,
> {
    #[serde(rename_all = "camelCase")]
    Account {
        issuer: IpIdentity,
        #[serde_as(as = "BTreeMap<serde_with::DisplayFromStr, _>")]
        values: BTreeMap<AttributeTag, AttributeType>,
        #[serde_as(as = "BTreeMap<serde_with::DisplayFromStr, _>")]
        randomness: BTreeMap<AttributeTag, pedersen_commitment::Randomness<C>>,
    },
    Identity(Box<OwnedIdentityCommitmentInputs<P, C, AttributeType>>),
    #[serde(rename_all = "camelCase")]
    Web3Issuer {
        signer: Web3IdSigner,
        #[serde_as(as = "BTreeMap<serde_with::DisplayFromStr, _>")]
        values: BTreeMap<String, AttributeType>,
        /// The randomness to go along with commitments in `values`. This has to
        /// have the same keys as the `values` field, but it is more
        /// convenient if it is a separate map itself.
        #[serde_as(as = "BTreeMap<serde_with::DisplayFromStr, _>")]
        randomness: BTreeMap<String, pedersen_commitment::Randomness<C>>,
        #[serde(
            serialize_with = "crate::common::base16_encode",
            deserialize_with = "crate::common::base16_decode"
        )]
        signature: ed25519_dalek::Signature,
    },
}

impl<
        'a,
        P: Pairing,
        C: Curve<Scalar = P::ScalarField>,
        AttributeType: Attribute<C::Scalar>,
        Web3IdSigner,
    > From<&'a OwnedCommitmentInputs<P, C, AttributeType, Web3IdSigner>>
    for CommitmentInputs<'a, P, C, AttributeType, Web3IdSigner>
{
    fn from(
        owned: &'a OwnedCommitmentInputs<P, C, AttributeType, Web3IdSigner>,
    ) -> CommitmentInputs<'a, P, C, AttributeType, Web3IdSigner> {
        match owned {
            OwnedCommitmentInputs::Account {
                issuer,
                values,
                randomness,
            } => CommitmentInputs::Account {
                issuer: *issuer,
                values,
                randomness,
            },
            OwnedCommitmentInputs::Identity(inputs) => {
                let OwnedIdentityCommitmentInputs {
                    ip_info,
                    ar_infos,
                    id_object,
                    id_object_use_data,
                } = &**inputs;

                CommitmentInputs::Identity {
                    ip_context: IpContextOnly {
                        ip_info,
                        ars_infos: &ar_infos.anonymity_revokers,
                    },
                    id_object,
                    id_object_use_data,
                }
            }
            OwnedCommitmentInputs::Web3Issuer {
                signer,
                values,
                randomness,
                signature,
            } => CommitmentInputs::Web3Issuer {
                signer,
                values,
                randomness,
                signature: *signature,
            },
        }
    }
}

#[derive(thiserror::Error, Debug)]
/// An error that can occur when attempting to produce a proof.
pub enum ProofError {
    #[error("Too many attributes to produce a proof.")]
    TooManyAttributes,
    #[error("Missing identity attribute.")]
    MissingAttribute,
    #[error("No attributes were provided.")]
    NoAttributes,
    #[error("Inconsistent values and randomness. Cannot construct commitments.")]
    InconsistentValuesAndRandomness,
    #[error("Cannot construct gluing proof.")]
    UnableToProve,
    #[error("The number of commitment inputs and statements is inconsistent.")]
    CommitmentsStatementsMismatch,
    #[error("The ID in the statement and in the provided signer do not match.")]
    InconsistentIds,
    #[error("Cannot prove identity attribute credentials: {0}")]
    IdentityAttributeCredentials(String),
}

/// The additional public inputs needed to verify the statements
/// in a [presentation](VersionedPresentation).
#[derive(Debug, serde::Deserialize)]
#[serde(
    bound = "C: Curve",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "type"
)]
pub enum CredentialsInputs<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    Account {
        // All the commitments of the credential.
        // In principle, we only ever need to borrow this, but it is simpler to
        // have the owned map instead of a reference to it.
        commitments: BTreeMap<AttributeTag, pedersen_commitment::Commitment<C>>,
    },
    Identity {
        /// Public information on the chosen identity provider.
        ip_info: IpInfo<P>,
        /// Public information on the __supported__ anonymity revokers.
        /// This is used by the identity provider and the chain to
        /// validate the identity object requests, to validate credentials,
        /// as well as by the account holder to create a credential.
        ars_infos: ArInfos<C>,
    },
    Web3 {
        /// The public key of the issuer.
        issuer_pk: IssuerKey,
    },
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, serde::Deserialize, Debug)]
#[serde(try_from = "serde_json::Value")]
/// A value of an attribute. This is the low-level representation. The
/// different variants are present to enable different representations in JSON,
/// and different embeddings as field elements when constructing and verifying
/// proofs.
pub enum Web3IdAttribute {
    /// A string value
    String(AttributeKind),
    /// A number that is embedded as is to the field element.
    Numeric(u64),
    /// A timestamp in milliseconds that is embedded like the
    /// [`Numeric`](Self::Numeric) variant, but has a different JSON
    /// representation, in ISO8601 compatible format.
    Timestamp(Timestamp),
}

impl Web3IdAttribute {
    /// Used to offset the duration stored in [`Web3IdAttribute::Timestamp`] to
    /// align with previous versions of chrono (<0.32), which introduced
    /// breaking changes to the value of [chrono::DateTime::MIN_UTC]
    const TIMESTAMP_DATE_OFFSET: i64 = 366;
    /// The lowest possible value to record in a [`Web3IdAttribute::Timestamp`]
    const TIMESTAMP_MIN_DATETIME: chrono::DateTime<chrono::Utc> =
        chrono::DateTime::<chrono::Utc>::MIN_UTC;
}

impl TryFrom<chrono::DateTime<chrono::Utc>> for Web3IdAttribute {
    type Error = anyhow::Error;

    fn try_from(value: chrono::DateTime<chrono::Utc>) -> Result<Self, Self::Error> {
        use anyhow::Context;
        // We construct a timestamp in milliseconds from the lowest possible value, and
        // add the offset to align with the previously defined lowest possible
        // value.
        let timestamp = value
            .signed_duration_since(Self::TIMESTAMP_MIN_DATETIME)
            .checked_add(
                &chrono::Duration::try_days(Self::TIMESTAMP_DATE_OFFSET)
                    .expect("Can contain offset duration"),
            )
            .context("Timestamp out of range")?
            .num_milliseconds();
        let timestamp = Timestamp::from_timestamp_millis(
            timestamp
                .try_into()
                .context("Timestamps before -262144-01-01T00:00:00Z are not supported.")?,
        );
        Ok(Self::Timestamp(timestamp))
    }
}

impl TryFrom<&Web3IdAttribute> for chrono::DateTime<chrono::Utc> {
    type Error = anyhow::Error;

    fn try_from(value: &Web3IdAttribute) -> Result<Self, Self::Error> {
        use anyhow::Context;

        let Web3IdAttribute::Timestamp(timestamp) = value else {
            anyhow::bail!("Cannot convert non timestamp web3 attribute values into date-time");
        };

        let millis: i64 = timestamp.timestamp_millis().try_into()?;
        // We construct a date-time by subtracting the timestamp offset from the
        // timestamp, and add this to the minimum date, thus acting as a
        // reversing the conversion from date-time to tiemstamp within the web3
        // id attribute context
        let date_time = chrono::Duration::try_milliseconds(millis)
            .and_then(|dur| {
                let ms = dur.checked_sub(
                    &chrono::Duration::try_days(Web3IdAttribute::TIMESTAMP_DATE_OFFSET)
                        .expect("Can contain offset duration"),
                )?;
                Web3IdAttribute::TIMESTAMP_MIN_DATETIME.checked_add_signed(ms)
            })
            .context("Timestamp out of range")?;
        Ok(date_time)
    }
}

impl TryFrom<serde_json::Value> for Web3IdAttribute {
    type Error = anyhow::Error;

    fn try_from(mut value: serde_json::Value) -> Result<Self, Self::Error> {
        use anyhow::Context;

        if let Some(v) = value.as_str() {
            Ok(Self::String(v.parse()?))
        } else if let Some(v) = value.as_u64() {
            Ok(Self::Numeric(v))
        } else {
            let obj = value
                .as_object_mut()
                .context("Not a string, number or object")?;
            if obj.get("type").and_then(|x| x.as_str()) != Some("date-time") {
                anyhow::bail!("Unknown or missing attribute `type`.")
            }
            let dt_value = obj
                .get_mut("timestamp")
                .context("Missing timestamp value.")?
                .take();
            let dt: chrono::DateTime<chrono::Utc> = serde_json::from_value(dt_value)?;
            dt.try_into()
        }
    }
}

impl serde::Serialize for Web3IdAttribute {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::{Error, SerializeMap};
        match self {
            Web3IdAttribute::String(ak) => ak.serialize(serializer),
            Web3IdAttribute::Numeric(n) => n.serialize(serializer),
            Web3IdAttribute::Timestamp(_) => {
                let dt =
                    chrono::DateTime::<chrono::Utc>::try_from(self).map_err(S::Error::custom)?;
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("type", "date-time")?;
                map.serialize_entry("timestamp", &dt)?;
                map.end()
            }
        }
    }
}

impl crate::common::Serial for Web3IdAttribute {
    fn serial<B: crate::common::Buffer>(&self, out: &mut B) {
        match self {
            Web3IdAttribute::String(ak) => {
                0u8.serial(out);
                ak.serial(out)
            }
            Web3IdAttribute::Numeric(n) => {
                1u8.serial(out);
                n.serial(out)
            }
            Web3IdAttribute::Timestamp(ts) => {
                2u8.serial(out);
                ts.serial(out)
            }
        }
    }
}

impl crate::common::Deserial for Web3IdAttribute {
    fn deserial<R: byteorder::ReadBytesExt>(source: &mut R) -> crate::common::ParseResult<Self> {
        use crate::common::Get;
        match source.get()? {
            0u8 => source.get().map(Web3IdAttribute::String),
            1u8 => source.get().map(Web3IdAttribute::Numeric),
            2u8 => source.get().map(Web3IdAttribute::Timestamp),
            n => anyhow::bail!("Unrecognized attribute tag: {n}"),
        }
    }
}

impl std::fmt::Display for Web3IdAttribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Web3IdAttribute::String(ak) => ak.fmt(f),
            Web3IdAttribute::Numeric(n) => n.fmt(f),
            Web3IdAttribute::Timestamp(ts) => {
                // If possible render as a RFC3339 string.
                // Revert to millisecond timestamp if this is not possible due to overflow.
                if let Ok(dt) = chrono::DateTime::<chrono::Utc>::try_from(self) {
                    dt.fmt(f)
                } else {
                    ts.fmt(f)
                }
            }
        }
    }
}

impl Attribute<<ArCurve as Curve>::Scalar> for Web3IdAttribute {
    fn to_field_element(&self) -> <ArCurve as Curve>::Scalar {
        match self {
            Web3IdAttribute::String(ak) => ak.to_field_element(),
            Web3IdAttribute::Numeric(n) => ArCurve::scalar_from_u64(*n),
            Web3IdAttribute::Timestamp(n) => ArCurve::scalar_from_u64(n.timestamp_millis()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::id_proof_types::{
        AttributeInRangeStatement, AttributeInSetStatement, AttributeNotInSetStatement,
        RevealAttributeStatement,
    };
    use crate::web3id::did::Network;
    use crate::web3id::{Web3IdAttribute, Web3IdCredential};
    use chrono::TimeZone;
    use rand::Rng;

    fn remove_whitespace(str: &str) -> String {
        str.chars().filter(|c| !c.is_whitespace()).collect()
    }

    #[test]
    /// Basic test that conversion of `Web3IdCredential` from/to JSON works.
    fn test_web3id_credential_json() {
        let mut rng = rand::thread_rng();
        let signer = ed25519_dalek::SigningKey::generate(&mut rng);
        let issuer = ed25519_dalek::SigningKey::generate(&mut rng);
        let mut randomness = BTreeMap::new();
        randomness.insert(
            0.to_string(),
            pedersen_commitment::Randomness::generate(&mut rng),
        );
        randomness.insert(
            3.to_string(),
            pedersen_commitment::Randomness::generate(&mut rng),
        );
        randomness.insert(
            17.to_string(),
            pedersen_commitment::Randomness::generate(&mut rng),
        );

        let mut values = BTreeMap::new();
        values.insert("0".into(), Web3IdAttribute::Numeric(1234));
        values.insert(
            "3".into(),
            Web3IdAttribute::String(AttributeKind::try_new("Hello".into()).unwrap()),
        );
        values.insert(
            "17".into(),
            Web3IdAttribute::String(AttributeKind::try_new("World".into()).unwrap()),
        );

        let cred = Web3IdCredential::<ArCurve, Web3IdAttribute> {
            holder_id: signer.verifying_key().into(),
            network: Network::Testnet,
            registry: ContractAddress::new(3, 17),
            credential_type: [
                "VerifiableCredential".into(),
                "ConcordiumVerifiableCredential".into(),
                "UniversityDegreeCredential".into(),
            ]
            .into_iter()
            .collect(),
            credential_schema: "http://link/to/schema".into(),
            issuer_key: issuer.verifying_key().into(),
            valid_from: chrono::Utc.timestamp_millis_opt(17).unwrap(),
            valid_until: chrono::Utc.timestamp_millis_opt(12345).earliest(),
            values,
            randomness,
            signature: issuer.sign(b"Something"),
        };

        let json: serde_json::Value = cred.clone().into();

        let value = Web3IdCredential::<ArCurve, Web3IdAttribute>::try_from(json)
            .expect("JSON parsing succeeds");

        assert_eq!(value, cred, "Credential and parsed credential differ.");
    }

    /// Tests JSON serialization of the `Timestamp` variant of `Web3IdAttribute`.
    #[test]
    fn test_web3_id_attribute_timestamp_serde() {
        let date_time = chrono::DateTime::parse_from_rfc3339("2023-08-28T00:00:00.000Z")
            .expect("Can parse datetime value");
        let value = serde_json::json!({"type": "date-time", "timestamp": date_time});
        let attr: Web3IdAttribute =
            serde_json::from_value(value.clone()).expect("Can deserialize from JSON");

        assert_eq!(
            attr,
            Web3IdAttribute::Timestamp(8336326032000000.into()),
            "Unexpected value for deserialized attribute"
        );

        let ser = serde_json::to_value(attr).expect("Serialize does not fail");
        assert_eq!(
            ser, value,
            "Expected deserialized value to serialize into its origin"
        );
    }

    /// Tests JSON serialization and deserialization of request and presentation. Test
    /// uses account credentials.
    #[test]
    fn test_request_and_presentation_account_json() {
        let challenge = Sha256Challenge::new(fixtures::seed0().gen());

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

        let credential_statements =
            vec![CredentialStatement::Account(AccountCredentialStatement {
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
            })];

        let request = Request::<ArCurve, Web3IdAttribute> {
            challenge,
            credential_statements,
        };

        let request_json = serde_json::to_string_pretty(&request).unwrap();
        println!("request:\n{}", request_json);
        let expected_request_json = r#"
{
  "challenge": "7fb27b941602d01d11542211134fc71aacae54e37e7d007bbb7b55eff062a284",
  "credentialStatements": [
    {
      "id": "did:ccd:testnet:cred:856793e4ba5d058cea0b5c3a1c8affb272efcf53bbab77ee28d3e2270d5041d220c1e1a9c6c8619c84e40ebd70fb583e",
      "statement": [
        {
          "attributeTag": "dob",
          "lower": 80,
          "type": "AttributeInRange",
          "upper": 1237
        },
        {
          "attributeTag": "sex",
          "set": [
            "aa",
            "ff",
            "zz"
          ],
          "type": "AttributeInSet"
        },
        {
          "attributeTag": "lastName",
          "set": [
            "aa",
            "ff",
            "zz"
          ],
          "type": "AttributeNotInSet"
        },
        {
          "attributeTag": "countryOfResidence",
          "lower": {
            "timestamp": "2023-08-27T23:12:15Z",
            "type": "date-time"
          },
          "type": "AttributeInRange",
          "upper": {
            "timestamp": "2023-08-29T23:12:15Z",
            "type": "date-time"
          }
        },
        {
          "attributeTag": "nationality",
          "type": "RevealAttribute"
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
        let request_deserialized: Request<ArCurve, Web3IdAttribute> =
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
  "presentationContext": "7fb27b941602d01d11542211134fc71aacae54e37e7d007bbb7b55eff062a284",
  "proof": {
    "created": "2023-08-28T23:12:15Z",
    "proofValue": [],
    "type": "ConcordiumWeakLinkingProofV1"
  },
  "type": "VerifiablePresentation",
  "verifiableCredential": [
    {
      "credentialSubject": {
        "id": "did:ccd:testnet:cred:856793e4ba5d058cea0b5c3a1c8affb272efcf53bbab77ee28d3e2270d5041d220c1e1a9c6c8619c84e40ebd70fb583e",
        "proof": {
          "created": "2023-08-28T23:12:15Z",
          "proofValue": [
            {
              "proof": "b12365d42dbcdda54216b524d94eda74809018b8179d90c747829da5d24df4b2d835d7f77879cf52d5b1809564c5ec49990998db469e5c04553de3f787a3998d660204fe2dd1033a310bfc06ab8a9e5426ff90fdaf554ac11e96bbf18b1e1da8a881ba424d4deb7715880d015d04a64fd37dfef5ec71d48efee4e8d4d640c505f47d6bb75c52545f01889aa503809d06835320bdc1035e9143aea9bffcb12e904549c4f4885ffcb11c4956b362153010506a4d2959a524be07dc01d717c7e3812d41eaf65a6feabe01babf8a7ae81b9726fd6ee688cd241b31c8219b928d2de7073df321c28040aea5820d8e52af2a23d9da963b335a7452473bdda093a4f8103c32680db7441639eac6d1279ed855ba5cd009a5d9999d4f48f2db031c1b2f3d00000007a7e39d70b58b37af8722528536e1ecd898f4b5060d39eeed8713bf28d58e963ab00e9b46cac7f542240515a9b477b6268322f52bafd7bb479c23c68c275b67fba7c7ccd4b386e61ef4b48d6bfbbeba45fcef3da404ea89c7f082838f8c97f6a88fcac670270f88647c325d842badb22aeec2876b956940b27945e5eb93aaf1d1ab8b2881dd8ebeb27a1871fa1a9e02db873c84ae38d0505fe0c40fca21fa757e928af08077716082cced518f315d694b32fe06568e5b3d1602062747b8911947b17f6535323fcb1a11f4e1807f7f10ad7dec744245bf33f4a183d4e1778be73f4f2028cc9b5731f54dc073763776979d96cf54b71d71f22d8035f7f01149bb205044d95c64be878f3d02a17b375df761b4e14f74a810d3e5de4e7790d19fa712a832cf4345394e0dfbf643d36e60cecc57585601fded8a44cde6e43be56c1a679eb0ccf5e66994d8e9b0354d128045eea70257f31a6c934ea4f4465b903d0dc64cacde6219d93500c798a1ad5abe63e067e2a23690bbc865b7aaaa557f782c4fb2cb9b2d4b0a81e8566627d546d21450e38d922c6749900808ddf06e6f01da92d7fcee94c66ebfa3058bcbfdbf655e9cac0bf73d693d0e57ec3d457910110a67e9124ee7814bf8f6c5836e153dd3a95355a8218df1f8aec1cd6213349e7f16d795ccf1d3a28fe24d63136909e5504faf640c2a99b12cb5a39ecc54a0b60081f00235adc9451b0aabfab24fc9d40dffc8ac9b2111f3369e941090b3242ad8334a54b7ec4940ae23ea4ad23bbef2376737977939097918f37c04b989f2d16a7d88b50818a60c730de62214903bfcfce0a45c107fd441f3b0d5da23afe5ad03baa0d6f1bf78aeb8ce94d4852c358c8200919337e4915f9732e74ebf6b0aa99af5f7bd768cacf9acbf70da2cf607f55567de34f263182984ff36a91e9cbb48918ab3483632fc1427ffad3124043b7111a213edda117c81c104a3351260afbc2b00ab567f82d9462916c8101a72e7fd3995b8734f8b8af18e415162ae47313c6bc738",
              "type": "AttributeInRange"
            },
            {
              "proof": "b39554bf77b9ad30ef725df82bdb6c5456adf9ac3187ffbeaab1b4ce68782829850f10182deb13eaa94edd3640768224a178b8bac224d12711c7d3bec925db4da9bd1424db872757a1f2e10c9dac40483a69972504e5d69163a9f13c5dc8fc60b7897a2f2d1e623b88284ca5eecea172d05bc25e83acd28f5e9e5a4f2637a0762a8a9bcbf052373d26cf38efbb25223ba91c2bff8115180e290bee9ed17b8e3e392b8bfb805f5ad854041d7a9c7669dc193e6e5091fc2fd38ac35eadb755d4b356efb4505072d3ca29c2158af6d2feb1faf939839a9b7d37b384ac3761bb7020319d8e2792cdd20ab483307f0004fa49fc9d9658daf7a7363f05767db6b1f73c344bff03f320bda0fc59a32d165b980c02d21416277a24231c0389b34f502c32000000028c4e5cf1c3505e536b50580d287728d58433e2e471af1500eefffa8d3db7eadbcc4115abcb58bc3cbad27fdd6b22676781235df2401fad1abaf9338f753c4d6606a4a2e04cf89347b398419169238a7fdc1d0ad7f1091db98cf1ea11b082be0a86aa22a16e1e022931fa71e69066894d15cd8525c87dcb1391b0b3502e0b96af9fcf7f6abd60030319137ec20d2d563196d9721142c308f02a8e6ff29fe113a6bc09f67ae02612c7c8b0fba524d7e077efecdbdc26320f10531a4dbd643f1a4e0a08dea12abf4eb723607be444120d6051bea73224fea2c33c3c335db19738536d0a8b7f89664da783709c21068e633e17b8ef6a04ff82235bd11aa73c565e9b",
              "type": "AttributeInSet"
            },
            {
              "proof": "8b69df7282cd3234e4423e85d15c09d49fc2005e869a4876fec01369c3b0ec0ae6f710797b4e5294a7fdf72c05341b6887da98066400436af27e739c140e3a481df2845cd78df942a2c0fb01429d5b04cd96b18c0b2bbf764b533a6f095edbeaaa72ae5ea7540bd7987ace8571e79822d6cab88b070cabe1d7102a01df2070d244548f1c0ea7524acc3078c9af52cd9295309836a5f188743eec08c2009c9510abdfd2fd67363ba5f4900d91fbe114f3c45fb6202e9f64a65a29c14e30e1986e1dd79a31dacf9f7804ba85b984525fc58be01578a8daef7530f98a6c92bc9a5a461af99e831c4094455010a2c58ed43c485e26733ca9a655a2ad5a9418fcd651130e22e918477fe17d3a1b850a837cdf8c8470025e6ed72b26092e2441580c45000000028f7d1d30615527b6882ac3d2e81d9568c50b64e8a68b233edf6237a891263ba6fd4e553bbf8975286c680ae6b1654989b7ac6688ba61e05683d3ad98b26e5ea8ee4d43d5dbaa91e304f6c38fc20be2801d9f4ec8d7438a14cfc1ea2d5229d90b91f280db6a74a3e6752cb24fa50692fd26948a63b87122ecb0e855f2ed1bb0b4b945766b2b6b7b1ea6473a5d878348099735dcb385a81381d2f4fc1d74bf38f7daa645e3e789f6f54485aebab151868ab2a6c8cdb6668dd7631e891d52dc12974e830668e2e8ef4010eec1b9a0456e0d40497c877abd9276de28b26eb986754217966dd19476ce48af7395bd71d5f98a5db3b8b21df3b8fcfbbc2007ad3ee60d",
              "type": "AttributeNotInSet"
            },
            {
              "proof": "b2a44460fcbf28d7ce0fce6c677113a88b88ec272d3cfac24d33afc47b6fa15259af84fa6543ef673cbd18a44d47420c8c53d7eaf9272dfa62fadd8d118c2055480b6494a67b0346c9fa0b2ba2cba9c0591224a2ed7b399ea35b89111a53059c8c7d20b41dfc713a82582e25874c162bf717cfdf7ab0f3dedc22fed5633b870c5eb714a00fc37e666bef3fc6814dee1d90f2b115a623605374b71a090959bee2dd551bf1a48fb27753fc3d4b9a8d8da806bd1e5d1365d0e2d6cf7147556777262489d5a31c46c9f23dba228d44245486f419d24f4251e2a63ba560f0ce42d6b25958729f2e30c3a4c341268ed85a0f356986599bd369bc510445fe1538ebf1bc500b47521554e8be3f453b00ef59fb98c4578ec2fe3cc888c07ff6201f4f5faa000000078ea76171f1796ae2db162060121747819af4f2450977132eb14fc6fb5a63a9477f31393cac24dfb4068c432fa62d87608d433fe841e5c913d4d82aee458e3a89d8f086db9b665909ad32bc0f67f24fa8f043c12adb283687c6838d9d9759840db5379d4ac2adb0456d50e504130f2dab1fdbf915860291425a70e9fcabb74df4f871a763b7c0466ed5a640f6a0a6efda8ee6ab7c162117f60ada430eb670a27743e7ce90c3dd112611c7e5b343202122139a5a32203a5939f71776f677bfd087b162c88efaa180b09dbf2c8da72e1461c666f753ba917290a1e46427dd953baa721f67ce975896d4bb2609a9a782b95a8e6cec6b4cfb6ae8f54cb46737c4cab442017e2983757c3d69132a3a27dd8fbe44799adb7cdf321db02d0740eba3e702b154e40752fd72449946772f6f88deaf25a50e648382d52a22fdba2632313e02b7c99974bee4c0263154ac58e43482ea87b622fea91b77b1e71d9c1d620b9c71ab95da9b09c58d2ea6bd45ddb7797e33373e8f2526540723e2b9501d39edddcba67fff703a703d89e59c3c5ff602549600ff7f45575b65cb15a50117173755702b9ba629f88ac0ded75801b922dcc2d6a6b4d859818e546e58c3812fbb61fc37401620b6f01e1da394b2c033d708e2089673492da20537e471de0aae3ff7a005b01011d3e7f524235ea56432a6eb543dcc7a3babb8e72b912995e59937776568c5a951a825e39ebf0f467cc4af13b7e1a19ec1802373974e20f2140f8ac038ed0c1227433d69c567ab2f52b5232e7eae74a35767e2400a3b6c45bd63125fe94ea3401d4d87a2c5c222ecc2afa0bf72cbc48d8240ae13248b13958cc6f60870736f2a1e79eb9e2233260f909d2535b20197fdc0c6351efd61c7b723f6e25128f7ad0326e2d29521cf0155eb5787b520ba980627867c67238697da551ccf659666387b3776ffab278f7d6093ad61f88b66cc960b6d0592b32664388b9e6a9d98411e4b4db9484c0a3000fb8ecbe8f09e3a82026c5e0f6e432c24dd24aa98a61f3d",
              "type": "AttributeInRange"
            },
            {
              "attribute": "testvalue",
              "proof": "6cb212f8809780343123510b29d72f449999cb81f55f493c44ebb4c465ae786c1ac3bdbd9ab4f0f4a721915c23063813830c9da8ba0f136592ff63136ab7bdfc",
              "type": "RevealAttribute"
            }
          ],
          "type": "ConcordiumZKProofV3"
        },
        "statement": [
          {
            "attributeTag": "dob",
            "lower": 80,
            "type": "AttributeInRange",
            "upper": 1237
          },
          {
            "attributeTag": "sex",
            "set": [
              "aa",
              "ff",
              "zz"
            ],
            "type": "AttributeInSet"
          },
          {
            "attributeTag": "lastName",
            "set": [
              "aa",
              "ff",
              "zz"
            ],
            "type": "AttributeNotInSet"
          },
          {
            "attributeTag": "countryOfResidence",
            "lower": {
              "timestamp": "2023-08-27T23:12:15Z",
              "type": "date-time"
            },
            "type": "AttributeInRange",
            "upper": {
              "timestamp": "2023-08-29T23:12:15Z",
              "type": "date-time"
            }
          },
          {
            "attributeTag": "nationality",
            "type": "RevealAttribute"
          }
        ]
      },
      "issuer": "did:ccd:testnet:idp:17",
      "type": [
        "VerifiableCredential",
        "ConcordiumVerifiableCredential"
      ]
    }
  ]
}
        "#;
        assert_eq!(
            remove_whitespace(&proof_json),
            remove_whitespace(expected_proof_json),
            "proof json"
        );
        let proof_deserialized: Presentation<ArCurve, Web3IdAttribute> =
            serde_json::from_str(&proof_json).unwrap();
        assert_eq!(proof_deserialized, proof);
    }

    /// Tests JSON serialization and deserialization of request and presentation. Test
    /// uses web3 credentials.
    #[test]
    fn test_request_and_presentation_web3_json() {
        let challenge = Sha256Challenge::new(fixtures::seed0().gen());

        let global_context = GlobalContext::generate("Test".into());

        let web3_cred_fixture = fixtures::web3_credentials_fixture(
            [
                ("3".into(), Web3IdAttribute::Numeric(137)),
                (
                    "1".into(),
                    Web3IdAttribute::String(AttributeKind::try_new("xkcd".into()).unwrap()),
                ),
                (
                    "2".into(),
                    Web3IdAttribute::String(AttributeKind::try_new("aa".into()).unwrap()),
                ),
                (
                    "5".into(),
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

        let credential_statements = vec![CredentialStatement::Web3Id(Web3IdCredentialStatement {
            ty: [
                "VerifiableCredential".into(),
                "ConcordiumVerifiableCredential".into(),
                "TestCredential".into(),
            ]
            .into_iter()
            .collect(),
            network: Network::Testnet,
            contract: web3_cred_fixture.contract,
            credential: web3_cred_fixture.cred_id,
            statements: vec![
                AtomicStatement::AttributeInRange {
                    statement: AttributeInRangeStatement {
                        attribute_tag: "3".into(),
                        lower: Web3IdAttribute::Numeric(80),
                        upper: Web3IdAttribute::Numeric(1237),
                        _phantom: PhantomData,
                    },
                },
                AtomicStatement::AttributeInSet {
                    statement: AttributeInSetStatement {
                        attribute_tag: "2".into(),
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
                        attribute_tag: "1".into(),
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
                        attribute_tag: "5".into(),
                    },
                },
            ],
        })];

        let request = Request::<ArCurve, Web3IdAttribute> {
            challenge,
            credential_statements,
        };

        let request_json = serde_json::to_string_pretty(&request).unwrap();
        println!("request:\n{}", request_json);
        let expected_request_json = r#"
{
  "challenge": "7fb27b941602d01d11542211134fc71aacae54e37e7d007bbb7b55eff062a284",
  "credentialStatements": [
    {
      "id": "did:ccd:testnet:sci:1337:42/credentialEntry/ee1aa49a4459dfe813a3cf6eb882041230c7b2558469de81f87c9bf23bf10a03",
      "statement": [
        {
          "attributeTag": "3",
          "lower": 80,
          "type": "AttributeInRange",
          "upper": 1237
        },
        {
          "attributeTag": "2",
          "set": [
            "aa",
            "ff",
            "zz"
          ],
          "type": "AttributeInSet"
        },
        {
          "attributeTag": "1",
          "set": [
            "aa",
            "ff",
            "zz"
          ],
          "type": "AttributeNotInSet"
        },
        {
          "attributeTag": "countryOfResidence",
          "lower": {
            "timestamp": "2023-08-27T23:12:15Z",
            "type": "date-time"
          },
          "type": "AttributeInRange",
          "upper": {
            "timestamp": "2023-08-29T23:12:15Z",
            "type": "date-time"
          }
        },
        {
          "attributeTag": "5",
          "type": "RevealAttribute"
        }
      ],
      "type": [
        "ConcordiumVerifiableCredential",
        "TestCredential",
        "VerifiableCredential"
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
        let request_deserialized: Request<ArCurve, Web3IdAttribute> =
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
                [web3_cred_fixture.commitment_inputs()].into_iter(),
                &mut fixtures::seed0(),
                now,
            )
            .expect("prove");

        let proof_json = serde_json::to_string_pretty(&proof).unwrap();
        println!("proof:\n{}", proof_json);
        let expected_proof_json = r#"
{
  "presentationContext": "7fb27b941602d01d11542211134fc71aacae54e37e7d007bbb7b55eff062a284",
  "proof": {
    "created": "2023-08-28T23:12:15Z",
    "proofValue": [
      "dee977ac4e8dbbdec77ebd3c82a061b1ed7e39216a7ea69a3b8d52a40492339ab63ea8b7df4ed5cda2c8c3bfb31a5f88db81bd4a51f2367bec9b49ce718eb801"
    ],
    "type": "ConcordiumWeakLinkingProofV1"
  },
  "type": "VerifiablePresentation",
  "verifiableCredential": [
    {
      "credentialSubject": {
        "id": "did:ccd:testnet:pkc:ee1aa49a4459dfe813a3cf6eb882041230c7b2558469de81f87c9bf23bf10a03",
        "proof": {
          "commitments": {
            "commitments": {
              "1": "9443780e625e360547c5a6a948de645e92b84d91425f4d9c0455bcf6040ef06a741b6977da833a1552e081fb9c4c9318",
              "2": "83a4e3bc337339a16a97dfa4bfb426f7e660c61168f3ed922dcf26d7711e083faa841d7e70d44a5f090a9a6a67eff5ad",
              "3": "a26ce49a7a289e68eaa43a0c4c33b2055be159f044eabf7d0282d1d9f6a0109956d7fb7b6d08c9f0f2ac6a42d2c68a47",
              "5": "8ae7a7fc631dc8566d0db1ce0258ae9b025ac5535bc7206db92775459ba291789ae6c40687763918c6c297b636b3991c",
              "countryOfResidence": "8e3c148518f00cd370cfeebdf0b09bec7376b859419e2585157adb38f4e87df35f70b087427fd22cac5d19d095dae8b2"
            },
            "signature": "fcd7470cfcee4459b0187855962895b22c475f4d495e843a62073632daaa9b8b83915bfeee88fcaf31866c2ca00fc59f92b7b18f2b39d4f62ac57b4e8ccbcc0a"
          },
          "created": "2023-08-28T23:12:15Z",
          "proofValue": [
            {
              "proof": "b12365d42dbcdda54216b524d94eda74809018b8179d90c747829da5d24df4b2d835d7f77879cf52d5b1809564c5ec49990998db469e5c04553de3f787a3998d660204fe2dd1033a310bfc06ab8a9e5426ff90fdaf554ac11e96bbf18b1e1da8a881ba424d4deb7715880d015d04a64fd37dfef5ec71d48efee4e8d4d640c505f47d6bb75c52545f01889aa503809d06835320bdc1035e9143aea9bffcb12e904549c4f4885ffcb11c4956b362153010506a4d2959a524be07dc01d717c7e3812d41eaf65a6feabe01babf8a7ae81b9726fd6ee688cd241b31c8219b928d2de7073df321c28040aea5820d8e52af2a23d9da963b335a7452473bdda093a4f8103c32680db7441639eac6d1279ed855ba5cd009a5d9999d4f48f2db031c1b2f3d00000007a7e39d70b58b37af8722528536e1ecd898f4b5060d39eeed8713bf28d58e963ab00e9b46cac7f542240515a9b477b6268322f52bafd7bb479c23c68c275b67fba7c7ccd4b386e61ef4b48d6bfbbeba45fcef3da404ea89c7f082838f8c97f6a88fcac670270f88647c325d842badb22aeec2876b956940b27945e5eb93aaf1d1ab8b2881dd8ebeb27a1871fa1a9e02db873c84ae38d0505fe0c40fca21fa757e928af08077716082cced518f315d694b32fe06568e5b3d1602062747b8911947b17f6535323fcb1a11f4e1807f7f10ad7dec744245bf33f4a183d4e1778be73f4f2028cc9b5731f54dc073763776979d96cf54b71d71f22d8035f7f01149bb205044d95c64be878f3d02a17b375df761b4e14f74a810d3e5de4e7790d19fa712a832cf4345394e0dfbf643d36e60cecc57585601fded8a44cde6e43be56c1a679eb0ccf5e66994d8e9b0354d128045eea70257f31a6c934ea4f4465b903d0dc64cacde6219d93500c798a1ad5abe63e067e2a23690bbc865b7aaaa557f782c4fb2cb9b2d4b0a81e8566627d546d21450e38d922c6749900808ddf06e6f01da92d7fcee94c66ebfa3058bcbfdbf655e9cac0bf73d693d0e57ec3d457910110a67e9124ee7814bf8f6c5836e153dd3a95355a8218df1f8aec1cd6213349e7f16d795ccf1d3a28fe24d63136909e5504faf640c2a99b12cb5a39ecc54a0b60081f00235adc9451b0aabfab24fc9d40dffc8ac9b2111f3369e941090b3242ad8334a54b7ec4940ae23ea4ad23bbef2376737977939097918f37c04b989f2d16a7d88b50818a60c730de62214903bfcfce0a45c107fd441f3b0d5da23afe5ad03baa0d6f1bf78aeb8ce94d4852c358c8200919337e4915f9732e74ebf6b0aa99af5f7bd768cacf9acbf70da2cf607f55567de34f263182984ff36a91e9cbb48918ab3483632fc1427ffad3124043b7111a213edda117c81c104a3351260afbc2b00ab567f82d9462916c8101a72e7fd3995b8734f8b8af18e415162ae47313c6bc738",
              "type": "AttributeInRange"
            },
            {
              "proof": "b39554bf77b9ad30ef725df82bdb6c5456adf9ac3187ffbeaab1b4ce68782829850f10182deb13eaa94edd3640768224a178b8bac224d12711c7d3bec925db4da9bd1424db872757a1f2e10c9dac40483a69972504e5d69163a9f13c5dc8fc60b7897a2f2d1e623b88284ca5eecea172d05bc25e83acd28f5e9e5a4f2637a0762a8a9bcbf052373d26cf38efbb25223ba91c2bff8115180e290bee9ed17b8e3e392b8bfb805f5ad854041d7a9c7669dc193e6e5091fc2fd38ac35eadb755d4b356efb4505072d3ca29c2158af6d2feb1faf939839a9b7d37b384ac3761bb7020319d8e2792cdd20ab483307f0004fa49fc9d9658daf7a7363f05767db6b1f73c344bff03f320bda0fc59a32d165b980c02d21416277a24231c0389b34f502c32000000028c4e5cf1c3505e536b50580d287728d58433e2e471af1500eefffa8d3db7eadbcc4115abcb58bc3cbad27fdd6b22676781235df2401fad1abaf9338f753c4d6606a4a2e04cf89347b398419169238a7fdc1d0ad7f1091db98cf1ea11b082be0a86aa22a16e1e022931fa71e69066894d15cd8525c87dcb1391b0b3502e0b96af9fcf7f6abd60030319137ec20d2d563196d9721142c308f02a8e6ff29fe113a6bc09f67ae02612c7c8b0fba524d7e077efecdbdc26320f10531a4dbd643f1a4e0a08dea12abf4eb723607be444120d6051bea73224fea2c33c3c335db19738536d0a8b7f89664da783709c21068e633e17b8ef6a04ff82235bd11aa73c565e9b",
              "type": "AttributeInSet"
            },
            {
              "proof": "8b69df7282cd3234e4423e85d15c09d49fc2005e869a4876fec01369c3b0ec0ae6f710797b4e5294a7fdf72c05341b6887da98066400436af27e739c140e3a481df2845cd78df942a2c0fb01429d5b04cd96b18c0b2bbf764b533a6f095edbeaaa72ae5ea7540bd7987ace8571e79822d6cab88b070cabe1d7102a01df2070d244548f1c0ea7524acc3078c9af52cd9295309836a5f188743eec08c2009c9510abdfd2fd67363ba5f4900d91fbe114f3c45fb6202e9f64a65a29c14e30e1986e1dd79a31dacf9f7804ba85b984525fc58be01578a8daef7530f98a6c92bc9a5a461af99e831c4094455010a2c58ed43c485e26733ca9a655a2ad5a9418fcd651130e22e918477fe17d3a1b850a837cdf8c8470025e6ed72b26092e2441580c45000000028f7d1d30615527b6882ac3d2e81d9568c50b64e8a68b233edf6237a891263ba6fd4e553bbf8975286c680ae6b1654989b7ac6688ba61e05683d3ad98b26e5ea8ee4d43d5dbaa91e304f6c38fc20be2801d9f4ec8d7438a14cfc1ea2d5229d90b91f280db6a74a3e6752cb24fa50692fd26948a63b87122ecb0e855f2ed1bb0b4b945766b2b6b7b1ea6473a5d878348099735dcb385a81381d2f4fc1d74bf38f7daa645e3e789f6f54485aebab151868ab2a6c8cdb6668dd7631e891d52dc12974e830668e2e8ef4010eec1b9a0456e0d40497c877abd9276de28b26eb986754217966dd19476ce48af7395bd71d5f98a5db3b8b21df3b8fcfbbc2007ad3ee60d",
              "type": "AttributeNotInSet"
            },
            {
              "proof": "b2a44460fcbf28d7ce0fce6c677113a88b88ec272d3cfac24d33afc47b6fa15259af84fa6543ef673cbd18a44d47420c8c53d7eaf9272dfa62fadd8d118c2055480b6494a67b0346c9fa0b2ba2cba9c0591224a2ed7b399ea35b89111a53059c8c7d20b41dfc713a82582e25874c162bf717cfdf7ab0f3dedc22fed5633b870c5eb714a00fc37e666bef3fc6814dee1d90f2b115a623605374b71a090959bee2dd551bf1a48fb27753fc3d4b9a8d8da806bd1e5d1365d0e2d6cf7147556777262489d5a31c46c9f23dba228d44245486f419d24f4251e2a63ba560f0ce42d6b25958729f2e30c3a4c341268ed85a0f356986599bd369bc510445fe1538ebf1bc500b47521554e8be3f453b00ef59fb98c4578ec2fe3cc888c07ff6201f4f5faa000000078ea76171f1796ae2db162060121747819af4f2450977132eb14fc6fb5a63a9477f31393cac24dfb4068c432fa62d87608d433fe841e5c913d4d82aee458e3a89d8f086db9b665909ad32bc0f67f24fa8f043c12adb283687c6838d9d9759840db5379d4ac2adb0456d50e504130f2dab1fdbf915860291425a70e9fcabb74df4f871a763b7c0466ed5a640f6a0a6efda8ee6ab7c162117f60ada430eb670a27743e7ce90c3dd112611c7e5b343202122139a5a32203a5939f71776f677bfd087b162c88efaa180b09dbf2c8da72e1461c666f753ba917290a1e46427dd953baa721f67ce975896d4bb2609a9a782b95a8e6cec6b4cfb6ae8f54cb46737c4cab442017e2983757c3d69132a3a27dd8fbe44799adb7cdf321db02d0740eba3e702b154e40752fd72449946772f6f88deaf25a50e648382d52a22fdba2632313e02b7c99974bee4c0263154ac58e43482ea87b622fea91b77b1e71d9c1d620b9c71ab95da9b09c58d2ea6bd45ddb7797e33373e8f2526540723e2b9501d39edddcba67fff703a703d89e59c3c5ff602549600ff7f45575b65cb15a50117173755702b9ba629f88ac0ded75801b922dcc2d6a6b4d859818e546e58c3812fbb61fc37401620b6f01e1da394b2c033d708e2089673492da20537e471de0aae3ff7a005b01011d3e7f524235ea56432a6eb543dcc7a3babb8e72b912995e59937776568c5a951a825e39ebf0f467cc4af13b7e1a19ec1802373974e20f2140f8ac038ed0c1227433d69c567ab2f52b5232e7eae74a35767e2400a3b6c45bd63125fe94ea3401d4d87a2c5c222ecc2afa0bf72cbc48d8240ae13248b13958cc6f60870736f2a1e79eb9e2233260f909d2535b20197fdc0c6351efd61c7b723f6e25128f7ad0326e2d29521cf0155eb5787b520ba980627867c67238697da551ccf659666387b3776ffab278f7d6093ad61f88b66cc960b6d0592b32664388b9e6a9d98411e4b4db9484c0a3000fb8ecbe8f09e3a82026c5e0f6e432c24dd24aa98a61f3d",
              "type": "AttributeInRange"
            },
            {
              "attribute": "testvalue",
              "proof": "6cb212f8809780343123510b29d72f449999cb81f55f493c44ebb4c465ae786c1ac3bdbd9ab4f0f4a721915c23063813830c9da8ba0f136592ff63136ab7bdfc",
              "type": "RevealAttribute"
            }
          ],
          "type": "ConcordiumZKProofV3"
        },
        "statement": [
          {
            "attributeTag": "3",
            "lower": 80,
            "type": "AttributeInRange",
            "upper": 1237
          },
          {
            "attributeTag": "2",
            "set": [
              "aa",
              "ff",
              "zz"
            ],
            "type": "AttributeInSet"
          },
          {
            "attributeTag": "1",
            "set": [
              "aa",
              "ff",
              "zz"
            ],
            "type": "AttributeNotInSet"
          },
          {
            "attributeTag": "countryOfResidence",
            "lower": {
              "timestamp": "2023-08-27T23:12:15Z",
              "type": "date-time"
            },
            "type": "AttributeInRange",
            "upper": {
              "timestamp": "2023-08-29T23:12:15Z",
              "type": "date-time"
            }
          },
          {
            "attributeTag": "5",
            "type": "RevealAttribute"
          }
        ]
      },
      "issuer": "did:ccd:testnet:sci:1337:42/issuer",
      "type": [
        "ConcordiumVerifiableCredential",
        "TestCredential",
        "VerifiableCredential"
      ]
    }
  ]
}
        "#;
        assert_eq!(
            remove_whitespace(&proof_json),
            remove_whitespace(expected_proof_json),
            "proof json"
        );
        let proof_deserialized: Presentation<ArCurve, Web3IdAttribute> =
            serde_json::from_str(&proof_json).unwrap();
        assert_eq!(proof_deserialized, proof);
    }
}

#[cfg(test)]
mod fixtures {
    use super::*;
    use crate::base::CredentialRegistrationID;
    use std::fmt::Debug;

    use crate::common;
    use crate::curve_arithmetic::Value;
    use crate::id::constants::{ArCurve, IpPairing};
    use crate::id::id_proof_types::{
        AttributeInRangeStatement, AttributeInSetStatement, AttributeNotInSetStatement,
        RevealAttributeStatement,
    };
    use crate::id::types::{
        ArInfos, AttributeList, AttributeTag, IdentityObjectV1, IpData, IpIdentity, YearMonth,
    };
    use crate::id::{identity_provider, test};
    use crate::web3id::{
        CredentialHolderId, OwnedCommitmentInputs, OwnedIdentityCommitmentInputs, Web3IdAttribute,
    };
    use concordium_contracts_common::ContractAddress;
    use rand::SeedableRng;

    pub struct IdentityCredentialsFixture<AttributeType: Attribute<<ArCurve as Curve>::Scalar>> {
        pub commitment_inputs:
            OwnedCommitmentInputs<IpPairing, ArCurve, AttributeType, ed25519_dalek::SigningKey>,
        pub credential_inputs: CredentialsInputs<IpPairing, ArCurve>,
        pub issuer: IpIdentity,
    }

    impl<AttributeType: Attribute<<ArCurve as Curve>::Scalar>>
        IdentityCredentialsFixture<AttributeType>
    {
        pub fn commitment_inputs(
            &self,
        ) -> CommitmentInputs<'_, IpPairing, ArCurve, AttributeType, ed25519_dalek::SigningKey>
        {
            CommitmentInputs::from(&self.commitment_inputs)
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
        let valid_to = YearMonth::try_from(2022 << 8 | 5).unwrap(); // May 2022
        let created_at = YearMonth::try_from(2020 << 8 | 5).unwrap(); // May 2020
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
        );
        let alist = create_attribute_list(attrs);
        let ip_sig =
            identity_provider::verify_credentials_v1(&pio, context, &alist, &ip_secret_key)
                .expect("verify credentials");

        let id_object = IdentityObjectV1 {
            pre_identity_object: pio,
            alist: alist.clone(),
            signature: ip_sig,
        };

        let commitment_inputs =
            OwnedCommitmentInputs::Identity(Box::new(OwnedIdentityCommitmentInputs {
                ip_info: ip_info.clone(),
                ar_infos: ars_infos.clone(),
                id_object,
                id_object_use_data,
            }));

        let credential_inputs = CredentialsInputs::Identity {
            ip_info: ip_info.clone(),
            ars_infos,
        };

        IdentityCredentialsFixture {
            commitment_inputs,
            credential_inputs,
            issuer: ip_info.ip_identity,
        }
    }

    pub struct AccountCredentialsFixture<AttributeType: Attribute<<ArCurve as Curve>::Scalar>> {
        pub commitment_inputs:
            OwnedCommitmentInputs<IpPairing, ArCurve, AttributeType, ed25519_dalek::SigningKey>,
        pub credential_inputs: CredentialsInputs<IpPairing, ArCurve>,
        pub cred_id: CredentialRegistrationID,
    }

    impl<AttributeType: Attribute<<ArCurve as Curve>::Scalar>>
        AccountCredentialsFixture<AttributeType>
    {
        pub fn commitment_inputs(
            &self,
        ) -> CommitmentInputs<'_, IpPairing, ArCurve, AttributeType, ed25519_dalek::SigningKey>
        {
            CommitmentInputs::from(&self.commitment_inputs)
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

        let commitment_inputs = OwnedCommitmentInputs::Account {
            values: attrs,
            randomness: attr_rand,
            issuer: IpIdentity::from(17u32),
        };

        let credential_inputs = CredentialsInputs::Account {
            commitments: attr_cmm,
        };

        AccountCredentialsFixture {
            commitment_inputs,
            credential_inputs,
            cred_id,
        }
    }

    pub struct Web3CredentialsFixture {
        pub commitment_inputs:
            OwnedCommitmentInputs<IpPairing, ArCurve, Web3IdAttribute, ed25519_dalek::SigningKey>,
        pub credential_inputs: CredentialsInputs<IpPairing, ArCurve>,
        pub cred_id: CredentialHolderId,
        pub contract: ContractAddress,
        pub issuer_key: ed25519_dalek::SigningKey,
    }

    impl Web3CredentialsFixture {
        pub fn commitment_inputs(
            &self,
        ) -> CommitmentInputs<'_, IpPairing, ArCurve, Web3IdAttribute, ed25519_dalek::SigningKey>
        {
            CommitmentInputs::from(&self.commitment_inputs)
        }
    }

    pub fn seed0() -> rand::rngs::StdRng {
        rand::rngs::StdRng::seed_from_u64(0)
    }

    pub fn web3_credentials_fixture(
        attrs: BTreeMap<String, Web3IdAttribute>,
        global_context: &GlobalContext<ArCurve>,
    ) -> Web3CredentialsFixture {
        let signer_key = ed25519_dalek::SigningKey::generate(&mut seed0());
        let cred_id = CredentialHolderId::new(signer_key.verifying_key());

        let issuer_key = ed25519_dalek::SigningKey::generate(&mut seed0());
        let contract = ContractAddress::new(1337, 42);

        let mut attr_rand = BTreeMap::new();
        let mut attr_cmm = BTreeMap::new();
        for (tag, attr) in &attrs {
            let attr_scalar = Value::<ArCurve>::new(attr.to_field_element());
            let (cmm, cmm_rand) = global_context
                .on_chain_commitment_key
                .commit(&attr_scalar, &mut seed0());
            attr_rand.insert(tag.clone(), cmm_rand);
            attr_cmm.insert(tag.clone(), cmm);
        }

        let signed_cmms = SignedCommitments::from_secrets(
            &global_context,
            &attrs,
            &attr_rand,
            &cred_id,
            &issuer_key,
            contract,
        )
        .unwrap();

        let commitment_inputs = OwnedCommitmentInputs::Web3Issuer {
            signer: signer_key,
            values: attrs,
            randomness: attr_rand,
            signature: signed_cmms.signature,
        };

        let credential_inputs = CredentialsInputs::Web3 {
            issuer_pk: issuer_key.verifying_key().into(),
        };

        Web3CredentialsFixture {
            commitment_inputs,
            credential_inputs,
            cred_id,
            contract,
            issuer_key,
        }
    }
}
