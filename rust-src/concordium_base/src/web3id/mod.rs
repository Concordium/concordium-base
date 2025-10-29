//! Functionality related to constructing and verifying Web3ID proofs.
//!
//! The main entrypoints in this module are the [`verify`](Presentation::verify)
//! function for verifying [`Presentation`]s in the context of given public
//! data, and the [`prove`](Request::prove) function for constructing a proof.

pub mod did;
mod proofs;

#[cfg(test)]
mod test;

use crate::id::types::{
    ArInfos, CredentialValidity, HasIdentityObjectFields, IdObjectUseData,
    IdentityAttributesCredentialsInfo, IdentityObjectV1, IpContextOnly, IpInfo,
};
use crate::{
    base::CredentialRegistrationID,
    cis4_types::IssuerKey,
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

use crate::curve_arithmetic::Pairing;
use serde::de::DeserializeOwned;
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

/// A statement about a single credential, either an identity credential or a
/// Web3 credential.
#[derive(Debug, Clone, serde::Deserialize, PartialEq, Eq)]
#[serde(
    try_from = "serde_json::Value",
    bound(deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + DeserializeOwned")
)]
pub enum CredentialStatement<C: Curve, AttributeType: Attribute<C::Scalar>> {
    /// Statement about an account credential derived from an identity issued by an
    /// identity provider.
    Account {
        network: Network,
        cred_id: CredentialRegistrationID,
        statement: Vec<AtomicStatement<C, AttributeTag, AttributeType>>,
    },
    /// Statement about identity attributes derived directly from an identity issued by an
    /// identity provider.
    Identity {
        network: Network,
        /// Attribute statements
        statement: Vec<AtomicStatement<C, AttributeTag, AttributeType>>,
    },
    /// Statement about a credential issued by a Web3 identity provider, a smart
    /// contract.
    Web3Id {
        /// The credential type. This is chosen by the provider to provide
        /// some information about what the credential is about.
        ty: BTreeSet<String>,
        network: Network,
        /// Reference to a specific smart contract instance that issued the
        /// credential.
        contract: ContractAddress,
        /// Credential identifier inside the contract.
        credential: CredentialHolderId,
        statement: Vec<AtomicStatement<C, String, AttributeType>>,
    },
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
            IdentifierType::Credential { cred_id } => {
                let statement = get_field(&mut value, "statement")?;
                Ok(Self::Account {
                    network: id.network,
                    cred_id,
                    statement: serde_json::from_value(statement)?,
                })
            }
            IdentifierType::ContractData {
                address,
                entrypoint,
                parameter,
            } => {
                let statement = get_field(&mut value, "statement")?;
                let ty = get_field(&mut value, "type")?;
                anyhow::ensure!(entrypoint == "credentialEntry", "Invalid entrypoint.");
                Ok(Self::Web3Id {
                    ty: serde_json::from_value(ty)?,
                    network: id.network,
                    contract: address,
                    credential: CredentialHolderId::new(ed25519_dalek::VerifyingKey::from_bytes(
                        &parameter.as_ref().try_into()?,
                    )?),
                    statement: serde_json::from_value(statement)?,
                })
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
            CredentialStatement::Account {
                network,
                cred_id,
                statement,
            } => {
                let json = serde_json::json!({
                    "id": format!("did:ccd:{network}:cred:{cred_id}"),
                    "statement": statement,
                });
                json.serialize(serializer)
            }
            CredentialStatement::Web3Id {
                network,
                contract,
                credential,
                statement,
                ty,
            } => {
                let json = serde_json::json!({
                    "type": ty,
                    "id": format!("did:ccd:{network}:sci:{}:{}/credentialEntry/{}", contract.index, contract.subindex, credential),
                    "statement": statement,
                });
                json.serialize(serializer)
            }
            CredentialStatement::Identity { .. } => {
                todo!()
            }
        }
    }
}

/// A pair of a statement and a proof.
pub type StatementWithProof<C, TagType, AttributeType> = (
    AtomicStatement<C, TagType, AttributeType>,
    AtomicProof<C, AttributeType>,
);

/// Metadata of a single credential.
pub enum CredentialMetadata {
    /// Metadata of an account credential, i.e., a credential derived from an
    /// identity object.
    Account {
        issuer: IpIdentity,
        cred_id: CredentialRegistrationID,
    },
    /// Metadata of identity attributes derived directly from an
    /// identity object.
    Identity {
        issuer: IpIdentity,
        validity: CredentialValidity,
    },
    /// Metadata of a Web3Id credential.
    Web3Id {
        contract: ContractAddress,
        holder: CredentialHolderId,
    },
}

/// Metadata about a single [`CredentialProof`].
pub struct ProofMetadata {
    /// Timestamp of when the proof was created.
    pub created: chrono::DateTime<chrono::Utc>,
    pub network: Network,
    /// The DID of the credential the proof is about.
    pub cred_metadata: CredentialMetadata,
}

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: Attribute<C::Scalar>>
    CredentialProof<P, C, AttributeType>
{
    pub fn metadata(&self) -> ProofMetadata {
        match self {
            CredentialProof::Account {
                created,
                network,
                cred_id,
                issuer,
                proofs: _,
            } => ProofMetadata {
                created: *created,
                network: *network,
                cred_metadata: CredentialMetadata::Account {
                    issuer: *issuer,
                    cred_id: *cred_id,
                },
            },
            CredentialProof::Identity {
                created,
                network,
                id_attr_cred_info,
                ..
            } => ProofMetadata {
                created: *created,
                network: *network,
                cred_metadata: CredentialMetadata::Identity {
                    issuer: id_attr_cred_info.values.ip_identity,
                    validity: id_attr_cred_info.values.validity.clone(),
                },
            },
            CredentialProof::Web3Id {
                created,
                holder,
                network,
                contract,
                ty: _,
                commitments: _,
                proofs: _,
            } => ProofMetadata {
                created: *created,
                network: *network,
                cred_metadata: CredentialMetadata::Web3Id {
                    contract: *contract,
                    holder: *holder,
                },
            },
        }
    }

    /// Extract the statement from the proof.
    pub fn statement(&self) -> CredentialStatement<C, AttributeType> {
        match self {
            CredentialProof::Account {
                network,
                cred_id,
                proofs,
                ..
            } => CredentialStatement::Account {
                network: *network,
                cred_id: *cred_id,
                statement: proofs.iter().map(|(x, _)| x.clone()).collect(),
            },
            CredentialProof::Identity {
                network, proofs, ..
            } => CredentialStatement::Identity {
                network: *network,
                statement: proofs.iter().map(|(x, _)| x.clone()).collect(),
            },
            CredentialProof::Web3Id {
                holder,
                network,
                contract,
                ty,
                proofs,
                ..
            } => CredentialStatement::Web3Id {
                ty: ty.clone(),
                network: *network,
                contract: *contract,
                credential: *holder,
                statement: proofs.iter().map(|(x, _)| x.clone()).collect(),
            },
        }
    }
}

#[derive(Clone, serde::Deserialize)]
#[serde(bound(deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + DeserializeOwned"))]
#[serde(try_from = "serde_json::Value")]
/// A proof corresponding to one [`CredentialStatement`]. This contains almost
/// all the information needed to verify it, except the issuer's public key in
/// case of the `Web3Id` proof, and the public commitments in case of the
/// `Account` proof.
pub enum CredentialProof<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
> {
    Account {
        /// Creation timestamp of the proof.
        created: chrono::DateTime<chrono::Utc>,
        network: Network,
        /// Reference to the credential to which this statement applies.
        cred_id: CredentialRegistrationID,
        /// Issuer of this credential, the identity provider index on the
        /// relevant network.
        issuer: IpIdentity,
        proofs: Vec<StatementWithProof<C, AttributeTag, AttributeType>>,
    },
    Identity {
        /// Creation timestamp of the proof.
        created: chrono::DateTime<chrono::Utc>,
        network: Network,
        /// Commitments to attribute values and their proofs
        id_attr_cred_info: IdentityAttributesCredentialsInfo<P, C, AttributeType>,
        proofs: Vec<StatementWithProof<C, AttributeTag, AttributeType>>,
    },
    Web3Id {
        /// Creation timestamp of the proof.
        created: chrono::DateTime<chrono::Utc>,
        /// Owner of the credential, a public key.
        holder: CredentialHolderId,
        network: Network,
        /// Reference to a specific smart contract instance.
        contract: ContractAddress,
        /// The credential type. This is chosen by the provider to provide
        /// some information about what the credential is about.
        ty: BTreeSet<String>,
        /// Commitments that the user has. These are all the commitments that
        /// are part of the credential, indexed by the attribute tag.
        commitments: SignedCommitments<C>,
        /// Individual proofs for statements.
        proofs: Vec<StatementWithProof<C, String, AttributeType>>,
    },
}

/// Commitments signed by the issuer.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, crate::common::Serialize)]
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

impl<
        P: Pairing,
        C: Curve<Scalar = P::ScalarField>,
        AttributeType: Attribute<C::Scalar> + serde::Serialize,
    > serde::Serialize for CredentialProof<P, C, AttributeType>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            CredentialProof::Account {
                created,
                network,
                cred_id,
                issuer,
                proofs,
            } => {
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
            CredentialProof::Web3Id {
                created,
                network,
                contract,
                ty,
                commitments,
                proofs,
                holder,
            } => {
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
            CredentialProof::Identity { .. } => {
                todo!()
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

impl<
        P: Pairing,
        C: Curve<Scalar = P::ScalarField>,
        AttributeType: Attribute<C::Scalar> + serde::de::DeserializeOwned,
    > TryFrom<serde_json::Value> for CredentialProof<P, C, AttributeType>
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
                let IdentifierType::Credential { cred_id } = id.1.ty else {
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
                Ok(Self::Account {
                    created,
                    network: issuer.network,
                    cred_id,
                    issuer: idp_identity,
                    proofs,
                })
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

                Ok(Self::Web3Id {
                    created,
                    holder: CredentialHolderId::new(key),
                    network: issuer.network,
                    contract: address,
                    commitments,
                    proofs,
                    ty,
                })
            }
            _ => anyhow::bail!("Only IDPs and smart contracts can be issuers."),
        }
    }
}

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: Attribute<C::Scalar>>
    crate::common::Serial for CredentialProof<P, C, AttributeType>
{
    fn serial<B: crate::common::Buffer>(&self, out: &mut B) {
        match self {
            CredentialProof::Account {
                created,
                network,
                cred_id,
                proofs,
                issuer,
            } => {
                0u8.serial(out);
                created.timestamp_millis().serial(out);
                network.serial(out);
                cred_id.serial(out);
                issuer.serial(out);
                proofs.serial(out)
            }
            CredentialProof::Web3Id {
                created,
                network,
                contract,
                commitments,
                proofs,
                holder,
                ty,
            } => {
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
            CredentialProof::Identity { .. } => {}
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

/// Context challenge that serves as a distinguishing context when requesting
/// proofs.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, serde::Deserialize, serde::Serialize, Debug)]
pub struct Context {
    /// This part of the challenge is supposed to be provided by the dapp backend (e.g. merchant backend).
    pub given: Vec<ContextProperty>,
    /// This part of the challenge is supposed to be provided by the wallet or ID app.
    pub requested: Vec<ContextProperty>,
}

#[derive(
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    serde::Deserialize,
    serde::Serialize,
    crate::common::Serial,
    crate::common::Deserial,
    Debug,
)]
pub struct ContextProperty {
    pub label: String,
    pub context: String,
}

/// A challenge that can be added to the proof transcript.
#[derive(serde::Deserialize, serde::Serialize)]
// The type is `untagged` to be backward compatible with old proofs and requests.
#[serde(untagged)]
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub enum Challenge {
    Sha256(Sha256Challenge),
    V1(Context),
}

#[derive(Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
#[serde(bound(
    serialize = "C: Curve, AttributeType: Attribute<C::Scalar> + serde::Serialize",
    deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + DeserializeOwned"
))]
/// A request for a proof. This is the statement and challenge. The secret data
/// comes separately.
pub struct Request<C: Curve, AttributeType: Attribute<C::Scalar>> {
    pub challenge: Challenge,
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

#[derive(serde::Deserialize)]
#[serde(bound(deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + DeserializeOwned"))]
#[serde(try_from = "serde_json::Value")]
/// A presentation is the response to a [`Request`]. It contains proofs for
/// statements, ownership proof for all Web3 credentials, and a context. The
/// only missing part to verify the proof are the public commitments.
pub struct Presentation<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
> {
    pub presentation_context: Challenge,
    pub verifiable_credential: Vec<CredentialProof<P, C, AttributeType>>,
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

impl<
        P: Pairing,
        C: Curve<Scalar = P::ScalarField>,
        AttributeType: Attribute<C::Scalar> + DeserializeOwned,
    > TryFrom<serde_json::Value> for Presentation<P, C, AttributeType>
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

impl<
        P: Pairing,
        C: Curve<Scalar = P::ScalarField>,
        AttributeType: Attribute<C::Scalar> + serde::Serialize,
    > serde::Serialize for Presentation<P, C, AttributeType>
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

#[derive(Debug, crate::common::SerdeBase16Serialize, crate::common::Serialize)]
/// A proof that establishes that the owner of the credential itself produced
/// the proof. Technically this means that there is a signature on the entire
/// rest of the presentation using the public key that is associated with the
/// Web3 credential. The identity credentials do not have linking proofs since
/// the owner of those credentials retains full control of their secret
/// material.
struct WeakLinkingProof {
    signature: ed25519_dalek::Signature,
}

#[derive(Debug, serde::Deserialize)]
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

/// The additional inputs, additional to the [`Request`] that are needed to
/// produce a [`Presentation`].
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

/// Public inputs to the verification function. These are the public commitments
/// that are contained in the credentials for identity credentials, and the
/// issuer's public key for Web3ID credentials which do not store commitments on
/// the chain.
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
    use crate::web3id::did::Network;
    use crate::web3id::{Web3IdAttribute, Web3IdCredential};
    use chrono::TimeZone;
    use rand::Rng;
    use crate::id::constants::IpPairing;
    use crate::id::id_proof_types::{AttributeInRangeStatement, AttributeInSetStatement, AttributeNotInSetStatement, RevealAttributeStatement};

    fn remove_whitespace(str: &str) -> String {
        str.chars().filter(|c| !c.is_whitespace()).collect()
    }

    #[test]
    /// Basic test that conversion of Web3IdCredential from/to JSON works.
    fn test_credential_json() {
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

    /// Tests JSON serialization and deserialization of request and presentation.
    #[test]
    fn test_request_and_presentation_json() {
        let challenge = Challenge::Sha256(Sha256Challenge::new(fixtures::seed0().gen()));

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
            ]
                .into_iter()
                .collect(),
            &global_context,
        );

        let credential_statements = vec![CredentialStatement::Account {
            network: Network::Testnet,
            cred_id: acc_cred_fixture.cred_id,
            statement: vec![
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
                AtomicStatement::RevealAttribute {
                    statement: RevealAttributeStatement {
                        attribute_tag: 5.into(),
                    },
                },
            ],
        }];

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
          "attributeTag": "nationality",
          "type": "RevealAttribute"
        }
      ]
    }
  ]
}
"#;
        assert_eq!(remove_whitespace(&request_json), remove_whitespace(expected_request_json), "request json");
        let request_deserialized: Request<ArCurve, Web3IdAttribute> = serde_json::from_str(&request_json).unwrap();
        assert_eq!(request_deserialized, request);

        // the easiest way to construct a presentation, is just to run the prover on a request
        let proof = request
            .clone()
            .prove(
                &global_context,
                [acc_cred_fixture.commitment_inputs()].into_iter(),
            )
            .expect("prove");

        let proof_json = serde_json::to_string_pretty(&proof).unwrap();
        println!("proof:\n{}", proof_json);
        let expected_proof_json = r#"
{
  "presentationContext": "7fb27b941602d01d11542211134fc71aacae54e37e7d007bbb7b55eff062a284",
  "proof": {
    "created": "2025-10-29T07:15:11.147432Z",
    "proofValue": [],
    "type": "ConcordiumWeakLinkingProofV1"
  },
  "type": "VerifiablePresentation",
  "verifiableCredential": [
    {
      "credentialSubject": {
        "id": "did:ccd:testnet:cred:856793e4ba5d058cea0b5c3a1c8affb272efcf53bbab77ee28d3e2270d5041d220c1e1a9c6c8619c84e40ebd70fb583e",
        "proof": {
          "created": "2025-10-29T07:15:11.143263Z",
          "proofValue": [
            {
              "proof": "99ccd3f86795b59a3d08a30dc856d26e323cfca58a164fd728c9324f3b60c81a706c8d3539f7b40daef0553f6dbb8bc18287af1628e3f7b4e2c2accfadbaefddefcbdf28b5c273149855f69315b5dac2a3f9060b9af03c92f89bb04da4f72271924634f60ad6134e1136c3c29c8847caf432e17342e6db304e35a75956d3f7894a850f5b1bef523692bb951b7cc6e6ce8b98070f579697cee918c3beb92046475e69195057584e966b349c814ca36aa9cf55ee3f8528e9532e0c6f61a93d8a795b358beb8b7bee8af393dfa87446b8fe84bd591e574ac45dfda2da40a97d72df07697a0b5e75c73bd0180356ab8c52242f12ca06a5a31b1097af2fb2b75594ee1c2712ea2156c1e87487a570f78a3b52a3221208774e98bfbe296b944eed528a0000000791cabffd3f1a80832eae0b6e33d32016794b4fca67da8074bea27ee96bfce96bf9b73c8596e74409de3ea1f82e68ca349395329a02f3980c0bb2b0f5955409484357374ba640627f33e9d39b5442f4c7d9d0c5142a064408adad5e49c8c10223aa0f38795b47c2b04a4616956ae09bfeb87b16a4088e9fbda03928e93210ceb4de54548cc8246ad3c1939625fc350770a91f8a101dc601abb8e4db53675476169396f80efaedec25822c92fcffe9e685f98b4359710b85ae525cc7143b7193bd8d249c752aa2e7a8c5bc076b71e6cd09f9bd1eb23c696db26a244b2865cc7331c40b5c5916bb9fe44b52d01980db965db395a3b43a7a098e5ebdfa1094d3fdd1a48a951b8b32af319f08d40411340a5903996a266c225f11dc8b7c2d792d8689ae0f193183adcfaf4ec81d3c7f2faf44cdf0927f42275e7ce2d2c2d01e1ff72e2f91989bcb80c58b112ed6f772ea8cd284327c9a5046d22f7a5f1a931bb0e512643f66b35738d1575080f6139756b8d5d77ab64f356bf849bf23af583f04bdb5af1e60cb2d79752ca4c466d098fa17a0aa171e2aef443476befc766de3d02c67f00337900049487146f2a902ba2c4e0aa76a79552639e6646db995005d9244b6b25d85d8c33b040dc89478d238646552d4bee669bcdafe1702350fc12af343ccb0524b8753422c7a71e70f394c358f38c4903ae0a6ba3cdaf76a52aba85dd311bdf74ea9af9700709b9a385fd7bfc17299dec889b3b3cd8f2ea1dae82a16b9c0f1922efa8af86ea0582442075388efd37c016c0366f566dbb3b077106a29fc2292b9a2f587d5b1b64932459ff3332c0f15feefcff4cd90aeb1701025d73c8d48cbb8b86ef233b43472b77b53cd71857ab3f49ec635dfb9d8de2c556814f9cf1af2636dbe5888e8fe6df25887c313d1d980423888866db379fcbc05af545312571d40891c354667ebfa8bd9c6436ba78aff9cad97c46ec34abeb8b8c644949cea2622409db5eeb501cf6e6d3465a560abd7005464a5af8469151b9a25d2cf8144",
              "type": "AttributeInRange"
            },
            {
              "proof": "89b851c6800184c0712153fee55c84df819bd1558c9e0ed42167bd09ee2e8f86fe53706fd54052cc530b9f01fb93b1a182a1b308a62d7d3a2f288c52f2273f23ead5b31f1914bf588778372a073b5aacf9001c457241f0641526a3e222a5febfacdbaf6a2bfd4fbbe232db4e11a0f6b5870f50ff6ebd07a9fe7d3be19c4b54f4769c12038bd739bd1c10b425c557d4438ab4e7f2485ddf9e95b497fca792488072cfc4b3b1c26c732e5f29d53acfd5f6407f18e58345800456de36b0e6f0ea1257a96d6dba20a122ebd224fe08a5d8c7a6758d5b6c9c1ece98e47755f0dd117b1ffc52b6aa946da7a23561f134adefbd1546e565ea1c8be393f83a2d211933c11d0bbdb00f8daf2345ae1d1c7c46552bfed957cae6b510087c3bd047851deb65000000029366bfbb11f95fe5fc222f9aa863882609fccf5dec9e34f1255e914b37ab545cad7b185216f8fd0c2399c89930b4129e844274b0ea74141422a4a4c9f4843ad2bc57e9eda0ba5902134b81668816c1d83329f690a798889ac030b4896583fc328b2c29fc9df5d4d341153a003b3cb4fa894d75a6e25671af5cfeb961a41c6df0afc13db5d9c0d3c7d1147ba62a5429baa3a026ffea8a07a677db3737fdea457387582b36a873fda9b05e319c15fa56777f939003c89c03e51acb69a7999f9f400696d77dc003e5c1ce3b7403f9815fe5b707166e8cb559c2ae94d07e00683f2c46a7362e5266bab1a188190e40ae15c4e765103394bc0fe5bcbdc39c3ebe38bb",
              "type": "AttributeInSet"
            },
            {
              "proof": "886ae46aeadebfe039fb28b66eca4dadafaa38aacc925028ad113a31d1c631125bfdfc4e02817aff4bde3c2ad2fc2c1d815ae32c5b8f4fd63eaaa97d9a1d48df5eb9a6b07e23772e48033b716084af54da798edbcbb0e7e67f331c62aa4c35fea5987168ab121fc0823a2c83a87cc4bc1304292f9bc7662dfccf1d035308fc9dd9b1f6c5f41caea298099caec7ef08708587b6ee12eee9cff7f5181bc12f44936337cf916119a36a2a1abb56ff822ca9635c06a80a82bdc958489ab46042047b2f7fc627adba6274c0574f5ad11e8f9c74feed4e332ebf610a1837843c8198e210d8a31c013c74fbd71edba7b2c0e862b811eb89b48bf058d694e443019cbbad5c0c3c14d376a9b321470402ee300fdfb0240920b0643f58f8aa3a43cf173f740000000291f244b3b7041177de79e0ceed19d272f1debb01e01287e97251d811f969ce22cc5c6cf75e988983c31ba12c903886b1b08c893d56800e348ecc325f1410ae4c0a820014bfd53f63e44b98257b43e8969339631df0c556d2289aa2586f2661be9131ed71e9a727e7f887b8d964ab2b1b77bc967a4232d5629d2da7b1e9d947d66cf65ca0664b7c9cb908edd21f25278eb1b823836c7434145bc206f5bd542d4f428b7bdf5e325ce57fffd148502c2d989b2bd3a670df696f6f1a38573a5206586d7127c5f1f27adbd4fb4740bba6397146161495f8afde713ac2f27fcecb98a16e3a74dd360d59d4d3d1dda39b4647ac0a972177ad7f17dc69a72e41423f95a5",
              "type": "AttributeNotInSet"
            },
            {
              "attribute": "testvalue",
              "proof": "01be44926efee98fd7cef69373dfe54d93a828b7f1c6f74656b2890027d555251ab34d5f999073f32e5fecee9398527caf19a4c328a80028471b8faef40edf6d",
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
        assert_eq!(remove_whitespace(&proof_json), remove_whitespace(expected_proof_json), "proof json");
        let proof_deserialized: Presentation<IpPairing, ArCurve, Web3IdAttribute> = serde_json::from_str(&proof_json).unwrap();
        assert_eq!(proof_deserialized, proof);
    }
}

#[cfg(test)]
mod fixtures {
    use super::*;
    use crate::base::CredentialRegistrationID;

    use crate::curve_arithmetic::Value;
    use crate::id::constants::{ArCurve, IpPairing};
    use crate::id::types::{
        ArInfos, AttributeList, AttributeTag, IdentityObjectV1, IpData, IpIdentity, YearMonth,
    };
    use crate::id::{identity_provider, test};
    use crate::web3id::{
        CredentialHolderId, OwnedCommitmentInputs,
        OwnedIdentityCommitmentInputs, Web3IdAttribute,
    };
    use concordium_contracts_common::ContractAddress;
    use rand::SeedableRng;

    pub struct IdentityCredentialsFixture<AttributeType: Attribute<<ArCurve as Curve>::Scalar>> {
        pub commitment_inputs:
            OwnedCommitmentInputs<IpPairing, ArCurve, AttributeType, ed25519_dalek::SigningKey>,
        pub credential_inputs: CredentialsInputs<IpPairing, ArCurve>,
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

        let credential_inputs = CredentialsInputs::Identity { ip_info, ars_infos };

        IdentityCredentialsFixture {
            commitment_inputs,
            credential_inputs,
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