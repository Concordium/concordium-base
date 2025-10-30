//! Functionality related to constructing and verifying Web3ID proofs.
//!
//! The main entrypoints in this module are the [`verify`](Presentation::verify)
//! function for verifying [`Presentation`]s in the context of given public
//! data, and the [`prove`](Request::prove) function for constructing a proof.

pub mod did;
mod proofs;
pub mod sdk;

#[cfg(test)]
mod test;

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
    /// Statement about a credential derived from an identity issued by an
    /// identity provider.
    Account {
        network: Network,
        cred_id: CredentialRegistrationID,
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

impl<C: Curve, AttributeType: Attribute<C::Scalar>> CredentialProof<C, AttributeType> {
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
pub enum CredentialProof<C: Curve, AttributeType: Attribute<C::Scalar>> {
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

impl<C: Curve, AttributeType: Attribute<C::Scalar> + serde::Serialize> serde::Serialize
    for CredentialProof<C, AttributeType>
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

impl<C: Curve, AttributeType: Attribute<C::Scalar>> crate::common::Serial
    for CredentialProof<C, AttributeType>
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
    pub given: Vec<GivenContext>,
    /// This part of the challenge is supposed to be provided by the wallet or ID app.
    pub requested: Vec<GivenContext>,
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
pub struct GivenContext {
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
pub struct Presentation<C: Curve, AttributeType: Attribute<C::Scalar>> {
    pub presentation_context: Challenge,
    pub verifiable_credential: Vec<CredentialProof<C, AttributeType>>,
    /// Signatures from keys of Web3 credentials (not from ID credentials).
    /// The order is the same as that in the `credential_proofs` field.
    pub linking_proof: LinkingProof,
}

#[derive(Debug, thiserror::Error)]
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
pub enum CommitmentInputs<'a, C: Curve, AttributeType, Web3IdSigner> {
    /// Inputs are for an identity credential issued by an identity provider.
    Account {
        issuer: IpIdentity,
        /// The values that are committed to and are required in the proofs.
        values: &'a BTreeMap<AttributeTag, AttributeType>,
        /// The randomness to go along with commitments in `values`.
        randomness: &'a BTreeMap<AttributeTag, pedersen_commitment::Randomness<C>>,
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
    pub fn into_inputs<'a, S: Web3IdSigner>(
        &'a self,
        signer: &'a S,
    ) -> CommitmentInputs<'a, C, AttributeType, S> {
        CommitmentInputs::Web3Issuer {
            signature: self.signature,
            signer,
            values: &self.values,
            randomness: &self.randomness,
        }
    }
}

#[serde_with::serde_as]
#[derive(serde::Deserialize)]
#[serde(bound(deserialize = "AttributeType: DeserializeOwned, Web3IdSigner: DeserializeOwned"))]
#[serde(rename_all = "camelCase", tag = "type")]
/// An owned version of [`CommitmentInputs`] that can be deserialized.
pub enum OwnedCommitmentInputs<C: Curve, AttributeType, Web3IdSigner> {
    #[serde(rename_all = "camelCase")]
    Account {
        issuer: IpIdentity,
        #[serde_as(as = "BTreeMap<serde_with::DisplayFromStr, _>")]
        values: BTreeMap<AttributeTag, AttributeType>,
        #[serde_as(as = "BTreeMap<serde_with::DisplayFromStr, _>")]
        randomness: BTreeMap<AttributeTag, pedersen_commitment::Randomness<C>>,
    },
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

impl<'a, C: Curve, AttributeType, Web3IdSigner>
    From<&'a OwnedCommitmentInputs<C, AttributeType, Web3IdSigner>>
    for CommitmentInputs<'a, C, AttributeType, Web3IdSigner>
{
    fn from(
        owned: &'a OwnedCommitmentInputs<C, AttributeType, Web3IdSigner>,
    ) -> CommitmentInputs<'a, C, AttributeType, Web3IdSigner> {
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
/// An error that can occurr when attempting to produce a proof.
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
pub enum CredentialsInputs<C: Curve> {
    Account {
        // All the commitments of the credential.
        // In principle we only ever need to borrow this, but it is simpler to
        // have the owned map instead of a reference to it.
        commitments: BTreeMap<AttributeTag, pedersen_commitment::Commitment<C>>,
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
            Web3IdAttribute::String(
                AttributeKind::try_new("Hello".into()).expect("attribute kind"),
            ),
        );
        values.insert(
            "17".into(),
            Web3IdAttribute::String(
                AttributeKind::try_new("World".into()).expect("attribute kind"),
            ),
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
}
