//! Functionality related to constructing and verifying Web3ID proofs.
//!
//! The main entrypoints in this module are the [`verify`](Presentation::verify)
//! function for verifying [`Presentation`]s in the context of given public
//! data, and the [`prove`](Request::prove) function for constructing a proof.

pub mod did;

// TODO:
// - Documentation.
use crate::{
    base::CredentialRegistrationID,
    cis4_types::IssuerKey,
    common::{base16_decode_string, base16_encode_string},
    curve_arithmetic::Curve,
    id::{
        constants::{ArCurve, AttributeKind},
        id_proof_types::{AtomicProof, AtomicStatement, ProofVersion},
        types::{Attribute, AttributeTag, GlobalContext, IpIdentity},
    },
    pedersen_commitment,
    random_oracle::RandomOracle,
};
use concordium_contracts_common::{
    hashes::HashBytes, ContractAddress, OwnedEntrypointName, OwnedParameter, Timestamp,
};
use did::*;
use ed25519_dalek::Verifier;
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
        let Some(Ok((_, id))) = id_value.as_str().map(parse_did) else {
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
    /// Verify signatures on the commitments in the context of the holder's
    /// public key, and the issuer contract.
    pub fn verify_signature(
        &self,
        holder: &CredentialHolderId,
        issuer_pk: &IssuerKey,
        issuer_contract: ContractAddress,
    ) -> bool {
        use crate::common::Serial;
        let mut data = COMMITMENT_SIGNATURE_DOMAIN_STRING.to_vec();
        holder.serial(&mut data);
        issuer_contract.serial(&mut data);
        self.commitments.serial(&mut data);
        issuer_pk.public_key.verify(&data, &self.signature).is_ok()
    }

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
        let issuer = parse_did(&issuer)
            .map_err(|e| anyhow::anyhow!("Unable to parse issuer: {e}"))?
            .1;
        match issuer.ty {
            IdentifierType::Idp { idp_identity } => {
                let id = get_field(&mut credential_subject, "id")?;
                let Some(Ok(id)) = id.as_str().map(parse_did) else {
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
                let Some(Ok(id)) = id.as_str().map(parse_did) else {
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

/// Challenge string that serves as a distinguishing context when requesting
/// proofs.
pub type Challenge = HashBytes<Web3IdChallengeMarker>;

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

impl<C: Curve, AttributeType: Attribute<C::Scalar>> Presentation<C, AttributeType> {
    /// Get an iterator over the metadata for each of the verifiable credentials
    /// in the order they appear in the presentation.
    pub fn metadata(&self) -> impl ExactSizeIterator<Item = ProofMetadata> + '_ {
        self.verifiable_credential.iter().map(|cp| cp.metadata())
    }

    /// Verify a presentation in the context of the provided public data and
    /// cryptographic parameters.
    ///
    /// In case of success returns the [`Request`] for which the presentation
    /// verifies.
    ///
    /// **NB:** This only verifies the cryptographic consistentcy of the data.
    /// It does not check metadata, such as expiry. This should be checked
    /// separately by the verifier.
    pub fn verify<'a>(
        &self,
        params: &GlobalContext<C>,
        public: impl ExactSizeIterator<Item = &'a CredentialsInputs<C>>,
    ) -> Result<Request<C, AttributeType>, PresentationVerificationError> {
        let mut transcript = RandomOracle::domain("ConcordiumWeb3ID");
        transcript.add_bytes(self.presentation_context);
        transcript.append_message(b"ctx", &params);

        let mut request = Request {
            challenge: self.presentation_context,
            credential_statements: Vec::new(),
        };

        // Compute the data that the linking proof signed.
        let to_sign =
            linking_proof_message_to_sign(self.presentation_context, &self.verifiable_credential);

        let mut linking_proof_iter = self.linking_proof.proof_value.iter();

        if public.len() != self.verifiable_credential.len() {
            return Err(PresentationVerificationError::InconsistentPublicData);
        }

        for (cred_public, cred_proof) in public.zip(&self.verifiable_credential) {
            request.credential_statements.push(cred_proof.statement());
            if let CredentialProof::Web3Id { holder: owner, .. } = &cred_proof {
                let Some(sig) = linking_proof_iter.next() else {
                    return Err(PresentationVerificationError::MissingLinkingProof);
                };
                if owner.public_key.verify(&to_sign, &sig.signature).is_err() {
                    return Err(PresentationVerificationError::InvalidLinkinProof);
                }
            }
            if !verify_single_credential(params, &mut transcript, cred_proof, cred_public) {
                return Err(PresentationVerificationError::InvalidCredential);
            }
        }

        // No bogus signatures should be left.
        if linking_proof_iter.next().is_none() {
            Ok(request)
        } else {
            Err(PresentationVerificationError::ExcessiveLinkingProof)
        }
    }
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> crate::common::Serial
    for Presentation<C, AttributeType>
{
    fn serial<B: crate::common::Buffer>(&self, out: &mut B) {
        self.presentation_context.serial(out);
        self.verifiable_credential.serial(out);
        self.linking_proof.serial(out);
    }
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
        let Some(Ok((_, id))) = id_value.as_str().map(parse_did) else {
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
            let Some(Ok((_, id))) = issuer_value.as_str().map(parse_did) else {
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
            let Some(Ok((_, cred_id))) = cred_id.as_str().map(parse_did) else {
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
            let Some(Ok((_, method))) = method.as_str().map(parse_did) else {
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

/// Verify a single credential. This only checks the cryptographic parts and
/// ignores the metadata such as issuance date.
fn verify_single_credential<C: Curve, AttributeType: Attribute<C::Scalar>>(
    global: &GlobalContext<C>,
    transcript: &mut RandomOracle,
    cred_proof: &CredentialProof<C, AttributeType>,
    public: &CredentialsInputs<C>,
) -> bool {
    match (&cred_proof, public) {
        (
            CredentialProof::Account {
                network: _,
                cred_id: _,
                proofs,
                created: _,
                issuer: _,
            },
            CredentialsInputs::Account { commitments },
        ) => {
            for (statement, proof) in proofs.iter() {
                if !statement.verify(
                    ProofVersion::Version2,
                    global,
                    transcript,
                    commitments,
                    proof,
                ) {
                    return false;
                }
            }
        }
        (
            CredentialProof::Web3Id {
                network: _proof_network,
                contract: proof_contract,
                commitments,
                proofs,
                created: _,
                holder: owner,
                ty: _,
            },
            CredentialsInputs::Web3 { issuer_pk },
        ) => {
            if !commitments.verify_signature(owner, issuer_pk, *proof_contract) {
                return false;
            }
            for (statement, proof) in proofs.iter() {
                if !statement.verify(
                    ProofVersion::Version2,
                    global,
                    transcript,
                    &commitments.commitments,
                    proof,
                ) {
                    return false;
                }
            }
        }
        _ => return false, // mismatch in data
    }
    true
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> CredentialStatement<C, AttributeType> {
    fn prove<Signer: Web3IdSigner>(
        self,
        global: &GlobalContext<C>,
        ro: &mut RandomOracle,
        csprng: &mut impl rand::Rng,
        input: CommitmentInputs<C, AttributeType, Signer>,
    ) -> Result<CredentialProof<C, AttributeType>, ProofError> {
        match (self, input) {
            (
                CredentialStatement::Account {
                    network,
                    cred_id,
                    statement,
                },
                CommitmentInputs::Account {
                    values,
                    randomness,
                    issuer,
                },
            ) => {
                let mut proofs = Vec::new();
                for statement in statement {
                    let proof = statement
                        .prove(
                            ProofVersion::Version2,
                            global,
                            ro,
                            csprng,
                            values,
                            randomness,
                        )
                        .ok_or(ProofError::MissingAttribute)?;
                    proofs.push((statement, proof));
                }
                let created = chrono::Utc::now();
                Ok(CredentialProof::Account {
                    cred_id,
                    proofs,
                    network,
                    created,
                    issuer,
                })
            }
            (
                CredentialStatement::Web3Id {
                    network,
                    contract,
                    credential,
                    statement,
                    ty,
                },
                CommitmentInputs::Web3Issuer {
                    signature,
                    values,
                    randomness,
                    signer,
                },
            ) => {
                let mut proofs = Vec::new();
                if credential != signer.id().into() {
                    return Err(ProofError::InconsistentIds);
                }
                if values.len() != randomness.len() {
                    return Err(ProofError::InconsistentValuesAndRandomness);
                }

                // We use the same commitment key to commit to values for all the different
                // attributes. TODO: This is not ideal, but is probably fine
                // since the tags are signed as well, so you cannot switch one
                // commitment for another. We could instead use bulletproof generators, that
                // would be cleaner.
                let cmm_key = &global.on_chain_commitment_key;

                let mut commitments = BTreeMap::new();
                for ((vi, value), (ri, randomness)) in values.iter().zip(randomness.iter()) {
                    if vi != ri {
                        return Err(ProofError::InconsistentValuesAndRandomness);
                    }
                    commitments.insert(
                        ri.clone(),
                        cmm_key.hide(
                            &pedersen_commitment::Value::<C>::new(value.to_field_element()),
                            randomness,
                        ),
                    );
                }
                // TODO: For better user experience/debugging we could check the signature here.
                let commitments = SignedCommitments {
                    signature,
                    commitments,
                };
                for statement in statement {
                    let proof = statement
                        .prove(
                            ProofVersion::Version2,
                            global,
                            ro,
                            csprng,
                            values,
                            randomness,
                        )
                        .ok_or(ProofError::MissingAttribute)?;
                    proofs.push((statement, proof));
                }
                let created = chrono::Utc::now();
                Ok(CredentialProof::Web3Id {
                    commitments,
                    proofs,
                    network,
                    contract,
                    created,
                    holder: signer.id().into(),
                    ty,
                })
            }
            _ => Err(ProofError::CommitmentsStatementsMismatch),
        }
    }
}

fn linking_proof_message_to_sign<C: Curve, AttributeType: Attribute<C::Scalar>>(
    challenge: Challenge,
    proofs: &[CredentialProof<C, AttributeType>],
) -> Vec<u8> {
    use crate::common::Serial;
    use sha2::Digest;
    // hash the context and proof.
    let mut out = sha2::Sha512::new();
    challenge.serial(&mut out);
    proofs.serial(&mut out);
    let mut msg = LINKING_DOMAIN_STRING.to_vec();
    msg.extend_from_slice(&out.finalize());
    msg
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> Request<C, AttributeType> {
    /// Construct a proof for the [`Request`] using the provided cryptographic
    /// parameters and secrets.
    pub fn prove<'a, Signer: 'a + Web3IdSigner>(
        self,
        params: &GlobalContext<C>,
        attrs: impl ExactSizeIterator<Item = CommitmentInputs<'a, C, AttributeType, Signer>>,
    ) -> Result<Presentation<C, AttributeType>, ProofError>
    where
        AttributeType: 'a,
    {
        let mut proofs = Vec::with_capacity(attrs.len());
        let mut transcript = RandomOracle::domain("ConcordiumWeb3ID");
        transcript.add_bytes(self.challenge);
        transcript.append_message(b"ctx", &params);
        let mut csprng = rand::thread_rng();
        if self.credential_statements.len() != attrs.len() {
            return Err(ProofError::CommitmentsStatementsMismatch);
        }
        let mut signers = Vec::new();
        for (cred_statement, attributes) in self.credential_statements.into_iter().zip(attrs) {
            if let CommitmentInputs::Web3Issuer { signer, .. } = attributes {
                signers.push(signer);
            }
            let proof = cred_statement.prove(params, &mut transcript, &mut csprng, attributes)?;
            proofs.push(proof);
        }
        let to_sign = linking_proof_message_to_sign(self.challenge, &proofs);
        // Linking proof
        let mut proof_value = Vec::new();
        for signer in signers {
            let signature = signer.sign(&to_sign);
            proof_value.push(WeakLinkingProof { signature });
        }
        let linking_proof = LinkingProof {
            created: chrono::Utc::now(),
            proof_value,
        };
        Ok(Presentation {
            presentation_context: self.challenge,
            linking_proof,
            verifiable_credential: proofs,
        })
    }
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
    use crate::curve_arithmetic::Value;
    use crate::id::id_proof_types::{
        AttributeInRangeStatement, AttributeInSetStatement, AttributeNotInSetStatement,
    };
    use anyhow::Context;
    use chrono::TimeZone;
    use rand::{Rng, SeedableRng};
    use std::marker::PhantomData;

    #[test]
    /// Test that constructing proofs for web3 only credentials works in the
    /// sense that the proof verifies.
    ///
    /// JSON serialization of requests and presentations is also tested.
    fn test_web3_only() -> anyhow::Result<()> {
        let mut rng = rand::thread_rng();
        let challenge = Challenge::new(rng.gen());
        let signer_1 = ed25519_dalek::SigningKey::generate(&mut rng);
        let signer_2 = ed25519_dalek::SigningKey::generate(&mut rng);
        let issuer_1 = ed25519_dalek::SigningKey::generate(&mut rng);
        let issuer_2 = ed25519_dalek::SigningKey::generate(&mut rng);
        let contract_1 = ContractAddress::new(1337, 42);
        let contract_2 = ContractAddress::new(1338, 0);
        let min_timestamp = chrono::Duration::try_days(Web3IdAttribute::TIMESTAMP_DATE_OFFSET)
            .unwrap()
            .num_milliseconds()
            .try_into()
            .unwrap();

        let credential_statements = vec![
            CredentialStatement::Web3Id {
                ty: [
                    "VerifiableCredential".into(),
                    "ConcordiumVerifiableCredential".into(),
                    "TestCredential".into(),
                ]
                .into_iter()
                .collect(),
                network: Network::Testnet,
                contract: contract_1,
                credential: CredentialHolderId::new(signer_1.verifying_key()),
                statement: vec![
                    AtomicStatement::AttributeInRange {
                        statement: AttributeInRangeStatement {
                            attribute_tag: "17".into(),
                            lower: Web3IdAttribute::Numeric(80),
                            upper: Web3IdAttribute::Numeric(1237),
                            _phantom: PhantomData,
                        },
                    },
                    AtomicStatement::AttributeInSet {
                        statement: AttributeInSetStatement {
                            attribute_tag: "23".into(),
                            set: [
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("ff".into()).expect("attribute kind"),
                                ),
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("aa".into()).expect("attribute kind"),
                                ),
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("zz".into()).expect("attribute kind"),
                                ),
                            ]
                            .into_iter()
                            .collect(),
                            _phantom: PhantomData,
                        },
                    },
                ],
            },
            CredentialStatement::Web3Id {
                ty: [
                    "VerifiableCredential".into(),
                    "ConcordiumVerifiableCredential".into(),
                    "TestCredential".into(),
                ]
                .into_iter()
                .collect(),
                network: Network::Testnet,
                contract: contract_2,
                credential: CredentialHolderId::new(signer_2.verifying_key()),
                statement: vec![
                    AtomicStatement::AttributeInRange {
                        statement: AttributeInRangeStatement {
                            attribute_tag: 0.to_string(),
                            lower: Web3IdAttribute::Numeric(80),
                            upper: Web3IdAttribute::Numeric(1237),
                            _phantom: PhantomData,
                        },
                    },
                    AtomicStatement::AttributeNotInSet {
                        statement: AttributeNotInSetStatement {
                            attribute_tag: 1u8.to_string(),
                            set: [
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("ff".into()).expect("attribute kind"),
                                ),
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("aa".into()).expect("attribute kind"),
                                ),
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("zz".into()).expect("attribute kind"),
                                ),
                            ]
                            .into_iter()
                            .collect(),
                            _phantom: PhantomData,
                        },
                    },
                    AtomicStatement::AttributeInRange {
                        statement: AttributeInRangeStatement {
                            attribute_tag: 2.to_string(),
                            lower: Web3IdAttribute::Timestamp(Timestamp::from_timestamp_millis(
                                min_timestamp,
                            )),
                            upper: Web3IdAttribute::Timestamp(Timestamp::from_timestamp_millis(
                                min_timestamp * 3,
                            )),
                            _phantom: PhantomData,
                        },
                    },
                ],
            },
        ];

        let request = Request::<ArCurve, Web3IdAttribute> {
            challenge,
            credential_statements,
        };
        let params = GlobalContext::generate("Test".into());
        let mut values_1 = BTreeMap::new();
        values_1.insert(17.to_string(), Web3IdAttribute::Numeric(137));
        values_1.insert(
            23.to_string(),
            Web3IdAttribute::String(AttributeKind::try_new("ff".into()).expect("attribute kind")),
        );
        let mut randomness_1 = BTreeMap::new();
        randomness_1.insert(
            17.to_string(),
            pedersen_commitment::Randomness::<ArCurve>::generate(&mut rng),
        );
        randomness_1.insert(
            23.to_string(),
            pedersen_commitment::Randomness::<ArCurve>::generate(&mut rng),
        );
        let commitments_1 = SignedCommitments::from_secrets(
            &params,
            &values_1,
            &randomness_1,
            &CredentialHolderId::new(signer_1.verifying_key()),
            &issuer_1,
            contract_1,
        )
        .unwrap();

        let secrets_1 = CommitmentInputs::Web3Issuer {
            signer: &signer_1,
            values: &values_1,
            randomness: &randomness_1,
            signature: commitments_1.signature,
        };

        let mut values_2 = BTreeMap::new();
        values_2.insert(0.to_string(), Web3IdAttribute::Numeric(137));
        values_2.insert(
            1.to_string(),
            Web3IdAttribute::String(AttributeKind::try_new("xkcd".into()).expect("attribute kind")),
        );
        values_2.insert(
            2.to_string(),
            Web3IdAttribute::Timestamp(Timestamp::from_timestamp_millis(min_timestamp * 2)),
        );
        let mut randomness_2 = BTreeMap::new();
        randomness_2.insert(
            0.to_string(),
            pedersen_commitment::Randomness::<ArCurve>::generate(&mut rng),
        );
        randomness_2.insert(
            1.to_string(),
            pedersen_commitment::Randomness::<ArCurve>::generate(&mut rng),
        );
        randomness_2.insert(
            2.to_string(),
            pedersen_commitment::Randomness::<ArCurve>::generate(&mut rng),
        );
        let commitments_2 = SignedCommitments::from_secrets(
            &params,
            &values_2,
            &randomness_2,
            &CredentialHolderId::new(signer_2.verifying_key()),
            &issuer_2,
            contract_2,
        )
        .unwrap();
        let secrets_2 = CommitmentInputs::Web3Issuer {
            signer: &signer_2,
            values: &values_2,
            randomness: &randomness_2,
            signature: commitments_2.signature,
        };
        let attrs = [secrets_1, secrets_2];
        let proof = request
            .clone()
            .prove(&params, attrs.into_iter())
            .context("Cannot prove")?;

        let public = vec![
            CredentialsInputs::Web3 {
                issuer_pk: issuer_1.verifying_key().into(),
            },
            CredentialsInputs::Web3 {
                issuer_pk: issuer_2.verifying_key().into(),
            },
        ];
        anyhow::ensure!(
            proof.verify(&params, public.iter())? == request,
            "Proof verification failed."
        );

        let data = serde_json::to_string_pretty(&proof)?;
        assert!(
            serde_json::from_str::<Presentation<ArCurve, Web3IdAttribute>>(&data).is_ok(),
            "Cannot deserialize proof correctly."
        );

        let data = serde_json::to_string_pretty(&request)?;
        assert_eq!(
            serde_json::from_str::<Request<ArCurve, Web3IdAttribute>>(&data)?,
            request,
            "Cannot deserialize request correctly."
        );

        Ok(())
    }

    #[test]
    /// Test that constructing proofs for a mixed (both web3 and id2 credentials
    /// involved) request works in the sense that the proof verifies.
    ///
    /// JSON serialization of requests and presentations is also tested.
    fn test_mixed() -> anyhow::Result<()> {
        let mut rng = rand::thread_rng();
        let challenge = Challenge::new(rng.gen());
        let params = GlobalContext::generate("Test".into());
        let cred_id_exp = ArCurve::generate_scalar(&mut rng);
        let cred_id = CredentialRegistrationID::from_exponent(&params, cred_id_exp);
        let signer_1 = ed25519_dalek::SigningKey::generate(&mut rng);
        let issuer_1 = ed25519_dalek::SigningKey::generate(&mut rng);
        let contract_1 = ContractAddress::new(1337, 42);
        let credential_statements = vec![
            CredentialStatement::Web3Id {
                ty: [
                    "VerifiableCredential".into(),
                    "ConcordiumVerifiableCredential".into(),
                    "TestCredential".into(),
                ]
                .into_iter()
                .collect(),
                network: Network::Testnet,
                contract: contract_1,
                credential: CredentialHolderId::new(signer_1.verifying_key()),
                statement: vec![
                    AtomicStatement::AttributeInRange {
                        statement: AttributeInRangeStatement {
                            attribute_tag: 17.to_string(),
                            lower: Web3IdAttribute::Numeric(80),
                            upper: Web3IdAttribute::Numeric(1237),
                            _phantom: PhantomData,
                        },
                    },
                    AtomicStatement::AttributeInSet {
                        statement: AttributeInSetStatement {
                            attribute_tag: 23u8.to_string(),
                            set: [
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("ff".into()).expect("attribute kind"),
                                ),
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("aa".into()).expect("attribute kind"),
                                ),
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("zz".into()).expect("attribute kind"),
                                ),
                            ]
                            .into_iter()
                            .collect(),
                            _phantom: PhantomData,
                        },
                    },
                ],
            },
            CredentialStatement::Account {
                network: Network::Testnet,
                cred_id,
                statement: vec![
                    AtomicStatement::AttributeInRange {
                        statement: AttributeInRangeStatement {
                            attribute_tag: 3.into(),
                            lower: Web3IdAttribute::Numeric(80),
                            upper: Web3IdAttribute::Numeric(1237),
                            _phantom: PhantomData,
                        },
                    },
                    AtomicStatement::AttributeNotInSet {
                        statement: AttributeNotInSetStatement {
                            attribute_tag: 1u8.into(),
                            set: [
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("ff".into()).expect("attribute kind"),
                                ),
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("aa".into()).expect("attribute kind"),
                                ),
                                Web3IdAttribute::String(
                                    AttributeKind::try_new("zz".into()).expect("attribute kind"),
                                ),
                            ]
                            .into_iter()
                            .collect(),
                            _phantom: PhantomData,
                        },
                    },
                ],
            },
        ];

        let request = Request::<ArCurve, Web3IdAttribute> {
            challenge,
            credential_statements,
        };
        let mut values_1 = BTreeMap::new();
        values_1.insert(17.to_string(), Web3IdAttribute::Numeric(137));
        values_1.insert(
            23.to_string(),
            Web3IdAttribute::String(AttributeKind::try_new("ff".into()).expect("attribute kind")),
        );
        let mut randomness_1 = BTreeMap::new();
        randomness_1.insert(
            17.to_string(),
            pedersen_commitment::Randomness::<ArCurve>::generate(&mut rng),
        );
        randomness_1.insert(
            23.to_string(),
            pedersen_commitment::Randomness::<ArCurve>::generate(&mut rng),
        );
        let signed_commitments_1 = SignedCommitments::from_secrets(
            &params,
            &values_1,
            &randomness_1,
            &CredentialHolderId::new(signer_1.verifying_key()),
            &issuer_1,
            contract_1,
        )
        .unwrap();
        let secrets_1 = CommitmentInputs::Web3Issuer {
            signer: &signer_1,
            values: &values_1,
            randomness: &randomness_1,
            signature: signed_commitments_1.signature,
        };

        let mut values_2 = BTreeMap::new();
        values_2.insert(3.into(), Web3IdAttribute::Numeric(137));
        values_2.insert(
            1.into(),
            Web3IdAttribute::String(AttributeKind::try_new("xkcd".into()).expect("attribute kind")),
        );
        let mut randomness_2 = BTreeMap::new();
        for tag in values_2.keys() {
            randomness_2.insert(
                *tag,
                pedersen_commitment::Randomness::<ArCurve>::generate(&mut rng),
            );
        }
        let secrets_2 = CommitmentInputs::Account {
            values: &values_2,
            randomness: &randomness_2,
            issuer: IpIdentity::from(17u32),
        };
        let attrs = [secrets_1, secrets_2];
        let proof = request
            .clone()
            .prove(&params, attrs.into_iter())
            .context("Cannot prove")?;

        let commitments_2 = {
            let key = params.on_chain_commitment_key;
            let mut comms = BTreeMap::new();
            for (tag, value) in randomness_2.iter() {
                let _ = comms.insert(
                    AttributeTag::from(*tag),
                    key.hide(
                        &pedersen_commitment::Value::<ArCurve>::new(
                            values_2.get(tag).unwrap().to_field_element(),
                        ),
                        value,
                    ),
                );
            }
            comms
        };

        let public = vec![
            CredentialsInputs::Web3 {
                issuer_pk: issuer_1.verifying_key().into(),
            },
            CredentialsInputs::Account {
                commitments: commitments_2,
            },
        ];
        anyhow::ensure!(
            proof
                .verify(&params, public.iter())
                .context("Verification of mixed presentation failed.")?
                == request,
            "Proof verification failed."
        );

        let data = serde_json::to_string_pretty(&proof)?;
        assert!(
            serde_json::from_str::<Presentation<ArCurve, Web3IdAttribute>>(&data).is_ok(),
            "Cannot deserialize proof correctly."
        );

        let data = serde_json::to_string_pretty(&request)?;
        assert_eq!(
            serde_json::from_str::<Request<ArCurve, Web3IdAttribute>>(&data)?,
            request,
            "Cannot deserialize request correctly."
        );

        Ok(())
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

    #[allow(dead_code)]
    struct AccountCredentialsFixture<AttributeType: Attribute<<ArCurve as Curve>::Scalar>> {
        commitment_inputs: OwnedCommitmentInputs<ArCurve, AttributeType, ed25519_dalek::SigningKey>,
        credential_inputs: CredentialsInputs<ArCurve>,
        cred_id: CredentialRegistrationID,
    }

    fn account_credentials_fixture<AttributeType: Attribute<<ArCurve as Curve>::Scalar>>(
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

    #[allow(dead_code)]
    struct Web3CredentialsFixture {
        commitment_inputs:
            OwnedCommitmentInputs<ArCurve, Web3IdAttribute, ed25519_dalek::SigningKey>,
        credential_inputs: CredentialsInputs<ArCurve>,
        cred_id: CredentialHolderId,
        contract: ContractAddress,
        issuer_key: ed25519_dalek::SigningKey,
    }

    fn seed0() -> rand::rngs::StdRng {
        rand::rngs::StdRng::seed_from_u64(0)
    }

    fn web3_credentials_fixture(
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

    /// Test that the verifier can verify previously generated proofs.
    #[test]
    fn test_stability_account() {
        let global_context = GlobalContext::generate("Test".into());

        let acc_cred_fixture = account_credentials_fixture(
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

        let proof_json = r#"
{
  "presentationContext": "7fb27b941602d01d11542211134fc71aacae54e37e7d007bbb7b55eff062a284",
  "proof": {
    "created": "2025-10-26T07:20:55.639111Z",
    "proofValue": [],
    "type": "ConcordiumWeakLinkingProofV1"
  },
  "type": "VerifiablePresentation",
  "verifiableCredential": [
    {
      "credentialSubject": {
        "id": "did:ccd:testnet:cred:856793e4ba5d058cea0b5c3a1c8affb272efcf53bbab77ee28d3e2270d5041d220c1e1a9c6c8619c84e40ebd70fb583e",
        "proof": {
          "created": "2025-10-26T07:20:55.638868Z",
          "proofValue": [
            {
              "proof": "ad2921ae1d65542c4d8f491c779028e989876ce7c95b817122b1d85b16f593d818792c9261dd83b097cd433e57ca5e05a273ada11a24afa3bc3fb3ea387e3a7569a6e5b962604146442305d0b272317d4232b06c3c51ab0d6fe52c600fdd7f648cbf4ef3174ee92910a9849cd1c948ba4c91ea92abfaf7068e4a026ebc39207404270d8420ccef4d0f99ca4964681fa6831ae08ff49f1d36c42ef14589f742a2539076002194b8bce2a776a4b987f73713f69aa29cc294e3ecf68c474d7abc570e1b2d902396bdec86e8713d3b0280a15eb73eaeb94ccb2a01f92aa0b3eb97c060864e8cd95c364a02a375873b319c911099b8514e3b37cce88d0cc5632a847b5496ba301d5e00c2769846f97289a2fd501d860966bea3ab867720f98754d57e00000007a58c2c0282d8a91ca553617311c51ca929c7a8f4cac3788d2b9a0a6cc92c90f332d7f8cec6fec159164049d15c0ba7e590d7657976135cba7acc2174245233dd44ea341f691e928306d66b074e02adb860cc740489a1f849f198cdc41045b38688ad8de18b6cb8f7ff4b026e7ec7228dcefe257bdc5a1c317a28662dd25349ac6018ef9868cb1b4d23a2ce29a0ff7a0ca49caef2e6838c6d54fb786a65e67ea252b4e5fedf15d6085a8abf2f725409851bc1ee2883272de5bcff7793477d56f3813889c8d8ad2dd2f83c4862f3092464e6d9dcf8c87d312c83dac7314467d5dbb9575b39aa72dade9a4d59328b79100e8ce2436e98a1e319324f4dcebff6c68d25d5834fc63c071090459692f644cba70f28593a0eb65f7f71efbe3022c6b438a178a45a266adb8ce205675425af8ffafc23cc4c542c6599cabbb1aa8f048388da74e4bdfec09913e2691f72c8eb804589640ba1d1cba99f9a20106506f4236fc72a8dd233aabd5333e1bb68b98ed7a3466d1d090ed581b85e521813fa6324fdb89d0b16585861afb706695be090a9ee847ec3221ee40a2442e6e8f6a91a42920a72f03e168d823abcd5594d6b339c4e969143a7c720885552657c0275d1d919b4beb031a12c0a1b179efc7e6339d2f2671d6f03024cf392fdb0774b778a585a9602d8f66833a5d6e5347327ad3027b7c583b3af18bbe30a28a5927ee848be6673883182c9591574c92030439a83250ea62a9ef2264294200608d86f654a29f876cfa77c369c43f0d801262b7da3368eb452a867dbfdf0613ec4401f0ffdd3fcb6da4220b4c96b3e8838d0936e03426d844a585269b50433f9da9e3b512992a559f7c28dfe165c267ac99a1d99e048d0a136ca1ca0ecf7941e4403364144f0ed4ddaa2788f57e690c63eb3c651609ed59a42f1f79861581932df7e9fe02d4e20058ee4afefaf9476c0e64bace57500a185d1ea272150e44f89cee08aa5a50c9f428be8e5dba12e21e2563675f7cd5a21a1d2ac0dc9b3542ccc87bb355aab2b63",
              "type": "AttributeInRange"
            },
            {
              "proof": "b3f32d6d31476315f369557429adc7e2c6e4f52e148e8cd08d6240cff29eedaa35308c83dd06c3bccfd07aeec8c60dceb93697c3ca588f29bb1126a20e930c2634e96915c4eaa05586acf07e691bee08ccb8d003ab246e139c81c051836f157ab914b460f1de18361d32703e91bcc48a21e6198c60177e84ca2491673b667f25fdfbeb42f636335eabf3befa4c913790a30b5cee7a4442c7eae1fd029a7016624ab1dd421a9ca3f8ccac6d3816cda42b5b1dcc6e9ad0b0c55cb8f23d4004246317dcdc128226ba6e4c3876381d4a92927b91a34adf49c80b05781c4368d9a1bf72cd55f71352e42859638551dde2de772b02a64ed63aa1c6605d67e29e407a7c023b37380ec18747d1ecbd068275c51e422a6798443e577d3e0398b64c8a3897000000028f357fb97de1f64f81b8b70b7ce077d294d2a8dcd6c24ac1720b6b5943c2b72064045b8d5655ddceadda4c2235be921e915061e61b8ac78f84dfbd9de4991436659e444a8931d3bf4e04fb306cff517dac1dd1c403931b72695ef7c853856d73b4452d9b85bd851a73426e966638e6d67fb5efb49a0e795a8c9c8f9c0ac36f341f991ca85f3d497bbf947867d5bf6b9db81f8b99c9631b0b6a02973ce1912d126477d32c381c4e6109c7f4fbe121b978c6fc6d7d03f5e5a4e93555be4fd92c7914baadc605adbe46b60cb1488dd8b3686860e75a291accd0ce941c9e8511ade24b9c3930a1d80993fa6081003038b01a2514cb6a0790c6af3e2432e54ce4bb20",
              "type": "AttributeInSet"
            },
            {
              "proof": "94d3ea2668881ae0d6e5d1e7fc463bad6e902e2a7cd8d9be4b11d48f8854b9652cf9b0181123d667c134e7d6fd8bac0fb413ef563ed3eff09f9a7e6f1cfb75e7d711caf19a70b4f0a4f6941daab261ba58796e74f6e29a87e991e4c7696ceb2484cd39aa81a4eb49f9be71caecba3e3a3b4a062a3eedc0b73405230e03150ab07f980f4840730f990e754b7dc78e9f1b8926cf57d6ef243966533d2b122670fa0cd8d94b49f149f8bd3a1a5f13fd31c68c3f584e6e4829c20bc95aaafc79e4fa3ba5ed019f3e72ff4bcb9ed680b73c94371749e45b4e74f8286fed5f52aa676b16c75c385da8a877494e1ed6019e2b1f827d3dfb0001396dee7764f640f0f6a610e50ada2a30ef5d8883a1f692d8c29cfef88d9164dd630e0757a9636ecefdaa00000002b839595e42d08fab8492ff918eaa954c6dcf515da600a629604041c1c02a7393423507158c9783b85585167f4c8e603bb9782a730d25940704ffb1707921031cab55329beb4cfe4da63d6eba70c76063e5c7176f274bdbf2054f0e9e9d978bb6a23e6bba5168513f0663d18227b3a0b948b40da12619050f06b8c015a820a3b5a240ceb50ef269ffca17c197cc461287a34950e33adc3993a4e38eb851fabddb85e3badba69962602f2c994a4bf8426e3e153c2e42b4a68d5e6388673c3e6f3c42a1d499cc42408f56671666f32d3bd5d764422e041027562549e8f41c6e913326a72534109ebdb87ef445677fa5a27114b511a0d131ad9eac163ebdc1c00104",
              "type": "AttributeNotInSet"
            },
            {
              "attribute": "testvalue",
              "proof": "fceb0900994b980e3bfab3733499731791634cd9a9bc2485cc027d88bc50a093637712584ac90ad0529d095de23705cdc0cffda27051f23bfb6ddaa8648b344d",
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
        let proof: Presentation<ArCurve, Web3IdAttribute> =
            serde_json::from_str(proof_json).unwrap();

        let public = vec![acc_cred_fixture.credential_inputs];

        proof
            .verify(&global_context, public.iter())
            .expect("verify");
    }

    /// Test that the verifier can verify previously generated proofs.
    #[test]
    fn test_stability_web3() {
        let global_context = GlobalContext::generate("Test".into());

        let web3_cred = web3_credentials_fixture(
            [
                (3.to_string(), Web3IdAttribute::Numeric(137)),
                (
                    1.to_string(),
                    Web3IdAttribute::String(AttributeKind::try_new("xkcd".into()).unwrap()),
                ),
                (
                    2.to_string(),
                    Web3IdAttribute::String(AttributeKind::try_new("aa".into()).unwrap()),
                ),
                (
                    5.to_string(),
                    Web3IdAttribute::String(AttributeKind::try_new("testvalue".into()).unwrap()),
                ),
            ]
            .into_iter()
            .collect(),
            &global_context,
        );

        let proof_json = r#"
{
  "presentationContext": "7fb27b941602d01d11542211134fc71aacae54e37e7d007bbb7b55eff062a284",
  "proof": {
    "created": "2025-10-26T07:28:08.545556Z",
    "proofValue": [
      "8dbdfb933b46a7661258cdd172547f16d17e2fdf335ddb55d91e1b9cf1dd9227a7e200207b53e494bf39ee821bc76b6c62d863a1103a0d577220dca418834100"
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
              "5": "8ae7a7fc631dc8566d0db1ce0258ae9b025ac5535bc7206db92775459ba291789ae6c40687763918c6c297b636b3991c"
            },
            "signature": "afeabe7b0948eaa432e7b664790338431399299f284c51bfb910706511c077e7bb6a19e4a18a537f3f930b89ba1cb7fd46413107fbb24633b127a2858729fe02"
          },
          "created": "2025-10-26T07:28:08.545294Z",
          "proofValue": [
            {
              "proof": "b88f478605769d1548cd2f2793cb28d32a8551cd0f5c182c655af40d1c9b59bd28ade9776b754249ae8f6c8aed632e8698b0a5c804d746ea6037eec874fd1154193c178c7ccee512bf14e9cc314950457320c7bcee75752990f2bc66b684e75fb1c80e7cd89e01c9242efcde33c53bb6a2c8d7334175b5cbcb069c47636000b351ad942f5e90a697976a7908583994ab98b595a4ab388c3b02447a9ea1df40fbf48621a73ef112e040925774a24aa1d888459649ac6ce9e6bacda26dc4a5a64025d740ccc27bc460ea8de1820cceb035e868c7414fe3c4bf27f5af5e5284bfa61d47841aec9d28373f5f6ce6f3c81910ee3a987433e901f77c23a65fb5332f9b394562e04c260f829b267f71116ad28f8c6e5a3ffc302137475c58266626928e00000007885033420a7f64541eb4dc8d89aa32daa1f245c1b6aa8c643d313cceed84b029142a5ab21a5007799d9152cc6cce7f5a80c4c2b32c55c0bf57c71fa87b2473c1d0f96d7f7942bfc0784ccc1bc0447a7aa96953366ded0f014314db95fd68ebd7a511c9c488f8e29c29c5147404c1be6f69d3b233d64586b3d46fde08d88920e09ab3e88f187e6a5b51f9e4d4956179c7ab38236b3d59648be8c44d06e006ea05290f8b5f9ebbf537f127637e4bab81d044511233c4398834019b68d529808cdca44a919b78ccc29bec5a6a06004a99727b11d19df7105988448ff7c96aef84b2aa4a1b033f563ef99da03ec7a11d51508dc8d869d1c070af1b365dd6fec9c2bd0c3d7bfb8e24044a27fb6df4a9cc3f35ff4280bfe5df1c9d7d1d698f2459ed90b696f2d7af8f2ef247bbb410ecad10c7fd8be6e5b5e0350f7341ab783fc706ee3c93cda8f5ba83456d8bfc6feb3eeda2b042361e9a223e41e69d2ab2988b491b5e2527f78e19c843b27e70157318db0659a1fceb913173432f89833cd6051f02b533a08fee16185a9f4d0b83ed49bd9340eba77fb4d9646762d4c0ae96ef41bdcfd4e1b05bbf943f47190ff55e9d355f862fd4dfb0448960623bfc0c8550adf6093787b5ebf41456224240c4cc51ab65e3566df9d65e3ec6e665daa1855c0d91b70e8f23ff3c5b74142dad5137b88e91cc0f8f94ae82a746b709ff00352abbceb304788a00774e1a5029b5ae88c4f1b5849e30999a85d4820ec5bb5bb5ea46bc2b263d9e4d73c28425fdc289494f17dc9ba046ad14d8fe698a888253386858daabd0c4820cc39b7865063bb71979a048b374f2744ed863f479805bd66d44720b139a84fa7dee3808f44a242867dd320b8aa4248f900e9a83ccc4ce2e4608085ee57650451259f62234d6947c331fe480e43ca438ee6dd47bc446ec5ec19ff1fd5ddce700f7da870aa0f8bb12b7a6dc1780f73a312e1142888138d7f18a0461de1287763fc8be3fa3d43d8a6d3d6050efb0049e43dfdb1c7a90ed716656a8dbf1",
              "type": "AttributeInRange"
            },
            {
              "proof": "ab55aaaf3ab5a759d8c71d13e7898310b3784fc4c6c8ada9ec909eccd38b9d40b73043428b4ae65be93c0442c3e3ba0ba0d68e0ab83af8ce6e5c2ea172ee0bd80d67f1620b92e86dacffd5b898130897d65a9a9355ce2b9ea51e668bec09945eb62d5cc55b18bad8ca41bf27e6173b23115d7ede12ddf3ce08ec19bb203216924cda455aba8b8a9c3c3a42d15b79daf4b57c9023549e8fe2269d0703c013164d27354506bfaf1da4000a50dded7e98a27259bc3f38526f20d2e182fd40da91ca3f4a2c2e715fcd911e091056d896246a8ceb3ff9649ffad269e9402e5005f3725e84739f2f3c0ce432e3a46e5129472b11aed524e08b81190a52994e75fc58191fd63592c02ca020815b6f2bd33b25366bce92c99a68f1abbc2c16d51140a8c700000002b0c94b4d02db076510bdaeb2aea3e09a0337d12137528a66e01e83781f6b35d2280e50bf07c10afcfecc3b9d50d78c9d8185c6dcd6db2eb3dfc700e3cb41c64f000f1e8e61afe55b0e875d8177c61c1a54790816d27ffb2e66ee04411a9cd9b7983b8e6725b5b175ba515705feb34911276763a96fade764d08097f9ba1cd2b98c188a2e39ba7074b32a4e3769e056d3846fbb3a62c306621945698bb4b7035e58539e99a2800a5a0a83d6fbff7a1694a2e8b67e3de34a3c1bc7000187b45c7563e5909ee8b29607c81890fc24fae6bc9bf5f0b01e41144c00b6fd99d023b7d618bd8bb7aa3a4259fe6f8679c5682d402db30a9572febc8c9bee97aa7ff57335",
              "type": "AttributeInSet"
            },
            {
              "proof": "ad019a1114ca11054347f80e5a0cb0433761a285456e5412a0a8a636681a0084b507a9e47ec7f45a94562d323085f1fc97349b1aaf71bff9f6463d7dbde0ee1a22d67ad94cd833fbed098db3ad73626a229c2a1fc91bd3a49e965021a68f16cca11835c2e3b6dc6632c3b0db3c154f277ae56803cbbacce5acd16eedec189b2ffa9e824f8062489059c642cb594010f6a7c42f756bf75fa40d47bb62654087e692089789c2d17bb6acf084ab46794819939554a0cd50f2d433483eaadcb1bbd14cd7eec6b29f86c6bcc704ea110d20b26cf9c44d89c974da31d5fafff9e46407016437111abf301253e9ed3a585740a5419db13baadaec7718223395865c8fb518cba9eb52509ab099476b3945eeb5cc5bb77adb6ff375760ffdaedc01afae8a00000002b26f1d85c9a5d6da3e05bcf2a8e81ea4623bd7f1d70e8d36241ae706713ee48245048c90864a22c62d3a0921eda2b70084e2f61260773e2e6cbab5022c868f1a228b652e1e19ad11e42e260e05f08b708423dcd0035bbeeb491a51d9a5bebb50849db1248de073213212e4ebfa7c2270f7c1452b3f8aae39d805e1bdac47039dbac66a734b117ea794dba4f51ec161898116e7a41cd043b4cd04d4f1f500fda04b12820346972653002bb1141bfcd1f4b62820e6cb17c324d1b9509feccd099a5ea3463a889e4c2eb865306c11937ee12c6d5c519e90587052e042ab20b549a6379654d209ae2f61ba657b5b94eb1cf90dfe7e661c770983e1f02741bdff7b25",
              "type": "AttributeNotInSet"
            },
            {
              "attribute": "testvalue",
              "proof": "4ea7503e43982ac82dc8d7ed87308572b63aef46167d8566a7e8efcdd572e4b22799c2303e27e3f1a83ee0f9d9df708af9a9029c41e285d2589256f2f55446ce",
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
        let proof: Presentation<ArCurve, Web3IdAttribute> =
            serde_json::from_str(proof_json).unwrap();

        let public = vec![web3_cred.credential_inputs];

        proof
            .verify(&global_context, public.iter())
            .expect("verify");
    }
}
