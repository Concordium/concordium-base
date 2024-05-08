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
        network:   Network,
        cred_id:   CredentialRegistrationID,
        statement: Vec<AtomicStatement<C, AttributeTag, AttributeType>>,
    },
    /// Statement about a credential issued by a Web3 identity provider, a smart
    /// contract.
    Web3Id {
        /// The credential type. This is chosen by the provider to provide
        /// some information about what the credential is about.
        ty:         BTreeSet<String>,
        network:    Network,
        /// Reference to a specific smart contract instance that issued the
        /// credential.
        contract:   ContractAddress,
        /// Credential identifier inside the contract.
        credential: CredentialHolderId,
        statement:  Vec<AtomicStatement<C, String, AttributeType>>,
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
                    ty:         serde_json::from_value(ty)?,
                    network:    id.network,
                    contract:   address,
                    credential: CredentialHolderId::new(ed25519_dalek::VerifyingKey::from_bytes(
                        &parameter.as_ref().try_into()?,
                    )?),
                    statement:  serde_json::from_value(statement)?,
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
        S: serde::Serializer, {
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
        issuer:  IpIdentity,
        cred_id: CredentialRegistrationID,
    },
    /// Metadata of a Web3Id credential.
    Web3Id {
        contract: ContractAddress,
        holder:   CredentialHolderId,
    },
}

/// Metadata about a single [`CredentialProof`].
pub struct ProofMetadata {
    /// Timestamp of when the proof was created.
    pub created:       chrono::DateTime<chrono::Utc>,
    pub network:       Network,
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
                created:       *created,
                network:       *network,
                cred_metadata: CredentialMetadata::Account {
                    issuer:  *issuer,
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
                created:       *created,
                network:       *network,
                cred_metadata: CredentialMetadata::Web3Id {
                    contract: *contract,
                    holder:   *holder,
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
                network:   *network,
                cred_id:   *cred_id,
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
                ty:         ty.clone(),
                network:    *network,
                contract:   *contract,
                credential: *holder,
                statement:  proofs.iter().map(|(x, _)| x.clone()).collect(),
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
        issuer:  IpIdentity,
        proofs:  Vec<StatementWithProof<C, AttributeTag, AttributeType>>,
    },
    Web3Id {
        /// Creation timestamp of the proof.
        created:     chrono::DateTime<chrono::Utc>,
        /// Owner of the credential, a public key.
        holder:      CredentialHolderId,
        network:     Network,
        /// Reference to a specific smart contract instance.
        contract:    ContractAddress,
        /// The credential type. This is chosen by the provider to provide
        /// some information about what the credential is about.
        ty:          BTreeSet<String>,
        /// Commitments that the user has. These are all the commitments that
        /// are part of the credential, indexed by the attribute tag.
        commitments: SignedCommitments<C>,
        /// Individual proofs for statements.
        proofs:      Vec<StatementWithProof<C, String, AttributeType>>,
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
    pub signature:   ed25519_dalek::Signature,
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
        S: serde::Serializer, {
        match self {
            CredentialProof::Account {
                created,
                network,
                cred_id,
                issuer,
                proofs,
            } => {
                let json = serde_json::json!({
                    "tag": "account",
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
                    "tag": "web3Id",
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
    pub challenge:             Challenge,
    pub credential_statements: Vec<CredentialStatement<C, AttributeType>>,
}

#[repr(transparent)]
#[doc(hidden)]
/// An ed25519 public key tagged with a phantom type parameter based on its
/// role, e.g., an owner of a credential or a revocation key.
pub struct Ed25519PublicKey<Role> {
    pub public_key: ed25519_dalek::VerifyingKey,
    phantom:        PhantomData<Role>,
}

impl<Role> From<ed25519_dalek::VerifyingKey> for Ed25519PublicKey<Role> {
    fn from(value: ed25519_dalek::VerifyingKey) -> Self { Self::new(value) }
}

impl<Role> serde::Serialize for Ed25519PublicKey<Role> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer, {
        let s = self.to_string();
        s.serialize(serializer)
    }
}

impl<'de, Role> serde::Deserialize<'de> for Ed25519PublicKey<Role> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>, {
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

    fn try_from(value: String) -> Result<Self, Self::Error> { Self::try_from(value.as_str()) }
}

impl<Role> FromStr for Ed25519PublicKey<Role> {
    type Err = Ed25519PublicKeyFromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::try_from(s) }
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
    fn eq(&self, other: &Self) -> bool { self.public_key.eq(&other.public_key) }
}

impl<Role> Clone for Ed25519PublicKey<Role> {
    fn clone(&self) -> Self { *self }
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
    pub presentation_context:  Challenge,
    pub verifiable_credential: Vec<CredentialProof<C, AttributeType>>,
    /// Signatures from keys of Web3 credentials (not from ID credentials).
    /// The order is the same as that in the `credential_proofs` field.
    pub linking_proof:         LinkingProof,
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
            challenge:             self.presentation_context,
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
                let Some(sig) = linking_proof_iter.next() else {return Err(PresentationVerificationError::MissingLinkingProof)};
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
        S: serde::Serializer, {
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
        S: serde::Serializer, {
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
    fn id(&self) -> ed25519_dalek::VerifyingKey { self.verifying_key() }

    fn sign(&self, msg: &impl AsRef<[u8]>) -> ed25519_dalek::Signature {
        ed25519_dalek::Signer::sign(self, msg.as_ref())
    }
}

impl Web3IdSigner for crate::common::types::KeyPair {
    fn id(&self) -> ed25519_dalek::VerifyingKey { self.public() }

    fn sign(&self, msg: &impl AsRef<[u8]>) -> ed25519_dalek::Signature { self.sign(msg.as_ref()) }
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
        issuer:     IpIdentity,
        /// The values that are committed to and are required in the proofs.
        values:     &'a BTreeMap<AttributeTag, AttributeType>,
        /// The randomness to go along with commitments in `values`.
        randomness: &'a BTreeMap<AttributeTag, pedersen_commitment::Randomness<C>>,
    },
    /// Inputs are for a credential issued by Web3ID issuer.
    Web3Issuer {
        signature:  ed25519_dalek::Signature,
        /// The signer that will sign the presentation.
        signer:     &'a Web3IdSigner,
        /// All the values the user has and are required in the proofs.
        values:     &'a BTreeMap<String, AttributeType>,
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
    pub holder_id:         CredentialHolderId,
    /// The network to which the credential applies.
    pub network:           Network,
    /// The address of the credential registry where the credential is tracked.
    pub registry:          ContractAddress,
    /// Credential type describing what kind of a credential it is.
    pub credential_type:   BTreeSet<String>,
    /// Link to the credential schema.
    pub credential_schema: String,
    /// The issuer's public key.
    pub issuer_key:        IssuerKey,
    /// Start of the validity of the credential.
    pub valid_from:        chrono::DateTime<chrono::Utc>,
    /// After this date, the credential becomes expired. `None` corresponds to a
    /// credential that cannot expire.
    pub valid_until:       Option<chrono::DateTime<chrono::Utc>>,
    /// The values of different attributes, indexed by attribute tags.
    pub values:            BTreeMap<String, AttributeType>,
    /// The randomness to go along with commitments in `values`. This has to
    /// have the same keys as the `values` field, but it is more
    /// convenient if it is a separate map itself.
    pub randomness:        BTreeMap<String, pedersen_commitment::Randomness<C>>,
    /// The signature on the holder's public key, the contract address of the
    /// issuer, and the commitments from the issuer.
    pub signature:         ed25519_dalek::Signature,
}

impl<C: Curve, AttributeType: serde::Serialize> From<Web3IdCredential<C, AttributeType>>
    for serde_json::Value
{
    fn from(value: Web3IdCredential<C, AttributeType>) -> Self {
        let id = Method {
            network: value.network,
            ty:      IdentifierType::ContractData {
                address:    value.registry,
                entrypoint: OwnedEntrypointName::new_unchecked("credentialEntry".into()),
                parameter:  OwnedParameter::from_serial(&value.holder_id).unwrap(),
            },
        };
        let verification_method = Method {
            network: value.network,
            ty:      IdentifierType::PublicKey {
                key: value.issuer_key.public_key,
            },
        };
        let cred_id = Method {
            network: value.network,
            ty:      IdentifierType::PublicKey {
                key: value.holder_id.public_key,
            },
        };
        let issuer = Method {
            network: value.network,
            ty:      IdentifierType::ContractData {
                address:    value.registry,
                entrypoint: OwnedEntrypointName::new_unchecked("issuer".into()),
                parameter:  OwnedParameter::empty(),
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
        } = id.ty else {
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
            } = id.ty else {
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
            let IdentifierType::PublicKey {
                key,
            } = cred_id.ty else {
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
            let IdentifierType::PublicKey {
                key,
            } = method.ty else {
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
        issuer:     IpIdentity,
        #[serde_as(as = "BTreeMap<serde_with::DisplayFromStr, _>")]
        values:     BTreeMap<AttributeTag, AttributeType>,
        #[serde_as(as = "BTreeMap<serde_with::DisplayFromStr, _>")]
        randomness: BTreeMap<AttributeTag, pedersen_commitment::Randomness<C>>,
    },
    #[serde(rename_all = "camelCase")]
    Web3Issuer {
        signer:     Web3IdSigner,
        #[serde_as(as = "BTreeMap<serde_with::DisplayFromStr, _>")]
        values:     BTreeMap<String, AttributeType>,
        /// The randomness to go along with commitments in `values`. This has to
        /// have the same keys as the `values` field, but it is more
        /// convenient if it is a separate map itself.
        #[serde_as(as = "BTreeMap<serde_with::DisplayFromStr, _>")]
        randomness: BTreeMap<String, pedersen_commitment::Randomness<C>>,
        #[serde(
            serialize_with = "crate::common::base16_encode",
            deserialize_with = "crate::common::base16_decode"
        )]
        signature:  ed25519_dalek::Signature,
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
        AttributeType: 'a, {
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
#[serde(bound = "C: Curve", rename_all = "camelCase", tag = "type")]
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
            let timestamp = dt
                .signed_duration_since(chrono::DateTime::<chrono::Utc>::MIN_UTC)
                .num_milliseconds();
            let timestamp = Timestamp::from_timestamp_millis(
                timestamp
                    .try_into()
                    .context("Timesetamps before -262144-01-01T00:00:00Z are not supported.")?,
            );
            Ok(Self::Timestamp(timestamp))
        }
    }
}

impl serde::Serialize for Web3IdAttribute {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer, {
        use serde::ser::{Error, SerializeMap};
        match self {
            Web3IdAttribute::String(ak) => ak.serialize(serializer),
            Web3IdAttribute::Numeric(n) => n.serialize(serializer),
            Web3IdAttribute::Timestamp(ts) => {
                let epoch = chrono::DateTime::<chrono::Utc>::MIN_UTC;
                let millis: i64 = ts.timestamp_millis().try_into().map_err(S::Error::custom)?;
                let Some(time_delta) = chrono::Duration::try_milliseconds(millis) else {
                    return Err(S::Error::custom("Timestamp out of range."));
                };
                let Some(dt) = epoch.checked_add_signed(time_delta) else {
                    return Err(S::Error::custom("Timestamp out of range."));
                };
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
                let epoch = chrono::DateTime::<chrono::Utc>::MIN_UTC;
                if let Some(dt) = ts
                    .timestamp_millis()
                    .try_into()
                    .ok()
                    .and_then(chrono::Duration::try_milliseconds)
                    .and_then(|ms| epoch.checked_add_signed(ms))
                {
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
    };
    use anyhow::Context;
    use chrono::TimeZone;
    use rand::Rng;
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
        let credential_statements = vec![
            CredentialStatement::Web3Id {
                ty:         [
                    "VerifiableCredential".into(),
                    "ConcordiumVerifiableCredential".into(),
                    "TestCredential".into(),
                ]
                .into_iter()
                .collect(),
                network:    Network::Testnet,
                contract:   contract_1,
                credential: CredentialHolderId::new(signer_1.verifying_key()),
                statement:  vec![
                    AtomicStatement::AttributeInRange {
                        statement: AttributeInRangeStatement {
                            attribute_tag: "17".into(),
                            lower:         Web3IdAttribute::Numeric(80),
                            upper:         Web3IdAttribute::Numeric(1237),
                            _phantom:      PhantomData,
                        },
                    },
                    AtomicStatement::AttributeInSet {
                        statement: AttributeInSetStatement {
                            attribute_tag: "23".into(),
                            set:           [
                                Web3IdAttribute::String(AttributeKind("ff".into())),
                                Web3IdAttribute::String(AttributeKind("aa".into())),
                                Web3IdAttribute::String(AttributeKind("zz".into())),
                            ]
                            .into_iter()
                            .collect(),
                            _phantom:      PhantomData,
                        },
                    },
                ],
            },
            CredentialStatement::Web3Id {
                ty:         [
                    "VerifiableCredential".into(),
                    "ConcordiumVerifiableCredential".into(),
                    "TestCredential".into(),
                ]
                .into_iter()
                .collect(),
                network:    Network::Testnet,
                contract:   contract_2,
                credential: CredentialHolderId::new(signer_2.verifying_key()),
                statement:  vec![
                    AtomicStatement::AttributeInRange {
                        statement: AttributeInRangeStatement {
                            attribute_tag: 0.to_string(),
                            lower:         Web3IdAttribute::Numeric(80),
                            upper:         Web3IdAttribute::Numeric(1237),
                            _phantom:      PhantomData,
                        },
                    },
                    AtomicStatement::AttributeNotInSet {
                        statement: AttributeNotInSetStatement {
                            attribute_tag: 1u8.to_string(),
                            set:           [
                                Web3IdAttribute::String(AttributeKind("ff".into())),
                                Web3IdAttribute::String(AttributeKind("aa".into())),
                                Web3IdAttribute::String(AttributeKind("zz".into())),
                            ]
                            .into_iter()
                            .collect(),
                            _phantom:      PhantomData,
                        },
                    },
                    AtomicStatement::AttributeInRange {
                        statement: AttributeInRangeStatement {
                            attribute_tag: 2.to_string(),
                            lower:         Web3IdAttribute::Timestamp(
                                Timestamp::from_timestamp_millis(10000),
                            ),
                            upper:         Web3IdAttribute::Timestamp(
                                Timestamp::from_timestamp_millis(20000),
                            ),
                            _phantom:      PhantomData,
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
            Web3IdAttribute::String(AttributeKind("ff".into())),
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
            signer:     &signer_1,
            values:     &values_1,
            randomness: &randomness_1,
            signature:  commitments_1.signature,
        };

        let mut values_2 = BTreeMap::new();
        values_2.insert(0.to_string(), Web3IdAttribute::Numeric(137));
        values_2.insert(
            1.to_string(),
            Web3IdAttribute::String(AttributeKind("xkcd".into())),
        );
        values_2.insert(
            2.to_string(),
            Web3IdAttribute::Timestamp(Timestamp::from_timestamp_millis(15000)),
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
            signer:     &signer_2,
            values:     &values_2,
            randomness: &randomness_2,
            signature:  commitments_2.signature,
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
                ty:         [
                    "VerifiableCredential".into(),
                    "ConcordiumVerifiableCredential".into(),
                    "TestCredential".into(),
                ]
                .into_iter()
                .collect(),
                network:    Network::Testnet,
                contract:   contract_1,
                credential: CredentialHolderId::new(signer_1.verifying_key()),
                statement:  vec![
                    AtomicStatement::AttributeInRange {
                        statement: AttributeInRangeStatement {
                            attribute_tag: 17.to_string(),
                            lower:         Web3IdAttribute::Numeric(80),
                            upper:         Web3IdAttribute::Numeric(1237),
                            _phantom:      PhantomData,
                        },
                    },
                    AtomicStatement::AttributeInSet {
                        statement: AttributeInSetStatement {
                            attribute_tag: 23u8.to_string(),
                            set:           [
                                Web3IdAttribute::String(AttributeKind("ff".into())),
                                Web3IdAttribute::String(AttributeKind("aa".into())),
                                Web3IdAttribute::String(AttributeKind("zz".into())),
                            ]
                            .into_iter()
                            .collect(),
                            _phantom:      PhantomData,
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
                            lower:         Web3IdAttribute::Numeric(80),
                            upper:         Web3IdAttribute::Numeric(1237),
                            _phantom:      PhantomData,
                        },
                    },
                    AtomicStatement::AttributeNotInSet {
                        statement: AttributeNotInSetStatement {
                            attribute_tag: 1u8.into(),
                            set:           [
                                Web3IdAttribute::String(AttributeKind("ff".into())),
                                Web3IdAttribute::String(AttributeKind("aa".into())),
                                Web3IdAttribute::String(AttributeKind("zz".into())),
                            ]
                            .into_iter()
                            .collect(),
                            _phantom:      PhantomData,
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
            Web3IdAttribute::String(AttributeKind("ff".into())),
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
            signer:     &signer_1,
            values:     &values_1,
            randomness: &randomness_1,
            signature:  signed_commitments_1.signature,
        };

        let mut values_2 = BTreeMap::new();
        values_2.insert(3.into(), Web3IdAttribute::Numeric(137));
        values_2.insert(
            1.into(),
            Web3IdAttribute::String(AttributeKind("xkcd".into())),
        );
        let mut randomness_2 = BTreeMap::new();
        for tag in values_2.keys() {
            randomness_2.insert(
                *tag,
                pedersen_commitment::Randomness::<ArCurve>::generate(&mut rng),
            );
        }
        let secrets_2 = CommitmentInputs::Account {
            values:     &values_2,
            randomness: &randomness_2,
            issuer:     IpIdentity::from(17u32),
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
            Web3IdAttribute::String(AttributeKind("Hello".into())),
        );
        values.insert(
            "17".into(),
            Web3IdAttribute::String(AttributeKind("World".into())),
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
}
