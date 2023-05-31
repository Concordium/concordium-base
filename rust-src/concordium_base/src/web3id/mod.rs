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
    curve_arithmetic::Curve,
    id::{
        constants::{ArCurve, AttributeKind},
        id_proof_types::{AtomicProof, AtomicStatement},
        sigma_protocols::{self, vcom_eq::VecComEq},
        types::{Attribute, AttributeTag, GlobalContext, IpIdentity},
    },
    pedersen_commitment::{self, VecCommitmentKey},
    random_oracle::RandomOracle,
};
use concordium_contracts_common::{hashes::HashBytes, ContractAddress};
use did::*;
use ed25519_dalek::Verifier;
use serde::de::DeserializeOwned;
use std::{
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
};

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
        statement: Vec<AtomicStatement<C, u8, AttributeType>>,
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
        statement:  Vec<AtomicStatement<C, u8, AttributeType>>,
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
                    credential: CredentialHolderId::new(ed25519_dalek::PublicKey::from_bytes(
                        parameter.as_ref(),
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
pub type StatementWithProof<C, AttributeType> = (
    AtomicStatement<C, u8, AttributeType>,
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
        owner:    CredentialHolderId,
    },
}

/// Metadata about a single [`CredentialProof`].
pub struct ProofMetadata {
    /// Timestamp of when the proof was created.
    pub created:       chrono::DateTime<chrono::Utc>,
    /// Issuance date/valid_from date of the credential.
    pub issuance_date: chrono::DateTime<chrono::Utc>,
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
                issuance_date,
                proofs: _,
            } => ProofMetadata {
                created:       *created,
                issuance_date: *issuance_date,
                network:       *network,
                cred_metadata: CredentialMetadata::Account {
                    issuer:  *issuer,
                    cred_id: *cred_id,
                },
            },
            CredentialProof::Web3Id {
                created,
                owner,
                network,
                contract,
                ty: _,
                issuance_date,
                additional_commitments: _,
                max_base_used: _,
                glueing_proof: _,
                proofs: _,
            } => ProofMetadata {
                created:       *created,
                issuance_date: *issuance_date,
                network:       *network,
                cred_metadata: CredentialMetadata::Web3Id {
                    contract: *contract,
                    owner:    *owner,
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
                owner,
                network,
                contract,
                ty,
                proofs,
                ..
            } => CredentialStatement::Web3Id {
                ty:         ty.clone(),
                network:    *network,
                contract:   *contract,
                credential: *owner,
                statement:  proofs.iter().map(|(x, _)| x.clone()).collect(),
            },
        }
    }
}

#[derive(Clone, serde::Deserialize)]
#[serde(bound(deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + DeserializeOwned"))]
#[serde(try_from = "serde_json::Value")]
/// A proof corresponding to one [`CredentialStatement`]. This contains the
/// statement and the metadata. The only data missing to verify the
/// cryptographic proof are the public commitments.
pub enum CredentialProof<C: Curve, AttributeType: Attribute<C::Scalar>> {
    Account {
        /// Creation timestamp of the proof.
        created:       chrono::DateTime<chrono::Utc>,
        network:       Network,
        /// Reference to the credential to which this statement applies.
        cred_id:       CredentialRegistrationID,
        /// Issuer of this credential, the identity provider index on the
        /// relevant network.
        issuer:        IpIdentity,
        /// Issuance date of the credential that the proof is about.
        /// This is an unfortunate name to conform to the standard, but the
        /// meaning here really is `validFrom` for the credential.
        issuance_date: chrono::DateTime<chrono::Utc>,
        proofs:        Vec<StatementWithProof<C, AttributeType>>,
    },
    Web3Id {
        /// Creation timestamp of the proof.
        created:                chrono::DateTime<chrono::Utc>,
        /// Owner of the credential, a public key.
        owner:                  CredentialHolderId,
        network:                Network,
        /// Reference to a specific smart contract instance.
        contract:               ContractAddress,
        /// The credential type. This is chosen by the provider to provide
        /// some information about what the credential is about.
        ty:                     BTreeSet<String>,
        /// Issuance date of the credential that the proof is about.
        /// This is an unfortunate name to conform to the standard, but the
        /// meaning here really is `validFrom` for the credential.
        issuance_date:          chrono::DateTime<chrono::Utc>,
        /// Additional commitments produced as part of the proof. These are
        /// commitments for the values in the statement.
        additional_commitments: BTreeMap<u8, pedersen_commitment::Commitment<C>>,
        /// The maximum index that is used in the vector commitment. This is
        /// needed since the vector commitment key is part of the
        /// context when constructing the proof, so it matters exactly
        /// what the key is, even if the rest (algebraic part) of the proof
        /// works equally well with the full key.
        max_base_used:          u8,
        /// The proof that the individual commitments that are part of
        /// `additional-commitments` above are commitments to the same
        /// values as those found inside the vector commitment that is part of
        /// the credential.
        glueing_proof: sigma_protocols::common::SigmaProof<sigma_protocols::vcom_eq::Witness<C>>,
        /// Individual proofs for statements.
        proofs:                 Vec<StatementWithProof<C, AttributeType>>,
    },
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
                issuance_date,
                proofs,
            } => {
                let json = serde_json::json!({
                    "type": ["VerifiableCredential", "ConcordiumVerifiableCredential"],
                    "issuer": format!("did:ccd:{network}:idp:{issuer}"),
                    "issuanceDate": issuance_date,
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
                issuance_date,
                additional_commitments,
                max_base_used,
                glueing_proof,
                proofs,
                owner,
            } => {
                let json = serde_json::json!({
                    "type": ty,
                    "issuer": format!("did:ccd:{network}:sci:{}:{}/issuer", contract.index, contract.subindex),
                    "issuanceDate": issuance_date,
                    "credentialSubject": {
                        "id": format!("did:ccd:{network}:pkc:{}", owner),
                        "statement": proofs.iter().map(|x| &x.0).collect::<Vec<_>>(),
                        "proof": {
                            "type": "ConcordiumZKProofV3",
                            "created": created,
                            "additionalCommitments": additional_commitments,
                            "maxBaseUsed": max_base_used,
                            "glueingProof": glueing_proof,
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

impl<C: Curve, AttributeType: Attribute<C::Scalar> + serde::de::DeserializeOwned>
    TryFrom<serde_json::Value> for CredentialProof<C, AttributeType>
{
    type Error = anyhow::Error;

    fn try_from(mut value: serde_json::Value) -> Result<Self, Self::Error> {
        use anyhow::Context;
        let issuer: String = serde_json::from_value(get_field(&mut value, "issuer")?)?;
        let ty: BTreeSet<String> = serde_json::from_value(get_field(&mut value, "type")?)?;
        anyhow::ensure!(
            ty.contains("VerifiableCredential") && ty.contains("ConcordiumVerifiableCredential")
        );
        let issuance_date = serde_json::from_value::<chrono::DateTime<chrono::Utc>>(
            value
                .get_mut("issuanceDate")
                .context("issuanceDate field not present")?
                .take(),
        )?;
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
                let proofs = statement.into_iter().zip(proof_value.into_iter()).collect();
                Ok(Self::Account {
                    created,
                    network: issuer.network,
                    cred_id,
                    issuer: idp_identity,
                    issuance_date,
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

                let additional_commitments =
                    serde_json::from_value(get_field(&mut proof, "additionalCommitments")?)?;

                let max_base_used = serde_json::from_value(get_field(&mut proof, "maxBaseUsed")?)?;

                let glueing_proof = serde_json::from_value(get_field(&mut proof, "glueingProof")?)?;

                let proof_value: Vec<_> =
                    serde_json::from_value(get_field(&mut proof, "proofValue")?)?;

                anyhow::ensure!(proof_value.len() == statement.len());
                let proofs = statement.into_iter().zip(proof_value.into_iter()).collect();

                Ok(Self::Web3Id {
                    created,
                    owner: CredentialHolderId::new(key),
                    network: issuer.network,
                    contract: address,
                    issuance_date,
                    additional_commitments,
                    max_base_used,
                    glueing_proof,
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
                issuance_date,
            } => {
                0u8.serial(out);
                created.timestamp_millis().serial(out);
                network.serial(out);
                cred_id.serial(out);
                issuer.serial(out);
                issuance_date.timestamp_millis().serial(out);
                proofs.serial(out)
            }
            CredentialProof::Web3Id {
                created,
                network,
                contract,
                additional_commitments,
                glueing_proof,
                proofs,
                issuance_date,
                max_base_used,
                owner,
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
                owner.serial(out);
                issuance_date.timestamp_millis().serial(out);
                additional_commitments.serial(out);
                max_base_used.serial(out);
                glueing_proof.serial(out);
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
    pub public_key: ed25519_dalek::PublicKey,
    phantom:        PhantomData<Role>,
}

impl<Role> From<ed25519_dalek::PublicKey> for Ed25519PublicKey<Role> {
    fn from(value: ed25519_dalek::PublicKey) -> Self { Self::new(value) }
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
        s.try_into().map_err(|e| D::Error::custom(e))
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

impl<Role> TryFrom<&str> for Ed25519PublicKey<Role> {
    type Error = Ed25519PublicKeyFromStrError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let bytes = hex::decode(value)?;
        Ok(Self::new(ed25519_dalek::PublicKey::from_bytes(&bytes)?))
    }
}

impl<Role> Ed25519PublicKey<Role> {
    pub fn new(public_key: ed25519_dalek::PublicKey) -> Self {
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
    fn clone(&self) -> Self {
        Self {
            public_key: self.public_key,
            phantom:    PhantomData,
        }
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
        let public_key = ed25519_dalek::PublicKey::from_bytes(&public_key_bytes)
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
        let public_key = ed25519_dalek::PublicKey::from_bytes(&public_key_bytes)
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
        let to_sign = message_to_sign(self.presentation_context, &self.verifiable_credential);

        let mut linking_proof_iter = self.linking_proof.proof_value.iter();

        if public.len() != self.verifiable_credential.len() {
            return Err(PresentationVerificationError::InconsistentPublicData);
        }

        for (cred_public, cred_proof) in public.zip(&self.verifiable_credential) {
            request.credential_statements.push(cred_proof.statement());
            if let CredentialProof::Web3Id { owner, .. } = &cred_proof {
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
    fn id(&self) -> CredentialHolderId;
    fn sign(&self, msg: &impl AsRef<[u8]>) -> ed25519_dalek::Signature;
}

impl Web3IdSigner for ed25519_dalek::Keypair {
    fn id(&self) -> CredentialHolderId { CredentialHolderId::new(self.public) }

    fn sign(&self, msg: &impl AsRef<[u8]>) -> ed25519_dalek::Signature {
        ed25519_dalek::Signer::sign(self, msg.as_ref())
    }
}

impl Web3IdSigner for ed25519_dalek::SecretKey {
    fn id(&self) -> CredentialHolderId { CredentialHolderId::new(self.into()) }

    fn sign(&self, msg: &impl AsRef<[u8]>) -> ed25519_dalek::Signature {
        let expanded: ed25519_dalek::ExpandedSecretKey = self.into();
        expanded.sign(msg.as_ref(), &self.into())
    }
}

/// The additional inputs, additional to the [`Request`] that are needed to
/// produce a [`Presentation`].
pub enum CommitmentInputs<'a, C: Curve, AttributeType, Web3IdSigner> {
    /// Inputs are for an identity credential issued by an identity provider.
    Account {
        /// Issuance date of the credential that the proof is about.
        /// This is an unfortunate name to conform to the standard, but the
        /// meaning here really is `validFrom` for the credential.
        issuance_date: chrono::DateTime<chrono::Utc>,
        issuer:        IpIdentity,
        /// The values that are committed to and are required in the proofs.
        values:        &'a BTreeMap<u8, AttributeType>,
        /// The randomness to go along with commitments in `values`.
        randomness:    &'a BTreeMap<u8, pedersen_commitment::Randomness<C>>,
    },
    /// Inputs are for a credential issued by Web3ID issuer.
    Web3Issuer {
        /// Issuance date of the credential that the proof is about.
        /// This is an unfortunate name to conform to the standard, but the
        /// meaning here really is `validFrom` for the credential.
        issuance_date: chrono::DateTime<chrono::Utc>,
        /// The signer that will sign the presentation.
        signer:        &'a Web3IdSigner,
        /// Values that are committed to.
        values:        &'a BTreeMap<u8, AttributeType>,
        /// The randomness for the vector commitment.
        randomness:    pedersen_commitment::Randomness<C>,
    },
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
    #[error("Cannot construct the vector commitment. This indicates a configuration error.")]
    CannotCommit,
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
                issuance_date: _,
            },
            CredentialsInputs::Account { commitments },
        ) => {
            for (statement, proof) in proofs.iter() {
                if !statement.verify(global, transcript, &commitments, proof) {
                    return false;
                }
            }
        }
        (
            CredentialProof::Web3Id {
                network: _proof_network,
                contract: _proof_contract,
                additional_commitments,
                glueing_proof,
                proofs,
                created: _,
                issuance_date: _,
                max_base_used,
                owner: _,
                ty: _,
            },
            CredentialsInputs::Web3 { commitment, .. },
        ) => {
            let (&rand_base, _, base) = global.vector_commitment_base();
            // TODO: This cloning here is a tiny bit wasteful.
            let gis = base.take((max_base_used + 1).into()).copied().collect();

            let verifier = VecComEq {
                comm: *commitment,
                comms: additional_commitments.clone(),
                gis,
                h: rand_base,
                g_bar: global.on_chain_commitment_key.g,
                h_bar: global.on_chain_commitment_key.h,
            };
            for (statement, proof) in proofs.iter() {
                if !statement.verify(global, transcript, additional_commitments, proof) {
                    return false;
                }
            }
            if !sigma_protocols::common::verify(transcript, &verifier, glueing_proof) {
                return false;
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
        let mut proofs = Vec::new();
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
                    issuance_date,
                    issuer,
                },
            ) => {
                for statement in statement {
                    let proof = statement
                        .prove(global, ro, csprng, values, randomness)
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
                    issuance_date,
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
                    values,
                    randomness,
                    signer,
                    issuance_date,
                },
            ) => {
                if credential != signer.id() {
                    return Err(ProofError::InconsistentIds);
                }
                let (&rand_base, base_size, base) = global.vector_commitment_base();
                // First construct individual commitments.

                // Get the last (maximum) key in the map.
                let vec_key = values.iter().rev().next().ok_or(ProofError::NoAttributes)?;
                if usize::from(*vec_key.0) >= base_size {
                    return Err(ProofError::TooManyAttributes);
                }
                // TODO: It is wasteful to use the entire commitment key here
                // But if we don't then we have to record how much of it we used
                // so that the verifier can use the same.
                let gis = base.take((*vec_key.0 + 1).into()).copied().collect();
                let vec_comm_key = VecCommitmentKey {
                    gs: gis,
                    h:  rand_base,
                };
                let committed_values = {
                    let mut out = Vec::new();
                    for (tag, value) in values.iter() {
                        while out.len() < usize::from(*tag) {
                            out.push(C::scalar_from_u64(0));
                        }
                        out.push(value.to_field_element());
                    }
                    out
                };
                let comm = vec_comm_key
                    .hide(&committed_values, &randomness)
                    .ok_or(ProofError::CannotCommit)?;
                let comm_key = &global.on_chain_commitment_key;
                let mut ris = BTreeMap::new();
                let individual = statement
                    .iter()
                    .map(|x| {
                        let attr = x.attribute();
                        let value = values.get(&attr).ok_or(ProofError::MissingAttribute)?;
                        let (ind_comm, randomness) = comm_key.commit(
                            &pedersen_commitment::Value::<C>::new(value.to_field_element()),
                            csprng,
                        );
                        ris.insert(attr, randomness.as_value());
                        Ok::<_, ProofError>((attr, ind_comm))
                    })
                    .collect::<Result<BTreeMap<_, _>, _>>()?;
                let prover = VecComEq {
                    comm,
                    comms: individual,
                    gis: vec_comm_key.gs,
                    h: rand_base,
                    g_bar: global.on_chain_commitment_key.g,
                    h_bar: global.on_chain_commitment_key.h,
                };
                for statement in statement {
                    let proof = statement
                        .prove(global, ro, csprng, values, &ris)
                        .ok_or(ProofError::MissingAttribute)?;
                    proofs.push((statement, proof));
                }
                let secrets = (committed_values, randomness.as_value(), ris);
                let glueing_proof = sigma_protocols::common::prove(ro, &prover, secrets, csprng)
                    .ok_or(ProofError::UnableToProve)?;
                let created = chrono::Utc::now();
                Ok(CredentialProof::Web3Id {
                    additional_commitments: prover.comms,
                    glueing_proof,
                    proofs,
                    network,
                    contract,
                    created,
                    issuance_date,
                    max_base_used: *vec_key.0,
                    owner: signer.id(),
                    ty,
                })
            }
            _ => Err(ProofError::CommitmentsStatementsMismatch),
        }
    }
}

fn message_to_sign<C: Curve, AttributeType: Attribute<C::Scalar>>(
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
        let to_sign = message_to_sign(self.challenge, &proofs);
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
/// that are contained in the credentials.
pub enum CredentialsInputs<C: Curve> {
    Account {
        // All the commitments of the credential.
        // In principle we only ever need to borrow this, but it is simpler to
        // have the owned map instead of a reference to it.
        commitments: BTreeMap<AttributeTag, pedersen_commitment::Commitment<C>>,
    },
    Web3 {
        commitment: pedersen_commitment::Commitment<C>,
    },
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, serde::Deserialize, Debug)]
#[serde(try_from = "serde_json::Value")]
/// A value of an attribute. This is the low-level representation. The two
/// different variants are present to enable range proofs for numeric values
/// since their embedding into field elements are more natural and more amenable
/// to range proof than string embeddings.
pub enum Web3IdAttribute {
    String(AttributeKind),
    Numeric(u64),
}

impl TryFrom<serde_json::Value> for Web3IdAttribute {
    type Error = anyhow::Error;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        use anyhow::Context;
        if let Some(v) = value.as_str() {
            Ok(Self::String(v.parse()?))
        } else {
            let v = value.as_u64().context("Not a string or number")?;
            Ok(Self::Numeric(v))
        }
    }
}

impl serde::Serialize for Web3IdAttribute {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer, {
        match self {
            Web3IdAttribute::String(ak) => ak.serialize(serializer),
            Web3IdAttribute::Numeric(n) => n.serialize(serializer),
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
        }
    }
}

impl crate::common::Deserial for Web3IdAttribute {
    fn deserial<R: byteorder::ReadBytesExt>(source: &mut R) -> crate::common::ParseResult<Self> {
        use crate::common::Get;
        match source.get()? {
            0u8 => source.get().map(Web3IdAttribute::String),
            1u8 => source.get().map(Web3IdAttribute::Numeric),
            n => anyhow::bail!("Unrecognized attribute tag: {n}"),
        }
    }
}

impl std::fmt::Display for Web3IdAttribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Web3IdAttribute::String(ak) => ak.fmt(f),
            Web3IdAttribute::Numeric(n) => n.fmt(f),
        }
    }
}

impl Attribute<<ArCurve as Curve>::Scalar> for Web3IdAttribute {
    fn to_field_element(&self) -> <ArCurve as Curve>::Scalar {
        match self {
            Web3IdAttribute::String(ak) => ak.to_field_element(),
            Web3IdAttribute::Numeric(n) => ArCurve::scalar_from_u64(*n),
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
        let signer_1 = ed25519_dalek::Keypair::generate(&mut rng);
        let signer_2 = ed25519_dalek::Keypair::generate(&mut rng);
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
                contract:   ContractAddress::new(1337, 42),
                credential: CredentialHolderId::new(signer_1.public),
                statement:  vec![
                    AtomicStatement::AttributeInRange {
                        statement: AttributeInRangeStatement {
                            attribute_tag: 17,
                            lower:         Web3IdAttribute::Numeric(80),
                            upper:         Web3IdAttribute::Numeric(1237),
                            _phantom:      PhantomData,
                        },
                    },
                    AtomicStatement::AttributeInSet {
                        statement: AttributeInSetStatement {
                            attribute_tag: 23u8,
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
                contract:   ContractAddress::new(1338, 0),
                credential: CredentialHolderId::new(signer_2.public),
                statement:  vec![
                    AtomicStatement::AttributeInRange {
                        statement: AttributeInRangeStatement {
                            attribute_tag: 0,
                            lower:         Web3IdAttribute::Numeric(80),
                            upper:         Web3IdAttribute::Numeric(1237),
                            _phantom:      PhantomData,
                        },
                    },
                    AtomicStatement::AttributeNotInSet {
                        statement: AttributeNotInSetStatement {
                            attribute_tag: 1u8,
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
        let params = GlobalContext::generate("Test".into());
        let mut values_1 = BTreeMap::new();
        values_1.insert(17, Web3IdAttribute::Numeric(137));
        values_1.insert(23, Web3IdAttribute::String(AttributeKind("ff".into())));
        let randomness_1 = pedersen_commitment::Randomness::<ArCurve>::generate(&mut rng);
        let secrets_1 = CommitmentInputs::Web3Issuer {
            issuance_date: chrono::Utc::now(),
            signer:        &signer_1,
            values:        &values_1,
            randomness:    randomness_1.clone(),
        };

        let mut values_2 = BTreeMap::new();
        values_2.insert(0, Web3IdAttribute::Numeric(137));
        values_2.insert(1, Web3IdAttribute::String(AttributeKind("xkcd".into())));
        let randomness_2 = pedersen_commitment::Randomness::<ArCurve>::generate(&mut rng);
        let secrets_2 = CommitmentInputs::Web3Issuer {
            issuance_date: chrono::Utc::now(),
            signer:        &signer_2,
            values:        &values_2,
            randomness:    randomness_2.clone(),
        };
        let attrs = [secrets_1, secrets_2];
        let proof = request
            .clone()
            .prove(&params, attrs.into_iter())
            .context("Cannot prove")?;

        let commitment_1 = {
            let (&rand_base, _, base) = params.vector_commitment_base();
            let gis = base.take(24).copied().collect();
            let vec_comm_key = VecCommitmentKey {
                gs: gis,
                h:  rand_base,
            };
            let committed_values = {
                let mut out = Vec::new();
                for (tag, value) in values_1.iter() {
                    while out.len() < usize::from(*tag) {
                        out.push(ArCurve::scalar_from_u64(0));
                    }
                    out.push(value.to_field_element());
                }
                out
            };
            vec_comm_key
                .hide(&committed_values, &randomness_1)
                .context("Unable to commit in the test.")?
        };
        let commitment_2 = {
            let (&rand_base, _, base) = params.vector_commitment_base();
            let gis = base.take(2).copied().collect();
            let vec_comm_key = VecCommitmentKey {
                gs: gis,
                h:  rand_base,
            };
            let committed_values = {
                let mut out = Vec::new();
                for (tag, value) in values_2.iter() {
                    while out.len() < usize::from(*tag) {
                        out.push(ArCurve::scalar_from_u64(0));
                    }
                    out.push(value.to_field_element());
                }
                out
            };
            vec_comm_key
                .hide(&committed_values, &randomness_2)
                .context("Unable to commit in the test.")?
        };
        let public = vec![
            CredentialsInputs::Web3 {
                commitment: commitment_1,
            },
            CredentialsInputs::Web3 {
                commitment: commitment_2,
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
        let signer_1 = ed25519_dalek::Keypair::generate(&mut rng);
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
                contract:   ContractAddress::new(1337, 42),
                credential: CredentialHolderId::new(signer_1.public),
                statement:  vec![
                    AtomicStatement::AttributeInRange {
                        statement: AttributeInRangeStatement {
                            attribute_tag: 17,
                            lower:         Web3IdAttribute::Numeric(80),
                            upper:         Web3IdAttribute::Numeric(1237),
                            _phantom:      PhantomData,
                        },
                    },
                    AtomicStatement::AttributeInSet {
                        statement: AttributeInSetStatement {
                            attribute_tag: 23u8,
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
                            attribute_tag: 3,
                            lower:         Web3IdAttribute::Numeric(80),
                            upper:         Web3IdAttribute::Numeric(1237),
                            _phantom:      PhantomData,
                        },
                    },
                    AtomicStatement::AttributeNotInSet {
                        statement: AttributeNotInSetStatement {
                            attribute_tag: 1u8,
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
        values_1.insert(17, Web3IdAttribute::Numeric(137));
        values_1.insert(23, Web3IdAttribute::String(AttributeKind("ff".into())));
        let randomness_1 = pedersen_commitment::Randomness::<ArCurve>::generate(&mut rng);
        let secrets_1 = CommitmentInputs::Web3Issuer {
            issuance_date: chrono::Utc::now(),
            signer:        &signer_1,
            values:        &values_1,
            randomness:    randomness_1.clone(),
        };

        let mut values_2 = BTreeMap::new();
        values_2.insert(3, Web3IdAttribute::Numeric(137));
        values_2.insert(1, Web3IdAttribute::String(AttributeKind("xkcd".into())));
        let mut randomness_2 = BTreeMap::new();
        for tag in values_2.keys() {
            randomness_2.insert(
                *tag,
                pedersen_commitment::Randomness::<ArCurve>::generate(&mut rng),
            );
        }
        let secrets_2 = CommitmentInputs::Account {
            issuance_date: chrono::Utc::now(),
            values:        &values_2,
            randomness:    &randomness_2,
            issuer:        IpIdentity::from(17u32),
        };
        let attrs = [secrets_1, secrets_2];
        let proof = request
            .clone()
            .prove(&params, attrs.into_iter())
            .context("Cannot prove")?;

        let commitment_1 = {
            let (&rand_base, _, base) = params.vector_commitment_base();
            let gis = base.take(24).copied().collect();
            let vec_comm_key = VecCommitmentKey {
                gs: gis,
                h:  rand_base,
            };
            let committed_values = {
                let mut out = Vec::new();
                for (tag, value) in values_1.iter() {
                    while out.len() < usize::from(*tag) {
                        out.push(ArCurve::scalar_from_u64(0));
                    }
                    out.push(value.to_field_element());
                }
                out
            };
            vec_comm_key
                .hide(&committed_values, &randomness_1)
                .context("Unable to commit in the test.")?
        };
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
                commitment: commitment_1,
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
}
