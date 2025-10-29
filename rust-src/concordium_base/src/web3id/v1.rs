mod proofs;

use crate::base::CredentialRegistrationID;
use crate::curve_arithmetic::{Curve, Pairing};
use crate::id::id_proof_types::AtomicStatement;
use crate::id::types::{
    Attribute, AttributeTag, CredentialValidity, IdentityAttributesCredentialsInfo, IpIdentity,
};
use crate::web3id::did::Network;
use crate::web3id::{CredentialHolderId, LinkingProof, SignedCommitments, StatementWithProof};
use concordium_contracts_common::ContractAddress;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdentityCredentialId {
    a: String,
}

/// Context challenge that serves as a distinguishing context when requesting
/// proofs.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, serde::Deserialize, serde::Serialize, Debug)]
pub struct ContextChallenge {
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

/// A statement about a single credential, either an identity credential or a
/// Web3 credential.
#[derive(Debug, Clone, serde::Deserialize, PartialEq, Eq)]
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

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize)]
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

#[derive(Debug, PartialEq, Eq, serde::Deserialize)]
/// A presentation is the response to a [`Request`]. It contains proofs for
/// statements, ownership proof for all Web3 credentials, and a context. The
/// only missing part to verify the proof are the public commitments.
pub struct Presentation<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
> {
    pub presentation_context: ContextChallenge,
    pub verifiable_credential: Vec<CredentialProof<P, C, AttributeType>>,
    /// Signatures from keys of Web3 credentials (not from ID credentials).
    /// The order is the same as that in the `credential_proofs` field.
    pub linking_proof: LinkingProof,
}
