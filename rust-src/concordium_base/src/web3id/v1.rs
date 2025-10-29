mod proofs;

use crate::curve_arithmetic::{Curve, Pairing};
use crate::id::types::Attribute;
use crate::web3id::did::Network;
use crate::web3id::{
    AccountCredentialMetadata, AccountCredentialProof, AccountCredentialStatement,
    IdentityCredentialMetadata, IdentityCredentialProof, IdentityCredentialStatement, LinkingProof,
    Web3IdCredentialProof, Web3IdCredentialStatement, Web3idCredentialMetadata,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdentityCredentialId {
    a: String,
}

/// Context challenge that serves as a distinguishing context when requesting
/// proofs.
#[derive(
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    serde::Deserialize,
    serde::Serialize,
    crate::common::Serialize,
    Debug,
)]
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

/// A statement about a single credential, either an account credential, an identity credential or a
/// Web3 credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialStatementV1<C: Curve, AttributeType: Attribute<C::Scalar>> {
    /// Statement about an account credential derived from an identity issued by an
    /// identity provider.
    Account(AccountCredentialStatement<C, AttributeType>),
    /// Statement about a credential issued by a Web3 identity provider, a smart
    /// contract.
    Web3Id(Web3IdCredentialStatement<C, AttributeType>),
    /// Statement about identity attributes derived directly from an identity issued by an
    /// identity provider.
    Identity(IdentityCredentialStatement<C, AttributeType>),
}

/// Metadata of a single credential.
pub enum CredentialMetadataV1 {
    /// Metadata of an account credential, i.e., a credential derived from an
    /// identity object.
    Account(AccountCredentialMetadata),
    /// Metadata of a Web3Id credential.
    Web3Id(Web3idCredentialMetadata),
    /// Metadata of identity attributes derived directly from an
    /// identity object.
    Identity(IdentityCredentialMetadata),
}

/// Metadata about a single [`CredentialProofV1`].
pub struct ProofMetadataV1 {
    /// Timestamp of when the proof was created.
    pub created: chrono::DateTime<chrono::Utc>,
    pub network: Network,
    /// The DID of the credential the proof is about.
    pub cred_metadata: CredentialMetadataV1,
}

/// A proof corresponding to one [`CredentialStatementV1`]. This contains almost
/// all the information needed to verify it, except the issuer's public key in
/// case of the `Web3Id` proof, and the public commitments in case of the
/// `Account` proof, and the identity provider and privacy guardian (anonymity revoker) keys
/// in case of the `Identity` proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialProofV1<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
> {
    Account(AccountCredentialProof<C, AttributeType>),
    Web3Id(Web3IdCredentialProof<C, AttributeType>),
    Identity(IdentityCredentialProof<P, C, AttributeType>),
}

impl<P: Pairing<ScalarField = C::Scalar>, C: Curve, AttributeType: Attribute<C::Scalar>>
    crate::common::Serial for CredentialProofV1<P, C, AttributeType>
{
    fn serial<B: crate::common::Buffer>(&self, out: &mut B) {
        // todo ar proof ser
        match self {
            CredentialProofV1::Account(AccountCredentialProof {
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
            CredentialProofV1::Web3Id(Web3IdCredentialProof {
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
            CredentialProofV1::Identity(IdentityCredentialProof {
                created,
                network,
                id_attr_cred_info,
                proofs,
            }) => {
                // todo ar update
                2u8.serial(out);
                created.timestamp_millis().serial(out);
                network.serial(out);
                id_attr_cred_info.serial(out);
                proofs.serial(out)
            }
        }
    }
}

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>, AttributeType: Attribute<C::Scalar>>
    CredentialProofV1<P, C, AttributeType>
{
    pub fn network(&self) -> Network {
        match self {
            CredentialProofV1::Account(acc) => acc.network,
            CredentialProofV1::Web3Id(web3) => web3.network,
            CredentialProofV1::Identity(id) => id.network,
        }
    }

    pub fn created(&self) -> chrono::DateTime<chrono::Utc> {
        match self {
            CredentialProofV1::Account(acc) => acc.created,
            CredentialProofV1::Web3Id(web3) => web3.created,
            CredentialProofV1::Identity(id) => id.created,
        }
    }

    pub fn metadata(&self) -> ProofMetadataV1 {
        let cred_metadata = match self {
            CredentialProofV1::Account(cred_proof) => {
                CredentialMetadataV1::Account(cred_proof.metadata())
            }
            CredentialProofV1::Web3Id(cred_proof) => {
                CredentialMetadataV1::Web3Id(cred_proof.metadata())
            }
            CredentialProofV1::Identity(cred_proof) => {
                CredentialMetadataV1::Identity(cred_proof.metadata())
            }
        };

        ProofMetadataV1 {
            created: self.created(),
            network: self.network(),
            cred_metadata,
        }
    }

    /// Extract the statement from the proof.
    pub fn statement(&self) -> CredentialStatementV1<C, AttributeType> {
        match self {
            CredentialProofV1::Account(cred_proof) => {
                CredentialStatementV1::Account(cred_proof.statement())
            }
            CredentialProofV1::Web3Id(cred_proof) => {
                CredentialStatementV1::Web3Id(cred_proof.statement())
            }
            CredentialProofV1::Identity(cred_proof) => {
                CredentialStatementV1::Identity(cred_proof.statement())
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
/// A presentation is the response to a [`RequestV1`]. It contains proofs for
/// statements, ownership proof for all Web3 credentials, and a context. The
/// only missing part to verify the proof are the public commitments.
pub struct PresentationV1<
    P: Pairing,
    C: Curve<Scalar = P::ScalarField>,
    AttributeType: Attribute<C::Scalar>,
> {
    pub presentation_context: ContextChallenge,
    pub verifiable_credential: Vec<CredentialProofV1<P, C, AttributeType>>,
    /// Signatures from keys of Web3 credentials (not from ID credentials).
    /// The order is the same as that in the `credential_proofs` field.
    pub linking_proof: LinkingProof,
}

#[derive(Clone, PartialEq, Eq, Debug)]
/// A request for a proof. This is the statement and challenge. The secret data
/// comes separately.
pub struct RequestV1<C: Curve, AttributeType: Attribute<C::Scalar>> {
    pub challenge: ContextChallenge,
    pub credential_statements: Vec<CredentialStatementV1<C, AttributeType>>,
}
