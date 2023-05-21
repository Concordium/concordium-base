pub use crate::cis2_types::MetadataUrl;
use crate::{
    contracts_common::{self, self as concordium_std},
    web3id::*,
};

/// Credential type is a string that corresponds to the value of the "name"
/// attribute of the credential schema.
#[derive(contracts_common::Serialize, PartialEq, Eq, Clone, Debug)]
pub struct CredentialType {
    #[concordium(size_length = 1)]
    pub credential_type: String,
}

/// A schema reference is a schema URL or DID address pointing to the JSON
/// schema for a verifiable credential.
#[derive(contracts_common::Serialize, PartialEq, Eq, Clone, Debug)]
pub struct SchemaRef {
    pub schema_ref: MetadataUrl,
}

#[derive(contracts_common::Serialize, PartialEq, Eq, Clone, Debug)]
pub struct CredentialInfo {
    /// The holder's identifier.
    pub holder_id:        CredentialHolderId,
    /// Whether the holder is allowed to revoke the credential or not.
    pub holder_revocable: bool,
    /// A vector Pedersen commitment to the attributes of the verifiable
    /// credential.
    #[concordium(size_length = 2)]
    pub commitment:       Vec<u8>,
    /// The date from which the credential is considered valid.
    pub valid_from:       contracts_common::Timestamp,
    /// After this date, the credential becomes expired. `None` corresponds to a
    /// credential that cannot expire.
    pub valid_until:      Option<contracts_common::Timestamp>,
    /// A type of the credential that is used to identify which schema the
    /// credential is based on.
    pub credential_type:  CredentialType,
    /// Metadata URL of the credential.
    pub metadata_url:     MetadataUrl,
}

/// Response to a credential data query.
#[derive(contracts_common::Serialize, Clone, Debug)]
pub struct CredentialEntry {
    pub credential_info:  CredentialInfo,
    /// A schema URL or DID address pointing to the JSON schema for a verifiable
    /// credential.
    pub schema_ref:       SchemaRef,
    /// The nonce is used to avoid replay attacks when checking the holder's
    /// signature on a revocation message. This is the nonce that should be used
    /// when signing a revocation.
    pub revocation_nonce: u64,
}

#[derive(
    contracts_common::Serialize,
    PartialOrd,
    Ord,
    Hash,
    PartialEq,
    Eq,
    Clone,
    Copy,
    Debug,
    derive_more::Display,
)]
/// The current status of a credential.
pub enum CredentialStatus {
    /// The credential is active.
    #[display(fmt = "Active")]
    Active,
    /// The credential has been revoked.
    #[display(fmt = "Revoked")]
    Revoked,
    /// The credential validity has expired.
    #[display(fmt = "Expired")]
    Expired,
    /// The credential is not yet valid, that is, it is before the valid period.
    #[display(fmt = "NotActivated")]
    NotActivated,
}

#[doc(hidden)]
pub enum RevocationKeyRole {}

pub type RevocationKey = Ed25519PublicKey<RevocationKeyRole>;

#[derive(contracts_common::Serialize, Debug)]
/// Revocation key together with a nonce that needs to be used for signing the
/// next revocation transaction.
pub struct RevocationKeyWithNonce {
    pub key:   RevocationKey,
    pub nonce: u64,
}

#[doc(hidden)]
pub enum IssuerKeyRole {}

pub type IssuerKey = Ed25519PublicKey<IssuerKeyRole>;

/// Data for events of registering and updating a credential.
/// Used by the tagged event `CredentialEvent`.
#[derive(contracts_common::Serialize, Debug, Clone)]
pub struct CredentialEventData {
    /// An identifier of a credential being registered/updated.
    credential_id:   CredentialId,
    /// A public key of the credential's holder.
    holder_id:       CredentialHolderId,
    /// A reference to the credential JSON schema.
    schema_ref:      SchemaRef,
    /// Type of the credential.
    credential_type: CredentialType,
}

/// A type for specifying who is revoking a credential, when registering a
/// revocation event.
#[derive(contracts_common::Serialize, Debug, Clone)]
pub enum Revoker {
    Issuer,
    Holder,
    /// `Other` is used for the cases when the revoker is not the issuer or
    /// holder. In this contract it is a revocation authority, which is
    /// identified using ther public key.
    Other(RevocationKey),
}

/// An untagged revocation event.
/// For a tagged version use `CredentialEvent`.
#[derive(contracts_common::Serialize, Debug, Clone)]
pub struct RevokeCredentialEvent {
    /// An identifier of a credential being revoked.
    credential_id: CredentialId,
    /// A public key of the credential's holder.
    holder_id:     CredentialHolderId,
    /// Who revokes the credential.
    revoker:       Revoker,
    /// An optional text clarifying the revocation reasons.
    /// The issuer can use this field to comment on the revocation, so the
    /// holder can observe it in the wallet.
    reason:        Option<Reason>,
}

/// An untagged restoration event.
/// For a tagged version use `CredentialEvent`.
#[derive(contracts_common::Serialize, Debug, Clone)]
pub struct RestoreCredentialEvent {
    /// An identifier of a credential being restored.
    credential_id: CredentialId,
    /// A public key of the credential's holder.
    holder_id:     CredentialHolderId,
    /// An optional text clarifying the restoring reasons.
    reason:        Option<Reason>,
}

#[derive(Debug, contracts_common::Serialize, Clone)]
pub struct IssuerMetadataEvent {
    /// The location of the metadata.
    pub metadata_url: MetadataUrl,
}

/// Tagged credential registry event.
/// This version should be used for logging the events.
#[derive(contracts_common::Serialize, Debug, Clone)]
pub enum CredentialEvent {
    /// Credential registration event. Logged when an entry in the registry is
    /// created for the first time.
    Register(CredentialEventData),
    /// Credential update event. Logged when updating an existing credential
    /// entry.
    Update(CredentialEventData),
    /// Credential revocation event.
    Revoke(RevokeCredentialEvent),
    /// Credential restoration (reversing revocation) event.
    Restore(RestoreCredentialEvent),
    /// The issuer metadata is updated.
    Metadata(IssuerMetadataEvent),
}

/// A short comment on a reason of revoking or restoring a credential.
/// The string is of a limited size of 256 bytes in order to fit into a single
/// log entry along with other data.
#[derive(contracts_common::Serialize, Clone, Debug)]
pub struct Reason {
    #[concordium(size_length = 1)]
    reason: String,
}
