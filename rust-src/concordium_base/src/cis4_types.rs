pub use crate::cis2_types::MetadataUrl;
use crate::contracts_common::{self, self as concordium_std};
use std::marker::PhantomData;

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

#[repr(transparent)]
#[doc(hidden)]
pub struct Ed25519PublicKey<Role> {
    pub public_key: ed25519_dalek::PublicKey,
    phantom:        PhantomData<Role>,
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

impl<Role> contracts_common::Serial for Ed25519PublicKey<Role> {
    fn serial<W: contracts_common::Write>(&self, out: &mut W) -> Result<(), W::Err> {
        out.write_all(self.public_key.as_bytes())
    }
}

impl<Role> contracts_common::Deserial for Ed25519PublicKey<Role> {
    fn deserial<R: contracts_common::Read>(source: &mut R) -> contracts_common::ParseResult<Self> {
        let public_key_bytes = <[u8; ed25519_dalek::PUBLIC_KEY_LENGTH]>::deserial(source)?;
        let public_key = ed25519_dalek::PublicKey::from_bytes(&public_key_bytes)
            .map_err(|_| contracts_common::ParseError {})?;
        Ok(Self {
            public_key,
            phantom: PhantomData,
        })
    }
}

#[doc(hidden)]
pub enum CredentialHolderIdRole {}

pub type CredentialHolderId = Ed25519PublicKey<CredentialHolderIdRole>;

#[derive(PartialEq, Eq, Clone, Copy, Debug, PartialOrd, Ord, Hash)]
pub struct CredentialId {
    pub id: uuid::Uuid,
}

impl contracts_common::Serial for CredentialId {
    fn serial<W: contracts_common::Write>(&self, out: &mut W) -> Result<(), W::Err> {
        out.write_all(self.id.as_bytes())
    }
}

impl contracts_common::Deserial for CredentialId {
    fn deserial<R: contracts_common::Read>(source: &mut R) -> contracts_common::ParseResult<Self> {
        let bytes = <[u8; 16]>::deserial(source)?;
        Ok(Self {
            id: uuid::Uuid::from_bytes(bytes),
        })
    }
}

#[derive(contracts_common::Serialize, PartialEq, Eq, Clone, Debug)]
pub struct CredentialInfo {
    /// The holder's identifier.
    holder_id:        CredentialHolderId,
    /// Whether the holder is allowed to revoke the credential or not.
    holder_revocable: bool,
    /// A vector Pedersen commitment to the attributes of the verifiable
    /// credential.
    #[concordium(size_length = 2)]
    commitment:       Vec<u8>,
    /// The date from which the credential is considered valid.
    valid_from:       contracts_common::Timestamp,
    /// After this date, the credential becomes expired. `None` corresponds to a
    /// credential that cannot expire.
    valid_until:      Option<contracts_common::Timestamp>,
    /// A type of the credential that is used to identify which schema the
    /// credential is based on.
    credential_type:  CredentialType,
    /// Metadata URL of the credential.
    metadata_url:     MetadataUrl,
}

/// Response to a credential data query.
#[derive(contracts_common::Serialize, Clone, Debug)]
pub struct CredentialEntry {
    credential_info:  CredentialInfo,
    /// A schema URL or DID address pointing to the JSON schema for a verifiable
    /// credential.
    schema_ref:       SchemaRef,
    /// The nonce is used to avoid replay attacks when checking the holder's
    /// signature on a revocation message. This is the nonce that should be used
    /// when signing a revocation.
    revocation_nonce: u64,
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
pub enum CredentialStatus {
    #[display(fmt = "Active")]
    Active,
    #[display(fmt = "Revoked")]
    Revoked,
    #[display(fmt = "Expired")]
    Expired,
    #[display(fmt = "NotActivated")]
    NotActivated,
}

#[doc(hidden)]
pub enum RevocationKeyRole {}

pub type RevocationKey = Ed25519PublicKey<RevocationKeyRole>;

#[derive(contracts_common::Serialize, Debug)]
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

pub const REVOKE_DOMAIN_STRING: &[u8] = b"WEB3ID:REVOKE";
