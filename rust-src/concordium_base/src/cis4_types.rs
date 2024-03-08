pub use crate::cis2_types::MetadataUrl;
use crate::{
    contracts_common::{self, self as concordium_std},
    web3id::*,
};

/// Credential type is a string that corresponds to the value of the "name"
/// attribute of the credential schema.
#[derive(
    contracts_common::Serialize, PartialEq, Eq, Clone, Debug, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct CredentialType {
    #[concordium(size_length = 1)]
    pub credential_type: String,
}

// TODO: make field above private, add TryFrom/Into instances

/// A schema reference is a schema URL pointing to the JSON
/// schema for a verifiable credential.
#[derive(
    contracts_common::Serialize, PartialEq, Eq, Clone, Debug, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct SchemaRef {
    pub schema_ref: MetadataUrl,
}

#[derive(
    serde::Serialize, serde::Deserialize, contracts_common::Serialize, PartialEq, Eq, Clone, Debug,
)]
#[serde(rename_all = "camelCase")]
pub struct CredentialInfo {
    /// The holder's identifier.
    pub holder_id:        CredentialHolderId,
    /// Whether the holder is allowed to revoke the credential or not.
    pub holder_revocable: bool,
    /// The date from which the credential is considered valid.
    pub valid_from:       contracts_common::Timestamp,
    /// After this date, the credential becomes expired. `None` corresponds to a
    /// credential that cannot expire.
    pub valid_until:      Option<contracts_common::Timestamp>,
    /// Metadata URL of the credential.
    pub metadata_url:     MetadataUrl,
}

/// Response to a credential data query.
#[derive(serde::Serialize, serde::Deserialize, contracts_common::Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
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
    serde::Serialize,
    serde::Deserialize,
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
#[serde(rename_all = "camelCase")]
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

/// A response type for the registry metadata request.
#[derive(contracts_common::Serialize, Debug, Clone)]
pub struct RegistryMetadata {
    /// A reference to the issuer's metadata.
    pub issuer_metadata:   MetadataUrl,
    /// The type of credentials used.
    pub credential_type:   CredentialType,
    /// A reference to the JSON schema corresponding to this type.
    pub credential_schema: SchemaRef,
}

#[doc(hidden)]
pub enum IssuerKeyRole {}

/// Public key of an issuer.
pub type IssuerKey = Ed25519PublicKey<IssuerKeyRole>;

/// Data for events of registering and updating a credential.
#[derive(contracts_common::Serialize, Debug, Clone)]
pub struct CredentialEventData {
    /// A public key of the credential's holder.
    pub holder_id:       CredentialHolderId,
    /// A reference to the credential JSON schema.
    pub schema_ref:      SchemaRef,
    /// Type of the credential.
    pub credential_type: CredentialType,
    /// The metadata URL of the newly registered credential.
    pub metadata_url:    MetadataUrl,
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
#[derive(contracts_common::Serialize, Debug, Clone)]
pub struct RevokeCredentialEvent {
    /// A public key of the credential's holder.
    pub holder_id: CredentialHolderId,
    /// Who revokes the credential.
    pub revoker:   Revoker,
    /// An optional text clarifying the revocation reasons.
    /// The issuer can use this field to comment on the revocation, so the
    /// holder can observe it in the wallet.
    pub reason:    Option<Reason>,
}

#[derive(Debug, contracts_common::Serialize, Clone)]
/// An event emitted when the issuer metadata is set, either
/// initially or when it is updated.
pub struct IssuerMetadataEvent {
    /// The location of the metadata.
    pub metadata_url: MetadataUrl,
}

/// The schema reference has been updated for the credential type.
#[derive(contracts_common::Serialize, Debug, Clone)]
pub struct CredentialSchemaRefEvent {
    pub r#type:     CredentialType,
    pub schema_ref: SchemaRef,
}

#[derive(Debug, Clone, contracts_common::Serialize)]
pub struct CredentialMetadataEvent {
    pub credential_id: CredentialHolderId,
    pub metadata_url:  MetadataUrl,
}

#[derive(contracts_common::Serialize, Debug, Clone)]
pub enum RevocationKeyAction {
    Register,
    Remove,
}

/// An untagged revocation key event.
/// Emitted when keys are registered and removed.
/// For a tagged version use `CredentialEvent`.
#[derive(contracts_common::Serialize, Debug, Clone)]
pub struct RevocationKeyEvent {
    /// The public key that is registered/removed
    pub key:    RevocationKey,
    /// A register/remove action.
    pub action: RevocationKeyAction,
}

/// An event specified by CIS4 standard.
#[derive(Debug, Clone)]
pub enum CredentialEvent {
    /// Credential registration event. Logged when an entry in the registry is
    /// created for the first time.
    Register(CredentialEventData),
    /// Credential revocation event.
    Revoke(RevokeCredentialEvent),
    /// Issuer's metadata changes, including the contract deployment.
    IssuerMetadata(MetadataUrl),
    /// Credential's metadata changes.
    CredentialMetadata(CredentialMetadataEvent),
    /// Credential's schema changes.
    Schema(CredentialSchemaRefEvent),
    /// Revocation key changes
    RevocationKey(RevocationKeyEvent),
    /// Event is not part of the CIS4 specification.
    Unknown,
}

impl contracts_common::Deserial for CredentialEvent {
    fn deserial<R: contracts_common::Read>(source: &mut R) -> contracts_common::ParseResult<Self> {
        use contracts_common::Get;
        match source.get()? {
            249u8 => Ok(Self::Register(source.get()?)),
            248u8 => Ok(Self::Revoke(source.get()?)),
            247u8 => Ok(Self::IssuerMetadata(source.get()?)),
            246u8 => Ok(Self::CredentialMetadata(source.get()?)),
            245u8 => Ok(Self::Schema(source.get()?)),
            244u8 => Ok(Self::RevocationKey(source.get()?)),
            _ => Ok(Self::Unknown),
        }
    }
}

/// Attempt to convert the event to a [`CredentialEvent`]. Return [`None`] in
/// case the event is not one specified by a CIS4 standard.
impl<'a> TryFrom<&'a crate::smart_contracts::ContractEvent> for CredentialEvent {
    type Error = crate::contracts_common::ParseError;

    fn try_from(value: &'a crate::smart_contracts::ContractEvent) -> Result<Self, Self::Error> {
        use crate::contracts_common::Get;
        let data = value.as_ref();
        let mut cursor = crate::contracts_common::Cursor::new(data);
        let event = cursor.get()?;
        // In case of a recognized event make sure that all of the input was consumed.
        if cursor.offset == data.len() || matches!(event, CredentialEvent::Unknown) {
            Ok(event)
        } else {
            Err(crate::contracts_common::ParseError {})
        }
    }
}

/// A short comment on a reason of revoking or restoring a credential.
/// The string is of a limited size of 256 bytes in order to fit into a single
/// log entry along with other data.
#[derive(contracts_common::Serialize, Clone, Debug)]
pub struct Reason {
    #[concordium(size_length = 1)]
    reason: String,
}
