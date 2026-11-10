//! Definition of Concordium DIDs and their parser.

use crate::web3id::v1::IdentityCredentialEphemeralId;
use crate::{base::CredentialRegistrationID, common::base16_decode_string, id::types::IpIdentity};
use concordium_contracts_common::{
    AccountAddress, ContractAddress, EntrypointName, OwnedEntrypointName, OwnedParameter,
};
use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{self, anychar},
    combinator::{cut, recognize},
    multi::many_m_n,
    IResult,
};

/// The number of bytes of a genesis block hash used to identify a network.
pub const GENESIS_HASH_PREFIX_LEN: usize = 16;

/// The first [`GENESIS_HASH_PREFIX_LEN`] bytes of the hash of a chain's
/// genesis block. This identifies a Concordium network without relying on a
/// name, and matches the reference part of `ccd:<prefix>` chain IDs.
///
/// Its string form is exactly 32 lowercase hex characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GenesisHashPrefix(pub [u8; GENESIS_HASH_PREFIX_LEN]);

impl GenesisHashPrefix {
    /// Genesis hash prefix of Concordium testnet.
    pub const TESTNET: Self = Self([
        0x42, 0x21, 0x33, 0x2d, 0x34, 0xe1, 0x69, 0x41, 0x68, 0xc2, 0xa0, 0xc0, 0xb3, 0xfd, 0x0f,
        0x27,
    ]);
    /// Genesis hash prefix of Concordium mainnet.
    pub const MAINNET: Self = Self([
        0x9d, 0xd9, 0xca, 0x4d, 0x19, 0xe9, 0x39, 0x38, 0x77, 0xd2, 0xc4, 0x4b, 0x70, 0xf8, 0x9a,
        0xcb,
    ]);

    /// Take the prefix of a full genesis block hash.
    pub fn from_genesis_hash(hash: &crate::hashes::BlockHash) -> Self {
        let mut bytes = [0u8; GENESIS_HASH_PREFIX_LEN];
        bytes.copy_from_slice(&hash.as_ref()[..GENESIS_HASH_PREFIX_LEN]);
        Self(bytes)
    }
}

impl std::fmt::Display for GenesisHashPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

#[derive(thiserror::Error, Debug)]
#[error("Invalid genesis hash prefix: {0}. Expected {len} lowercase hex characters.", len = 2 * GENESIS_HASH_PREFIX_LEN)]
/// An error that can occur when parsing a [`GenesisHashPrefix`].
pub struct GenesisHashPrefixFromStrError(String);

impl std::str::FromStr for GenesisHashPrefix {
    type Err = GenesisHashPrefixFromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || GenesisHashPrefixFromStrError(s.to_string());
        // Require the canonical (lowercase) form so the textual representation of
        // a network is unique.
        if s.len() != 2 * GENESIS_HASH_PREFIX_LEN
            || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(err());
        }
        let mut bytes = [0u8; GENESIS_HASH_PREFIX_LEN];
        hex::decode_to_slice(s, &mut bytes).map_err(|_| err())?;
        Ok(Self(bytes))
    }
}

/// The network part of a Concordium DID.
///
/// A network is written either by name (`testnet`, `mainnet`) or by the
/// prefix of its genesis block hash (see [`GenesisHashPrefix`]). The latter
/// works for any chain, including ones without a well-known name.
///
/// Equality, ordering and hashing compare the *chain* a network refers to,
/// not how it is written: `Network::Testnet` is equal to
/// `Network::Genesis(GenesisHashPrefix::TESTNET)`. Serialization (string,
/// JSON and binary) preserves the form the value was constructed with, so
/// existing data is unaffected.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(into = "String", try_from = "String")]
#[non_exhaustive]
pub enum Network {
    /// Concordium testnet, written `testnet`.
    Testnet,
    /// Concordium mainnet, written `mainnet`.
    Mainnet,
    /// Any network, identified by the prefix of its genesis block hash.
    Genesis(GenesisHashPrefix),
}

impl Network {
    /// The genesis hash prefix of the chain this network refers to.
    pub fn genesis_hash_prefix(&self) -> GenesisHashPrefix {
        match self {
            Network::Testnet => GenesisHashPrefix::TESTNET,
            Network::Mainnet => GenesisHashPrefix::MAINNET,
            Network::Genesis(prefix) => *prefix,
        }
    }

    /// Whether `self` and `other` refer to the same chain. Equivalent to `==`.
    pub fn same_chain(&self, other: &Network) -> bool {
        self.genesis_hash_prefix() == other.genesis_hash_prefix()
    }
}

impl From<GenesisHashPrefix> for Network {
    fn from(prefix: GenesisHashPrefix) -> Self {
        Network::Genesis(prefix)
    }
}

impl PartialEq for Network {
    fn eq(&self, other: &Self) -> bool {
        self.same_chain(other)
    }
}

impl Eq for Network {}

impl std::hash::Hash for Network {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.genesis_hash_prefix().hash(state)
    }
}

impl PartialOrd for Network {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Network {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.genesis_hash_prefix().cmp(&other.genesis_hash_prefix())
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Network::Testnet => f.write_str("testnet"),
            Network::Mainnet => f.write_str("mainnet"),
            Network::Genesis(prefix) => prefix.fmt(f),
        }
    }
}

#[derive(thiserror::Error, Debug)]
#[error("Unsupported network: {network}")]
/// An error that can occur when converting a string to a network.
pub struct NetworkFromStrError {
    network: String,
}

impl std::str::FromStr for Network {
    type Err = NetworkFromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "testnet" => Ok(Self::Testnet),
            "mainnet" => Ok(Self::Mainnet),
            other => other
                .parse::<GenesisHashPrefix>()
                .map(Self::Genesis)
                .map_err(|_| NetworkFromStrError {
                    network: other.to_string(),
                }),
        }
    }
}

impl From<Network> for String {
    fn from(value: Network) -> Self {
        value.to_string()
    }
}

impl TryFrom<String> for Network {
    type Error = NetworkFromStrError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl crate::common::Serial for Network {
    fn serial<B: crate::common::Buffer>(&self, out: &mut B) {
        match self {
            Network::Testnet => 0u8.serial(out),
            Network::Mainnet => 1u8.serial(out),
            Network::Genesis(prefix) => {
                2u8.serial(out);
                out.write_all(&prefix.0)
                    .expect("Writing to a buffer should succeed.");
            }
        }
    }
}

impl crate::common::Deserial for Network {
    fn deserial<R: byteorder::ReadBytesExt>(source: &mut R) -> crate::common::ParseResult<Self> {
        match u8::deserial(source)? {
            0u8 => Ok(Self::Testnet),
            1u8 => Ok(Self::Mainnet),
            2u8 => {
                let mut bytes = [0u8; GENESIS_HASH_PREFIX_LEN];
                source.read_exact(&mut bytes)?;
                Ok(Self::Genesis(GenesisHashPrefix(bytes)))
            }
            n => anyhow::bail!("Unrecognized network tag {n}"),
        }
    }
}

/// The supported DID identifiers on Concordium.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentifierType {
    /// Reference to an account via an address.
    Account { address: AccountAddress },
    /// Reference to an account credential via the account credential registration ID.
    Credential { cred_id: CredentialRegistrationID },
    /// Reference to a specific smart contract instance.
    ContractData {
        address: ContractAddress,
        entrypoint: OwnedEntrypointName,
        parameter: OwnedParameter,
    },
    /// Reference to a specific Ed25519 public key.
    PublicKey { key: ed25519_dalek::VerifyingKey },
    /// Reference to a specific identity provider.
    Idp { idp_identity: IpIdentity },
    /// Encrypted, ephemeral identifier for an identity credential. It is the encryption of IdCredPub.
    /// The identifier is ephemeral since the encryption is randomized.
    EncryptedIdentityCredentialId {
        cred_id: IdentityCredentialEphemeralId,
    },
}

impl IdentifierType {
    /// If `self` is the [`ContractData`](Self::ContractData) variant then
    /// check if the entrypoint is as specified, and attempt to parse the
    /// parameter into the provided type.
    pub fn extract_contract<D: concordium_contracts_common::Deserial>(
        &self,
        ep: EntrypointName,
    ) -> Option<(ContractAddress, D)> {
        let IdentifierType::ContractData {
            address,
            entrypoint,
            parameter,
        } = self
        else {
            return None;
        };
        if entrypoint.as_entrypoint_name() != ep {
            return None;
        }
        let d = concordium_contracts_common::from_bytes(parameter.as_ref()).ok()?;
        Some((*address, d))
    }

    /// If `self` is the [`PublicKey`](Self::PublicKey) variant then extract the
    /// public key, otherwise return [`None`].
    pub fn extract_public_key(&self) -> Option<ed25519_dalek::VerifyingKey> {
        let IdentifierType::PublicKey { key } = self else {
            return None;
        };
        Some(*key)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(try_from = "String", into = "String")]
/// A DID method.
pub struct Method {
    /// The network part of the method.
    pub network: Network,
    /// The remaining identifier.
    pub ty: IdentifierType,
}

impl Method {
    /// Construct variant [`Idp`](IdentifierType::Idp)
    pub fn new_idp(network: Network, idp_identity: IpIdentity) -> Self {
        Self {
            network,
            ty: IdentifierType::Idp { idp_identity },
        }
    }

    /// Construct variant [`Account`](IdentifierType::Account)
    pub fn new_account(network: Network, address: AccountAddress) -> Self {
        Self {
            network,
            ty: IdentifierType::Account { address },
        }
    }

    /// Construct variant [`AccountCredential`](IdentifierType::Credential)
    pub fn new_account_credential(network: Network, cred_id: CredentialRegistrationID) -> Self {
        Self {
            network,
            ty: IdentifierType::Credential { cred_id },
        }
    }

    /// Construct variant [`PublicKey`](IdentifierType::PublicKey)
    pub fn new_public_key(network: Network, key: ed25519_dalek::VerifyingKey) -> Self {
        Self {
            network,
            ty: IdentifierType::PublicKey { key },
        }
    }

    /// Construct variant [`IdentityCredential`](IdentifierType::EncryptedIdentityCredentialId)
    pub fn new_identity_credential(
        network: Network,
        cred_id: IdentityCredentialEphemeralId,
    ) -> Self {
        Self {
            network,
            ty: IdentifierType::EncryptedIdentityCredentialId { cred_id },
        }
    }
}

#[derive(Debug, thiserror::Error)]
/// An error that can occur when attempting to parse a string as a DID
/// [`Method`].
pub enum MethodFromStrError {
    #[error("Unable to parse DID: {0}")]
    Parse(#[from] nom::Err<nom::error::Error<String>>),
    #[error("The input was not consumed. There is a leftover: {0}")]
    Leftover(String),
}

impl<'a> TryFrom<&'a str> for Method {
    type Error = MethodFromStrError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let (r, v) = parse_did(value).map_err(|e| e.to_owned())?;
        if r.is_empty() {
            Ok(v)
        } else {
            Err(MethodFromStrError::Leftover(r.into()))
        }
    }
}

impl TryFrom<String> for Method {
    type Error = MethodFromStrError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl std::str::FromStr for Method {
    type Err = MethodFromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.ty {
            IdentifierType::Account { address } => {
                write!(f, "did:ccd:{}:acc:{address}", self.network)
            }
            IdentifierType::Credential { cred_id } => {
                write!(f, "did:ccd:{}:cred:{cred_id}", self.network)
            }
            IdentifierType::ContractData {
                address,
                entrypoint,
                parameter,
            } => {
                write!(
                    f,
                    "did:ccd:{}:sci:{}:{}/{entrypoint}/{parameter}",
                    self.network, address.index, address.subindex
                )
            }
            IdentifierType::PublicKey { key } => {
                write!(
                    f,
                    "did:ccd:{}:pkc:{}",
                    self.network,
                    hex::encode(key.as_bytes())
                )
            }
            IdentifierType::Idp { idp_identity } => {
                write!(f, "did:ccd:{}:idp:{idp_identity}", self.network)
            }
            IdentifierType::EncryptedIdentityCredentialId { cred_id } => {
                let cred_id_hex = hex::encode(&cred_id.0);
                write!(f, "did:ccd:{}:encidcred:{cred_id_hex}", self.network)
            }
        }
    }
}

impl From<Method> for String {
    fn from(value: Method) -> Self {
        value.to_string()
    }
}

fn prefix(input: &str) -> IResult<&str, ()> {
    let (input, _) = tag("did:ccd:")(input)?;
    Ok((input, ()))
}

fn network(input: &str) -> IResult<&str, Network> {
    match alt::<&str, &str, _, _>((
        tag::<&str, &str, nom::error::Error<&str>>("testnet"),
        tag("mainnet"),
    ))(input)
    {
        Ok((input, network)) => {
            let (input, _) = tag(":")(input)?;
            if network == "testnet" {
                Ok((input, Network::Testnet))
            } else {
                Ok((input, Network::Mainnet))
            }
        }
        Err(_) => {
            // A run of hex digits followed by `:` is a genesis hash prefix. Identifier
            // type tags are short (the only all-hex one is `acc`), so a run longer than
            // that which is not exactly a prefix is reported as a bad network rather
            // than falling through to a confusing identifier error.
            let hex_len = input.bytes().take_while(|b| b.is_ascii_hexdigit()).count();
            if hex_len > 3 && input.as_bytes().get(hex_len) == Some(&b':') {
                let Ok(prefix) = input[..hex_len].parse::<GenesisHashPrefix>() else {
                    return Err(nom::Err::Failure(nom::error::Error::new(
                        input,
                        nom::error::ErrorKind::Verify,
                    )));
                };
                return Ok((&input[hex_len + 1..], Network::Genesis(prefix)));
            }
            // No network means we default to mainnet.
            Ok((input, Network::Mainnet))
        }
    }
}

fn ty<'a>(input: &'a str) -> IResult<&'a str, IdentifierType> {
    let account = |input: &'a str| {
        let (input, _) = tag("acc:")(input)?;
        let (input, data) = cut(recognize(many_m_n(50, 50, cut(anychar))))(input)?;
        let address = data.parse::<AccountAddress>().map_err(|_| {
            nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Verify))
        })?;
        Ok((input, IdentifierType::Account { address }))
    };
    let account_credential = |input: &'a str| {
        let (input, _) = tag("cred:")(input)?;
        let (input, data) = cut(recognize(many_m_n(96, 96, cut(anychar))))(input)?;
        let cred_id = data.parse::<CredentialRegistrationID>().map_err(|_| {
            nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Verify))
        })?;
        Ok((input, IdentifierType::Credential { cred_id }))
    };
    let identity_credential = |input: &'a str| {
        let (input, _) = tag("encidcred:")(input)?;
        let bytes = hex::decode(input).map_err(|_| {
            nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Verify))
        })?;
        let cred_id = IdentityCredentialEphemeralId(bytes);
        Ok((
            "",
            IdentifierType::EncryptedIdentityCredentialId { cred_id },
        ))
    };
    let contract = |input| {
        let (input, _) = tag("sci:")(input)?;
        let (input, index) = cut(complete::u64)(input)?;
        let (input, subindex) = {
            let r = nom::combinator::opt(|input| {
                let (input, _) = tag(":")(input)?;
                cut(complete::u64)(input)
            })(input)?;
            (r.0, r.1.unwrap_or(0))
        };
        let (input, _) = tag("/")(input)?;
        let (input, entrypoint_str): (_, &str) = cut(nom::combinator::recognize(
            nom::multi::many0(nom::character::complete::satisfy(|x| x != '/')),
        ))(input)?;
        let Ok(entrypoint) = OwnedEntrypointName::new(entrypoint_str.into()) else {
            return Err(nom::Err::Failure(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Verify,
            )));
        };
        let (input, parameter) = {
            let (input, r) = nom::combinator::opt(|input| {
                let (input, _) = tag("/")(input)?;
                let (input, param_str) = cut(nom::combinator::recognize(
                    nom::character::complete::hex_digit0,
                ))(input)?;
                let Ok(v) = hex::decode(param_str) else {
                    return Err(nom::Err::Failure(nom::error::Error::new(
                        input,
                        nom::error::ErrorKind::Verify,
                    )));
                };
                let Ok(param) = OwnedParameter::try_from(v) else {
                    return Err(nom::Err::Failure(nom::error::Error::new(
                        input,
                        nom::error::ErrorKind::Verify,
                    )));
                };
                Ok((input, param))
            })(input)?;
            match r {
                None => (input, OwnedParameter::empty()),
                Some(d) => (input, d),
            }
        };
        Ok((
            input,
            IdentifierType::ContractData {
                address: ContractAddress::new(index, subindex),
                entrypoint,
                parameter,
            },
        ))
    };
    let pkc = |input| {
        let (input, _) = tag("pkc:")(input)?;
        let (input, data) = cut(recognize(many_m_n(64, 64, cut(anychar))))(input)?;
        let key = base16_decode_string(data).map_err(|_| {
            nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Verify))
        })?;
        Ok((input, IdentifierType::PublicKey { key }))
    };

    let idp = |input| {
        let (input, _) = tag("idp:")(input)?;
        let (input, data) = cut(nom::character::complete::u32)(input)?;
        let idp_identity = IpIdentity::from(data);
        Ok((input, IdentifierType::Idp { idp_identity }))
    };

    alt((
        account,
        account_credential,
        identity_credential,
        contract,
        pkc,
        idp,
    ))(input)
}

/// Parse a DID, returning either an error or the parsed method and leftover
/// input.
pub fn parse_did(input: &str) -> IResult<&str, Method> {
    let (input, _) = prefix(input)?;
    let (input, network) = network(input)?;
    let (input, ty) = ty(input)?;
    Ok((input, Method { network, ty }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elgamal::Cipher;
    use crate::id::types::{ArIdentity, ChainArData};
    use crate::web3id::fixtures;
    use crate::web3id::v1::IdentityCredentialEphemeralIdDataRef;

    use crate::id::constants::ArCurve;
    use crate::id::secret_sharing::Threshold;
    use std::collections::BTreeMap;

    #[test]
    fn test_account() -> anyhow::Result<()> {
        let address = "3kBx2h5Y2veb4hZgAJWPrr8RyQESKm5TjzF3ti1QQ4VSYLwK1G".parse()?;
        let target = Method {
            network: Network::Mainnet,
            ty: IdentifierType::Account { address },
        };
        assert_eq!(format!("did:ccd:acc:{address}").parse::<Method>()?, target);
        assert_eq!(
            format!("did:ccd:mainnet:acc:{address}").parse::<Method>()?,
            target
        );
        let s = target.to_string();
        assert_eq!(s.parse::<Method>()?, target);
        assert_eq!(
            format!("did:ccd:testnet:acc:{address}").parse::<Method>()?,
            Method {
                network: Network::Testnet,
                ..target
            }
        );
        assert!(format!("did:ccd:acc:{address}/ff")
            .parse::<Method>()
            .is_err());
        Ok(())
    }

    #[test]
    fn test_contract() -> anyhow::Result<()> {
        let index = 37;
        let subindex = 123;
        let entrypoint = OwnedEntrypointName::new_unchecked("viewStuff".into());
        let parameter = OwnedParameter::new_unchecked(vec![123, 11, 0, 0, 13]);
        let target = Method {
            network: Network::Mainnet,
            ty: IdentifierType::ContractData {
                address: ContractAddress::new(index, subindex),
                entrypoint: entrypoint.clone(),
                parameter: parameter.clone(),
            },
        };
        assert_eq!(
            format!("did:ccd:sci:{index}:{subindex}/{entrypoint}/{parameter}").parse::<Method>()?,
            target
        );
        assert_eq!(
            format!("did:ccd:mainnet:sci:{index}:{subindex}/{entrypoint}/{parameter}")
                .parse::<Method>()?,
            target
        );
        let s = target.to_string();
        assert_eq!(s.parse::<Method>()?, target);
        assert_eq!(
            format!("did:ccd:testnet:sci:{index}:{subindex}/{entrypoint}/{parameter}")
                .parse::<Method>()?,
            Method {
                network: Network::Testnet,
                ..target
            }
        );
        assert!(
            format!("did:ccd:testnet:sci:{index}:{subindex}/{entrypoint}/{parameter}/ff")
                .parse::<Method>()
                .is_err()
        );

        // Section to test that omitting the subindex is OK when it is 0, and omitting
        // the parameter is OK when it is empty.
        let index = 37;
        let subindex = 0;
        let entrypoint = OwnedEntrypointName::new_unchecked("viewStuff".into());
        let parameter = OwnedParameter::new_unchecked(vec![]);
        let target = Method {
            network: Network::Mainnet,
            ty: IdentifierType::ContractData {
                address: ContractAddress::new(index, subindex),
                entrypoint: entrypoint.clone(),
                parameter: parameter.clone(),
            },
        };
        assert_eq!(
            format!("did:ccd:sci:{index}:{subindex}/{entrypoint}/{parameter}").parse::<Method>()?,
            target
        );
        assert_eq!(
            format!("did:ccd:sci:{index}/{entrypoint}/{parameter}").parse::<Method>()?,
            target
        );
        assert_eq!(
            format!("did:ccd:sci:{index}/{entrypoint}/").parse::<Method>()?,
            target
        );
        assert_eq!(
            format!("did:ccd:sci:{index}/{entrypoint}").parse::<Method>()?,
            target
        );
        assert_eq!(
            format!("did:ccd:mainnet:sci:{index}:{subindex}/{entrypoint}/{parameter}")
                .parse::<Method>()?,
            target
        );
        assert_eq!(
            format!("did:ccd:mainnet:sci:{index}/{entrypoint}/{parameter}").parse::<Method>()?,
            target
        );
        assert_eq!(
            format!("did:ccd:mainnet:sci:{index}/{entrypoint}").parse::<Method>()?,
            target
        );
        assert_eq!(
            format!("did:ccd:mainnet:sci:{index}/{entrypoint}/").parse::<Method>()?,
            target
        );
        let s = target.to_string();
        assert_eq!(s.parse::<Method>()?, target);
        assert_eq!(
            format!("did:ccd:testnet:sci:{index}:{subindex}/{entrypoint}/{parameter}")
                .parse::<Method>()?,
            Method {
                network: Network::Testnet,
                ..target
            }
        );
        Ok(())
    }

    /// On-chain account credential
    #[test]
    fn test_account_credential() -> anyhow::Result<()> {
        let cred_id = "a5bedc6d92d6cc8333684aa69091095c425d0b5971f554964a6ac8e297a3074748d25268f1d217234c400f3103669f90".parse()?;
        let target = Method {
            network: Network::Mainnet,
            ty: IdentifierType::Credential { cred_id },
        };
        assert_eq!(format!("did:ccd:cred:{cred_id}").parse::<Method>()?, target);
        assert_eq!(
            format!("did:ccd:mainnet:cred:{cred_id}").parse::<Method>()?,
            target
        );
        let s = target.to_string();
        assert_eq!(s.parse::<Method>()?, target);
        assert_eq!(
            format!("did:ccd:testnet:cred:{cred_id}").parse::<Method>()?,
            Method {
                network: Network::Testnet,
                ..target
            }
        );
        assert!(format!("did:ccd:cred:{cred_id}/ff")
            .parse::<Method>()
            .is_err());
        Ok(())
    }

    #[test]
    fn test_public_key() -> anyhow::Result<()> {
        let key = "9cb20e36766a8c1fee1cae8e09eca75785f3bfda220f83b2f0d865cc8a44cd86";
        let target = Method {
            network: Network::Mainnet,
            ty: IdentifierType::PublicKey {
                key: base16_decode_string(key)?,
            },
        };
        assert_eq!(format!("did:ccd:pkc:{key}").parse::<Method>()?, target);
        assert_eq!(
            format!("did:ccd:mainnet:pkc:{key}").parse::<Method>()?,
            target
        );
        let s = target.to_string();
        assert_eq!(s.parse::<Method>()?, target);
        assert_eq!(
            format!("did:ccd:testnet:pkc:{key}").parse::<Method>()?,
            Method {
                network: Network::Testnet,
                ..target
            }
        );
        assert!(format!("did:ccd:cred:{key}/ff").parse::<Method>().is_err());
        Ok(())
    }

    #[test]
    fn test_idp() -> anyhow::Result<()> {
        let idp_identity = "37".parse()?;
        let target = Method {
            network: Network::Mainnet,
            ty: IdentifierType::Idp { idp_identity },
        };
        assert_eq!(
            format!("did:ccd:idp:{idp_identity}").parse::<Method>()?,
            target
        );
        assert_eq!(
            format!("did:ccd:mainnet:idp:{idp_identity}").parse::<Method>()?,
            target
        );
        let s = target.to_string();
        assert_eq!(s.parse::<Method>()?, target);
        assert_eq!(
            format!("did:ccd:testnet:idp:{idp_identity}").parse::<Method>()?,
            Method {
                network: Network::Testnet,
                ..target
            }
        );
        assert!(format!("did:ccd:idp:{idp_identity}/ff")
            .parse::<Method>()
            .is_err());
        Ok(())
    }

    const TESTNET_PREFIX: &str = "4221332d34e1694168c2a0c0b3fd0f27";
    const CUSTOM_PREFIX: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn test_network_string_round_trip() -> anyhow::Result<()> {
        for s in ["testnet", "mainnet", TESTNET_PREFIX, CUSTOM_PREFIX] {
            let network: Network = s.parse()?;
            assert_eq!(network.to_string(), s, "Display must preserve the form");
            let json = serde_json::to_string(&network)?;
            assert_eq!(json, format!("\"{s}\""));
            let back: Network = serde_json::from_str(&json)?;
            assert_eq!(back.to_string(), s);
        }
        assert!(matches!(
            TESTNET_PREFIX.parse::<Network>()?,
            Network::Genesis(_)
        ));
        // Not canonical / not a network.
        for s in [
            "Testnet",
            "4221332D34E1694168C2A0C0B3FD0F27",
            "4221332d34e1694168c2a0c0b3fd0f2",
            "4221332d34e1694168c2a0c0b3fd0f2700",
            "stagenet",
        ] {
            assert!(s.parse::<Network>().is_err(), "{s} should not parse");
        }
        Ok(())
    }

    #[test]
    fn test_network_binary_serialization() -> anyhow::Result<()> {
        // Existing encodings must be unchanged.
        assert_eq!(crate::common::to_bytes(&Network::Testnet), vec![0u8]);
        assert_eq!(crate::common::to_bytes(&Network::Mainnet), vec![1u8]);

        let custom: Network = CUSTOM_PREFIX.parse()?;
        let bytes = crate::common::to_bytes(&custom);
        assert_eq!(bytes.len(), 1 + GENESIS_HASH_PREFIX_LEN);
        assert_eq!(bytes[0], 2u8);
        assert_eq!(&bytes[1..], hex::decode(CUSTOM_PREFIX)?.as_slice());

        for network in [Network::Testnet, Network::Mainnet, custom] {
            let back: Network = crate::common::from_bytes(&mut std::io::Cursor::new(
                crate::common::to_bytes(&network),
            ))?;
            assert_eq!(back.to_string(), network.to_string());
        }
        Ok(())
    }

    #[test]
    fn test_network_same_chain_equality() -> anyhow::Result<()> {
        let testnet_genesis: Network = TESTNET_PREFIX.parse()?;
        assert_eq!(Network::Testnet, testnet_genesis);
        assert_eq!(
            Network::Mainnet,
            Network::Genesis(GenesisHashPrefix::MAINNET)
        );
        assert_ne!(Network::Testnet, Network::Mainnet);
        assert_ne!(Network::Testnet, CUSTOM_PREFIX.parse::<Network>()?);

        let mut set = std::collections::HashSet::new();
        set.insert(Network::Testnet);
        assert!(set.contains(&testnet_genesis));

        let hash = "4221332d34e1694168c2a0c0b3fd0f273809612cb13d000d5c2e00e85f50f796"
            .parse::<crate::hashes::BlockHash>()?;
        assert_eq!(
            GenesisHashPrefix::from_genesis_hash(&hash),
            GenesisHashPrefix::TESTNET
        );
        Ok(())
    }

    #[test]
    fn test_genesis_network_dids() -> anyhow::Result<()> {
        let address: AccountAddress =
            "3kBx2h5Y2veb4hZgAJWPrr8RyQESKm5TjzF3ti1QQ4VSYLwK1G".parse()?;
        let cred_id = "a5bedc6d92d6cc8333684aa69091095c425d0b5971f554964a6ac8e297a3074748d25268f1d217234c400f3103669f90";
        let key = "9cb20e36766a8c1fee1cae8e09eca75785f3bfda220f83b2f0d865cc8a44cd86";
        let encidcred = hex::encode(&identity_cred_id_fixture().0);
        for prefix in [TESTNET_PREFIX, CUSTOM_PREFIX] {
            let network: Network = prefix.parse()?;
            for s in [
                format!("did:ccd:{prefix}:acc:{address}"),
                format!("did:ccd:{prefix}:cred:{cred_id}"),
                format!("did:ccd:{prefix}:sci:37:123/viewStuff/7b0b00000d"),
                format!("did:ccd:{prefix}:pkc:{key}"),
                format!("did:ccd:{prefix}:idp:37"),
                format!("did:ccd:{prefix}:encidcred:{encidcred}"),
            ] {
                let method: Method = s.parse()?;
                assert!(matches!(method.network, Network::Genesis(_)));
                assert_eq!(method.network, network);
                assert_eq!(method.network.to_string(), prefix);
                assert_eq!(method.to_string(), s, "Display must round trip");
            }
        }
        // The genesis form of testnet refers to the same DID as the named form.
        assert_eq!(
            format!("did:ccd:{TESTNET_PREFIX}:idp:37").parse::<Method>()?,
            "did:ccd:testnet:idp:37".parse::<Method>()?
        );
        // Malformed prefixes are rejected instead of being read as mainnet.
        for s in [
            "did:ccd:4221332d34e1694168c2a0c0b3fd0f2:idp:37",
            "did:ccd:4221332D34E1694168C2A0C0B3FD0F27:idp:37",
            "did:ccd:4221332d34e1694168c2a0c0b3fd0f273809612cb13d000d5c2e00e85f50f796:idp:37",
        ] {
            assert!(s.parse::<Method>().is_err(), "{s} should not parse");
        }
        Ok(())
    }

    /// Create an [`IdentityCredentialEphemeralId`] to use in tests
    fn identity_cred_id_fixture() -> IdentityCredentialEphemeralId {
        let mut ar_data = BTreeMap::new();
        ar_data.insert(
            ArIdentity::try_from(1).unwrap(),
            ChainArData {
                enc_id_cred_pub_share: Cipher::generate(&mut fixtures::seed(0)),
            },
        );
        ar_data.insert(
            ArIdentity::try_from(2).unwrap(),
            ChainArData {
                enc_id_cred_pub_share: Cipher::generate(&mut fixtures::seed(1)),
            },
        );
        ar_data.insert(
            ArIdentity::try_from(3).unwrap(),
            ChainArData {
                enc_id_cred_pub_share: Cipher::generate(&mut fixtures::seed(2)),
            },
        );

        IdentityCredentialEphemeralId::from_data(IdentityCredentialEphemeralIdDataRef::<ArCurve> {
            ar_data: &ar_data,
            threshold: Threshold::try_new(2).expect("Threshold of 2 will never fail"),
        })
    }

    #[test]
    fn test_identity_credential() {
        let cred_id = identity_cred_id_fixture();
        let cred_id_hex = hex::encode(&cred_id.0);

        let target = Method {
            network: Network::Mainnet,
            ty: IdentifierType::EncryptedIdentityCredentialId { cred_id },
        };

        assert_eq!(
            format!("did:ccd:encidcred:{cred_id_hex}")
                .parse::<Method>()
                .unwrap(),
            target
        );
        assert_eq!(
            format!("did:ccd:mainnet:encidcred:{cred_id_hex}")
                .parse::<Method>()
                .unwrap(),
            target
        );
        let s = target.to_string();
        assert_eq!(s, "did:ccd:mainnet:encidcred:02000300000001ac5f20234d022490c77c18f9a9ec845811a9faa539361b166ee752ddd1cc71ba2a2c37d9b0b1d43b8dd04994d9b8da04b7b14843f9c078c28c20341d435358cd150ecdebdbab7d880a1397cd68346e8dd4c347d4efaaad32979237a71969c41e0000000281da2c786ecca7be2bb2c44f2ccce6ec658497d3481d1c761b728b718258341261331a25d257df8108ef8354af3ca5fa95ec67e89275e82f068d5406e1457b6f54c79992739161437f84fc269bc62c7d26b85befab6111825a4e96e47f4f3e4f00000003af3d3fa6bdd3be106fc225ce6dcaade80c8d1d74f1f6a76d5f6492aa668e6baad87ac13af2af2822ca37b4ef8c6ad63990a190cf220735cca125fb9843eb2dd9a155fda9f8fe112885ded270de3e16814d763ea3d0ee74c9970107d2286918ce");
        assert_eq!(s.parse::<Method>().unwrap(), target);
        assert_eq!(
            format!("did:ccd:testnet:encidcred:{cred_id_hex}")
                .parse::<Method>()
                .unwrap(),
            Method {
                network: Network::Testnet,
                ..target
            }
        );
        assert!("did:ccd:encidcred:asdf".parse::<Method>().is_err());
    }
}
