//! Definition of Concordium DIDs and their parser.

use crate::curve_arithmetic::Curve;
use crate::web3id::v1::IdentityCredentialId;
use crate::{
    base::CredentialRegistrationID, common, common::base16_decode_string, id::types::IpIdentity,
};
use concordium_contracts_common::{
    AccountAddress, ContractAddress, EntrypointName, OwnedEntrypointName, OwnedParameter,
};
use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{self, anychar},
    combinator::{cut, recognize},
    multi::many_m_n,
    AsBytes, IResult,
};

#[derive(
    Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq, PartialOrd, Ord,
)]
/// Supported networks for Concordium DIDs.
pub enum Network {
    #[serde(rename = "testnet")]
    Testnet,
    #[serde(rename = "mainnet")]
    Mainnet,
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Network::Testnet => f.write_str("testnet"),
            Network::Mainnet => f.write_str("mainnet"),
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
            other => Err(NetworkFromStrError {
                network: other.to_string(),
            }),
        }
    }
}

impl crate::common::Serial for Network {
    fn serial<B: crate::common::Buffer>(&self, out: &mut B) {
        match self {
            Network::Testnet => 0u8.serial(out),
            Network::Mainnet => 1u8.serial(out),
        }
    }
}

impl crate::common::Deserial for Network {
    fn deserial<R: byteorder::ReadBytesExt>(source: &mut R) -> crate::common::ParseResult<Self> {
        match u8::deserial(source)? {
            0u8 => Ok(Self::Testnet),
            1u8 => Ok(Self::Mainnet),
            n => anyhow::bail!("Unrecognized network tag {n}"),
        }
    }
}

/// The supported DID identifiers on Concordium.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentifierType<C: Curve> {
    /// Reference to an account via an address.
    Account { address: AccountAddress },
    /// Reference to an account credential via its the account credential registration ID.
    AccountCredential { cred_id: CredentialRegistrationID },
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
    /// Reference to an identity credential via the IdCredSec encryption.
    IdentityCredential { cred_id: IdentityCredentialId<C> },
}

impl<C: Curve> IdentifierType<C> {
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
#[serde(bound(serialize = "", deserialize = ""))]
/// A DID method.
pub struct Method<C: Curve> {
    /// The network part of the method.
    pub network: Network,
    /// The remaining identifier.
    pub ty: IdentifierType<C>,
}

impl<C: Curve> Method<C> {
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

    /// Construct variant [`AccountCredential`](IdentifierType::AccountCredential)
    pub fn new_account_credential(network: Network, cred_id: CredentialRegistrationID) -> Self {
        Self {
            network,
            ty: IdentifierType::AccountCredential { cred_id },
        }
    }


    /// Construct variant [`PublicKey`](IdentifierType::PublicKey)
    pub fn new_public_key(network: Network, key: ed25519_dalek::VerifyingKey) -> Self {
        Self {
            network,
            ty: IdentifierType::PublicKey { key },
        }
    }

    /// Construct variant [`IdentityCredential`](IdentifierType::IdentityCredential)
    pub fn new_identity_credential(network: Network, cred_id: IdentityCredentialId<C>) -> Self {
        Self {
            network,
            ty: IdentifierType::IdentityCredential { cred_id },
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

impl<'a, C: Curve> TryFrom<&'a str> for Method<C> {
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

impl<C: Curve> TryFrom<String> for Method<C> {
    type Error = MethodFromStrError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl<C: Curve> std::str::FromStr for Method<C> {
    type Err = MethodFromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl<C: Curve> std::fmt::Display for Method<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.ty {
            IdentifierType::Account { address } => {
                write!(f, "did:ccd:{}:acc:{address}", self.network)
            }
            IdentifierType::AccountCredential { cred_id } => {
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
            IdentifierType::IdentityCredential { cred_id } => {
                let cred_id_hex = hex::encode(common::to_bytes(&cred_id));
                write!(f, "did:ccd:{}:idcred:{cred_id_hex}", self.network)
            }
        }
    }
}

impl<C: Curve> From<Method<C>> for String {
    fn from(value: Method<C>) -> Self {
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
            // No network means we default to mainnet.
            Ok((input, Network::Mainnet))
        }
    }
}

fn ty<'a, C: Curve>(input: &'a str) -> IResult<&'a str, IdentifierType<C>> {
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
        Ok((input, IdentifierType::AccountCredential { cred_id }))
    };
    let identity_credential = |input: &'a str| {
        let (input, _) = tag("idcred:")(input)?;
        let bytes = hex::decode(input).map_err(|_| {
            nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Verify))
        })?;
        let cred_id: IdentityCredentialId<C> =
            common::from_bytes(&mut bytes.as_bytes()).map_err(|_| {
                nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Verify))
            })?;
        Ok(("", IdentifierType::IdentityCredential { cred_id }))
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
pub fn parse_did<C: Curve>(input: &str) -> IResult<&str, Method<C>> {
    let (input, _) = prefix(input)?;
    let (input, network) = network(input)?;
    let (input, ty) = ty(input)?;
    Ok((input, Method { network, ty }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common;
    use crate::elgamal::Cipher;
    use crate::id::constants::ArCurve;
    use crate::id::types::{ArIdentity, ChainArData};
    use crate::web3id::fixtures;
    use std::collections::BTreeMap;

    #[test]
    fn test_account() -> anyhow::Result<()> {
        let address = "3kBx2h5Y2veb4hZgAJWPrr8RyQESKm5TjzF3ti1QQ4VSYLwK1G".parse()?;
        let target = Method {
            network: Network::Mainnet,
            ty: IdentifierType::Account { address },
        };
        assert_eq!(
            format!("did:ccd:acc:{address}").parse::<Method<ArCurve>>()?,
            target
        );
        assert_eq!(
            format!("did:ccd:mainnet:acc:{address}").parse::<Method<ArCurve>>()?,
            target
        );
        let s = target.to_string();
        assert_eq!(s.parse::<Method<ArCurve>>()?, target);
        assert_eq!(
            format!("did:ccd:testnet:acc:{address}").parse::<Method<ArCurve>>()?,
            Method {
                network: Network::Testnet,
                ..target
            }
        );
        assert!(format!("did:ccd:acc:{address}/ff")
            .parse::<Method<ArCurve>>()
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
            format!("did:ccd:sci:{index}:{subindex}/{entrypoint}/{parameter}")
                .parse::<Method<ArCurve>>()?,
            target
        );
        assert_eq!(
            format!("did:ccd:mainnet:sci:{index}:{subindex}/{entrypoint}/{parameter}")
                .parse::<Method<ArCurve>>()?,
            target
        );
        let s = target.to_string();
        assert_eq!(s.parse::<Method<ArCurve>>()?, target);
        assert_eq!(
            format!("did:ccd:testnet:sci:{index}:{subindex}/{entrypoint}/{parameter}")
                .parse::<Method<ArCurve>>()?,
            Method {
                network: Network::Testnet,
                ..target
            }
        );
        assert!(
            format!("did:ccd:testnet:sci:{index}:{subindex}/{entrypoint}/{parameter}/ff")
                .parse::<Method<ArCurve>>()
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
            format!("did:ccd:sci:{index}:{subindex}/{entrypoint}/{parameter}")
                .parse::<Method<ArCurve>>()?,
            target
        );
        assert_eq!(
            format!("did:ccd:sci:{index}/{entrypoint}/{parameter}").parse::<Method<ArCurve>>()?,
            target
        );
        assert_eq!(
            format!("did:ccd:sci:{index}/{entrypoint}/").parse::<Method<ArCurve>>()?,
            target
        );
        assert_eq!(
            format!("did:ccd:sci:{index}/{entrypoint}").parse::<Method<ArCurve>>()?,
            target
        );
        assert_eq!(
            format!("did:ccd:mainnet:sci:{index}:{subindex}/{entrypoint}/{parameter}")
                .parse::<Method<ArCurve>>()?,
            target
        );
        assert_eq!(
            format!("did:ccd:mainnet:sci:{index}/{entrypoint}/{parameter}")
                .parse::<Method<ArCurve>>()?,
            target
        );
        assert_eq!(
            format!("did:ccd:mainnet:sci:{index}/{entrypoint}").parse::<Method<ArCurve>>()?,
            target
        );
        assert_eq!(
            format!("did:ccd:mainnet:sci:{index}/{entrypoint}/").parse::<Method<ArCurve>>()?,
            target
        );
        let s = target.to_string();
        assert_eq!(s.parse::<Method<ArCurve>>()?, target);
        assert_eq!(
            format!("did:ccd:testnet:sci:{index}:{subindex}/{entrypoint}/{parameter}")
                .parse::<Method<ArCurve>>()?,
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
            ty: IdentifierType::AccountCredential { cred_id },
        };
        assert_eq!(
            format!("did:ccd:cred:{cred_id}").parse::<Method<ArCurve>>()?,
            target
        );
        assert_eq!(
            format!("did:ccd:mainnet:cred:{cred_id}").parse::<Method<ArCurve>>()?,
            target
        );
        let s = target.to_string();
        assert_eq!(s.parse::<Method<ArCurve>>()?, target);
        assert_eq!(
            format!("did:ccd:testnet:cred:{cred_id}").parse::<Method<ArCurve>>()?,
            Method {
                network: Network::Testnet,
                ..target
            }
        );
        assert!(format!("did:ccd:cred:{cred_id}/ff")
            .parse::<Method<ArCurve>>()
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
        assert_eq!(
            format!("did:ccd:pkc:{key}").parse::<Method<ArCurve>>()?,
            target
        );
        assert_eq!(
            format!("did:ccd:mainnet:pkc:{key}").parse::<Method<ArCurve>>()?,
            target
        );
        let s = target.to_string();
        assert_eq!(s.parse::<Method<ArCurve>>()?, target);
        assert_eq!(
            format!("did:ccd:testnet:pkc:{key}").parse::<Method<ArCurve>>()?,
            Method {
                network: Network::Testnet,
                ..target
            }
        );
        assert!(format!("did:ccd:cred:{key}/ff")
            .parse::<Method<ArCurve>>()
            .is_err());
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
            format!("did:ccd:idp:{idp_identity}").parse::<Method<ArCurve>>()?,
            target
        );
        assert_eq!(
            format!("did:ccd:mainnet:idp:{idp_identity}").parse::<Method<ArCurve>>()?,
            target
        );
        let s = target.to_string();
        assert_eq!(s.parse::<Method<ArCurve>>()?, target);
        assert_eq!(
            format!("did:ccd:testnet:idp:{idp_identity}").parse::<Method<ArCurve>>()?,
            Method {
                network: Network::Testnet,
                ..target
            }
        );
        assert!(format!("did:ccd:idp:{idp_identity}/ff")
            .parse::<Method<ArCurve>>()
            .is_err());
        Ok(())
    }

    /// Create an [`IdentityCredentialId`] to use in tests
    fn identity_cred_id_fixture() -> IdentityCredentialId<ArCurve> {
        let mut ar_data = BTreeMap::new();
        ar_data.insert(
            ArIdentity::try_from(1).unwrap(),
            ChainArData {
                enc_id_cred_pub_share: Cipher::generate(&mut fixtures::seed0()),
            },
        );
        ar_data.insert(
            ArIdentity::try_from(2).unwrap(),
            ChainArData {
                enc_id_cred_pub_share: Cipher::generate(&mut fixtures::seed0()),
            },
        );
        ar_data.insert(
            ArIdentity::try_from(3).unwrap(),
            ChainArData {
                enc_id_cred_pub_share: Cipher::generate(&mut fixtures::seed0()),
            },
        );

        IdentityCredentialId { ar_data }
    }

    #[test]
    fn test_identity_credential() {
        let cred_id = identity_cred_id_fixture();
        let cred_id_hex = hex::encode(common::to_bytes(&cred_id));

        let target = Method {
            network: Network::Mainnet,
            ty: IdentifierType::IdentityCredential { cred_id },
        };

        assert_eq!(
            format!("did:ccd:idcred:{cred_id_hex}")
                .parse::<Method<ArCurve>>()
                .unwrap(),
            target
        );
        assert_eq!(
            format!("did:ccd:mainnet:idcred:{cred_id_hex}")
                .parse::<Method<ArCurve>>()
                .unwrap(),
            target
        );
        let s = target.to_string();
        assert_eq!(s, "did:ccd:mainnet:idcred:000000000000000300000001ac5f20234d022490c77c18f9a9ec845811a9faa539361b166ee752ddd1cc71ba2a2c37d9b0b1d43b8dd04994d9b8da04b7b14843f9c078c28c20341d435358cd150ecdebdbab7d880a1397cd68346e8dd4c347d4efaaad32979237a71969c41e00000002ac5f20234d022490c77c18f9a9ec845811a9faa539361b166ee752ddd1cc71ba2a2c37d9b0b1d43b8dd04994d9b8da04b7b14843f9c078c28c20341d435358cd150ecdebdbab7d880a1397cd68346e8dd4c347d4efaaad32979237a71969c41e00000003ac5f20234d022490c77c18f9a9ec845811a9faa539361b166ee752ddd1cc71ba2a2c37d9b0b1d43b8dd04994d9b8da04b7b14843f9c078c28c20341d435358cd150ecdebdbab7d880a1397cd68346e8dd4c347d4efaaad32979237a71969c41e");
        assert_eq!(s.parse::<Method<ArCurve>>().unwrap(), target);
        assert_eq!(
            format!("did:ccd:testnet:idcred:{cred_id_hex}")
                .parse::<Method<ArCurve>>()
                .unwrap(),
            Method {
                network: Network::Testnet,
                ..target
            }
        );
        assert!("did:ccd:idcred:aaff00dd"
            .parse::<Method<ArCurve>>()
            .is_err());
    }
}
