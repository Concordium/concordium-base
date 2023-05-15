use crate::{base::CredentialRegistrationID, common::base16_decode_string, id::types::IpIdentity};
use concordium_contracts_common::{
    AccountAddress, ContractAddress, OwnedEntrypointName, OwnedParameter,
};
use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{self, anychar},
    combinator::{cut, recognize},
    multi::many_m_n,
    IResult,
};

#[derive(
    Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq, PartialOrd, Ord,
)]
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

#[derive(Debug, Clone)]
/// The supported DID identifiers on Concordium.
pub enum IdentifierType {
    /// Reference to an account via an address.
    Account { address: AccountAddress },
    /// Reference to a specific credential via its ID.
    Credential { cred_id: CredentialRegistrationID },
    /// Reference to a specific smart contract instance.
    ContractData {
        address:    ContractAddress,
        entrypoint: OwnedEntrypointName,
        parameter:  OwnedParameter,
    },
    /// Reference to a specific Ed25519 public key.
    PublicKey { key: ed25519_dalek::PublicKey },
    /// Reference to a specific identity provider.
    Idp { idp_identity: IpIdentity },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Method {
    pub network: Network,
    pub ty:      IdentifierType,
}

impl<'a> TryFrom<&'a str> for Method {
    type Error = nom::Err<nom::error::Error<String>>;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        // TODO: Ensure the string is consumed.
        let (r, v) = parse_did(value).map_err(|e| e.to_owned())?;
        Ok(v)
    }
}

impl TryFrom<String> for Method {
    type Error = nom::Err<nom::error::Error<String>>;

    fn try_from(value: String) -> Result<Self, Self::Error> { Self::try_from(value.as_str()) }
}

impl std::str::FromStr for Method {
    type Err = nom::Err<nom::error::Error<String>>;

    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::try_from(s) }
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
        }
    }
}

impl From<Method> for String {
    fn from(value: Method) -> Self { value.to_string() }
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

fn ty<'a>(input: &'a str) -> IResult<&'a str, IdentifierType> {
    let account = |input: &'a str| {
        let (input, _) = tag("acc:")(input)?;
        let (input, data) = cut(recognize(many_m_n(50, 50, cut(anychar))))(input)?;
        let address = data.parse::<AccountAddress>().map_err(|_| {
            nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Verify))
        })?;
        Ok((input, IdentifierType::Account { address }))
    };
    let credential = |input: &'a str| {
        let (input, _) = tag("cred:")(input)?;
        let (input, data) = cut(recognize(many_m_n(96, 96, cut(anychar))))(input)?;
        let cred_id = data.parse::<CredentialRegistrationID>().map_err(|_| {
            nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Verify))
        })?;
        Ok((input, IdentifierType::Credential { cred_id }))
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
            return Err(nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Verify)));
        };
        let (input, parameter) = {
            let (input, r) = nom::combinator::opt(|input| {
                let (input, _) = tag("/")(input)?;
                let (input, param_str) = cut(nom::combinator::recognize(
                    nom::character::complete::hex_digit0,
                ))(input)?;
                let Ok(v) = hex::decode(param_str) else {
                    return Err(nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Verify)));
                };
                let Ok(param) = OwnedParameter::try_from(v) else {
                    return Err(nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Verify)));
                };
                Ok((input, param))
            })(input)?;
            match r {
                None => (input, OwnedParameter::empty()),
                Some(d) => (input, d),
            }
        };
        Ok((input, IdentifierType::ContractData {
            address: ContractAddress::new(index, subindex),
            entrypoint,
            parameter,
        }))
    };
    let pkc = |input| {
        let (input, _) = tag("pkc:")(input)?;
        let (input, data) = cut(recognize(many_m_n(64, 64, cut(anychar))))(input)?;
        let key = base16_decode_string(data).map_err(|_| {
            nom::Err::Failure(nom::error::Error::new(input, nom::error::ErrorKind::Verify))
        })?;
        Ok((input, IdentifierType::PublicKey { key }))
    };

    alt((account, credential, contract, pkc))(input)
}

pub fn parse_did<'a>(input: &'a str) -> IResult<&'a str, Method> {
    let (input, _) = prefix(input)?;
    let (input, network) = network(input)?;
    let (input, ty) = ty(input)?;
    Ok((input, Method { network, ty }))
}
