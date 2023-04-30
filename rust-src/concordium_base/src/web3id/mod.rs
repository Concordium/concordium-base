use std::{collections::BTreeMap, fmt::Display, str::FromStr};

// TODO:
// - have proper parser for hex values
// - base encoding prefix?
// - Add FromStr and Display for Method.
// - ensure EOF?
// - Documentation.
// - Revise the use of AttributeTag
use crate::{
    base::CredentialRegistrationID,
    common::base16_decode_string,
    curve_arithmetic::Curve,
    id::{
        constants::AttributeKind,
        id_proof_types::{AtomicProof, AtomicStatement},
        sigma_protocols::{self, vcom_eq::VecComEq},
        types::{Attribute, CredentialDeploymentCommitments, GlobalContext, IpIdentity},
    },
    pedersen_commitment::{self, VecCommitmentKey},
    random_oracle::RandomOracle,
};
use concordium_contracts_common::{hashes::HashBytes, AccountAddress, ContractAddress};
use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{self, anychar},
    combinator::{cut, recognize},
    multi::many_m_n,
    IResult,
};
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};

#[derive(Debug, Clone, Copy)]
pub enum Network {
    Testnet,
    Mainnet,
}

#[derive(Debug, Clone)]
/// The supported DID identifiers on Concordium.
pub enum IdentifierType {
    /// Reference to an account via an address.
    Account { address: AccountAddress },
    /// Reference to a specific credential via its ID.
    Credential { cred_id: CredentialRegistrationID },
    /// Reference to a specific smart contract instance.
    Instance { address: ContractAddress },
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

impl FromStr for Method {
    type Err = nom::Err<nom::error::Error<String>>;

    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::try_from(s) }
}

impl Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { todo!() }
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

        Ok((input, IdentifierType::Instance {
            address: ContractAddress::new(index, subindex),
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

pub fn parse_did(input: &str) -> IResult<&str, Method> {
    let (input, _) = prefix(input)?;
    let (input, network) = network(input)?;
    let (input, ty) = ty(input)?;
    Ok((input, Method { network, ty }))
}

/// A statement about a single credential.
#[derive(Debug, Clone, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeSerialize",
    deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
pub struct CredentialStatement<C: Curve, AttributeType: Attribute<C::Scalar>> {
    /// Reference to the credential to which this statement applies.
    pub reference: Method,
    /// The statement composed by one or more atomic statements for the same
    /// method. The statements are grouped together since that fits
    /// naturally into how the proof is constructed.
    pub statement: Vec<AtomicStatement<C, u8, AttributeType>>,
}

#[derive(Debug, Clone, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(
    serialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeSerialize",
    deserialize = "C: Curve, AttributeType: Attribute<C::Scalar> + SerdeDeserialize<'de>"
))]
pub struct CredentialProof<C: Curve, AttributeType: Attribute<C::Scalar>> {
    /// Reference to the credential to which this statement applies.
    /// TODO: This should not be a Method, but a more precise identifier, either
    /// normal credential or ID 3.0 credential.
    pub reference:     Method,
    // TODO: This might be inlined with AtomicProof. Fix serialization in JSON so that null is
    // None.
    pub glueing_proof: GlueingProof<C>,
    /// The statement composed by one or more atomic statements.
    pub proofs:        Vec<AtomicProof<C, AttributeType>>,
}

#[derive(Debug, Clone, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(serialize = "C: Curve", deserialize = "C: Curve"))]
#[serde(tag = "type")]
pub enum GlueingProof<C: Curve> {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "proof", rename_all = "camelCase")]
    Proof {
        additional_commitments: BTreeMap<u8, pedersen_commitment::Commitment<C>>,
        proof: sigma_protocols::common::SigmaProof<sigma_protocols::vcom_eq::Witness<C>>,
    },
}

#[doc(hidden)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
/// Used as a phantom type to indicate a hash is a web3id challenge.
pub enum Web3IdChallengeMarker {}

pub type Challenge = HashBytes<Web3IdChallengeMarker>;

pub struct Request<C: Curve, AttributeType: Attribute<C::Scalar>> {
    challenge:  Challenge,
    statements: Vec<CredentialStatement<C, AttributeType>>,
}

pub enum AttributeType {
    String(AttributeKind),
    UnsignedU64(u64),
}

pub struct Proof<C: Curve, AttributeType: Attribute<C::Scalar>> {
    pub challenge: Challenge,
    pub proofs:    Vec<CredentialProof<C, AttributeType>>,
}

pub enum CommitmentInputs<'a, C: Curve, AttributeType> {
    Single {
        // TODO: Should be able to supply AttributeList here directly. Now there is a problem since
        // u8 != AttributeTag.
        values:     &'a BTreeMap<u8, AttributeType>,
        randomness: &'a BTreeMap<u8, pedersen_commitment::Randomness<C>>,
    },
    Vector {
        values:     &'a BTreeMap<u8, AttributeType>,
        randomness: pedersen_commitment::Randomness<C>,
    },
}

#[derive(thiserror::Error, Debug)]
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
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> CredentialStatement<C, AttributeType> {
    fn verify<'a>(
        &self,
        global: &GlobalContext<C>,
        transcript: &mut RandomOracle,
        cred_proof: &CredentialProof<C, AttributeType>,
        public: CredentialsInputs<'a, C>,
    ) -> bool {
        match (&cred_proof.glueing_proof, public) {
            (GlueingProof::None, CredentialsInputs::Single { commitments }) => {
                if self.statement.len() != cred_proof.proofs.len() {
                    return false;
                }
                for (statement, proof) in self.statement.iter().zip(cred_proof.proofs.iter()) {
                    if !statement.verify(global, transcript, &commitments.cmm_attributes, proof) {
                        return false;
                    }
                }
            }
            (
                GlueingProof::Proof {
                    additional_commitments,
                    proof,
                },
                CredentialsInputs::Vector { commitment },
            ) => {
                if additional_commitments.len() != self.statement.len() {
                    return false;
                }
                let (&rand_base, _, base) = global.vector_commitment_base();
                // TODO: This cloning here is a tiny bit wasteful.
                let gis = base.copied().collect();
                let vec_comm_key = VecCommitmentKey {
                    gs: gis,
                    h:  rand_base,
                };

                let verifier = VecComEq {
                    comm:  commitment,
                    comms: additional_commitments.clone(),
                    gis:   vec_comm_key.gs,
                    h:     rand_base,
                    g_bar: global.on_chain_commitment_key.g,
                    h_bar: global.on_chain_commitment_key.h,
                };
                if !sigma_protocols::common::verify(transcript, &verifier, &proof) {
                    return false;
                }
                for (statement, proof) in self.statement.iter().zip(cred_proof.proofs.iter()) {
                    if !statement.verify(global, transcript, &additional_commitments, proof) {
                        return false;
                    }
                }
            }
            (GlueingProof::None, CredentialsInputs::Vector { .. }) => return false,
            (GlueingProof::Proof { .. }, CredentialsInputs::Single { .. }) => return false,
        }
        true
    }

    fn prove<'a>(
        &self,
        global: &GlobalContext<C>,
        ro: &mut RandomOracle,
        csprng: &mut impl rand::Rng,
        input: CommitmentInputs<'a, C, AttributeType>,
    ) -> Result<CredentialProof<C, AttributeType>, ProofError> {
        let mut proofs = Vec::new();
        match input {
            CommitmentInputs::Single { values, randomness } => {
                for statement in &self.statement {
                    let proof = statement
                        .prove(global, ro, csprng, values, randomness)
                        .ok_or(ProofError::MissingAttribute)?;
                    proofs.push(proof);
                }
                Ok(CredentialProof {
                    reference: self.reference.clone(),
                    glueing_proof: GlueingProof::None,
                    proofs,
                })
            }
            CommitmentInputs::Vector { values, randomness } => {
                let (&rand_base, base_size, base) = global.vector_commitment_base();
                // First construct individual commitments.
                let vec_key = values.last_key_value().ok_or(ProofError::NoAttributes)?;
                if usize::from(*vec_key.0) >= base_size {
                    return Err(ProofError::TooManyAttributes);
                }
                let gis = base.take((*vec_key.0).into()).copied().collect();
                let vec_comm_key = VecCommitmentKey {
                    gs: gis,
                    h:  rand_base,
                };
                let committed_values = {
                    let mut out = Vec::new();
                    for (idx, (tag, value)) in values.iter().enumerate() {
                        for _ in idx..usize::from(*tag) {
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
                let individual = self
                    .statement
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
                for statement in &self.statement {
                    let proof = statement
                        .prove(global, ro, csprng, values, &ris)
                        .ok_or(ProofError::MissingAttribute)?;
                    proofs.push(proof);
                }
                let secrets = (committed_values, randomness.as_value(), ris);
                let proof = sigma_protocols::common::prove(ro, &prover, secrets, csprng)
                    .ok_or(ProofError::UnableToProve)?;
                Ok(CredentialProof {
                    reference: self.reference.clone(),
                    glueing_proof: GlueingProof::Proof {
                        additional_commitments: prover.comms,
                        proof,
                    },
                    proofs,
                })
            }
        }
    }
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> Request<C, AttributeType> {
    pub fn prove<'a>(
        &self,
        params: &GlobalContext<C>,
        attrs: impl ExactSizeIterator<Item = CommitmentInputs<'a, C, AttributeType>>,
    ) -> Result<Proof<C, AttributeType>, ProofError>
    where
        AttributeType: 'a, {
        let mut proofs = Vec::with_capacity(attrs.len());
        let mut transcript = RandomOracle::domain("Concordium ID3.0 proof");
        transcript.add_bytes(self.challenge);
        transcript.append_message(b"ctx", &params);
        let mut csprng = rand::thread_rng();
        if self.statements.len() != attrs.len() {
            return Err(ProofError::CommitmentsStatementsMismatch);
        }
        for (cred_statement, attributes) in self.statements.iter().zip(attrs) {
            proofs.push(cred_statement.prove(params, &mut transcript, &mut csprng, attributes)?);
        }
        Ok(Proof {
            challenge: self.challenge,
            proofs,
        })
    }
}

pub enum CredentialsInputs<'a, C: Curve> {
    Single {
        commitments: &'a CredentialDeploymentCommitments<C>,
    },
    Vector {
        commitment: pedersen_commitment::Commitment<C>,
    },
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> Request<C, AttributeType> {
    pub fn verify<'a>(
        &self,
        params: &GlobalContext<C>,
        public: impl ExactSizeIterator<Item = CredentialsInputs<'a, C>>,
        proof: &Proof<C, AttributeType>,
    ) -> bool {
        let mut transcript = RandomOracle::domain("Concordium ID3.0 proof");
        transcript.add_bytes(self.challenge);
        transcript.append_message(b"ctx", &params);
        if self.statements.len() != public.len() || self.statements.len() != proof.proofs.len() {
            return false;
        }
        for ((cred_statement, cred_public), cred_proof) in
            self.statements.iter().zip(public).zip(&proof.proofs)
        {
            if !cred_statement.verify(params, &mut transcript, cred_proof, cred_public) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    // TODO
}
