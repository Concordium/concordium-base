//! Definitions related to the language of ZK statements

use bulletproofs::range_proof::{self, Generators, RangeProof};
use crypto_common::Serialize;
use curve_arithmetic::Curve;
use pairing::bls12_381::G1;
use pedersen_scheme::{Commitment, CommitmentKey, Randomness};
use rand::{rngs::ThreadRng, Rng};
use random_oracle::RandomOracle;

use crate::{
    constants::AttributeKind,
    curve_arithmetic,
    sigma_protocols::{
        self, com_mult,
        common::{Either, EitherAdapter, SigmaProof, SigmaProtocol},
        dlog,
    },
    types::{
        Attribute, AttributeList, AttributeTag, CommitmentsRandomness,
        CredentialDeploymentCommitments,
    },
};

type AttributeValue = AttributeKind;

/// Atomic Σ-protocol statements
pub enum SigmaAtom {
    Eq(AttributeTag, AttributeValue),
    NotEq(AttributeTag, AttributeValue),
}

/// Atomic bulletproof statements
pub enum BpAtom {
    Range(AttributeTag, AttributeValue, AttributeValue), // val1 <= tag <= val2
    In(AttributeTag, AttributeValue),
    NotIn(AttributeTag, AttributeValue),
}

/// All atomic statements
pub enum Atom {
    SAtom(SigmaAtom),
    BPAtom(BpAtom),
}

/// Composite statements
pub enum ZkStatement {
    Atom(Atom),
    And(Vec<Atom>),
}

/// This struct represents account/id data stored on-chain.
/// It combines data needed to build both public and secret input for generating
/// and verifying proofs
pub struct AccountInfo<C: Curve, AttributeType: Attribute<C::Scalar>> {
    secrets:     AttributeList<C::Scalar, AttributeType>,
    commitments: CredentialDeploymentCommitments<C>,
    randomness:  CommitmentsRandomness<C>,
}

impl<C: Curve, AttributeType: Attribute<C::Scalar>> AccountInfo<C, AttributeType> {
    fn get_secret(&self, tag: &AttributeTag) -> Option<&AttributeType> {
        self.secrets.alist.get(&tag)
    }

    fn get_commitment(&self, tag: &AttributeTag) -> Option<&Commitment<C>> {
        self.commitments.cmm_attributes.get(&tag)
    }

    fn get_randomness(&self, tag: &AttributeTag) -> Option<&Randomness<C>> {
        self.randomness.attributes_rand.get(&tag)
    }
}

/// All supported Sigma-protocols are represented as a single (possibly nested
/// `EitherAdapter`)
type SupportedSigma = EitherAdapter<dlog::Dlog<G1>, com_mult::ComMult<G1>>;

/// Range proofs get they own wrapper around the functionality implemented in
/// bulletproofs::range_proof
//  Note: a similar thing could be done for set (non) mebership protocols
pub struct RangeProofProtocol<C: Curve> {
    transcript: RandomOracle,
    n:          u8,
    m:          u8,
    v_vec:      Vec<u64>,
    gens:       Generators<C>,
    v_keys:     CommitmentKey<C>,
    randomness: Vec<Randomness<C>>,
}

impl<C: Curve> RangeProofProtocol<C> {
    fn prove<T: Rng>(&mut self, mut csprng: T) -> Option<RangeProof<C>> {
        bulletproofs::range_proof::prove(
            &mut self.transcript,
            &mut csprng,
            self.n,
            self.m,
            self.v_vec.as_mut_slice(),
            &self.gens,
            &self.v_keys,
            self.randomness.as_mut_slice(),
        )
    }
}

/// All supported protocols.
/// All Sigma-protocols represented by a single constructor, since we have a
/// common type for these. The sigma protocol constructor also carries secret
/// data need to generate proofs. Maybe the same could be used for bulletproofs
/// as well.
pub enum Protocol {
    Range(RangeProofProtocol<G1>),
    Sigma(
        SupportedSigma,
        <SupportedSigma as SigmaProtocol>::SecretData,
    ),
}

/// Type of generated proofs.
/// All Sigma-protocol proofs are represented by a single constructor and each
/// bulletproof gets its own constructor.
pub enum Proof<W: Serialize> {
    Range(RangeProof<G1>),
    Sigma(SigmaProof<W>),
}

/// This implementation provides `proof` and `verify` functionality by
/// dispatching on the type of protocols
impl Protocol {
    fn prove<T: Rng>(
        self,
        acc_info: &AccountInfo<G1, AttributeValue>,
        rng: &mut T,
    ) -> Option<Proof<<SupportedSigma as SigmaProtocol>::ProverWitness>> {
        match self {
            Protocol::Range(mut protocol) => {
                let p = protocol.prove(rng)?;
                Some(Proof::Range(p))
            }
            Protocol::Sigma(protocol, secret_data) => {
                let mut ro = RandomOracle::empty();
                let p = sigma_protocols::common::prove(&mut ro, &protocol, secret_data, rng)?;
                Some(Proof::Sigma(p))
            }
        }
    }
    // TODO: add verity
}

/// The resulting proof that corresponds to a vector of protocols
type SerialProof = Vec<Proof<<SupportedSigma as SigmaProtocol>::ProverWitness>>;

/// Run the proof generation sequentially
pub fn prove_serial<T: Rng>(
    acc_info: &AccountInfo<G1, AttributeValue>,
    mut rng: &mut T,
    protocols: Vec<Protocol>,
) -> Option<SerialProof> {
    protocols
        .into_iter()
        .map(|x| x.prove(acc_info, &mut rng))
        .collect()
}

/// Given account info, a tag for an attribute and a value for the attribute,
/// produce an instance of the Dlog protocol
//  Note: the "ZK Functionality" document (section "Basic Proofs") says that it
// shoul be 2 proofs, so maybe we'll use AND dapter here
fn eq_procotol(
    acc_info: &AccountInfo<G1, AttributeValue>,
    tag: &AttributeTag,
    val: AttributeValue,
) -> Option<dlog::Dlog<G1>> {
    let Commitment(cmm) = acc_info.get_commitment(tag)?;
    let attr_value = acc_info.get_secret(tag)?;
    let rnd = acc_info.get_randomness(tag)?;
    let elem = attr_value.to_field_element();
    // TODO: instantiate Dlog properly here
    // Some(dlog::Dlog { public: _ , coeff: _})
    todo!()
}

/// Given account info, a tag for an attribute and a value for the attribute,
/// produce an instance of the ComMult protocol
fn not_eq_procotol(
    acc_info: &AccountInfo<G1, AttributeValue>,
    tag: &AttributeTag,
    val: AttributeValue,
) -> Option<com_mult::ComMult<G1>> {
    let Commitment(cmm) = acc_info.get_commitment(tag)?;
    let attr_value = acc_info.get_secret(tag)?;
    let rnd = acc_info.get_randomness(tag)?;
    let elem = attr_value.to_field_element();
    // TODO: instantiate ComMult properly here
    // Some(com_mult::ComMult { public: _ , coeff: _})
    todo!()
}

/// Get secret input for Sigma-protocol
fn get_eq_secret(
    acc_info: &AccountInfo<G1, AttributeValue>,
    tag: &AttributeTag,
) -> Option<<dlog::Dlog<G1> as SigmaProtocol>::SecretData> {
    todo!()
}

/// Get secret input for Sigma-protocol
fn get_not_eq_secret(
    acc_info: &AccountInfo<G1, AttributeValue>,
    tag: &AttributeTag,
) -> Option<<com_mult::ComMult<G1> as SigmaProtocol>::SecretData> {
    todo!()
}

fn interpret_sigma_atom(
    acc_info: &AccountInfo<G1, AttributeValue>,
    s: SigmaAtom,
) -> Option<(
    SupportedSigma,
    <SupportedSigma as SigmaProtocol>::SecretData,
)> {
    match s {
        SigmaAtom::Eq(tag, cst) => {
            let protocol = eq_procotol(&acc_info, &tag, cst)?;
            let secret = get_eq_secret(acc_info, &tag)?;
            Some((
                EitherAdapter {
                    protocol: Either::Left(protocol),
                },
                Either::Left(secret),
            ))
        }
        SigmaAtom::NotEq(tag, cst) => {
            let protocol = not_eq_procotol(&acc_info, &tag, cst)?;
            let secret = get_not_eq_secret(acc_info, &tag)?;
            Some((
                EitherAdapter {
                    protocol: Either::Right(protocol),
                },
                Either::Right(secret),
            ))
        }
    }
}

fn range_protocol(
    acc_info: &AccountInfo<G1, AttributeValue>,
    tag: &AttributeTag,
    min: AttributeKind,
    max: AttributeKind,
) -> Option<RangeProofProtocol<G1>> {
    todo!()
}

fn interpret_bp_atom(
    acc_info: &AccountInfo<G1, AttributeValue>,
    s: BpAtom,
) -> Option<RangeProofProtocol<G1>> {
    match s {
        BpAtom::Range(tag, min, max) => range_protocol(acc_info, &tag, min, max),
        BpAtom::In(tag, values) => {
            todo!()
        }
        BpAtom::NotIn(tag, values) => {
            todo!()
        }
    }
}

fn interpret_atom(acc_info: &AccountInfo<G1, AttributeValue>, s: Atom) -> Option<Protocol> {
    match s {
        Atom::SAtom(s) => interpret_sigma_atom(acc_info, s).map(|x| Protocol::Sigma(x.0, x.1)),
        Atom::BPAtom(s) => interpret_bp_atom(acc_info, s).map(Protocol::Range),
    }
}

/// The interpretation function that assignes a vector of protocols to a given
/// ZK statement. If one of the protocols fails to be instantiated, returns
/// `None`
//  Note: As an optimisation we might consider running all Sigma-protocol statements using the `ReplicateAdapter`
pub fn interpret_zk_statement(
    acc_info: &AccountInfo<G1, AttributeValue>,
    s: ZkStatement,
) -> Option<Vec<Protocol>> {
    match s {
        ZkStatement::Atom(s) => interpret_atom(acc_info, s).map(|x| vec![x]),
        ZkStatement::And(statements) => statements
            .into_iter()
            .map(|x| interpret_atom(acc_info, x))
            .collect(),
    }
}

pub fn example(acc_info: &AccountInfo<G1, AttributeValue>) -> Option<SerialProof> {
    let mut csprng = rand::thread_rng();
    let s_eq = SigmaAtom::Eq(AttributeTag(0), AttributeKind("John".to_string()));
    let statement = ZkStatement::Atom(Atom::SAtom(s_eq));
    let protocols: Vec<Protocol> = interpret_zk_statement(acc_info, statement).unwrap();
    prove_serial(acc_info, &mut csprng, protocols)
}
