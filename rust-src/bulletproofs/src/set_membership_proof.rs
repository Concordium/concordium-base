use crate::{inner_product_proof::*, range_proof::{Generators}};
use crypto_common::*;
use crypto_common_derive::*;
use curve_arithmetic::Curve;
use pedersen_scheme::*;
use rand::*;
use random_oracle::RandomOracle;

#[derive(Clone, Serialize, SerdeBase16Serialize, Debug)]
#[allow(non_snake_case)]
pub struct SetMembershipProof<C: Curve> {
    /// Commitment to the evalutation indicator function Iv on S
    A:        C,
    /// Commitment to the blinding factors in s_L and s_R
    S:        C,
    /// Commitment to the t_1 coefficient of polynomial t(x)
    T_1:      C,
    /// Commitment to the t_2 coefficient of polynomial t(x)
    T_2:      C,
    /// Evaluation of t(x) at the challenge point x
    tx:       C::Scalar,
    /// Blinding factor for the commitment to tx
    tx_tilde: C::Scalar,
    /// Blinding factor for the commitment to the inner-product arguments
    e_tilde:  C::Scalar,
    /// Inner product proof
    ip_proof: InnerProductProof<C>,
}

/// Error messages detailing why proof generation failed
pub enum ProverError {
    /// The length of G_H was less than |S|, which is too small
    NotEnoughGenerators,
}

/// This function produces a set membership proof, i.e. a proof of knowledge
/// of a value v that is in a given set S  and that is consistent with the commitment V to v.
/// The arguments are
/// - transcript - the random oracle for Fiat Shamir
/// - csprng - cryptographic safe randomness generator
/// - S - the set S as a vector
/// - v the value
/// - gens - generators containing vectors G and H both of length nm
/// - v_keys - commitmentment keys B and B_tilde
/// - v_rand - the randomness used to commit to each v using v_keys
pub fn prove<C: Curve, R: Rng>(
    transcript: &mut RandomOracle,
    csprng: &mut R,
    S: &[u64],
    v: u64,
    gens: &Generators<C>,
    v_keys: &CommitmentKey<C>,
    v_rand: &[Randomness<C>],
) -> Result<SetMembershipProof<C>,ProverError>{
    Err(ProverError::NotEnoughGenerators) 
}

/// Error messages detailing why proof verification failed
pub enum VerificationError {
    /// The length of G_H was less than |S|, which is too small
    NotEnoughGenerators,    
}

/// This function verifies a set membership proof, i.e. a proof of knowledge
/// of value v that is in a set S and that is consistent
/// with commitments V to v. The arguments are
/// - S - the set as a vector
/// - V - commitments to v
/// - proof - the set membership proof
/// - gens - generators containing vectors G and H both of length nm
/// - v_keys - commitment keys B and B_tilde
pub fn verify_efficient<C: Curve>(
    transcript: &mut RandomOracle,
    S: &[u64],
    V: &[Commitment<C>],
    proof: &SetMembershipProof<C>,
    gens: &Generators<C>,
    v_keys: &CommitmentKey<C>,
) -> Result<(), VerificationError> {
    Err(VerificationError::NotEnoughGenerators) 
}