use std::sync::Arc;

use crate::{inner_product_proof::*, utils::*};
use crypto_common::*;
use crypto_common_derive::*;
use curve_arithmetic::Curve;
use ff::Field;
use pedersen_scheme::*;
use rand::*;
use random_oracle::RandomOracle;

#[derive(Clone, Serialize, SerdeBase16Serialize, Debug)]
#[allow(non_snake_case)]
pub struct SetMembershipProof<C: Curve> {
    /// Commitment to the evalutation of the indicator function I_{v} on the_set
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


/// This function takes a set (as a vector) and a value v as input.
/// If v in S the function computes bit vectors aL and aR where
/// aL_i = 1 <=> s_i = v
/// and a_R is the bit-wise negation of a_L
/// Note: For multi sets this function only sets the first hit to one.
#[allow(non_snake_case)]
fn a_L_a_R<F: Field>(v: F, set_vec: Vec<F>) -> Option<(Vec<F>, Vec<F>)> {
    let n = set_vec.len();
    let mut a_L = Vec::with_capacity(usize::from(n));
    let mut a_R = Vec::with_capacity(usize::from(n));
    let mut found_element = false;
    for i in 0..n {
        let mut bit = F::zero();
        let s_i = set_vec.get(i);
        if s_i.is_none() {
            return None
        }
        if (!found_element) && (v == *s_i.unwrap()){
            bit = F::one();
            found_element = true;
        }
        a_L.push(bit);
        bit.sub_assign(&F::one());
        a_R.push(bit);
    }
    //The set does not contain v
    if !found_element {
        return None
    }
    Some((a_L, a_R))
}

/// This function produces a set membership proof, i.e. a proof of knowledge
/// of a value v that is in a given set the_set  and that is consistent with the
/// commitment V to v. The arguments are
/// - transcript - the random oracle for Fiat Shamir
/// - csprng - cryptographic safe randomness generator
/// - the_set - the set as a vector
/// - v the value
/// - gens - generators containing vectors G and H both of length nm
/// - v_keys - commitmentment keys B and B_tilde
/// - v_rand - the randomness used to commit to each v using v_keys
pub fn prove<C: Curve, R: Rng>(
    transcript: &mut RandomOracle,
    csprng: &mut R,
    the_set: &[u64],
    v: u64,
    gens: &Generators<C>,
    v_keys: &CommitmentKey<C>,
    v_rand: &[Randomness<C>],
) -> Result<SetMembershipProof<C>, ProverError> {
    // Part 1: Setup and generation of vector commitments

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
    the_set: &[u64],
    V: &[Commitment<C>],
    proof: &SetMembershipProof<C>,
    gens: &Generators<C>,
    v_keys: &CommitmentKey<C>,
) -> Result<(), VerificationError> {
    Err(VerificationError::NotEnoughGenerators)
}

#[cfg(test)]
mod tests {}
