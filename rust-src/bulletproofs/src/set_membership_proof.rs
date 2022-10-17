use crate::{inner_product_proof::*, utils::*};
use crypto_common::*;
use crypto_common_derive::*;
use curve_arithmetic::{multiexp_table, multiexp_worker_given_table, Curve};
use ff::Field;
use pedersen_scheme::*;
use rand::*;
use random_oracle::RandomOracle;
use std::iter::once;

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
    /// Set conversion failed
    SetConversionFailed,
    /// The length of G_H was less than |S|, which is too small
    NotEnoughGenerators,
    /// Could not compute the indicator
    CouldNotFindValueInSet,
    /// Could not generate inner product proof
    InnerProductProofFailure,
}

/// This function takes a set (as a vector) and a value v as input.
/// If v in S the function computes bit vectors aL and aR where
/// aL_i = 1 <=> s_i = v
/// and a_R is the bit-wise negation of a_L
/// Note: For multi sets this function only sets the first hit to one.
#[allow(non_snake_case)]
fn a_L_a_R<F: Field>(v: F, set_vec: Vec<F>) -> Option<(Vec<F>, Vec<F>)> {
    // TODO: Add proper error types
    let n = set_vec.len();
    let mut a_L = Vec::with_capacity(usize::from(n));
    let mut a_R = Vec::with_capacity(usize::from(n));
    let mut found_element = false;
    for i in 0..n {
        let mut bit = F::zero();
        let s_i = set_vec.get(i);
        if s_i.is_none() {
            return None;
        }
        if (!found_element) && (v == *s_i.unwrap()) {
            bit = F::one();
            found_element = true;
        }
        a_L.push(bit);
        bit.sub_assign(&F::one());
        a_R.push(bit);
    }
    // The set does not contain v
    if !found_element {
        return None;
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
#[allow(non_snake_case)]
pub fn prove<C: Curve, R: Rng>(
    transcript: &mut RandomOracle,
    csprng: &mut R,
    the_set: &[u64],
    v: u64,
    gens: &Generators<C>,
    v_keys: &CommitmentKey<C>,
    v_rand: &Randomness<C>,
) -> Result<SetMembershipProof<C>, ProverError> {
    // Part 0: Add public inputs to transcript
    // Domain separation
    transcript.add_bytes(b"SetMembershipProof");
    // Compute commitment V for v
    let v_scalar = C::scalar_from_u64(v);
    let v_value = Value::<C>::new(v_scalar);
    let V = v_keys.hide(&v_value, v_rand);
    // Append V to the transcript
    transcript.append_message(b"V", &V.0);
    // Convert the u64 set into a field element vector
    let maybe_set: Option<Vec<C::Scalar>> = get_set_vector(the_set);
    if maybe_set.is_none() {
        return Err(ProverError::SetConversionFailed);
    }
    let set_vec = maybe_set.unwrap();
    // Append the set to the transcript
    transcript.append_message(b"theSet", &set_vec);

    // Part 1: Setup and generation of vector commitments
    let n = set_vec.len();
    // Check that we have enough generators for vector commitments
    if gens.G_H.len() < n {
        return Err(ProverError::NotEnoughGenerators);
    }
    // Select generators for vector commitments
    let (G, H): (Vec<_>, Vec<_>) = gens.G_H.iter().take(n).cloned().unzip();
    // Generators for single commitments and blinding
    let B = v_keys.g;
    let B_tilde = v_keys.h;
    // Compute aL (indicator vector) and aR
    let maybe_aLaR: Option<(Vec<C::Scalar>, Vec<C::Scalar>)> = a_L_a_R(v_scalar, set_vec);
    if maybe_aLaR.is_none() {
        return Err(ProverError::CouldNotFindValueInSet);
    }
    let (a_L, a_R): (Vec<C::Scalar>, Vec<C::Scalar>) = maybe_aLaR.unwrap();
    // Setup blinding factors for a_L and a_R
    let mut s_L = Vec::with_capacity(usize::from(n));
    let mut s_R = Vec::with_capacity(usize::from(n));
    for _ in 0..n {
        s_L.push(C::generate_scalar(csprng));
        s_R.push(C::generate_scalar(csprng));
    }
    // Commitment randomness for A and S
    let a_tilde = C::generate_scalar(csprng); // Randomness::<C>::generate(csprng);
    let s_tilde = C::generate_scalar(csprng);
    // get scalars for A commitment, that is (a_L,a_r,a_tilde)
    let A_scalars: Vec<C::Scalar> = a_L
        .iter()
        .chain(a_R.iter())
        .copied()
        .chain(once(a_tilde))
        .collect();
    // get scalars for S commitment, that is (s_L,s_r,s_tilde_sum)
    let S_scalars: Vec<C::Scalar> = s_L
        .iter()
        .chain(s_R.iter())
        .copied()
        .chain(once(s_tilde))
        .collect();
    // get generator vector for blinded vector commitments, i.e. (G,H,B_tilde)
    let GH_B_tilde: Vec<C> = G
        .iter()
        .chain(H.iter())
        .copied()
        .chain(once(B_tilde))
        .collect();
    // compute A and S comittments using multi exponentiation
    let window_size = 4;
    let table = multiexp_table(&GH_B_tilde, window_size);
    let A = multiexp_worker_given_table(&A_scalars, &table, window_size);
    let S = multiexp_worker_given_table(&S_scalars, &table, window_size);
    // append commitments A and S to transcript
    transcript.append_message(b"A", &A);
    transcript.append_message(b"S", &S);

    // Part 2: Computation of vector polynomials l(x),r(x)
    // get challenges y,z from transcript
    let y: C::Scalar = transcript.challenge_scalar::<C, _>(b"y");
    let z: C::Scalar = transcript.challenge_scalar::<C, _>(b"z");

    Err(ProverError::InnerProductProofFailure)
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
