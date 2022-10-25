//! Implementation of set-non-membership proof along the lines of bulletproofs
use crate::{inner_product_proof::*, utils::*};
use crypto_common::*;
use crypto_common_derive::*;
use curve_arithmetic::{multiexp, Curve};
use ff::Field;
use pedersen_scheme::*;
use random_oracle::RandomOracle;

#[derive(Clone, Serialize, SerdeBase16Serialize, Debug)]
#[allow(non_snake_case)]
pub struct SetNonMembershipProof<C: Curve> {
    /// Commitment to the multiplicative inverse of (v-s_i) for each i
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

/// Error messages detailing why proof verification failed
#[derive(Debug, PartialEq, Eq)]
pub enum VerificationError {
    /// The set must have a size of a power of two
    SetSizeNotPowerOfTwo,
    /// The length of `gens` was less than `|the_set|`
    NotEnoughGenerators,
    /// The consistency check for `t_0` failed
    InconsistentT0,
    /// Choice of randomness led to verification failure
    DivisionError,
    /// Inner product proof verification failed
    IPVerificationError,
}

/// This function verifies a set-non-membership proof, i.e., a proof of
/// knowledge of value v that is not in a set S and that is consistent
/// with a commitment V to v. The arguments are
/// - `transcript` - the random oracle for Fiat Shamir
/// - `the_set` - the set as a vector
/// - `V` - commitment to `v`
/// - `proof` - the set membership proof to verify
/// - `gens` - generators containing vectors `G` and `H` both of length at least
///   `|the_set|` (bold **g**,**h** in bluepaper)
/// - `v_keys` - commitment keys `B` and `B_tilde` (`g,h` in bluepaper)
#[allow(non_snake_case)]
pub fn verify<C: Curve>(
    transcript: &mut RandomOracle,
    the_set: &[u64],
    V: &Commitment<C>,
    proof: &SetNonMembershipProof<C>,
    gens: &Generators<C>,
    v_keys: &CommitmentKey<C>,
) -> Result<(), VerificationError> {
    // Part 1: Setup
    let n = the_set.len();
    if !n.is_power_of_two() {
        return Err(VerificationError::SetSizeNotPowerOfTwo);
    }
    if gens.G_H.len() < n {
        return Err(VerificationError::NotEnoughGenerators);
    }
    let the_set_vec = get_set_vector::<C>(the_set);

    // Domain separation
    transcript.add_bytes(b"SetNonMembershipProof");
    // append commitment V to transcript
    transcript.append_message(b"V", &V.0);
    transcript.append_message(b"theSet", &the_set_vec);

    // define the commitments A,S
    let A = proof.A;
    let S = proof.S;
    // append commitments A and S to transcript
    transcript.append_message(b"A", &A);
    transcript.append_message(b"S", &S);

    // get challenges y,z from transcript
    let y: C::Scalar = transcript.challenge_scalar::<C, _>(b"y");
    let z: C::Scalar = transcript.challenge_scalar::<C, _>(b"z");

    // define the commitments T1, T2
    let T_1 = proof.T_1;
    let T_2 = proof.T_2;
    // append T1, T2 commitments to transcript
    transcript.append_message(b"T1", &T_1);
    transcript.append_message(b"T2", &T_2);

    // get challenge x (evaluation point) from transcript
    let x: C::Scalar = transcript.challenge_scalar::<C, _>(b"x");

    // define polynomial evaluation value
    let tx = proof.tx;
    // define blinding factors for tx and IP proof
    let tx_tilde = proof.tx_tilde;
    let e_tilde = proof.e_tilde;
    // append tx, tx_tilde, e_tilde to transcript
    transcript.append_message(b"tx", &tx);
    transcript.append_message(b"tx_tilde", &tx_tilde);
    transcript.append_message(b"e_tilde", &e_tilde);

    // get challenge w from transcript
    let w: C::Scalar = transcript.challenge_scalar::<C, _>(b"w");

    // compute delta(y,z) = <1, y^n>  - z<s, y^n>
    let yn = z_vec(y, 0, n);
    let one_vec = vec![C::Scalar::one(); n];
    let ip_one_yn = inner_product(&one_vec, &yn);
    let mut zip_s_yn = inner_product(&the_set_vec, &yn);
    zip_s_yn.mul_assign(&z);
    let mut delta_yz = ip_one_yn;
    delta_yz.sub_assign(&zip_s_yn);

    // Part 2: Verify consistency of t_0
    // i.e., check 0 = V^(z <1, yn>) * g^(delta_yz - tx) * T_1^x * T_2^x^2 *
    // h^(-tx_tilde)
    let mut zip_one_yn = ip_one_yn;
    zip_one_yn.mul_assign(&z);
    let mut delta_minus_tx = delta_yz;
    delta_minus_tx.sub_assign(&tx);
    let mut x2 = x; // x^2
    x2.mul_assign(&x);
    let mut minus_tx_tilde = tx_tilde;
    minus_tx_tilde.negate();

    let t0_check_base_points = vec![V.0, v_keys.g, T_1, T_2, v_keys.h];
    let t0_check_exponents = vec![zip_one_yn, delta_minus_tx, x, x2, minus_tx_tilde];

    let rhs = multiexp(&t0_check_base_points, &t0_check_exponents);
    if !rhs.is_zero_point() {
        return Err(VerificationError::InconsistentT0);
    }

    // Part 3: Verify inner product
    // First compute helper variables g_hat, h_prime, and P_prime
    let g_hat = v_keys.g.mul_by_scalar(&w);

    let y_inv = match y.inverse() {
        Some(inv) => inv,
        None => return Err(VerificationError::DivisionError),
    };
    let y_inv_n = z_vec(y_inv, 0, n);
    let mut minus_e_tilde = e_tilde;
    minus_e_tilde.negate();

    // get exponent for g, i.e., [z, z, ..., z]
    let mut gexp = vec![z; n];

    let mut P_prime_exps = Vec::with_capacity(2 * n + 4);
    P_prime_exps.append(&mut gexp);

    // compute exponent for h, i.e., -s, and add it to P_prime_exps
    for si in the_set_vec {
        let mut hexpi = C::Scalar::zero();
        hexpi.sub_assign(&si);
        P_prime_exps.push(hexpi);
    }

    // add remaining exponents
    P_prime_exps.push(tx);
    P_prime_exps.push(minus_e_tilde);
    P_prime_exps.push(C::Scalar::one());
    P_prime_exps.push(x);

    let P_prime_bases = vec![g_hat, v_keys.h, A, S]; // G and H are implicit

    // Finally verify inner product
    let ip_verification = verify_inner_product_with_scalars(
        transcript,
        gens,
        &y_inv_n,
        &P_prime_bases,
        &P_prime_exps,
        &g_hat,
        &proof.ip_proof,
    );

    if !ip_verification {
        return Err(VerificationError::IPVerificationError);
    }

    Ok(())
}
