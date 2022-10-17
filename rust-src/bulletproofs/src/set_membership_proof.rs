use crate::{inner_product_proof::*, utils::*};
use crypto_common::*;
use crypto_common_derive::*;
use curve_arithmetic::{multiexp_table, multiexp_worker_given_table, Curve};
use ff::Field;
use pedersen_scheme::*;
use rand::*;
use random_oracle::RandomOracle;
use std::{iter::once, borrow::BorrowMut};

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
    /// Could not invert y
    CouldNotInvertY
}

/// This function takes a set (as a vector) and a value v as input.
/// If v in S the function computes bit vectors aL and aR where
/// aL_i = 1 <=> s_i = v
/// and a_R is the bit-wise negation of a_L
/// Note: For multi sets this function only sets the first hit to one.
#[allow(non_snake_case)]
fn a_L_a_R<F: Field>(v: &F, set_vec: &Vec<F>) -> Option<(Vec<F>, Vec<F>)> {
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
        if (!found_element) && (*v == *s_i.unwrap()) {
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
    let maybe_aLaR: Option<(Vec<C::Scalar>, Vec<C::Scalar>)> = a_L_a_R(&v_scalar, &set_vec);
    if maybe_aLaR.is_none() {
        return Err(ProverError::CouldNotFindValueInSet);
    }
    let (a_L, a_R): (Vec<C::Scalar>, Vec<C::Scalar>) = maybe_aLaR.unwrap();
    // Setup blinding factors for a_L and a_R
    let mut s_L = Vec::with_capacity(n);
    let mut s_R = Vec::with_capacity(n);
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

    // y_n = (1,y,..,y^(n-1))
    let y_n = z_vec(y, 0, n);
    // powers of z
    let z_sq = {
        let mut z_sq = z;
        z_sq.mul_assign(&z);
        z_sq
    };
    let z_cb = {
        let mut z_cb = z_sq;
        z_cb.mul_assign(&z);
        z_cb
    };
    // coefficients of l(x) and r(x)
    // compute l_0 and l_1
    let mut l_0 = Vec::with_capacity(n);
    let mut l_1 = Vec::with_capacity(n);
    for i in 0..n {
        // l_0[i] <- a_L[i] - z
        let mut l_0_i = a_L[i];
        l_0_i.sub_assign(&z);
        l_0.push(l_0_i);
        // l_1[i] <- s_L[i]
        l_1.push(s_L[i]);
    }
    // compute r_0 and r_1
    let mut r_0 = Vec::with_capacity(n);
    let mut r_1 = Vec::with_capacity(n);
    for i in 0..n {
        // r_0[i] <- y_n[i] * (a_R[i] + z) + z^3 + z^2*set_vec[i]
        let mut r_0_i = a_R[i];
        r_0_i.add_assign(&z);
        r_0_i.mul_assign(&y_n[i]);
        r_0_i.add_assign(&z_cb); // y_n[i] * (a_R[i] + z)
        let mut z_cb_si = z_sq;
        z_cb_si.add_assign(&set_vec[i]); // z^2*set_vec[i]
        r_0_i.add_assign(&z_cb_si);
        r_0.push(r_0_i);

        // r_1[i] <- y_n[i] * s_R[i]
        let mut r_1_i = y_n[i];
        r_1_i.mul_assign(&s_R[i]);
        r_1.push(r_1_i);
    }

    // Part 3: Computation of polynomial t(x) = <l(x),r(x)>
    // t_0 <- <l_0,r_0>
    let t_0 = inner_product(&l_0, &r_0);
    // t_2 <- <l_1,r_1>
    let t_2 = inner_product(&l_1, &r_1);
    // t_1 <- <l_0+l_1,r_0+r_1> - t_0 - t_1
    let mut t_1 = C::Scalar::zero();
    // add <l_0+l_1,r_0+r_1>
    for i in 0..n {
        let mut l_side = l_0[i];
        l_side.add_assign(&l_1[i]);
        let mut r_side = r_0[i];
        r_side.add_assign(&r_1[i]);
        let mut prod = l_side;
        prod.mul_assign(&r_side);
        t_1.add_assign(&prod);
    }
    // subtract t_0 and t_1
    t_1.sub_assign(&t_0);
    t_1.sub_assign(&t_2);

    // Commit to t_1 and t_2
    let t_1_tilde = C::generate_scalar(csprng);
    let t_2_tilde = C::generate_scalar(csprng);
    let T_1 = B
        .mul_by_scalar(&t_1)
        .plus_point(&B_tilde.mul_by_scalar(&t_1_tilde));
    let T_2 = B
        .mul_by_scalar(&t_2)
        .plus_point(&B_tilde.mul_by_scalar(&t_2_tilde));
    // append T1, T2 commitments to transcript
    transcript.append_message(b"T1", &T_1);
    transcript.append_message(b"T2", &T_2);

    // Part 4: Evaluate l(.), r(.), and t(.) at challenge point x
    // get challenge x from transcript
    let x: C::Scalar = transcript.challenge_scalar::<C, _>(b"x");
    let mut x_sq = x;
    x_sq.mul_assign(&x);
    // Compute l(x) and r(x)
    let mut lx = Vec::with_capacity(n);
    let mut rx = Vec::with_capacity(n);
    for i in 0..n {
        // l[i] <- l_0[i] + x* l_1[i]
        let mut lx_i = l_1[i];
        lx_i.mul_assign(&x);
        lx_i.add_assign(&l_0[i]);
        lx.push(lx_i);
        // r[i] = r_0[i] + x* r_1[i]
        let mut rx_i = r_1[i];
        rx_i.mul_assign(&x);
        rx_i.add_assign(&r_0[i]);
        rx.push(rx_i);
    }
    // Compute t(x)
    // tx <- t_0 + t_1*x + t_2*x^2
    let mut tx = t_0;
    let mut tx_1 = t_1;
    tx_1.mul_assign(&x);
    tx.add_assign(&tx_1);
    let mut tx_2 = t_2;
    tx_2.mul_assign(&x_sq);
    tx.add_assign(&tx_2);
    // Compute the blinding t_x_tilde
    // t_x_tilde <- z^2*v_rand + t_1_tilde*x + t_2_tilde*x^2
    let mut tx_tilde = z_sq;
    tx_tilde.mul_assign(&v_rand);
    let mut tx_s1 = t_1_tilde;
    tx_s1.mul_assign(&x);
    tx_tilde.add_assign(&tx_s1);
    let mut tx_s2 = t_2_tilde;
    tx_s2.mul_assign(&x_sq);
    tx_tilde.add_assign(&tx_s2);
    // Compute blinding e_tilde
    // e_tilde <- a_tilde + s_tilde * x
    let mut e_tilde = s_tilde;
    e_tilde.mul_assign(&x);
    e_tilde.add_assign(&a_tilde);
    // append tx, tx_tilde, e_tilde to transcript
    transcript.append_message(b"tx", &tx);
    transcript.append_message(b"tx_tilde", &tx_tilde);
    transcript.append_message(b"e_tilde", &e_tilde);

    // Part 5: Inner product proof for tx = <lx,rx>
    // get challenge w from transcript
    let w: C::Scalar = transcript.challenge_scalar::<C, _>(b"w");
    // get generator q
    let Q = B.mul_by_scalar(&w);
    // compute scalars c such that c*H = H', that is H_prime_scalars = (1, y^-1,.., y^-(n-1))
    let y_inv = match y.inverse() {
        Some(inv) => inv,
        None => return Err(ProverError::CouldNotInvertY),
    };
    let H_prime_scalars = z_vec(y_inv, 0, n);
    // compute inner product proof
    let proof = prove_inner_product_with_scalars(transcript, &G, &H, &H_prime_scalars, &Q, &lx, &rx);

    // return range proof
    if let Some(ip_proof) = proof {
        return Ok(SetMembershipProof {
            A,
            S,
            T_1,
            T_2,
            tx,
            tx_tilde,
            e_tilde,
            ip_proof,
        });
    }
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
