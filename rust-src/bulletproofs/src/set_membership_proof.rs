//! Implementation of set membership proof along the lines of bulletproofs
use crate::{inner_product_proof::*, utils::*};
use crypto_common::*;
use crypto_common_derive::*;
use curve_arithmetic::{multiexp, multiexp_table, multiexp_worker_given_table, Curve};
use ff::Field;
use pedersen_scheme::*;
use rand::*;
use random_oracle::RandomOracle;
use std::{convert::TryInto, iter::once};

/// Bulletproof style set-membership proof
#[derive(Clone, Serialize, SerdeBase16Serialize, Debug)]
#[allow(non_snake_case)]
pub struct SetMembershipProof<C: Curve> {
    /// Commitments to the evaluation of the indicator function `I_{v}` on
    /// the_set and `I_{v] - 1`
    A:        C,
    /// Commitment to the blinding factors in `s_L` and `s_R`
    S:        C,
    /// Commitment to the t_1 coefficient of polynomial `t(x)`
    T_1:      C,
    /// Commitment to the t_2 coefficient of polynomial `t(x)`
    T_2:      C,
    /// Evaluation of t(x) at the challenge point `x`
    tx:       C::Scalar,
    /// Blinding factor for the commitment to `tx`
    tx_tilde: C::Scalar,
    /// Blinding factor for the commitment to the inner-product arguments
    e_tilde:  C::Scalar,
    /// Inner product proof
    ip_proof: InnerProductProof<C>,
}

/// Error messages detailing why proof generation failed
#[derive(Debug, PartialEq, Eq)]
pub enum ProverError {
    /// The length of the generator vector `gens` was too short
    NotEnoughGenerators,
    /// Could not find the value `v` in the given set
    CouldNotFindValueInSet,
    /// Could not generate inner product proof
    InnerProductProofFailure,
    /// Could not invert `y`
    DivisionError,
}

/// This function takes a set (as a slice) and a value v as input.
/// If v in S, the function computes bit vectors aL and aR where
/// aL_i = 1 <=> s_i = v
/// and a_R is the bit-wise negation of a_L
/// Note: For multisets this function only sets the first hit to one, to allow
/// set membership proofs in multisets.
#[allow(non_snake_case)]
fn a_L_a_R<F: Field>(v: &F, set_slice: &[F]) -> Option<(Vec<F>, Vec<F>)> {
    let n = set_slice.len();
    let mut a_L = Vec::with_capacity(n);
    let mut a_R = Vec::with_capacity(n);
    let mut found_element = false;
    for si in set_slice {
        let mut bit = F::zero();
        if (!found_element) && (v == si) {
            bit = F::one();
            found_element = true;
        }
        a_L.push(bit);
        bit.sub_assign(&F::one());
        a_R.push(bit);
    }
    if found_element {
        Some((a_L, a_R))
    } else {
        None
    }
}

/// This function produces a set membership proof, i.e. a proof of knowledge
/// of a value v that is in a given set `the_set` and that is consistent with
/// the commitment `V` to `v`. The arguments are
/// - `transcript` - the random oracle for Fiat Shamir
/// - `csprng` - cryptographic safe randomness generator
/// - `the_set` - the set as a vector of scalars
/// - `v` the value, a scalar
/// - `gens` - generators containing vectors `G` and `H` both of at least length
///   `k` where k is the smallest power of two >= `|the_set|`
/// - `v_keys` - commitment keys `B` and `B_tilde` (`g,h` in the bluepaper)
/// - `v_rand` - the randomness used to commit to `v` using `v_keys`
#[allow(non_snake_case)]
pub fn prove<C: Curve, R: Rng>(
    transcript: &mut RandomOracle,
    csprng: &mut R,
    the_set: &[C::Scalar],
    v: C::Scalar,
    gens: &Generators<C>,
    v_keys: &CommitmentKey<C>,
    v_rand: &Randomness<C>,
) -> Result<SetMembershipProof<C>, ProverError> {
    // Part 0: Add public inputs to transcript
    // Domain separation
    transcript.add_bytes(b"SetMembershipProof");
    // Compute commitment V for v
    let v_value = Value::<C>::new(v);
    let V = v_keys.hide(&v_value, v_rand);
    // Append V to the transcript
    transcript.append_message(b"V", &V.0);

    // Pad set if not power of two
    let mut set_vec = the_set.to_vec();
    pad_vector_to_power_of_two(&mut set_vec);
    let n = set_vec.len();
    // Append the set to the transcript
    transcript.append_message(b"theSet", &set_vec);

    // Part 1: Setup and generation of vector commitments
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
    let (a_L, a_R) = a_L_a_R(&v, &set_vec).ok_or(ProverError::CouldNotFindValueInSet)?;
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
    // compute A and S commitments using multi exponentiation
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
        r_0_i.add_assign(&z_cb);
        let mut z_cb_si = z_sq;
        z_cb_si.mul_assign(&set_vec[i]);
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
    tx_tilde.mul_assign(v_rand);
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
    // compute scalars c such that c*H = H', that is H_prime_scalars = (1, y^-1,..,
    // y^-(n-1))
    let y_inv = match y.inverse() {
        Some(inv) => inv,
        None => return Err(ProverError::DivisionError),
    };
    let H_prime_scalars = z_vec(y_inv, 0, n);
    // compute inner product proof
    let proof =
        prove_inner_product_with_scalars(transcript, &G, &H, &H_prime_scalars, &Q, &lx, &rx);

    // return set membership proof
    if let Some(ip_proof) = proof {
        Ok(SetMembershipProof {
            A,
            S,
            T_1,
            T_2,
            tx,
            tx_tilde,
            e_tilde,
            ip_proof,
        })
    } else {
        Err(ProverError::InnerProductProofFailure)
    }
}

/// Error messages detailing why proof verification failed
#[derive(Debug, PartialEq, Eq)]
pub enum VerificationError {
    /// The set size must be representable by an unsigned 64-bit integer
    SetTooLarge,
    /// The length of `gens` was less than `|the_set|`
    NotEnoughGenerators,
    /// The consistency check for `t_0` failed, i.e., the commitments from the
    /// prover are not consistent with the provided values.
    InconsistentT0,
    /// Choice of randomness led to verification failure
    DivisionError,
    /// Inner product proof verification failed
    IPVerificationError,
}

/// This function verifies a set membership proof, i.e. a proof of knowledge
/// of value v that is in a set S and that is consistent
/// with a commitment V to v. The arguments are
/// - `transcript` - the random oracle for Fiat Shamir
/// - `the_set` - the set as a vector of scalars
/// - `V` - commitment to `v`
/// - `proof` - the set membership proof to verify
/// - `gens` - generators containing vectors `G` and `H` both of length at least
///   `k` where k is the smallest power of two >= `|the_set|` (bold **g**,**h**
///   in bluepaper)
/// - `v_keys` - commitment keys `B` and `B_tilde` (`g,h` in bluepaper)
#[allow(non_snake_case)]
pub fn verify<C: Curve>(
    transcript: &mut RandomOracle,
    the_set: &[C::Scalar],
    V: &Commitment<C>,
    proof: &SetMembershipProof<C>,
    gens: &Generators<C>,
    v_keys: &CommitmentKey<C>,
) -> Result<(), VerificationError> {
    // Part 1: Setup
    // Pad set if not power of two
    let mut set_vec = the_set.to_vec();
    pad_vector_to_power_of_two(&mut set_vec);
    let n = set_vec.len();
    if gens.G_H.len() < n {
        return Err(VerificationError::NotEnoughGenerators);
    }
    // Select generators for vector commitments
    let (G, H): (Vec<_>, Vec<_>) = gens.G_H.iter().take(n).cloned().unzip();

    // Domain separation
    transcript.add_bytes(b"SetMembershipProof");
    // append commitment V to transcript
    transcript.append_message(b"V", &V.0);
    transcript.append_message(b"theSet", &set_vec);

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

    // compute delta(y,z) = z^3 (1 - zn - <1,s>) + (z - z^2) (<1,y^n>)
    // first compute helper values
    let mut z2 = z; // z^2
    z2.mul_assign(&z);
    let mut z3 = z2; // z^3
    z3.mul_assign(&z);
    let n64: u64 = n.try_into().map_err(|_| VerificationError::SetTooLarge)?;
    let ns = C::scalar_from_u64(n64); // n as scalar

    // compute yn = <1, y_n>
    let mut yi = C::Scalar::one(); // y^0
    let mut ip_1_yn = C::Scalar::zero();
    for _ in 0..n {
        ip_1_yn.add_assign(&yi);
        yi.mul_assign(&y);
    }

    let mut delta_yz = z; // delta_yz = z
    delta_yz.sub_assign(&z2); // delta_yz = z - z^2
    delta_yz.mul_assign(&ip_1_yn); // delta_yz = (z - z^2) (<1,y^n>)

    // compute ip_1_s = <1,s>
    let mut ip_1_s = C::Scalar::zero();
    for si in &set_vec {
        ip_1_s.add_assign(si);
    }

    // compute nz
    let mut zn = ns;
    zn.mul_assign(&z);

    // compute z3_term = z^3 (1 - zn - <1,s>)
    let mut z3_term = C::Scalar::one();
    z3_term.sub_assign(&zn);
    z3_term.sub_assign(&ip_1_s);
    z3_term.mul_assign(&z3);

    // delta_yz = z^3 (1 - zn - <1,s>) + (z - z^2) (<1,y^n>)
    delta_yz.add_assign(&z3_term);
    // End of delta_yz computation

    // Part 2: Verify consistency of t_0, i.e., check that
    // V^z^2 * g^(delta_yz - t_x) * T_1^x * T_2^x^2 * h^(-tx_tilde)
    // is the neutral element
    let mut delta_minus_tx = delta_yz;
    delta_minus_tx.sub_assign(&tx);
    let mut x2 = x; // x^2
    x2.mul_assign(&x);
    let mut minus_tx_tilde = tx_tilde;
    minus_tx_tilde.negate();

    let t0_check_base_points = vec![V.0, v_keys.g, T_1, T_2, v_keys.h];
    let t0_check_exponents = vec![z2, delta_minus_tx, x, x2, minus_tx_tilde];

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

    // get exponent for g, i.e., [-z, -z, ..., -z]
    let mut minus_z = z;
    minus_z.negate();
    let mut minus_z_vec = vec![minus_z; n];

    let mut P_prime_exps = Vec::with_capacity(2 * n + 4);
    P_prime_exps.append(&mut minus_z_vec);

    // compute exponent for h, i.e., z1 + z^2y^-n * s + z^3y^-n
    for i in 0..n {
        let mut hexp = z;
        let mut z2ynisi = z2;
        z2ynisi.mul_assign(&y_inv_n[i]);
        z2ynisi.mul_assign(&set_vec[i]);
        hexp.add_assign(&z2ynisi);
        let mut z3yni = z3;
        z3yni.mul_assign(&y_inv_n[i]);
        hexp.add_assign(&z3yni);

        P_prime_exps.push(hexp);
    }

    // add remaining exponents
    P_prime_exps.push(tx);
    P_prime_exps.push(minus_e_tilde);
    P_prime_exps.push(C::Scalar::one());
    P_prime_exps.push(x);

    // P_prime_bases starts with G, H, and Q = g_hat
    let mut P_prime_bases = Vec::with_capacity(2 * n + 4);
    P_prime_bases.extend(G);
    P_prime_bases.extend(H);
    P_prime_bases.push(g_hat);

    // add remaining bases
    P_prime_bases.push(v_keys.h);
    P_prime_bases.push(A);
    P_prime_bases.push(S);

    // Finally verify inner product
    let ip_verification = verify_inner_product_with_scalars(
        transcript,
        &y_inv_n,
        &P_prime_bases,
        &P_prime_exps,
        &proof.ip_proof,
    );

    if !ip_verification {
        return Err(VerificationError::IPVerificationError);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::G1;
    type SomeCurve = G1;

    /// Converts the u64 set vector into a vector over the field
    fn get_set_vector<C: Curve>(the_set: &[u64]) -> Vec<C::Scalar> {
        the_set.iter().copied().map(C::scalar_from_u64).collect()
    }

    /// generates several values used in tests
    fn generate_helper_values(n: usize) -> (Generators<G1>, CommitmentKey<G1>, Randomness<G1>) {
        let rng = &mut thread_rng();
        let gens = Generators::generate(n, rng);
        let b = SomeCurve::generate(rng);
        let b_tilde = SomeCurve::generate(rng);
        let v_keys = CommitmentKey { g: b, h: b_tilde };
        let v_rand = Randomness::generate(rng);

        (gens, v_keys, v_rand)
    }

    /// Generates commitment to v given commitment key and randomness
    fn get_v_com(
        v: <SomeCurve as Curve>::Scalar,
        v_keys: CommitmentKey<G1>,
        v_rand: Randomness<G1>,
    ) -> Commitment<G1> {
        let v_value = Value::<SomeCurve>::new(v);
        let v_com = v_keys.hide(&v_value, &v_rand);

        v_com
    }

    #[test]
    /// Test whether verifying an honestly generated proof works
    fn test_smp_prove_verify() {
        let rng = &mut thread_rng();

        let the_set = get_set_vector::<SomeCurve>(&[1, 7, 3, 5]);
        let v = SomeCurve::scalar_from_u64(3);
        let n = the_set.len();
        let (gens, v_keys, v_rand) = generate_helper_values(n);

        // prove
        let mut transcript = RandomOracle::empty();
        let proof = prove(&mut transcript, rng, &the_set, v, &gens, &v_keys, &v_rand);
        assert!(proof.is_ok());
        let proof = proof.unwrap();

        // verify
        let v_com = get_v_com(v, v_keys, v_rand);
        let mut transcript = RandomOracle::empty();
        let result = verify(&mut transcript, &the_set, &v_com, &proof, &gens, &v_keys);
        assert!(result.is_ok());
    }

    /// Test that sets with sizes not a power of two work
    #[test]
    fn test_smp_prove_not_power_of_two() {
        let rng = &mut thread_rng();

        let the_set = get_set_vector::<SomeCurve>(&[1, 7, 3, 5, 6]);
        let v = SomeCurve::scalar_from_u64(3);
        let n = the_set.len();
        let k = n.next_power_of_two();
        let (gens, v_keys, v_rand) = generate_helper_values(k);

        let mut transcript = RandomOracle::empty();
        let proof = prove(&mut transcript, rng, &the_set, v, &gens, &v_keys, &v_rand);
        assert!(proof.is_ok());
        let proof = proof.unwrap();

        // verify
        let v_com = get_v_com(v, v_keys, v_rand);
        let mut transcript = RandomOracle::empty();
        let result = verify(&mut transcript, &the_set, &v_com, &proof, &gens, &v_keys);
        assert!(result.is_ok());
    }

    /// Test that proof fails if element is not in set
    #[test]
    fn test_smp_prove_not_in_set() {
        let rng = &mut thread_rng();

        let the_set = get_set_vector::<SomeCurve>(&[1, 7, 3, 5]);
        let v = SomeCurve::scalar_from_u64(4);
        let n = the_set.len();
        let (gens, v_keys, v_rand) = generate_helper_values(n);

        let mut transcript = RandomOracle::empty();
        let proof = prove(&mut transcript, rng, &the_set, v, &gens, &v_keys, &v_rand);
        assert!(matches!(proof, Err(ProverError::CouldNotFindValueInSet)));
    }

    /// Test whether verifying a proof generated for a different v fails to
    /// verify (even if the new v is still in the set). This should cause an
    /// invalid T_0 error.
    #[test]
    fn test_smp_verify_different_value() {
        let rng = &mut thread_rng();

        let the_set = get_set_vector::<SomeCurve>(&[1, 7, 3, 5]);
        let v = SomeCurve::scalar_from_u64(3);
        let n = the_set.len();
        let (gens, v_keys, v_rand) = generate_helper_values(n);

        // prove
        let mut transcript = RandomOracle::empty();
        let proof = prove(&mut transcript, rng, &the_set, v, &gens, &v_keys, &v_rand);
        assert!(proof.is_ok());
        let proof = proof.unwrap();

        // verify
        let v = SomeCurve::scalar_from_u64(5); // different v still in set
        let v_com = get_v_com(v, v_keys, v_rand);
        let mut transcript = RandomOracle::empty();
        let result = verify(&mut transcript, &the_set, &v_com, &proof, &gens, &v_keys);
        assert!(matches!(result, Err(VerificationError::InconsistentT0)));
    }

    #[test]
    /// Test whether verifying with different set (still containing v) fails.
    /// This should cause an Inconsistent T0.
    fn test_smp_verify_different_set() {
        let rng = &mut thread_rng();

        let the_set = get_set_vector::<SomeCurve>(&[1, 7, 3, 5]);
        let v = SomeCurve::scalar_from_u64(3);
        let n = the_set.len();
        let (gens, v_keys, v_rand) = generate_helper_values(n);

        // prove
        let mut transcript = RandomOracle::empty();
        let proof = prove(&mut transcript, rng, &the_set, v, &gens, &v_keys, &v_rand);
        assert!(proof.is_ok());
        let proof = proof.unwrap();

        // verify
        let new_set = get_set_vector::<SomeCurve>(&[2, 7, 3, 5]);
        let v_com = get_v_com(v, v_keys, v_rand);
        let mut transcript = RandomOracle::empty();
        let result = verify(&mut transcript, &new_set, &v_com, &proof, &gens, &v_keys);
        assert!(matches!(result, Err(VerificationError::InconsistentT0)));
    }

    #[test]
    /// Test whether modifying inner proof causes invalid IP proof error.
    fn test_smp_verify_invalid_inner_product() {
        let rng = &mut thread_rng();

        let the_set = get_set_vector::<SomeCurve>(&[1, 7, 3, 5]);
        let v = SomeCurve::scalar_from_u64(3);
        let n = the_set.len();
        let (gens, v_keys, v_rand) = generate_helper_values(n);

        // prove
        let mut transcript = RandomOracle::empty();
        let proof = prove(&mut transcript, rng, &the_set, v, &gens, &v_keys, &v_rand);
        assert!(proof.is_ok());
        let mut proof = proof.unwrap();

        proof.ip_proof.a.negate(); // tamper with IP proof

        // verify
        let v_com = get_v_com(v, v_keys, v_rand);
        let mut transcript = RandomOracle::empty();
        let result = verify(&mut transcript, &the_set, &v_com, &proof, &gens, &v_keys);
        assert!(matches!(
            result,
            Err(VerificationError::IPVerificationError)
        ));
    }

    #[test]
    /// Test honest proof supplying more generators than needed
    fn test_smp_prove_many_generators() {
        let rng = &mut thread_rng();

        let the_set = get_set_vector::<SomeCurve>(&[1, 7, 3, 5]);
        let v = SomeCurve::scalar_from_u64(3);
        let num_gens = 2112;
        let (gens, v_keys, v_rand) = generate_helper_values(num_gens);

        // prove
        let mut transcript = RandomOracle::empty();
        let proof = prove(&mut transcript, rng, &the_set, v, &gens, &v_keys, &v_rand);
        assert!(proof.is_ok());
        let proof = proof.unwrap();

        // verify
        let v_com = get_v_com(v, v_keys, v_rand);
        let mut transcript = RandomOracle::empty();
        let result = verify(&mut transcript, &the_set, &v_com, &proof, &gens, &v_keys);
        assert!(result.is_ok());
    }
}
