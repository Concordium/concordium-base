//! Implementation of set-non-membership proof along the lines of bulletproofs
use crate::{inner_product_proof::*, utils::*};
use crypto_common::*;
use crypto_common_derive::*;
use curve_arithmetic::{multiexp, multiexp_table, multiexp_worker_given_table, Curve};
use ff::Field;
use pedersen_scheme::*;
use rand::*;
use random_oracle::RandomOracle;

/// Bulletproof style set-non-membership proof
#[derive(Clone, Serialize, SerdeBase16Serialize, Debug)]
#[allow(non_snake_case)]
pub struct SetNonMembershipProof<C: Curve> {
    /// Commitment to the multiplicative inverse of `v-s_i` for each `i`
    A:        C,
    /// Commitment to the blinding factors in `s_L` and `s_R`
    S:        C,
    /// Commitment to the `t_1` coefficient of polynomial `t(X)`
    T_1:      C,
    /// Commitment to the `t_2` coefficient of polynomial `t(X)`
    T_2:      C,
    /// Evaluation of `t(X)` at the challenge point `x`
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
    /// Could find the value `v` in the given set
    CouldFindValueInSet,
    /// Could not generate inner product proof
    InnerProductProofFailure,
    /// Could not invert an element
    DivisionError,
}

/// This function produces a set-non-membership proof, i.e., a proof of
/// knowledge of a value v that is not in a given set `the_set` and that is
/// consistent with the commitment `V` to `v`. The arguments are
/// - `transcript` - the random oracle for Fiat Shamir
/// - `csprng` - cryptographic safe randomness generator
/// - `the_set` - the set as a vector
/// - `v` the value
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
) -> Result<SetNonMembershipProof<C>, ProverError> {
    // Part 0: Add public inputs to transcript
    // Domain separation
    transcript.add_bytes(b"SetNonMembershipProof");
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

    // Get generator vector for blinded vector commitments, i.e. (G,H,B_tilde)
    let mut GH_B_tilde: Vec<C> = Vec::with_capacity(2 * n + 1);
    let (mut G, mut H): (Vec<_>, Vec<_>) = gens.G_H.iter().take(n).cloned().unzip();
    GH_B_tilde.append(&mut G);
    GH_B_tilde.append(&mut H);

    // Generators for single commitments and blinding
    let B = v_keys.g;
    let B_tilde = v_keys.h;
    GH_B_tilde.push(B_tilde);

    // define aliases to amek G and H available again
    let G = &GH_B_tilde[0..n];
    let H = &GH_B_tilde[n..2 * n];

    // Compute A_scalars, that is a_L, a_R and a_tilde
    let mut A_scalars = Vec::with_capacity(2 * n + 1);
    // Compute a_L_i <- (v - si)^-1
    for si in &set_vec {
        let mut v_minus_si = v;
        v_minus_si.sub_assign(si);
        // inverse not defined => difference==0 => v in set
        let v_minus_si_inv = match v_minus_si.inverse() {
            Some(inv) => inv,
            None => return Err(ProverError::CouldFindValueInSet),
        };
        A_scalars.push(v_minus_si_inv);
    }
    // Compute a_R_i = v
    for _ in 0..n {
        A_scalars.push(v);
    }
    // generate a_tilde
    A_scalars.push(C::generate_scalar(csprng));
    // Aliases
    let a_L = &A_scalars[0..n];
    let a_R = &A_scalars[n..2 * n];
    let a_tilde = &A_scalars[2 * n];
    // Compute S_scalars, i.e., the blinding factors
    let mut S_scalars = Vec::with_capacity(2 * n + 1);
    for _ in 0..2 * n + 1 {
        S_scalars.push(C::generate_scalar(csprng));
    }
    // Aliases
    let s_L = &S_scalars[0..n];
    let s_R = &S_scalars[n..2 * n];
    let s_tilde = &S_scalars[2 * n];

    // Compute A and S commitments using multi exponentiation
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
    // ip_y_n = <1,y_n>
    let mut ip_y_n = C::Scalar::zero();
    for y_i in &y_n {
        ip_y_n.add_assign(y_i);
    }
    // coefficients of l(x) and r(x)
    // compute l_0 and l_1
    let mut l_0 = Vec::with_capacity(n);
    let mut l_1 = Vec::with_capacity(n);
    for i in 0..n {
        // l_0[i] <- a_L[i] + z
        let mut l_0_i = a_L[i];
        l_0_i.add_assign(&z);
        l_0.push(l_0_i);
        // l_1[i] <- s_L[i]
        l_1.push(s_L[i]);
    }
    // compute r_0 and r_1
    let mut r_0 = Vec::with_capacity(n);
    let mut r_1 = Vec::with_capacity(n);
    for i in 0..n {
        // r_0[i] <- y_n[i] * (a_R[i] - s)
        let mut r_0_i = a_R[i];
        r_0_i.sub_assign(&set_vec[i]);
        r_0_i.mul_assign(&y_n[i]);
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
    // t_x_tilde <- z*<1,y^n>*v_rand + t_1_tilde*x + t_2_tilde*x^2
    let mut tx_tilde = z;
    tx_tilde.mul_assign(&ip_y_n);
    tx_tilde.mul_assign(v_rand);
    let mut tx_s1 = t_1_tilde;
    tx_s1.mul_assign(&x);
    tx_tilde.add_assign(&tx_s1);
    let mut tx_s2 = t_2_tilde;
    tx_s2.mul_assign(&x_sq);
    tx_tilde.add_assign(&tx_s2);
    // Compute blinding e_tilde
    // e_tilde <- a_tilde + s_tilde * x
    let mut e_tilde = *s_tilde;
    e_tilde.mul_assign(&x);
    e_tilde.add_assign(a_tilde);
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
    let proof = prove_inner_product_with_scalars(transcript, G, H, &H_prime_scalars, &Q, &lx, &rx);

    // return set membership proof
    if let Some(ip_proof) = proof {
        Ok(SetNonMembershipProof {
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

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::G1;
    type SomeCurve = G1;

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
    fn get_v_com(v: u64, v_keys: CommitmentKey<G1>, v_rand: Randomness<G1>) -> Commitment<G1> {
        let v_scalar = SomeCurve::scalar_from_u64(v);
        let v_value = Value::<SomeCurve>::new(v_scalar);
        let v_com = v_keys.hide(&v_value, &v_rand);

        v_com
    }

    #[test]
    /// Test whether verifying an honestly generated proof works
    fn test_smp_prove_verify() {
        let rng = &mut thread_rng();

        let the_set: [u64; 4] = [1, 7, 3, 5];
        let n = the_set.len();
        let v = 2;
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

    /// Test that sets with sizes not a power of two are rejected by prove
    #[test]
    fn test_smp_prove_not_power_of_two() {
        let rng = &mut thread_rng();

        let the_set: [u64; 5] = [1, 7, 3, 5, 6];
        let n = the_set.len();
        let v = 2;
        let (gens, v_keys, v_rand) = generate_helper_values(n);

        let mut transcript = RandomOracle::empty();
        let proof = prove(&mut transcript, rng, &the_set, v, &gens, &v_keys, &v_rand);
        assert!(matches!(proof, Err(ProverError::SetSizeNotPowerOfTwo)));
    }

    /// Test that proof fails if element is in the set
    #[test]
    fn test_smp_prove_in_set() {
        let rng = &mut thread_rng();

        let the_set: [u64; 4] = [1, 7, 3, 5];
        let n = the_set.len();
        let v = 3;
        let (gens, v_keys, v_rand) = generate_helper_values(n);

        let mut transcript = RandomOracle::empty();
        let proof = prove(&mut transcript, rng, &the_set, v, &gens, &v_keys, &v_rand);
        assert!(matches!(proof, Err(ProverError::CouldFindValueInSet)));
    }

    /// Test that verification fails if set has size not a power of two
    #[test]
    fn test_smp_verify_not_power_of_two() {
        let rng = &mut thread_rng();

        // generate proof for set with correct size since otherwise proof generation
        // fails
        let the_set: [u64; 4] = [1, 7, 3, 5];
        let n = the_set.len();
        let v = 2;
        let (gens, v_keys, v_rand) = generate_helper_values(n);

        let mut transcript = RandomOracle::empty();
        let proof = prove(&mut transcript, rng, &the_set, v, &gens, &v_keys, &v_rand);
        assert!(proof.is_ok());
        let proof = proof.unwrap();

        // now define new set and try to verify
        let invalid_set: [u64; 5] = [1, 7, 3, 5, 6];
        let v_com = get_v_com(v, v_keys, v_rand);
        let mut transcript = RandomOracle::empty();
        let result = verify(
            &mut transcript,
            &invalid_set,
            &v_com,
            &proof,
            &gens,
            &v_keys,
        );
        assert!(matches!(
            result,
            Err(VerificationError::SetSizeNotPowerOfTwo)
        ));
    }

    /// Test whether verifying a proof generated for a different v fails to
    /// verify (even if the new v is still not in the set). This should cause an
    /// inconsistent T0 error.
    #[test]
    fn test_smp_verify_different_value() {
        let rng = &mut thread_rng();

        let the_set: [u64; 4] = [1, 7, 3, 5];
        let n = the_set.len();
        let v = 2;
        let (gens, v_keys, v_rand) = generate_helper_values(n);

        // prove
        let mut transcript = RandomOracle::empty();
        let proof = prove(&mut transcript, rng, &the_set, v, &gens, &v_keys, &v_rand);
        assert!(proof.is_ok());
        let proof = proof.unwrap();

        // verify
        let v = 4; // different v still not in the set
        let v_com = get_v_com(v, v_keys, v_rand);
        let mut transcript = RandomOracle::empty();
        let result = verify(&mut transcript, &the_set, &v_com, &proof, &gens, &v_keys);
        assert!(matches!(result, Err(VerificationError::InconsistentT0)));
    }

    #[test]
    /// Test whether verifying with different set (still not containing v)
    /// fails. This should cause an inconsistent T0 error.
    fn test_smp_verify_different_set() {
        let rng = &mut thread_rng();

        let the_set: [u64; 4] = [1, 7, 3, 5];
        let n = the_set.len();
        let v = 17;
        let (gens, v_keys, v_rand) = generate_helper_values(n);

        // prove
        let mut transcript = RandomOracle::empty();
        let proof = prove(&mut transcript, rng, &the_set, v, &gens, &v_keys, &v_rand);
        assert!(proof.is_ok());
        let proof = proof.unwrap();

        // verify
        let new_set: [u64; 4] = [2, 7, 3, 5];
        let v_com = get_v_com(v, v_keys, v_rand);
        let mut transcript = RandomOracle::empty();
        let result = verify(&mut transcript, &new_set, &v_com, &proof, &gens, &v_keys);
        assert!(matches!(result, Err(VerificationError::InconsistentT0)));
    }

    #[test]
    /// Test whether modifying inner product proof causes invalid IP proof
    /// error.
    fn test_smp_verify_invalid_inner_product() {
        let rng = &mut thread_rng();

        let the_set: [u64; 4] = [1, 7, 3, 5];
        let n = the_set.len();
        let v = 42;
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
}
