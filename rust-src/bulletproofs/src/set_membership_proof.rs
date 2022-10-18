use crate::{inner_product_proof::*, utils::*};
use crypto_common::*;
use crypto_common_derive::*;
use curve_arithmetic::{multiexp, multiexp_table, multiexp_worker_given_table, Curve};
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
#[derive(Debug, PartialEq)]
pub enum ProverError {
    /// The set must have a size of a power of two
    SetSizeNotPowerOfTwo,
    /// The length of G_H was less than |S|, which is too small
    NotEnoughGenerators,
    /// Could not compute the indicator
    CouldNotFindValueInSet,
    /// Could not generate inner product proof
    InnerProductProofFailure,
    /// Could not invert y
    CouldNotInvertY,
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
    let mut a_L = Vec::with_capacity(n);
    let mut a_R = Vec::with_capacity(n);
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
    let n = the_set.len();
    if !n.is_power_of_two() {
        return Err(ProverError::SetSizeNotPowerOfTwo);
    }
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
    let set_vec = get_set_vector::<C>(&the_set);
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
    // compute scalars c such that c*H = H', that is H_prime_scalars = (1, y^-1,..,
    // y^-(n-1))
    let y_inv = match y.inverse() {
        Some(inv) => inv,
        None => return Err(ProverError::CouldNotInvertY),
    };
    let H_prime_scalars = z_vec(y_inv, 0, n);
    // compute inner product proof
    let proof =
        prove_inner_product_with_scalars(transcript, &G, &H, &H_prime_scalars, &Q, &lx, &rx);

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
#[derive(Debug, PartialEq)]
pub enum VerificationError {
    /// The length of G_H was less than |S|, which is too small
    NotEnoughGenerators,
    /// The consistency check for t_0 failed
    InconsistentT0,
    /// Choice of randomness led to verification failure
    DivisionError,
    /// inner product proof verification failed
    IPVerificationError,
}

/// This function verifies a set membership proof, i.e. a proof of knowledge
/// of value v that is in a set S and that is consistent
/// with a commitment V to v. The arguments are
/// - S - the set as a vector
/// - V - commitment to v
/// - proof - the set membership proof to verify
/// - gens - generators containing vectors G and H both of length at least |S|
///   (bold g,h in bluepaper)
/// - v_keys - commitment keys B and B_tilde (g,h in bluepaper)
#[allow(non_snake_case)]
pub fn verify<C: Curve>(
    transcript: &mut RandomOracle,
    the_set: &[u64],
    V: &Commitment<C>,
    proof: &SetMembershipProof<C>,
    gens: &Generators<C>,
    v_keys: &CommitmentKey<C>,
) -> Result<(), VerificationError> {
    // Part 1: Setup
    // TODO: Check that n := |S| is a power of 2?
    // TODO: Check whether this should be done for range proof verification
    let n = the_set.len();
    if gens.G_H.len() < n {
        return Err(VerificationError::NotEnoughGenerators);
    }

    // TODO: Check whether n fits into u64
    let n = n as u64;

    // append commitment V to transcript
    transcript.append_message(b"V", &V.0);

    // define the commitments A,S
    let A = proof.A;
    let S = proof.S;
    // append commitments A and S to transcript
    transcript.append_message(b"A", &A);
    transcript.append_message(b"S", &S);

    // get challenges y,z from transcript
    let y: C::Scalar = transcript.challenge_scalar::<C, _>(b"y");
    let z: C::Scalar = transcript.challenge_scalar::<C, _>(b"z");

    // define the commitments A,S
    let T_1 = proof.T_1;
    let T_2 = proof.T_2;
    // append T1, T2 commitments to transcript
    transcript.append_message(b"T1", &T_1);
    transcript.append_message(b"T2", &T_2);

    // get challenge x (evaluation point) from transcript
    let x: C::Scalar = transcript.challenge_scalar::<C, _>(b"x");

    // define polynomial evaluation value
    let tx = proof.tx;
    // define blinding factors for tx and i.p. proof
    let tx_tilde = proof.tx_tilde;
    let e_tilde = proof.e_tilde;
    // append tx, tx_tilde, e_tilde to transcript
    transcript.append_message(b"tx", &tx);
    transcript.append_message(b"tx_tilde", &tx_tilde);
    transcript.append_message(b"e_tilde", &e_tilde);

    // get challenge w from transcript
    let w: C::Scalar = transcript.challenge_scalar::<C, _>(b"w");

    // compute delta(y,z) = -nz^4 + z^3 (1 - <1,s>) + (z-z^2) (<1,y^n>)
    // first compute helper values
    let mut z2 = z; // z^2
    z2.mul_assign(&z);
    let mut z3 = z2; // z^3
    z3.mul_assign(&z);
    let mut z4 = z3; // z^4
    z4.mul_assign(&z);
    let ns = C::scalar_from_u64(n); // n as scalar
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
    for si in the_set {
        let sis = C::scalar_from_u64(*si);
        ip_1_s.add_assign(&sis);
    }

    // compute z3_one_minus_ip_1_s = z^3 (1 - <1,s>)
    let mut one_minus_ip_1_s = C::Scalar::one();
    one_minus_ip_1_s.sub_assign(&ip_1_s);
    let mut z3_one_minus_ip_1_s = z3;
    z3_one_minus_ip_1_s.mul_assign(&one_minus_ip_1_s);

    // delta_yz = (z - z^2) (<1,y^n>) + z^3 (1 - <1,s>)
    delta_yz.add_assign(&z3_one_minus_ip_1_s);

    // compute nz^4
    let mut nz4 = ns;
    nz4.mul_assign(&z4);

    // delta_yz = (z - z^2) (<1,y^n>) + z^3 (1 - <1,s>)
    delta_yz.sub_assign(&nz4);
    // End of delta_yz computation

    // Part 2: Verify consistency of t_0
    // i.e., check 0 = V^z^2 * g^(delta_yz - t_x) * T_1^x * T_2^x^2 * h^(-tx_tilde)
    let mut delta_minus_tx = delta_yz;
    delta_minus_tx.sub_assign(&tx);
    let mut x2 = x; // x^2
    x2.mul_assign(&x);
    let mut minus_tx_tilde = C::Scalar::zero();
    minus_tx_tilde.sub_assign(&tx_tilde);

    let base_points = vec![V.0, v_keys.g, T_1, T_2, v_keys.h];
    let exponents = vec![z2, delta_minus_tx, x, x2, minus_tx_tilde];

    let rhs = multiexp(&base_points, &exponents);
    if !rhs.is_zero_point() {
        return Err(VerificationError::InconsistentT0);
    }

    // Part 3: Verify inner product
    // First compute helper variables g_hat, h_prime, and P_prime
    let mut g_hat = v_keys.g;
    g_hat.mul_by_scalar(&w);

    let y_inv = match y.inverse() {
        Some(inv) => inv,
        None => return Err(VerificationError::DivisionError),
    };
    let y_inv_n = z_vec(y_inv, 0, n as usize); // TODO: Unify whether z_vec takes usize or u64

    let (G, H): (Vec<_>, Vec<_>) = gens.G_H.iter().cloned().unzip();
    let mut h_prime = multiexp(&H, &y_inv_n);

    let P_prime = A; // TODO!

    let ip_verification = false; // TODO, verify_inner_product(transcript, G_vec, H_vec, &P_prime, Q, proof);

    if !ip_verification {
        return Err(VerificationError::IPVerificationError);
    }

    return Ok(());
}

#[derive(Debug, PartialEq)]
pub enum UltraVerificationError {
    /// The length of G_H was less than |S|, which is too small
    NotEnoughGenerators,
    /// Could not compute the inner product scalars
    IpScalarCheckFailed,
    /// Could not invert the given y
    CouldNotInvertY,
}

#[allow(non_snake_case)]
pub fn verify_ultra_efficient<C: Curve, R: Rng>(
    transcript: &mut RandomOracle,
    csprng: &mut R,
    the_set: &[u64],
    V: &Commitment<C>,
    proof: &SetMembershipProof<C>,
    gens: &Generators<C>,
    v_keys: &CommitmentKey<C>,
) -> Result<bool, UltraVerificationError> {
    // Domain separation
    transcript.add_bytes(b"SetMembershipProof");
    transcript.append_message(b"V", &V.0);
    // Convert the u64 set into a field element vector
    let set_vec = get_set_vector::<C>(&the_set);
    let n = set_vec.len();
    // Append the set to the transcript
    transcript.append_message(b"theSet", &set_vec);

    // Check that we have enough generators for vector commitments
    if gens.G_H.len() < n {
        return Err(UltraVerificationError::NotEnoughGenerators);
    }
    // Define generators
    let (G, H): (Vec<_>, Vec<_>) = gens.G_H.iter().take(n).cloned().unzip();
    let B = v_keys.g;
    let B_tilde = v_keys.h;

    let A = proof.A;
    let S = proof.S;
    transcript.append_message(b"A", &A);
    transcript.append_message(b"S", &S);
    let y: C::Scalar = transcript.challenge_scalar::<C, _>(b"y");
    let z: C::Scalar = transcript.challenge_scalar::<C, _>(b"z");
    let mut z2 = z;
    z2.mul_assign(&z);
    let mut z3 = z2;
    z3.mul_assign(&z);

    let T_1 = proof.T_1;
    let T_2 = proof.T_2;
    transcript.append_message(b"T1", &T_1);
    transcript.append_message(b"T2", &T_2);
    let x: C::Scalar = transcript.challenge_scalar::<C, _>(b"x");
    let mut x2 = x;
    x2.mul_assign(&x);

    let tx = proof.tx;
    let tx_tilde = proof.tx_tilde;
    let e_tilde = proof.e_tilde;
    transcript.append_message(b"tx", &tx);
    transcript.append_message(b"tx_tilde", &tx_tilde);
    transcript.append_message(b"e_tilde", &e_tilde);
    let w: C::Scalar = transcript.challenge_scalar::<C, _>(b"w");
    // Calculate delta(x,y) <- z^3(1-zn-<1,s>)+(z-z^2)*<1,y^n>
    //<1,y^n>
    let mut ip_1_y = C::Scalar::zero();
    let mut yi = C::Scalar::one();
    for _ in 0..n {
        ip_1_y.add_assign(&yi);
        yi.mul_assign(&y);
    }
    //<1,s>
    let mut ip_1_s = C::Scalar::zero();
    for s_i in &set_vec {
        ip_1_s.add_assign(&s_i);
    }
    let mut zn = C::scalar_from_u64(n as u64);
    zn.mul_assign(&z);
    // z^3(1-zn-<1,s>)
    let mut z3_term = C::Scalar::one();
    z3_term.sub_assign(&zn);
    z3_term.sub_assign(&ip_1_s);
    z3_term.mul_assign(&z3);
    let mut yn_term = z;
    yn_term.sub_assign(&z2);
    yn_term.mul_assign(&ip_1_y);
    let mut delta_yz = z3_term;
    delta_yz.add_assign(&yn_term);

    // Get ip scalars
    let ip_proof = &proof.ip_proof;
    let verification_scalars = verify_scalars(transcript, n, ip_proof);
    if verification_scalars.is_none() {
        return Err(UltraVerificationError::IpScalarCheckFailed);
    }
    let verification_scalars = verification_scalars.unwrap();
    let (u_sq, u_inv_sq, s) = (
        verification_scalars.u_sq,
        verification_scalars.u_inv_sq,
        verification_scalars.s,
    );

    let a = ip_proof.a;
    let b = ip_proof.b;
    let (L, R): (Vec<_>, Vec<_>) = ip_proof.lr_vec.iter().cloned().unzip();
    let mut s_inv = s.clone();
    s_inv.reverse();
    let y_inv = match y.inverse() {
        Some(inv) => inv,
        None => return Err(UltraVerificationError::CouldNotInvertY),
    };
    let y_n_inv = z_vec(y_inv, 0, n);

    // Select random c
    let c = C::generate_scalar(csprng);

    // Compute scalars
    let A_scalar = C::Scalar::one();
    let S_scalar = x;
    let mut V_scalar = c;
    V_scalar.mul_assign(&z2);
    let mut T_1_scalar = c;
    T_1_scalar.mul_assign(&x);
    let mut T_2_scalar = T_1_scalar;
    T_2_scalar.mul_assign(&x);
    // B_scalar <- w(tx-ab)+c(delta_yz-tx)
    let mut ab = a;
    ab.mul_assign(&b);
    let mut c_delta_minus_tx = delta_yz;
    c_delta_minus_tx.sub_assign(&tx);
    c_delta_minus_tx.mul_assign(&c);
    let mut B_scalar = tx;
    B_scalar.sub_assign(&ab);
    B_scalar.mul_assign(&w);
    B_scalar.add_assign(&c_delta_minus_tx);
    // B_tilde_scalar <- -e_tilde-c*tx_tilde
    let mut minus_e_tilde = e_tilde;
    minus_e_tilde.negate();
    let mut ctx_tilde = tx_tilde;
    ctx_tilde.mul_assign(&c);
    let mut B_tilde_scalar = minus_e_tilde;
    B_tilde_scalar.sub_assign(&ctx_tilde);
    // G_scalars g_i <- -z-a*s_i
    let mut G_scalars = Vec::with_capacity(n);
    for si in s {
        let mut G_scalar = z;
        G_scalar.negate();
        let mut sa = si;
        sa.mul_assign(&a);
        G_scalar.sub_assign(&sa);
        G_scalars.push(G_scalar);
    }
    // H_scalars h_i <- y^-i * (z^2set_i-b*s_inv_i+z^3) + z
    let mut H_scalars = Vec::with_capacity(n);
    for i in 0..n {
        let mut H_scalar = set_vec[i];
        H_scalar.mul_assign(&z2);
        let mut bs_inv = b;
        bs_inv.mul_assign(&s_inv[i]);
        H_scalar.sub_assign(&bs_inv);
        H_scalar.add_assign(&z3);
        H_scalar.mul_assign(&y_n_inv[i]);
        H_scalar.add_assign(&z);
        H_scalars.push(H_scalar);
    }
    // L and R scalars
    let mut L_scalars = u_sq;
    let mut R_scalars = u_inv_sq;

    // Combine scalar vectors
    let mut all_scalars = vec![A_scalar];
    all_scalars.push(S_scalar);
    all_scalars.push(T_1_scalar);
    all_scalars.push(T_2_scalar);
    all_scalars.push(B_scalar);
    all_scalars.push(B_tilde_scalar);
    all_scalars.push(V_scalar);
    all_scalars.append(&mut G_scalars);
    all_scalars.append(&mut H_scalars);
    all_scalars.append(&mut L_scalars);
    all_scalars.append(&mut R_scalars);
    // Combine generator vectors
    let mut all_points = vec![A];
    all_points.push(S);
    all_points.push(T_1);
    all_points.push(T_2);
    all_points.push(B);
    all_points.push(B_tilde);
    all_points.push(V.0);
    all_points.extend_from_slice(&G);
    all_points.extend_from_slice(&H);
    all_points.extend_from_slice(&L);
    all_points.extend_from_slice(&R);

    let sum = multiexp(&all_points, &all_scalars);

    Ok(sum.is_zero_point())
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve_arithmetic::multiexp;
    use pairing::bls12_381::G1;

    type SomeCurve = G1;

    #[test]
    fn test_smp_with_ultra_verification() {
        let rng = &mut thread_rng();
        let mut transcript = RandomOracle::empty();

        let the_set: [u64; 4] = [1, 7, 3, 5];
        let v: u64 = 3;
        let n = the_set.len();

        let gens = Generators::generate(n, rng);
        let B = SomeCurve::generate(rng);
        let B_tilde = SomeCurve::generate(rng);
        let v_keys = CommitmentKey { g: B, h: B_tilde };

        let v_rand = Randomness::generate(rng);
        let v_scalar = SomeCurve::scalar_from_u64(v);
        let v_value = Value::<SomeCurve>::new(v_scalar);
        let v_com = v_keys.hide(&v_value, &v_rand);

        let proof = prove(&mut transcript, rng, &the_set, v, &gens, &v_keys, &v_rand);

        assert!(proof.is_ok());
        let proof = proof.unwrap();

        let mut transcript = RandomOracle::empty();
        let result = verify_ultra_efficient(
            &mut transcript,
            rng,
            &the_set,
            &v_com,
            &proof,
            &gens,
            &v_keys,
        );
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result);
    }
}
