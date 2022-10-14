use crate::{inner_product_proof::*, utils::*};
use crypto_common::*;
use crypto_common_derive::*;
use curve_arithmetic::{multiexp, multiexp_table, multiexp_worker_given_table, Curve, Value};
use ff::{Field, PrimeField};
use pedersen_scheme::*;
use rand::*;
use random_oracle::RandomOracle;
use std::iter::once;

#[derive(Clone, Serialize, SerdeBase16Serialize, Debug)]
#[allow(non_snake_case)]
pub struct RangeProof<C: Curve> {
    /// Commitment to the bits of the value
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

/// Determine whether the i-th bit (counting from least significant) is set in
/// the given u64 value.
fn ith_bit_bool(v: u64, i: u8) -> bool { v & (1 << i) != 0 }

/// This function computes the n-bit binary representation a_L of input value v
/// The vector a_R is the bit-wise negation of a_R
#[allow(non_snake_case)]
fn a_L_a_R<F: Field>(v: u64, n: u8) -> (Vec<F>, Vec<F>) {
    let mut a_L = Vec::with_capacity(usize::from(n));
    let mut a_R = Vec::with_capacity(usize::from(n));
    for i in 0..n {
        let mut bit = F::zero();
        if ith_bit_bool(v, i) {
            bit = F::one();
        }
        a_L.push(bit);
        bit.sub_assign(&F::one());
        a_R.push(bit);
    }
    (a_L, a_R)
}

/// This function takes one argument n and returns the
/// vector (1, 2, ..., 2^{n-1}) in F^n for any field F
///
/// This could use the next `z_vec` function, but for efficiency it implements
/// the special-case logic for doubling directly.
#[allow(non_snake_case)]
fn two_n_vec<F: Field>(n: u8) -> Vec<F> {
    let mut two_n = Vec::with_capacity(usize::from(n));
    let mut two_i = F::one();
    for _ in 0..n {
        two_n.push(two_i);
        two_i.double();
    }
    two_n
}

/// This function produces a range proof given scalars in a prime field
/// instead of integers. It invokes prove(), documented below.
///
/// See the documentation of `prove` below for the meaning of arguments.
#[allow(clippy::too_many_arguments)]
pub fn prove_given_scalars<C: Curve, T: Rng>(
    transcript: &mut RandomOracle,
    csprng: &mut T,
    n: u8,
    m: u8,
    v_vec: &[C::Scalar],
    gens: &Generators<C>,
    v_keys: &CommitmentKey<C>,
    randomness: &[Randomness<C>],
) -> Option<RangeProof<C>> {
    let mut v_integers = Vec::with_capacity(v_vec.len());
    for &v in v_vec {
        let rep = v.into_repr();
        let r = rep.as_ref()[0];
        v_integers.push(r);
    }

    prove(
        transcript,
        csprng,
        n,
        m,
        &v_integers,
        gens,
        v_keys,
        randomness,
    )
}

/// This function produces a range proof, i.e. a proof of knowledge
/// of value v_1, v_2, ..., v_m that are all in [0, 2^n) that are consistent
/// with commitments V_i to v_i. The arguments are
/// - n - the number n such that v_i is in [0,2^n) for all i
/// - m - the number of values that is proved to be in [0,2^n)
/// - v_vec - the vector having v_1, ..., v_m as entrances
/// - gens - generators containing vectors G and H both of length nm
/// - v_keys - commitmentment keys B and B_tilde
/// - randomness - the randomness used to commit to each v_i using v_keys
#[allow(clippy::many_single_char_names)]
#[allow(non_snake_case)]
#[allow(clippy::too_many_arguments)]
pub fn prove<C: Curve, T: Rng>(
    transcript: &mut RandomOracle,
    csprng: &mut T,
    n: u8,
    m: u8,
    v_vec: &[u64],
    gens: &Generators<C>,
    v_keys: &CommitmentKey<C>,
    randomness: &[Randomness<C>],
) -> Option<RangeProof<C>> {
    // Part 1: Setup and generation of vector commitments
    // V (for the values),
    // A (their binary representation),
    // S (the blinding factors)
    let nm = usize::from(n) * usize::from(m);
    // Check that we have enough generators for vector commitments
    if gens.G_H.len() < nm {
        return None;
    }
    // Select generators for vector commitments
    let (G, H): (Vec<_>, Vec<_>) = gens.G_H.iter().take(nm).cloned().unzip();
    // Generator for single commitments
    let B = v_keys.g;
    // Generator for the blinding of commitments
    let B_tilde = v_keys.h;
    // Setup blinding factors for a_L and a_R
    let mut s_L = Vec::with_capacity(usize::from(n));
    let mut s_R = Vec::with_capacity(usize::from(n));
    for _ in 0..nm {
        s_L.push(C::generate_scalar(csprng));
        s_R.push(C::generate_scalar(csprng));
    }
    // Vectors for binary representation of values in v_vec
    let mut a_L: Vec<C::Scalar> = Vec::with_capacity(usize::from(n));
    let mut a_R: Vec<C::Scalar> = Vec::with_capacity(usize::from(n));
    // Vectors for value commitments V_j
    let mut V_vec: Vec<Commitment<C>> = Vec::with_capacity(usize::from(m));
    // Blinding factors for V_j,A_j,S_j committments
    let mut v_tilde_vec: Vec<C::Scalar> = Vec::with_capacity(usize::from(m));
    let mut a_tilde_vec: Vec<C::Scalar> = Vec::with_capacity(usize::from(m));
    let mut s_tilde_vec: Vec<C::Scalar> = Vec::with_capacity(usize::from(m));
    for j in 0..v_vec.len() {
        // get binary representation of value j
        let (a_L_j, a_R_j) = a_L_a_R(v_vec[j], n);
        a_L.extend(&a_L_j);
        a_R.extend(&a_R_j);
        // generate blinding factors
        let v_j_tilde = &randomness[j]; // let v_j_tilde = Randomness::<C>::generate(csprng);
        let a_j_tilde = Randomness::<C>::generate(csprng);
        let s_j_tilde = Randomness::<C>::generate(csprng);
        v_tilde_vec.push(*v_j_tilde.as_ref());
        a_tilde_vec.push(*a_j_tilde);
        s_tilde_vec.push(*s_j_tilde);
        // convert value to scalar in base field of C
        let v_scalar = C::scalar_from_u64(v_vec[j]);
        let v_value = Value::<C>::new(v_scalar);
        // generate commitment V_j to value v_j
        let V_j = v_keys.hide(&v_value, v_j_tilde);
        // append commitment V_j to transcript!
        transcript.append_message(b"Vj", &V_j.0);
        V_vec.push(V_j);
    }
    // compute blinding factor of A and S
    let mut a_tilde_sum = C::Scalar::zero();
    let mut s_tilde_sum = C::Scalar::zero();
    for i in 0..a_tilde_vec.len() {
        a_tilde_sum.add_assign(&a_tilde_vec[i]);
        s_tilde_sum.add_assign(&s_tilde_vec[i]);
    }
    // get scalars for A commitment, that is (a_L,a_r,a_tilde_sum)
    let A_scalars: Vec<C::Scalar> = a_L
        .iter()
        .chain(a_R.iter())
        .copied()
        .chain(once(a_tilde_sum))
        .collect();
    // get scalars for S commitment, that is (s_L,s_r,s_tilde_sum)
    let S_scalars: Vec<C::Scalar> = s_L
        .iter()
        .chain(s_R.iter())
        .copied()
        .chain(once(s_tilde_sum))
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

    // y_nm = (1,y,..,y^(nm-1))
    let y_nm = z_vec(y, 0, nm);
    // two_n = (1, 2, ..., 2^{n-1})
    let two_n: Vec<C::Scalar> = two_n_vec(n);
    // z_m = (1,z,..,z^(m-1))
    let z_m = z_vec(z, 0, usize::from(m));
    // z squared
    let z_sq = if z_m.len() > 2 {
        z_m[2]
    } else {
        let mut z_sq = z;
        z_sq.mul_assign(&z);
        z_sq
    };

    // coefficients of l(x) and r(x)
    let mut l_0 = Vec::with_capacity(nm);
    let mut l_1 = Vec::with_capacity(nm);
    let mut r_0 = Vec::with_capacity(nm);
    let mut r_1 = Vec::with_capacity(nm);
    // compute l_0 and l_1
    for i in 0..a_L.len() {
        // l_0[i] <- a_L[i] - z
        let mut l_0_i = a_L[i];
        l_0_i.sub_assign(&z);
        l_0.push(l_0_i);
        // l_1[i] <- s_L[i]
        l_1.push(s_L[i]);
    }
    // compute r_0 and r_1
    for i in 0..a_R.len() {
        // r_0[i] <- y_nm[i] * (a_R[i] + z) + z^2*z_m[i//n]*two_n[i%n]
        let mut r_0_i = a_R[i];
        r_0_i.add_assign(&z);
        r_0_i.mul_assign(&y_nm[i]);
        let j = i / (usize::from(n));
        let mut z_jz_2_2_n = z_m[j];
        let two_i = two_n[i % (usize::from(n))];
        z_jz_2_2_n.mul_assign(&z_sq);
        z_jz_2_2_n.mul_assign(&two_i);
        r_0_i.add_assign(&z_jz_2_2_n);
        r_0.push(r_0_i);

        // r_1[i] <- y_nm[i] * s_R[i]
        let mut r_1_i = y_nm[i];
        r_1_i.mul_assign(&s_R[i]);
        r_1.push(r_1_i);
    }

    // Part 3: Computation of polynomial t(x) = <l(x),r(x)>
    // coefficients of polynomials t_j(x)
    let mut t_0 = Vec::with_capacity(usize::from(m));
    let mut t_1 = Vec::with_capacity(usize::from(m));
    let mut t_2 = Vec::with_capacity(usize::from(m));
    // blinding factors for upper coefficients of t_j(x)
    let mut t_1_tilde = Vec::with_capacity(usize::from(m));
    let mut t_2_tilde = Vec::with_capacity(usize::from(m));

    // for each t_j(x)
    for j in 0..usize::from(m) {
        let n = usize::from(n);
        // compute coefficients of t_j(x)
        // t_0,j <- <l_{0,j},r_{0,j}>
        let t_0_j = inner_product(&l_0[j * n..(j + 1) * n], &r_0[j * n..(j + 1) * n]);
        // t_2,j <- <l_{1,j},r_{1,j}>
        let t_2_j = inner_product(&l_1[j * n..(j + 1) * n], &r_1[j * n..(j + 1) * n]);
        // t_1,j <- <l_{0,j}+l_{1,j},r_{0,j}+r_{1,j}> - t_0,j - t_2,j
        let mut t_1_j: C::Scalar = C::Scalar::zero();
        for i in 0..n {
            let mut l_0_j_l_1_j = l_0[j * n + i];
            l_0_j_l_1_j.add_assign(&l_1[j * n + i]);
            let mut r_0_j_r_1_j = r_0[j * n + i];
            r_0_j_r_1_j.add_assign(&r_1[j * n + i]);
            let mut prod = l_0_j_l_1_j;
            prod.mul_assign(&r_0_j_r_1_j);
            t_1_j.add_assign(&prod);
        }
        t_1_j.sub_assign(&t_0_j);
        t_1_j.sub_assign(&t_2_j);

        t_0.push(t_0_j);
        t_1.push(t_1_j);
        t_2.push(t_2_j);

        // compute blinding factors
        let t_1_j_tilde = Randomness::<C>::generate(csprng);
        let t_2_j_tilde = Randomness::<C>::generate(csprng);
        t_1_tilde.push(t_1_j_tilde);
        t_2_tilde.push(t_2_j_tilde);
    }

    // compute commitments T_1 and T_2 for upper coefficents
    let mut t_1_sum = C::Scalar::zero();
    let mut t_1_tilde_sum = C::Scalar::zero();
    let mut t_2_sum = C::Scalar::zero();
    let mut t_2_tilde_sum = C::Scalar::zero();
    for i in 0..t_1.len() {
        t_1_sum.add_assign(&t_1[i]);
        t_1_tilde_sum.add_assign(&t_1_tilde[i]);
        t_2_sum.add_assign(&t_2[i]);
        t_2_tilde_sum.add_assign(&t_2_tilde[i]);
    }
    let T_1 = B
        .mul_by_scalar(&t_1_sum)
        .plus_point(&B_tilde.mul_by_scalar(&t_1_tilde_sum));
    let T_2 = B
        .mul_by_scalar(&t_2_sum)
        .plus_point(&B_tilde.mul_by_scalar(&t_2_tilde_sum));
    // append T1, T2 commitments to transcript
    transcript.append_message(b"T1", &T_1);
    transcript.append_message(b"T2", &T_2);

    // Part 4: Evaluate l(x), r(x), and t(x) at challenge point x
    // get challenge x from transcript
    let x: C::Scalar = transcript.challenge_scalar::<C, _>(b"x");
    // println!("prover's x = {:?}", x);
    let mut x2 = x;
    x2.mul_assign(&x);
    let mut l: Vec<C::Scalar> = Vec::with_capacity(nm);
    let mut r: Vec<C::Scalar> = Vec::with_capacity(nm);

    // evalute l(x) and r(x)
    for i in 0..nm {
        // l[i] <- l_0[i] + x* l_1[i]
        let mut l_i = l_1[i];
        l_i.mul_assign(&x);
        l_i.add_assign(&l_0[i]);
        // r[i] = r_0[i] + x* r_1[i]
        let mut r_i = r_1[i];
        r_i.mul_assign(&x);
        r_i.add_assign(&r_0[i]);
        l.push(l_i);
        r.push(r_i);
    }

    // evaluate t(x) at challenge point x,
    // compute blinding factor tx_tilde for t(x) evaluation committment,
    // and compute bilding factor e_tilde for the inner product committment
    let mut tx: C::Scalar = C::Scalar::zero();
    let mut tx_tilde: C::Scalar = C::Scalar::zero();
    let mut e_tilde: C::Scalar = C::Scalar::zero();
    for j in 0..usize::from(m) {
        // Around 1 ms
        // tx_j <- t_0[j] + t_1[j]*x + t_2[j]*x^2
        let mut t1jx = t_1[j];
        t1jx.mul_assign(&x);
        let mut t2jx2 = t_2[j];
        t2jx2.mul_assign(&x2);
        let mut tjx = t_0[j];
        tjx.add_assign(&t1jx);
        tjx.add_assign(&t2jx2);
        tx.add_assign(&tjx);

        // tx_j_tilde <- z^2*z_j*v_j_tilde + t_1_j_tilde*x + t_2_j_tilde*x^2
        let mut z2vj_tilde = z_sq;
        z2vj_tilde.mul_assign(&z_m[j]); // This line is MISSING in the Bulletproof documentation (https://doc-internal.dalek.rs/bulletproofs/range_proof/index.html), but shows in https://doc-internal.dalek.rs/bulletproofs/notes/range_proof/index.html
        z2vj_tilde.mul_assign(&v_tilde_vec[j]);
        let mut xt1j_tilde = x;
        xt1j_tilde.mul_assign(&t_1_tilde[j]);
        let mut x2t2j_tilde = x2;
        x2t2j_tilde.mul_assign(&t_2_tilde[j]);
        let mut txj_tilde = z2vj_tilde;
        txj_tilde.add_assign(&xt1j_tilde);
        txj_tilde.add_assign(&x2t2j_tilde);
        tx_tilde.add_assign(&txj_tilde);

        // e_tilde_j <- a_tilde_j + s_tilde_j * x
        let mut ej_tilde = x;
        ej_tilde.mul_assign(&s_tilde_vec[j]);
        ej_tilde.add_assign(&a_tilde_vec[j]);
        e_tilde.add_assign(&ej_tilde);
    }
    // append tx, tx_tilde, e_tilde to transcript
    transcript.append_message(b"tx", &tx);
    transcript.append_message(b"tx_tilde", &tx_tilde);
    transcript.append_message(b"e_tilde", &e_tilde);

    // Part 5: Inner product proof for t(x) = <l(x),r(x)>
    // get challenge w from transcript
    let w: C::Scalar = transcript.challenge_scalar::<C, _>(b"w");
    // get generator q
    let Q = B.mul_by_scalar(&w);

    // let mut H_prime : Vec<C> = Vec::with_capacity(nm);
    // compute scalars such that c*H = H', that is H_prime_scalars = (1, y^-1,
    // \dots, y^-(nm-1))
    let mut H_prime_scalars: Vec<C::Scalar> = Vec::with_capacity(nm);
    let y_inv = match y.inverse() {
        Some(inv) => inv,
        None => return None,
    };
    let mut y_inv_i = C::Scalar::one();
    for _i in 0..nm {
        // H_prime.push(H[i].mul_by_scalar(&y_inv_i));
        H_prime_scalars.push(y_inv_i);
        y_inv_i.mul_assign(&y_inv);
    }
    // compute inner product proof
    let proof = prove_inner_product_with_scalars(transcript, &G, &H, &H_prime_scalars, &Q, &l, &r);

    // return range proof
    if let Some(ip_proof) = proof {
        return Some(RangeProof {
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
    None
}

/// The verifier does two checks. In case verification fails, it can be useful
/// to know which of the checks led to failure.
#[derive(Debug, PartialEq)]
pub enum VerificationError {
    /// Choice of randomness led to verification failure.
    DivisionError,
    /// The first check failed (see function below for what this means)
    First,
    /// The second check failed.
    Second,
    /// The length of G_H was less than nm, which is too small
    NotEnoughGenerators,
}

/// This function verifies a range proof, i.e. a proof of knowledge
/// of value v_1, v_2, ..., v_m that are all in [0, 2^n) that are consistent
/// with commitments V_i to v_i. The arguments are
/// - n - the number n such that each v_i is claimed to be in [0, 2^n) by the
///   prover
/// - commitments - commitments V_i to each v_i
/// - proof - the range proof
/// - gens - generators containing vectors G and H both of length nm
/// - v_keys - commitment keys B and B_tilde
///
/// This function is more efficient than the naive_verify since it
/// unfolds what the inner product proof verifier does using the verification
/// scalars.
#[allow(non_snake_case)]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::many_single_char_names)]
pub fn verify_efficient<C: Curve>(
    transcript: &mut RandomOracle,
    n: u8,
    commitments: &[Commitment<C>],
    proof: &RangeProof<C>,
    gens: &Generators<C>,
    v_keys: &CommitmentKey<C>,
) -> Result<(), VerificationError> {
    // Part 1: Setup
    let m = commitments.len();
    let nm = usize::from(n) * m;
    // Check that we have enough generators for vector commitments
    if gens.G_H.len() < nm {
        return Err(VerificationError::NotEnoughGenerators);
    }
    // Select generators G, H, B, B_tilde
    let (G, H): (Vec<_>, Vec<_>) = gens.G_H.iter().take(nm).cloned().unzip();
    let B = v_keys.g;
    let B_tilde = v_keys.h;
    // append commitment V_j to transcript!
    for V in commitments {
        transcript.append_message(b"Vj", &V.0);
    }
    // define the commitments A,S,T_1,T_2
    let A = proof.A;
    let S = proof.S;
    let T_1 = proof.T_1;
    let T_2 = proof.T_2;
    // define polynomial evaluation value
    let tx = proof.tx;
    // define blinding factors for tx and i.p. proof
    let tx_tilde = proof.tx_tilde;
    let e_tilde = proof.e_tilde;
    // append commitments A and S to transcript
    transcript.append_message(b"A", &A);
    transcript.append_message(b"S", &S);
    // get challenges y,z from transcript
    let y: C::Scalar = transcript.challenge_scalar::<C, _>(b"y");
    let z: C::Scalar = transcript.challenge_scalar::<C, _>(b"z");
    let mut z2 = z;
    z2.mul_assign(&z);
    let mut z3 = z2;
    z3.mul_assign(&z);
    // append T1, T2 commitments to transcript
    transcript.append_message(b"T1", &T_1);
    transcript.append_message(b"T2", &T_2);
    // get challenge x (evaluation point) from transcript
    let x: C::Scalar = transcript.challenge_scalar::<C, _>(b"x");
    let mut x2 = x;
    x2.mul_assign(&x);
    // println!("verifier's x = {:?}", x);
    // append tx, tx_tilde, e_tilde to transcript
    transcript.append_message(b"tx", &tx);
    transcript.append_message(b"tx_tilde", &tx_tilde);
    transcript.append_message(b"e_tilde", &e_tilde);
    // get challenge w from transcript
    let w: C::Scalar = transcript.challenge_scalar::<C, _>(b"w");

    // Part 2: Check verification equation 1
    // Calculate delta(x,y) <- (z-z^2)*<1,y_nm> -  <1,2_nm> * sum_j=0^m-1 z^(j+3)
    // ip_1_y_nm <- <1,y_nm>
    let mut ip_1_y_nm = C::Scalar::zero();
    let mut yi = C::Scalar::one();
    for _ in 0..G.len() {
        ip_1_y_nm.add_assign(&yi);
        yi.mul_assign(&y);
    }
    // ip_1_2_n <- <1,2_nm>
    let mut ip_1_2_n = C::Scalar::zero();
    let mut two_i = C::Scalar::one();
    for _ in 0..usize::from(n) {
        ip_1_2_n.add_assign(&two_i);
        two_i.double();
    }
    let mut sum = C::Scalar::zero();
    let mut zj3 = z3;
    for _ in 0..m {
        sum.add_assign(&zj3);
        zj3.mul_assign(&z);
    }
    sum.mul_assign(&ip_1_2_n);
    let mut delta_yz = z;
    delta_yz.sub_assign(&z2);
    delta_yz.mul_assign(&ip_1_y_nm);
    delta_yz.sub_assign(&sum);

    // eq1 LHS  <- t_x*B + t_tilde(x)*B_tilde
    let LHS = B
        .mul_by_scalar(&tx)
        .plus_point(&B_tilde.mul_by_scalar(&tx_tilde));

    // eq2 RHS <- sum_j=0^m-1 z^(j+2)*V_j + delta(x,y)*B + x*T_1 + x^2*T_2
    let mut RHS = {
        let mut zj2 = z2;
        let mut powers = Vec::with_capacity(m);
        for _ in 0..m {
            powers.push(zj2);
            zj2.mul_assign(&z);
        }
        // sum_j=0^m-1 z^(j+2)*V_j
        multiexp::<C, Commitment<C>>(commitments, &powers)
    };
    RHS = RHS.plus_point(&multiexp(&[B, T_1, T_2], &[delta_yz, x, x2]));

    // LHS - RHS ?= 0
    let first = LHS.minus_point(&RHS).is_zero_point();
    if !first {
        // Terminate early to avoid wasted effort.
        return Err(VerificationError::First);
    }

    // Part 2: Check verification equation 2
    //
    // Equation 2 is of the form: scalar_G * G + scalar_H * H + ...
    //
    // Thus:
    // 1) Compute all scalars
    // 2) Multiexponentiation to comptue the summands
    // 3) Check that the sum is zero
    //
    let ip_proof = &proof.ip_proof;
    // compute vectors u^2,u^-2,s
    let verification_scalars = verify_scalars(transcript, G.len(), ip_proof);
    if verification_scalars.is_none() {
        return Err(VerificationError::DivisionError);
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
    // (z^2,...,z^(m+2-1))
    let z_2_m = z_vec(z, 2, m);
    // (s_0^-1,s_1^-1,...)
    let mut s_inv = s;
    s_inv.reverse(); // the inverses of s is the reversed list
                     // (1,2,...,2^(n-1))
    let two_n: Vec<C::Scalar> = two_n_vec(n);

    // compute scalar H_scalars[j] <- z+y^-j*(z^(2+j//n)*2^(j%n)-b*s_j^-1)
    let mut H_scalars: Vec<C::Scalar> = Vec::with_capacity(G.len());
    let mut y_i = C::Scalar::one();
    let y_inv = match y.inverse() {
        Some(inv) => inv,
        None => return Err(VerificationError::DivisionError),
    };
    for i in 0..G.len() {
        let j = i / usize::from(n);
        let mut H_scalar = two_n[i % usize::from(n)];
        H_scalar.mul_assign(&z_2_m[j]);
        let mut bs_inv = b;
        bs_inv.mul_assign(&s_inv[i]);
        H_scalar.sub_assign(&bs_inv);
        H_scalar.mul_assign(&y_i);
        y_i.mul_assign(&y_inv);
        H_scalar.add_assign(&z);
        H_scalars.push(H_scalar);
    }
    // compute H_term
    let H_term = multiexp(&H, &H_scalars); // Expensive!

    // compute L,R, A, and S terms
    let A_term = A;
    let S_term = S.mul_by_scalar(&x);
    let L_term = multiexp(&L, &u_sq); // Expensive!
    let R_term = multiexp(&R, &u_inv_sq); // Expensive!

    // compute B_scalar <- w*(t_x-ab)
    let mut B_scalar = tx;
    let mut ab = a;
    ab.mul_assign(&b);
    B_scalar.sub_assign(&ab);
    B_scalar.mul_assign(&w);
    // compute B term
    let B_term = B.mul_by_scalar(&B_scalar);

    // compute B_tilde_scalar <- -e_tilde
    let mut minus_e_tilde = e_tilde;
    minus_e_tilde.negate();
    let B_tilde_scalar = minus_e_tilde;
    // compute B_tilde term
    let B_tilde_term = B_tilde.mul_by_scalar(&B_tilde_scalar);

    // compute G_scalar[i] <- -z-a*s_i
    let mut G_scalars = Vec::with_capacity(G.len());
    s_inv.reverse();
    let s = s_inv;
    for si in s {
        let mut G_scalar = z;
        G_scalar.negate();
        let mut sa = si;
        sa.mul_assign(&a);
        G_scalar.sub_assign(&sa);
        G_scalars.push(G_scalar);
    }
    // compute G_term
    let G_term = multiexp(&G, &G_scalars); // Expensive!

    // compute sum for equation 2
    let sum = A_term
        .plus_point(&S_term)
        .plus_point(&B_term)
        .plus_point(&B_tilde_term)
        .plus_point(&G_term)
        .plus_point(&H_term)
        .plus_point(&L_term)
        .plus_point(&R_term);
    // sum ?= 0
    let second = sum.is_zero_point();
    if first && second {
        Ok(())
    } else {
        // We know now the second check failed since we would have terminated
        // early if the first one had failed.
        Err(VerificationError::Second)
    }
}

/// For proving that a <= b for integers a,b
/// It is assumed that a,b \in [0, 2^n)
#[allow(clippy::too_many_arguments)]
pub fn prove_less_than_or_equal<C: Curve, T: Rng>(
    transcript: &mut RandomOracle,
    csprng: &mut T,
    n: u8,
    a: u64,
    b: u64,
    gens: &Generators<C>,
    key: &CommitmentKey<C>,
    randomness_a: &Randomness<C>,
    randomness_b: &Randomness<C>,
) -> Option<RangeProof<C>> {
    let mut randomness = **randomness_b;
    randomness.sub_assign(randomness_a);
    prove(transcript, csprng, n, 2, &[b - a, a], gens, key, &[
        Randomness::new(randomness),
        Randomness::new(**randomness_a),
    ])
}

/// Given commitments to a and b, verify that a <= b
/// It is assumed that b \in [0, 2^n),
/// but it should follow that a \in [0, 2^n) if the
/// proof verifies.
pub fn verify_less_than_or_equal<C: Curve>(
    transcript: &mut RandomOracle,
    n: u8,
    commitment_a: &Commitment<C>,
    commitment_b: &Commitment<C>,
    proof: &RangeProof<C>,
    gens: &Generators<C>,
    key: &CommitmentKey<C>,
) -> bool {
    let commitment = Commitment(commitment_b.0.minus_point(&commitment_a.0));
    verify_efficient(
        transcript,
        n,
        &[commitment, *commitment_a],
        proof,
        gens,
        key,
    )
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::G1;

    /// This function produces a proof that will satisfy the verifier's first
    /// check, even if the values are not in the interval.
    /// The second check will fail.
    /// This is tested by checking if the verifier returns
    /// Err(Err(VerificationError::Second))
    type SomeCurve = G1;
    #[allow(non_snake_case)]
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::many_single_char_names)]
    fn cheat_prove<C: Curve, T: Rng>(
        n: u8,
        m: u8,
        v_vec: Vec<u64>,
        G: Vec<C>,
        H: Vec<C>,
        B: C,
        B_tilde: C,
        csprng: &mut T,
        transcript: &mut RandomOracle,
    ) -> (Vec<Commitment<C>>, Option<RangeProof<C>>) {
        let nm = (usize::from(n)) * (usize::from(m));
        let v_copy = v_vec.clone();
        let mut V_vec: Vec<Commitment<C>> = Vec::with_capacity(usize::from(m));
        let mut v_tilde_vec: Vec<C::Scalar> = Vec::with_capacity(usize::from(m));
        let v_keys = CommitmentKey { g: B, h: B_tilde };
        for v in v_vec {
            let v_scalar = C::scalar_from_u64(v);
            let v_value = Value::<C>::new(v_scalar);
            let v_j_tilde = Randomness::<C>::generate(csprng);
            v_tilde_vec.push(*v_j_tilde);
            let V_j = v_keys.hide(&v_value, &v_j_tilde);
            transcript.append_message(b"Vj", &V_j.0);
            V_vec.push(V_j);
        }
        let A = C::zero_point();
        let S = C::zero_point();
        transcript.append_message(b"A", &A);
        transcript.append_message(b"S", &S);
        let y: C::Scalar = transcript.challenge_scalar::<C, _>(b"y");
        let z: C::Scalar = transcript.challenge_scalar::<C, _>(b"z");
        let z_m = z_vec(z, 0, usize::from(m));

        // z squared
        let z_sq = if z_m.len() > 2 {
            z_m[2]
        } else {
            let mut z_sq = z;
            z_sq.mul_assign(&z);
            z_sq
        };

        let T_1 = C::zero_point();
        let T_2 = C::zero_point();

        let mut tx: C::Scalar = C::Scalar::zero();
        let mut tx_tilde: C::Scalar = C::Scalar::zero();
        let e_tilde: C::Scalar = C::Scalar::zero();
        transcript.append_message(b"T1", &T_1);
        transcript.append_message(b"T2", &T_2);
        let _x: C::Scalar = transcript.challenge_scalar::<C, _>(b"x");
        // println!("Cheating prover's x = {}", x);
        for j in 0..usize::from(m) {
            // tx:
            let mut z2vj = z_sq;
            z2vj.mul_assign(&z_m[j]); // This line is MISSING in the Bulletproof documentation
            let v_value = C::scalar_from_u64(v_copy[j]);
            z2vj.mul_assign(&v_value);
            let tjx = z2vj;
            tx.add_assign(&tjx);

            // tx tilde:
            let mut z2vj_tilde = z_sq;
            z2vj_tilde.mul_assign(&z_m[j]); // This line is MISSING in the Bulletproof documentation
            z2vj_tilde.mul_assign(&v_tilde_vec[j]);
            let txj_tilde = z2vj_tilde;
            tx_tilde.add_assign(&txj_tilde);
        }
        // delta:
        let mut ip_1_y_nm = C::Scalar::zero();
        let mut yi = C::Scalar::one();
        for _ in 0..G.len() {
            ip_1_y_nm.add_assign(&yi);
            yi.mul_assign(&y);
        }
        let mut ip_1_2_n = C::Scalar::zero();
        let mut two_i = C::Scalar::one();
        for _ in 0..usize::from(n) {
            ip_1_2_n.add_assign(&two_i);
            two_i.double();
        }
        let mut sum = C::Scalar::zero();
        let mut zj3 = if z_m.len() > 3 {
            z_m[3]
        } else {
            let mut zj3 = z_sq;
            zj3.mul_assign(&z);
            zj3
        };
        for _ in 0..m {
            sum.add_assign(&zj3);
            zj3.mul_assign(&z);
        }
        sum.mul_assign(&ip_1_2_n);
        let mut delta_yz = z;
        delta_yz.sub_assign(&z_sq);
        delta_yz.mul_assign(&ip_1_y_nm);
        delta_yz.sub_assign(&sum);
        tx.add_assign(&delta_yz);

        let proof = prove_inner_product(
            transcript,
            &G,
            &H,
            &C::zero_point(),
            &vec![C::Scalar::zero(); nm],
            &vec![C::Scalar::zero(); nm],
        );

        #[allow(clippy::manual_map)]
        let rangeproof = match proof {
            Some(ip_proof) => Some(RangeProof {
                A,
                S,
                T_1,
                T_2,
                tx,
                tx_tilde,
                e_tilde,
                ip_proof,
            }),
            _ => None,
        };
        (V_vec, rangeproof)
    }

    /// This function verifies a range proof, i.e. a proof of knowledge
    /// of values v_1, v_2, ..., v_m that are all in [0, 2^n) that are
    /// consistent with commitments V_i to v_i. The arguments are
    /// - n - the number n such that each v_i is claimed to be in [0, 2^n) by
    ///   the prover
    /// - commitments - commitments V_i to each v_i
    /// - gens - generators containing vectors G and H both of length nm
    /// - v_keys - commitmentment keys B and B_tilde
    /// It uses the inner product proof verifier.
    #[allow(non_snake_case)]
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::many_single_char_names)]
    fn naive_verify<C: Curve>(
        transcript: &mut RandomOracle,
        n: u8,
        commitments: &[Commitment<C>],
        proof: &RangeProof<C>,
        gens: &Generators<C>,
        v_keys: &CommitmentKey<C>,
    ) -> bool {
        let (G, H): (Vec<_>, Vec<_>) = gens.G_H.iter().cloned().unzip();
        let B = v_keys.g;
        let B_tilde = v_keys.h;
        let m = commitments.len();
        for V in commitments {
            transcript.append_message(b"Vj", &V.0);
        }
        let A = proof.A;
        let S = proof.S;
        let T_1 = proof.T_1;
        let T_2 = proof.T_2;
        let tx = proof.tx;
        let tx_tilde = proof.tx_tilde;
        let e_tilde = proof.e_tilde;
        transcript.append_message(b"A", &A);
        transcript.append_message(b"S", &S);
        let y: C::Scalar = transcript.challenge_scalar::<C, _>(b"y");
        let z: C::Scalar = transcript.challenge_scalar::<C, _>(b"z");
        let mut z2 = z;
        z2.mul_assign(&z);
        let mut z3 = z2;
        z3.mul_assign(&z);
        transcript.append_message(b"T1", &T_1);
        transcript.append_message(b"T2", &T_2);
        let x: C::Scalar = transcript.challenge_scalar::<C, _>(b"x");
        let mut x2 = x;
        x2.mul_assign(&x);
        // println!("verifier's x = {:?}", x);
        transcript.append_message(b"tx", &tx);
        transcript.append_message(b"tx_tilde", &tx_tilde);
        transcript.append_message(b"e_tilde", &e_tilde);
        let w: C::Scalar = transcript.challenge_scalar::<C, _>(b"w");
        // Calculate delta(x,y):
        let mut ip_1_y_nm = C::Scalar::zero();
        let mut yi = C::Scalar::one();
        for _ in 0..G.len() {
            ip_1_y_nm.add_assign(&yi);
            yi.mul_assign(&y);
        }
        let mut ip_1_2_n = C::Scalar::zero();
        let mut two_i = C::Scalar::one();
        for _ in 0..usize::from(n) {
            ip_1_2_n.add_assign(&two_i);
            two_i.double();
        }
        let mut sum = C::Scalar::zero();
        let mut zj3 = z3;
        for _ in 0..m {
            sum.add_assign(&zj3);
            zj3.mul_assign(&z);
        }
        sum.mul_assign(&ip_1_2_n);
        let mut delta_yz = z;
        delta_yz.sub_assign(&z2);
        delta_yz.mul_assign(&ip_1_y_nm);
        delta_yz.sub_assign(&sum);

        // LHS of check equation 1:
        let LHS = B
            .mul_by_scalar(&tx)
            .plus_point(&B_tilde.mul_by_scalar(&tx_tilde));
        let mut RHS = C::zero_point();
        let mut zj2 = z2;
        for com in commitments {
            let Vj = com.0;
            // println!("V_{:?} = {:?}", j, Vj);
            RHS = RHS.plus_point(&Vj.mul_by_scalar(&zj2));
            zj2.mul_assign(&z);
        }
        RHS = RHS
            .plus_point(&B.mul_by_scalar(&delta_yz))
            .plus_point(&T_1.mul_by_scalar(&x))
            .plus_point(&T_2.mul_by_scalar(&x2));

        // println!("--------------- VERIFICATION ----------------");
        // println!("LHS = {:?}", LHS);
        // println!("RHS = {:?}", RHS);
        // println!("Are they equal? {:?}", LHS == RHS);
        let first = LHS.minus_point(&RHS).is_zero_point();
        if !first {
            return false;
        }
        // println!("First check = {:?}", first);

        let ip_proof = &proof.ip_proof;
        let mut z_2_nm: Vec<C::Scalar> = Vec::with_capacity(G.len());
        let mut y_i = C::Scalar::one();
        let z_2_m = z_vec(z, 2, m);
        let y_inv = match y.inverse() {
            Some(inv) => inv,
            None => return false,
        };
        let two_n: Vec<C::Scalar> = two_n_vec(n);
        for i in 0..G.len() {
            let j = i / usize::from(n);
            let mut prod = two_n[i % usize::from(n)];
            prod.mul_assign(&z_2_m[j]);
            prod.mul_assign(&y_i);
            y_i.mul_assign(&y_inv);
            z_2_nm.push(prod);
        }
        let one = C::Scalar::one();
        let ip1z = multiexp(&G, &vec![one; G.len()]).mul_by_scalar(&z);
        let ip2z = multiexp(&H, &vec![one; H.len()]).mul_by_scalar(&z);
        // println!("len = {}", H.len());
        let ip3 = multiexp(&H, &z_2_nm); // Expensive!
        let P = A
            .plus_point(&S.mul_by_scalar(&x))
            .minus_point(&B_tilde.mul_by_scalar(&e_tilde))
            .minus_point(&ip1z)
            .plus_point(&ip2z)
            .plus_point(&ip3);
        let mut txw = tx;
        txw.mul_assign(&w);
        let Q = B.mul_by_scalar(&w);
        let P_prime = P.plus_point(&Q.mul_by_scalar(&tx));
        // let (u_sq, u_inv_sq, s) = verify_scalars(transcript, usize::from(n),
        // ip_proof);
        let mut H_prime: Vec<C> = Vec::with_capacity(m * usize::from(n));
        let y_inv = match y.inverse() {
            Some(inv) => inv,
            None => return false,
        };
        let mut y_inv_i = C::Scalar::one();
        for x in H {
            H_prime.push(x.mul_by_scalar(&y_inv_i)); // Expensive!
            y_inv_i.mul_assign(&y_inv);
        }

        // println!("Verifier's P' = {:?}", P_prime);
        let second: bool = verify_inner_product(transcript, &G, &H_prime, &P_prime, &Q, ip_proof); // Very expensive
        second
    }

    /// This function does the same as verify_efficient. It groups
    /// some of the verification checks a bit more and could be more efficient,
    /// but it seems in practice that the difference in efficieny is small.
    #[allow(non_snake_case)]
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::many_single_char_names)]
    pub fn verify_more_efficient<C: Curve>(
        transcript: &mut RandomOracle,
        n: u8,
        commitments: &[Commitment<C>],
        proof: &RangeProof<C>,
        gens: &Generators<C>,
        v_keys: &CommitmentKey<C>,
    ) -> bool {
        let (G, H): (Vec<_>, Vec<_>) = gens.G_H.iter().cloned().unzip();
        let B = v_keys.g;
        let B_tilde = v_keys.h;
        let m = commitments.len();
        for V in commitments {
            transcript.append_message(b"Vj", &V.0);
        }
        let A = proof.A;
        let S = proof.S;
        let T_1 = proof.T_1;
        let T_2 = proof.T_2;
        let tx = proof.tx;
        let tx_tilde = proof.tx_tilde;
        let e_tilde = proof.e_tilde;
        transcript.append_message(b"A", &A);
        transcript.append_message(b"S", &S);
        let y: C::Scalar = transcript.challenge_scalar::<C, _>(b"y");
        let z: C::Scalar = transcript.challenge_scalar::<C, _>(b"z");
        let mut z2 = z;
        z2.mul_assign(&z);
        let mut z3 = z2;
        z3.mul_assign(&z);
        transcript.append_message(b"T1", &T_1);
        transcript.append_message(b"T2", &T_2);
        let x: C::Scalar = transcript.challenge_scalar::<C, _>(b"x");
        let mut x2 = x;
        x2.mul_assign(&x);
        // println!("verifier's x = {:?}", x);
        transcript.append_message(b"tx", &tx);
        transcript.append_message(b"tx_tilde", &tx_tilde);
        transcript.append_message(b"e_tilde", &e_tilde);
        let w: C::Scalar = transcript.challenge_scalar::<C, _>(b"w");
        // Calculate delta(x,y):
        let mut ip_1_y_nm = C::Scalar::zero();
        let mut yi = C::Scalar::one();
        for _ in 0..G.len() {
            ip_1_y_nm.add_assign(&yi);
            yi.mul_assign(&y);
        }
        let mut ip_1_2_n = C::Scalar::zero();
        let mut two_i = C::Scalar::one();
        for _ in 0..usize::from(n) {
            ip_1_2_n.add_assign(&two_i);
            two_i.double();
        }
        let mut sum = C::Scalar::zero();
        let mut zj3 = z3;
        for _ in 0..m {
            sum.add_assign(&zj3);
            zj3.mul_assign(&z);
        }
        sum.mul_assign(&ip_1_2_n);
        let mut delta_yz = z;
        delta_yz.sub_assign(&z2);
        delta_yz.mul_assign(&ip_1_y_nm);
        delta_yz.sub_assign(&sum);
        // println!("--------------- VERIFICATION ----------------");

        let ip_proof = &proof.ip_proof;
        let mut H_scalars: Vec<C::Scalar> = Vec::with_capacity(G.len());
        let mut y_i = C::Scalar::one();
        let z_2_m = z_vec(z, 2, m);
        let verification_scalars = verify_scalars(transcript, G.len(), ip_proof);
        if verification_scalars.is_none() {
            return false;
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
            None => return false,
        };
        let two_n: Vec<C::Scalar> = two_n_vec(n);
        for i in 0..G.len() {
            let j = i / usize::from(n);
            let mut H_scalar = two_n[i % usize::from(n)];
            H_scalar.mul_assign(&z_2_m[j]);
            let mut bs_inv = b;
            bs_inv.mul_assign(&s_inv[i]);
            H_scalar.sub_assign(&bs_inv);
            H_scalar.mul_assign(&y_i);
            y_i.mul_assign(&y_inv);
            H_scalar.add_assign(&z);
            H_scalars.push(H_scalar);
        }
        let A_scalar = C::Scalar::one();
        let S_scalar = x;
        let c = w; // TODO: Shuld be generated randomly
        let mut T_1_scalar = c;
        T_1_scalar.mul_assign(&x);
        let mut T_2_scalar = T_1_scalar;
        T_2_scalar.mul_assign(&x);

        let mut V_scalars = Vec::with_capacity(m);
        let mut cz_i = c;
        cz_i.mul_assign(&z);
        cz_i.mul_assign(&z);
        for _ in 0..m {
            V_scalars.push(cz_i);
            cz_i.mul_assign(&z);
        }

        let mut B_scalar = tx;
        let mut ab = a;
        ab.mul_assign(&b);
        B_scalar.sub_assign(&ab);
        B_scalar.mul_assign(&w);
        let mut c_delta_minus_tx = delta_yz;
        c_delta_minus_tx.sub_assign(&tx);
        c_delta_minus_tx.mul_assign(&c);
        B_scalar.add_assign(&c_delta_minus_tx);
        let mut minus_e_tilde = e_tilde;
        minus_e_tilde.negate();
        let mut B_tilde_scalar = minus_e_tilde;
        let mut ctx_tilde = tx_tilde;
        ctx_tilde.mul_assign(&c);
        B_tilde_scalar.sub_assign(&ctx_tilde);
        let mut G_scalars = Vec::with_capacity(G.len());
        for si in s {
            let mut G_scalar = z;
            G_scalar.negate();
            let mut sa = si;
            sa.mul_assign(&a);
            G_scalar.sub_assign(&sa);
            G_scalars.push(G_scalar);
        }
        let mut Vjs: Vec<C> = commitments.iter().map(|x| x.0).collect();
        let mut all_scalars = vec![A_scalar];
        all_scalars.push(S_scalar);
        all_scalars.push(T_1_scalar);
        all_scalars.push(T_2_scalar);
        all_scalars.push(B_scalar);
        all_scalars.push(B_tilde_scalar);
        all_scalars.append(&mut V_scalars);
        all_scalars.append(&mut G_scalars);
        all_scalars.append(&mut H_scalars);
        let mut L_scalars = u_sq;
        let mut R_scalars = u_inv_sq;
        all_scalars.append(&mut L_scalars);
        all_scalars.append(&mut R_scalars);
        let mut all_points = vec![A];
        all_points.push(S);
        all_points.push(T_1);
        all_points.push(T_2);
        all_points.push(B);
        all_points.push(B_tilde);
        all_points.append(&mut Vjs);
        all_points.extend_from_slice(&G);
        all_points.extend_from_slice(&H);
        all_points.extend_from_slice(&L);
        all_points.extend_from_slice(&R);

        let sum2 = multiexp(&all_points, &all_scalars);

        let b: bool = sum2.is_zero_point();
        b
    }

    #[allow(non_snake_case)]
    #[test]
    fn test_prove() {
        // Test for nm = 512
        let rng = &mut thread_rng();
        let n = 32;
        let m = 16u8;
        let nm = (usize::from(n)) * (usize::from(m));
        let mut G = Vec::with_capacity(nm);
        let mut H = Vec::with_capacity(nm);
        let mut G_H = Vec::with_capacity(nm);
        let mut randomness = Vec::with_capacity(usize::from(m));
        let mut commitments = Vec::with_capacity(usize::from(m));

        for _i in 0..(nm) {
            let g = SomeCurve::generate(rng);
            let h = SomeCurve::generate(rng);
            G.push(g);
            H.push(h);
            G_H.push((g, h));
        }

        let gens = Generators { G_H };
        let B = SomeCurve::generate(rng);
        let B_tilde = SomeCurve::generate(rng);
        let keys = CommitmentKey { g: B, h: B_tilde };

        // Some numbers in [0, 2^n):
        let v_vec: Vec<u64> = vec![
            7, 4, 255, 15, 2, 15, 4294967295, 4, 4, 5, 6, 8, 12, 13, 10,
            8, /* ,7,4,15,15,2,15,5,4,4,5,6,8,12,13,10,8
               * ,7,4,15,15,2,15,5,4,4,5,6,8,12,13,10,8
               * ,7,4,15,15,2,15,5,4,4,5,6,8,12,13,10,8
               * ,7,4,15,15,2,15,5,4,4,5,6,8,12,13,10,8
               * ,7,4,15,15,2,15,5,4,4,5,6,8,12,13,10,8
               * ,7,4,15,15,2,15,5,4,4,5,6,8,12,13,10,8
               * ,7,4,15,15,2,15,5,4,4,5,6,8,12,13,10,8 */
        ];

        for &v in v_vec.iter().take(m.into()) {
            let r = Randomness::generate(rng);
            let v_scalar = SomeCurve::scalar_from_u64(v);
            let v_value = Value::<SomeCurve>::new(v_scalar);
            let com = keys.hide(&v_value, &r);
            randomness.push(r);
            commitments.push(com);
        }
        let mut transcript = RandomOracle::empty();
        let proof = prove(
            &mut transcript,
            rng,
            n,
            m,
            &v_vec,
            &gens,
            &keys,
            &randomness,
        );
        assert!(proof.is_some());
        let proof = proof.unwrap();
        let mut transcript = RandomOracle::empty();
        let b1 = naive_verify(&mut transcript, n, &commitments, &proof, &gens, &keys);

        let mut transcript = RandomOracle::empty();
        let b2 = verify_efficient(&mut transcript, n, &commitments, &proof, &gens, &keys);

        // Testing the even more efficient verifier:
        let mut transcript = RandomOracle::empty();
        let b3 = verify_more_efficient(&mut transcript, n, &commitments, &proof, &gens, &keys);
        assert!(b1);
        assert!(b2.is_ok());
        assert!(b3);
    }

    #[allow(non_snake_case)]
    #[test]
    fn test_single_value() {
        // Test for nm = 512
        let rng = &mut thread_rng();
        let n = 32;
        let m = 1;
        let nm = (usize::from(n)) * (usize::from(m));
        let mut G = Vec::with_capacity(nm);
        let mut H = Vec::with_capacity(nm);
        let mut G_H = Vec::with_capacity(nm);
        let mut randomness = Vec::with_capacity(usize::from(m));
        let mut commitments = Vec::with_capacity(usize::from(m));

        for _i in 0..(nm) {
            let g = SomeCurve::generate(rng);
            let h = SomeCurve::generate(rng);
            G.push(g);
            H.push(h);
            G_H.push((g, h));
        }

        let gens = Generators { G_H };
        let B = SomeCurve::generate(rng);
        let B_tilde = SomeCurve::generate(rng);
        let keys = CommitmentKey { g: B, h: B_tilde };

        // Some numbers in [0, 2^n):
        let v_vec: Vec<u64> = vec![
            4294967295, /* , 4, 255, 15, 2, 15, 4294967295, 4, 4, 5, 6, 8, 12, 13, 10,
                        * 8, *//* ,7,4,15,15,2,15,5,4,4,5,6,8,12,13,10,8
                        * ,7,4,15,15,2,15,5,4,4,5,6,8,12,13,10,8
                        * ,7,4,15,15,2,15,5,4,4,5,6,8,12,13,10,8
                        * ,7,4,15,15,2,15,5,4,4,5,6,8,12,13,10,8
                        * ,7,4,15,15,2,15,5,4,4,5,6,8,12,13,10,8
                        * ,7,4,15,15,2,15,5,4,4,5,6,8,12,13,10,8
                        * ,7,4,15,15,2,15,5,4,4,5,6,8,12,13,10,8 */
        ];

        for &v in v_vec.iter().take(m.into()) {
            let r = Randomness::generate(rng);
            let v_scalar = SomeCurve::scalar_from_u64(v);
            let v_value = Value::<SomeCurve>::new(v_scalar);
            let com = keys.hide(&v_value, &r);
            randomness.push(r);
            commitments.push(com);
        }
        let mut transcript = RandomOracle::empty();
        let proof = prove(
            &mut transcript,
            rng,
            n,
            m,
            &v_vec,
            &gens,
            &keys,
            &randomness,
        );
        assert!(proof.is_some());
        let proof = proof.unwrap();
        let mut transcript = RandomOracle::empty();
        let b1 = naive_verify(&mut transcript, n, &commitments, &proof, &gens, &keys);

        let mut transcript = RandomOracle::empty();
        let b2 = verify_efficient(&mut transcript, n, &commitments, &proof, &gens, &keys);

        // Testing the even more efficient verifier:
        let mut transcript = RandomOracle::empty();
        let b3 = verify_more_efficient(&mut transcript, n, &commitments, &proof, &gens, &keys);
        assert!(b1);
        assert!(b2.is_ok());
        assert!(b3);
    }

    #[allow(non_snake_case)]
    #[test]
    fn test_less_than_or_equal_to() {
        // Test for nm = 512
        let rng = &mut thread_rng();
        let n = 16;
        let m = 10u8;
        let nm = (usize::from(n)) * (usize::from(m));
        let mut G = Vec::with_capacity(nm);
        let mut H = Vec::with_capacity(nm);
        let mut G_H = Vec::with_capacity(nm);

        for _i in 0..(nm) {
            let g = SomeCurve::generate(rng);
            let h = SomeCurve::generate(rng);
            G.push(g);
            H.push(h);
            G_H.push((g, h));
        }

        let gens = Generators { G_H };
        let B = SomeCurve::generate(rng);
        let B_tilde = SomeCurve::generate(rng);
        let key = CommitmentKey { g: B, h: B_tilde };

        let a = 499;
        let b = 500;

        let r_a = Randomness::generate(rng);
        let r_b = Randomness::generate(rng);
        let a_scalar = SomeCurve::scalar_from_u64(a);
        let b_scalar = SomeCurve::scalar_from_u64(b);
        let com_a = key.hide_worker(&a_scalar, &r_a);
        let com_b = key.hide_worker(&b_scalar, &r_b);
        let mut transcript = RandomOracle::empty();
        let proof =
            prove_less_than_or_equal(&mut transcript, rng, n, a, b, &gens, &key, &r_a, &r_b)
                .unwrap();
        let mut transcript = RandomOracle::empty();
        assert!(verify_less_than_or_equal(
            &mut transcript,
            n,
            &com_a,
            &com_b,
            &proof,
            &gens,
            &key
        ));
    }

    #[allow(non_snake_case)]
    #[test]
    fn test_cheating_prover() {
        let rng = &mut thread_rng();
        let n = 32;
        let m = 16;
        let nm = (usize::from(n)) * (usize::from(m));
        let mut G = Vec::with_capacity(nm);
        let mut H = Vec::with_capacity(nm);
        let mut G_H = Vec::with_capacity(nm);

        for _i in 0..(nm) {
            let g = SomeCurve::generate(rng);
            let h = SomeCurve::generate(rng);
            G.push(g);
            H.push(h);
            G_H.push((g, h));
        }
        let gens = Generators { G_H };
        let B = SomeCurve::generate(rng);
        let B_tilde = SomeCurve::generate(rng);
        let keys = CommitmentKey { g: B, h: B_tilde };

        // Some numbers in [0, 2^n):
        let v_vec: Vec<u64> = vec![
            7, 4, 255, 15, 2, 15, 4294967295, 4, 4, 5, 6, 8, 12, 13, 10,
            8, /* ,7,4,15,15,2,15,5,4,4,5,6,8,12,13,10,8
               * ,7,4,15,15,2,15,5,4,4,5,6,8,12,13,10,8
               * ,7,4,15,15,2,15,5,4,4,5,6,8,12,13,10,8
               * ,7,4,15,15,2,15,5,4,4,5,6,8,12,13,10,8
               * ,7,4,15,15,2,15,5,4,4,5,6,8,12,13,10,8
               * ,7,4,15,15,2,15,5,4,4,5,6,8,12,13,10,8
               * ,7,4,15,15,2,15,5,4,4,5,6,8,12,13,10,8 */
        ];
        // CHEATING prover:
        let mut transcript = RandomOracle::empty();
        let (commitments, proof) = cheat_prove(
            n,
            m,
            v_vec,
            G.clone(),
            H.clone(),
            B,
            B_tilde,
            rng,
            &mut transcript,
        );
        assert!(proof.is_some());
        let proof = proof.unwrap();
        let mut transcript = RandomOracle::empty();
        let b1 = verify_efficient(&mut transcript, n, &commitments, &proof, &gens, &keys);
        let mut transcript = RandomOracle::empty();
        let b2 = verify_more_efficient(&mut transcript, n, &commitments, &proof, &gens, &keys);
        assert_eq!(
            b1,
            Err(VerificationError::Second),
            "The first check should have succeeded, and the second one failed."
        );
        assert!(!b2);
    }
}
