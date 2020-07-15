use crate::{inner_product_proof::*, transcript::TranscriptProtocol};
use curve_arithmetic::{multiexp, multiexp_table, multiexp_worker_given_table, Curve, Value};
use ff::Field;
use merlin::Transcript;
use pedersen_scheme::*;
use rand::*;
use std::iter::once;

#[allow(non_snake_case)]
#[derive(Clone)]
pub struct RangeProof<C: Curve> {
    A:        C,
    S:        C,
    T_1:      C,
    T_2:      C,
    tx:       C::Scalar,
    tx_tilde: C::Scalar,
    e_tilde:  C::Scalar,
    ip_proof: InnerProductProof<C>,
}

#[allow(non_snake_case)]
fn ith_bit_bool(v: u64, i: u8) -> bool { v & (1 << i) != 0 }

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

/// This function takes one argument n and returns the
/// vector (z^j, z^{j+1}, ..., z^{j+n-1}) in F^n for any field F
/// The arguments are
/// - z - the field element z
/// - first_power - the first power j
/// - n - the integer n
#[allow(non_snake_case)]
fn z_vec<F: Field>(z: F, first_power: usize, n: usize) -> Vec<F> {
    let mut z_n = Vec::with_capacity(usize::from(n));
    let mut z_i = F::one();
    for _ in 0..first_power {
        z_i.mul_assign(&z);
    }
    for _ in 0..n {
        z_n.push(z_i);
        z_i.mul_assign(&z);
    }
    z_n
}

/// Struct containing generators G and H needed for range proofs
#[allow(non_snake_case)]
#[derive(Clone)]
pub struct Generators<C> {
    pub G_H: Vec<(C, C)>,
}

/// This function produces a range proof, i.e. a proof of knowledge
/// of value v_1, v_2, ..., v_m that are all in [0, 2^n) that are consistent
/// with commitments V_i to v_i. The arguments are
/// - n - the number n such that v_i is in [0,2^n) for all i
/// - m - the number of values that is proved to be in [0,2^n)
/// - v_vec - the vector having v_1, ..., v_m as entrances
/// - gens - generators containing vectors G and H both of length nm
/// - v_keys - commitmentment keys B and B_tilde
#[allow(clippy::many_single_char_names)]
#[allow(non_snake_case)]
#[allow(clippy::too_many_arguments)]
pub fn prove<C: Curve, T: Rng>(
    transcript: &mut Transcript,
    csprng: &mut T,
    n: u8,
    m: u8,
    v_vec: &[u64],
    gens: &Generators<C>,
    v_keys: &CommitmentKey<C>,
) -> (Vec<Commitment<C>>, Option<RangeProof<C>>) {
    let (G, H): (Vec<_>, Vec<_>) = gens.G_H.iter().cloned().unzip();
    let B = v_keys.0;
    let B_tilde = v_keys.1;
    let nm = G.len();
    let mut a_L: Vec<C::Scalar> = Vec::with_capacity(usize::from(n));
    let mut a_R: Vec<C::Scalar> = Vec::with_capacity(usize::from(n));
    let mut V_vec: Vec<Commitment<C>> = Vec::with_capacity(usize::from(m));
    let mut s_L = Vec::with_capacity(usize::from(n));
    let mut s_R = Vec::with_capacity(usize::from(n));
    for _ in 0..nm {
        s_L.push(C::generate_scalar(csprng));
        s_R.push(C::generate_scalar(csprng));
    }
    let mut v_tilde_vec: Vec<C::Scalar> = Vec::with_capacity(usize::from(m));
    let mut a_tilde_vec: Vec<C::Scalar> = Vec::with_capacity(usize::from(m));
    let mut s_tilde_vec: Vec<C::Scalar> = Vec::with_capacity(usize::from(m));
    for &v in v_vec {
        let (a_L_j, a_R_j) = a_L_a_R(v, n);
        a_L.extend(&a_L_j);
        a_R.extend(&a_R_j);
        let v_j_tilde = Randomness::<C>::generate(csprng);
        let a_j_tilde = Randomness::<C>::generate(csprng);
        let s_j_tilde = Randomness::<C>::generate(csprng);
        v_tilde_vec.push(*v_j_tilde);
        a_tilde_vec.push(*a_j_tilde);
        s_tilde_vec.push(*s_j_tilde);

        let v_scalar = C::scalar_from_u64(v);
        let v_value = Value::<C>::new(v_scalar);
        let V_j = v_keys.hide(&v_value, &v_j_tilde);
        transcript.append_point(b"Vj", &V_j.0);
        V_vec.push(V_j);
    }
    let mut a_tilde_sum = C::Scalar::zero();
    let mut s_tilde_sum = C::Scalar::zero();
    for i in 0..a_tilde_vec.len() {
        a_tilde_sum.add_assign(&a_tilde_vec[i]);
        s_tilde_sum.add_assign(&s_tilde_vec[i]);
    }
    let A_scalars: Vec<C::Scalar> = a_L
        .iter()
        .chain(a_R.iter())
        .copied()
        .chain(once(a_tilde_sum))
        .collect();
    let S_scalars: Vec<C::Scalar> = s_L
        .iter()
        .chain(s_R.iter())
        .copied()
        .chain(once(s_tilde_sum))
        .collect();
    let GH_B_tilde: Vec<C> = G
        .iter()
        .chain(H.iter())
        .copied()
        .chain(once(B_tilde))
        .collect();
    let window_size = 4;
    let table = multiexp_table(&GH_B_tilde, window_size);
    let A = multiexp_worker_given_table(&A_scalars, &table, window_size);
    let S = multiexp_worker_given_table(&S_scalars, &table, window_size);
    transcript.append_point(b"A", &A);
    transcript.append_point(b"S", &S);
    let y: C::Scalar = transcript.challenge_scalar::<C>(b"y");
    let z: C::Scalar = transcript.challenge_scalar::<C>(b"z");

    let mut l_0 = Vec::with_capacity(nm);
    let mut l_1 = Vec::with_capacity(nm);
    let mut r_0 = Vec::with_capacity(nm);
    let mut r_1 = Vec::with_capacity(nm);
    for i in 0..a_L.len() {
        let mut l_0_i = a_L[i];
        l_0_i.sub_assign(&z);
        l_0.push(l_0_i);
        l_1.push(s_L[i]);
    }

    
    let y_nm = z_vec(y, 0, nm);

    let two_n: Vec<C::Scalar> = two_n_vec(n);

    let z_m = z_vec(z, 0, usize::from(m));

    // r_0 and r_1
    for i in 0..a_R.len() {
        let mut r_0_i = a_R[i];
        r_0_i.add_assign(&z);
        r_0_i.mul_assign(&y_nm[i]);
        let j = i / (usize::from(n));
        let mut z_jz_2_2_n = z_m[j];
        let two_i = two_n[i % (usize::from(n))];
        z_jz_2_2_n.mul_assign(&z_m[2]);
        z_jz_2_2_n.mul_assign(&two_i);
        r_0_i.add_assign(&z_jz_2_2_n);
        r_0.push(r_0_i);

        let mut r_1_i = y_nm[i];
        r_1_i.mul_assign(&s_R[i]);
        r_1.push(r_1_i);
    }

    let mut t_0 = Vec::with_capacity(usize::from(m));
    let mut t_1 = Vec::with_capacity(usize::from(m));
    let mut t_2 = Vec::with_capacity(usize::from(m));
    let mut t_1_tilde = Vec::with_capacity(usize::from(m));
    let mut t_2_tilde = Vec::with_capacity(usize::from(m));

    for j in 0..usize::from(m) {
        let n = usize::from(n);
        let t_0_j = inner_product(&l_0[j * n..(j + 1) * n], &r_0[j * n..(j + 1) * n]);
        let t_2_j = inner_product(&l_1[j * n..(j + 1) * n], &r_1[j * n..(j + 1) * n]);

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

        let t_1_j_tilde = Randomness::<C>::generate(csprng);
        let t_2_j_tilde = Randomness::<C>::generate(csprng);
        t_1_tilde.push(t_1_j_tilde);
        t_2_tilde.push(t_2_j_tilde);
    }

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

    transcript.append_point(b"T1", &T_1);
    transcript.append_point(b"T2", &T_2);
    let x: C::Scalar = transcript.challenge_scalar::<C>(b"x");
    // println!("prover's x = {:?}", x);
    let mut x2 = x;
    x2.mul_assign(&x);
    let mut l: Vec<C::Scalar> = Vec::with_capacity(nm);
    let mut r: Vec<C::Scalar> = Vec::with_capacity(nm);

    for i in 0..nm {
        let mut l_i = l_1[i];
        l_i.mul_assign(&x);
        l_i.add_assign(&l_0[i]);
        let mut r_i = r_1[i];
        r_i.mul_assign(&x);
        r_i.add_assign(&r_0[i]);
        l.push(l_i);
        r.push(r_i);
    }

    let mut tx: C::Scalar = C::Scalar::zero();
    let mut tx_tilde: C::Scalar = C::Scalar::zero();
    let mut e_tilde: C::Scalar = C::Scalar::zero();
    for j in 0..usize::from(m) {
        // Around 1 ms
        // tx:
        let mut t1jx = t_1[j];
        t1jx.mul_assign(&x);
        let mut t2jx2 = t_2[j];
        t2jx2.mul_assign(&x2);
        let mut tjx = t_0[j];
        tjx.add_assign(&t1jx);
        tjx.add_assign(&t2jx2);
        tx.add_assign(&tjx);

        // tx tilde:
        let mut z2vj_tilde = z_m[2];
        z2vj_tilde.mul_assign(&z_m[j]); // This line is MISSING in the Bulletproof documentation
        z2vj_tilde.mul_assign(&v_tilde_vec[j]);
        let mut xt1j_tilde = x;
        xt1j_tilde.mul_assign(&t_1_tilde[j]);
        let mut x2t2j_tilde = x2;
        x2t2j_tilde.mul_assign(&t_2_tilde[j]);
        let mut txj_tilde = z2vj_tilde;
        txj_tilde.add_assign(&xt1j_tilde);
        txj_tilde.add_assign(&x2t2j_tilde);
        tx_tilde.add_assign(&txj_tilde);

        // e tilde:
        let mut ej_tilde = x;
        ej_tilde.mul_assign(&s_tilde_vec[j]);
        ej_tilde.add_assign(&a_tilde_vec[j]);
        e_tilde.add_assign(&ej_tilde);
    }

    transcript.append_scalar::<C>(b"tx", &tx);
    transcript.append_scalar::<C>(b"tx_tilde", &tx_tilde);
    transcript.append_scalar::<C>(b"e_tilde", &e_tilde);
    let w: C::Scalar = transcript.challenge_scalar::<C>(b"w");
    let Q = B.mul_by_scalar(&w);
    // let mut H_prime : Vec<C> = Vec::with_capacity(nm);
    let mut H_prime_scalars: Vec<C::Scalar> = Vec::with_capacity(nm);
    let y_inv = match y.inverse() {
        Some(inv) => inv,
        None => return (V_vec, None),
    };
    let mut y_inv_i = C::Scalar::one();
    for _i in 0..nm {
        // H_prime.push(H[i].mul_by_scalar(&y_inv_i));
        H_prime_scalars.push(y_inv_i);
        y_inv_i.mul_assign(&y_inv);
    }

    let proof =
        prove_inner_product_with_scalars(transcript, &G, &H, &H_prime_scalars, &Q, &l, &r);
    
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
        _ => None
    };

    (V_vec, rangeproof)
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
/// This function is more efficient than the naive_verify since it
/// unfolds what the inner product proof verifier does using the verification
/// scalars.
#[allow(non_snake_case)]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::many_single_char_names)]
pub fn verify_efficient<C: Curve>(
    transcript: &mut Transcript,
    n: u8,
    commitments: &[Commitment<C>],
    proof: &RangeProof<C>,
    gens: &Generators<C>,
    v_keys: &CommitmentKey<C>,
) -> bool {
    let (G, H): (Vec<_>, Vec<_>) = gens.G_H.iter().cloned().unzip();
    let B = v_keys.0;
    let B_tilde = v_keys.1;
    let m = commitments.len();
    for V in commitments {
        transcript.append_point(b"Vj", &V.0);
    }
    let A = proof.A;
    let S = proof.S;
    let T_1 = proof.T_1;
    let T_2 = proof.T_2;
    let tx = proof.tx;
    let tx_tilde = proof.tx_tilde;
    let e_tilde = proof.e_tilde;
    transcript.append_point(b"A", &A);
    transcript.append_point(b"S", &S);
    let y: C::Scalar = transcript.challenge_scalar::<C>(b"y");
    let z: C::Scalar = transcript.challenge_scalar::<C>(b"z");
    let mut z2 = z;
    z2.mul_assign(&z);
    let mut z3 = z2;
    z3.mul_assign(&z);
    transcript.append_point(b"T1", &T_1);
    transcript.append_point(b"T2", &T_2);
    let x: C::Scalar = transcript.challenge_scalar::<C>(b"x");
    let mut x2 = x;
    x2.mul_assign(&x);
    // println!("verifier's x = {:?}", x);
    transcript.append_scalar::<C>(b"tx", &tx);
    transcript.append_scalar::<C>(b"tx_tilde", &tx_tilde);
    transcript.append_scalar::<C>(b"e_tilde", &e_tilde);
    let w: C::Scalar = transcript.challenge_scalar::<C>(b"w");
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
    let mut RHS = {
        let mut zj2 = z2;
        let mut powers = Vec::with_capacity(m);
        for _ in 0..m {
            powers.push(zj2);
            zj2.mul_assign(&z);
        }
        multiexp::<C, Commitment<C>>(commitments, &powers)
    };

    RHS = RHS.plus_point(&multiexp(&[B, T_1, T_2], &[delta_yz, x, x2]));

    // println!("--------------- VERIFICATION ----------------");
    let first = LHS.minus_point(&RHS).is_zero_point();
    if !first {
        return false;
    }
    // println!("First check = {:?}", first);

    let ip_proof = &proof.ip_proof;
    let mut H_scalars: Vec<C::Scalar> = Vec::with_capacity(G.len());
    let mut y_i = C::Scalar::one();
    let z_2_m = z_vec(z, 2, m);
    let verification_scalars = verify_scalars(transcript, G.len(), &ip_proof);
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
    let mut s_inv = s;
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
    s_inv.reverse();
    let s = s_inv;
    let H_term = multiexp(&H, &H_scalars); // Expensive!
    let A_term = A;
    let S_term = S.mul_by_scalar(&x);
    let mut B_scalar = tx;
    let mut ab = a;
    ab.mul_assign(&b);
    B_scalar.sub_assign(&ab);
    B_scalar.mul_assign(&w);
    let B_term = B.mul_by_scalar(&B_scalar);
    let mut minus_e_tilde = e_tilde;
    minus_e_tilde.negate();
    let B_tilde_scalar = minus_e_tilde;
    let B_tilde_term = B_tilde.mul_by_scalar(&B_tilde_scalar);
    let mut G_scalars = Vec::with_capacity(G.len());
    for si in s {
        let mut G_scalar = z;
        G_scalar.negate();
        let mut sa = si;
        sa.mul_assign(&a);
        G_scalar.sub_assign(&sa);
        G_scalars.push(G_scalar);
    }
    let G_term = multiexp(&G, &G_scalars); // Expensive!
    let L_term = multiexp(&L, &u_sq); // Expensive!
    let R_term = multiexp(&R, &u_inv_sq); // Expensive!

    let sum = A_term
        .plus_point(&S_term)
        .plus_point(&B_term)
        .plus_point(&B_tilde_term)
        .plus_point(&G_term)
        .plus_point(&H_term)
        .plus_point(&L_term)
        .plus_point(&R_term);

    // let second = sum.is_zero_point();
    // println!("Second check = {:?}", second);
    sum.is_zero_point()
}

/// This function does the same as verify_efficient. It groups
/// some of the verification checks a bit more and could be more efficient,
/// but it seems in practice that the difference in efficieny is small.
#[allow(non_snake_case)]
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::many_single_char_names)]
pub fn verify_more_efficient<C: Curve>(
    transcript: &mut Transcript,
    n: u8,
    commitments: &[Commitment<C>],
    proof: &RangeProof<C>,
    gens: &Generators<C>,
    v_keys: &CommitmentKey<C>,
) -> bool {
    let (G, H): (Vec<_>, Vec<_>) = gens.G_H.iter().cloned().unzip();
    let B = v_keys.0;
    let B_tilde = v_keys.1;
    let m = commitments.len();
    for V in commitments {
        transcript.append_point(b"Vj", &V.0);
    }
    let A = proof.A;
    let S = proof.S;
    let T_1 = proof.T_1;
    let T_2 = proof.T_2;
    let tx = proof.tx;
    let tx_tilde = proof.tx_tilde;
    let e_tilde = proof.e_tilde;
    transcript.append_point(b"A", &A);
    transcript.append_point(b"S", &S);
    let y: C::Scalar = transcript.challenge_scalar::<C>(b"y");
    let z: C::Scalar = transcript.challenge_scalar::<C>(b"z");
    let mut z2 = z;
    z2.mul_assign(&z);
    let mut z3 = z2;
    z3.mul_assign(&z);
    transcript.append_point(b"T1", &T_1);
    transcript.append_point(b"T2", &T_2);
    let x: C::Scalar = transcript.challenge_scalar::<C>(b"x");
    let mut x2 = x;
    x2.mul_assign(&x);
    // println!("verifier's x = {:?}", x);
    transcript.append_scalar::<C>(b"tx", &tx);
    transcript.append_scalar::<C>(b"tx_tilde", &tx_tilde);
    transcript.append_scalar::<C>(b"e_tilde", &e_tilde);
    let w: C::Scalar = transcript.challenge_scalar::<C>(b"w");
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
    let z_2_m = z_vec(z,2, m);
    let verification_scalars = verify_scalars(transcript, G.len(), &ip_proof);
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

    // println!("Second check = {:?}", sum.is_zero_point());
    let b: bool = sum2.is_zero_point();
    // println!(" check = {:?}", b);
    // println!("sum1==sum2? {:?}", sum==sum2);
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::G1;

    /// This function produces a proof that will satisfy the verifier's first
    /// check, even if the values are not in the interval.
    /// The second check will fail, and therefore in the tests below the
    /// verifier should output fail when checking a proof produced by
    /// cheat_prove
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
        transcript: &mut Transcript,
    ) -> (Vec<Commitment<C>>, Option<RangeProof<C>>) {
        let nm = (usize::from(n)) * (usize::from(m));
        let v_copy = v_vec.clone();
        let mut V_vec: Vec<Commitment<C>> = Vec::with_capacity(usize::from(m));
        let mut v_tilde_vec: Vec<C::Scalar> = Vec::with_capacity(usize::from(m));
        let v_keys = CommitmentKey(B, B_tilde);
        for v in v_vec {
            let v_scalar = C::scalar_from_u64(v);
            let v_value = Value::<C>::new(v_scalar);
            let v_j_tilde = Randomness::<C>::generate(csprng);
            v_tilde_vec.push(*v_j_tilde);
            let V_j = v_keys.hide(&v_value, &v_j_tilde);
            transcript.append_point(b"Vj", &V_j.0);
            V_vec.push(V_j);
        }
        let A = C::zero_point();
        let S = C::zero_point();
        transcript.append_point(b"A", &A);
        transcript.append_point(b"S", &S);
        let y: C::Scalar = transcript.challenge_scalar::<C>(b"y");
        let z: C::Scalar = transcript.challenge_scalar::<C>(b"z");
        let z_m = z_vec(z, 0, usize::from(m));
        let T_1 = C::zero_point();
        let T_2 = C::zero_point();

        let mut tx: C::Scalar = C::Scalar::zero();
        let mut tx_tilde: C::Scalar = C::Scalar::zero();
        let e_tilde: C::Scalar = C::Scalar::zero();
        transcript.append_point(b"T1", &T_1);
        transcript.append_point(b"T2", &T_2);
        let _x: C::Scalar = transcript.challenge_scalar::<C>(b"x");
        // println!("Cheating prover's x = {}", x);
        for j in 0..usize::from(m) {
            // tx:
            let mut z2vj = z_m[2];
            z2vj.mul_assign(&z_m[j]); // This line is MISSING in the Bulletproof documentation
            let v_value = C::scalar_from_u64(v_copy[j]);
            z2vj.mul_assign(&v_value);
            let tjx = z2vj;
            tx.add_assign(&tjx);

            // tx tilde:
            let mut z2vj_tilde = z_m[2];
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
        let mut zj3 = z_m[3];
        for _ in 0..m {
            sum.add_assign(&zj3);
            zj3.mul_assign(&z);
        }
        sum.mul_assign(&ip_1_2_n);
        let mut delta_yz = z;
        delta_yz.sub_assign(&z_m[2]);
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
            _ => None
        };
        (V_vec, rangeproof)
    }

    /// This function verifies a range proof, i.e. a proof of knowledge
    /// of value v_1, v_2, ..., v_m that are all in [0, 2^n) that are consistent
    /// with commitments V_i to v_i. The arguments are
    /// - n - the number n such that each v_i is claimed to be in [0, 2^n) by
    ///   the prover
    /// - commitments - commitments V_i to each v_i
    /// - gens - generators containing vectors G and H both of length nm
    /// - v_keys - commitmentment keys B and B_tilde
    /// It uses the inner product proof verifier.
    #[allow(non_snake_case)]
    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::many_single_char_names)]
    fn naive_verify<C: Curve>(
        transcript: &mut Transcript,
        n: u8,
        commitments: &[Commitment<C>],
        proof: &RangeProof<C>,
        gens: &Generators<C>,
        v_keys: &CommitmentKey<C>,
    ) -> bool {
        let (G, H): (Vec<_>, Vec<_>) = gens.G_H.iter().cloned().unzip();
        let B = v_keys.0;
        let B_tilde = v_keys.1;
        let m = commitments.len();
        for V in commitments.clone() {
            transcript.append_point(b"Vj", &V.0);
        }
        let A = proof.A;
        let S = proof.S;
        let T_1 = proof.T_1;
        let T_2 = proof.T_2;
        let tx = proof.tx;
        let tx_tilde = proof.tx_tilde;
        let e_tilde = proof.e_tilde;
        transcript.append_point(b"A", &A);
        transcript.append_point(b"S", &S);
        let y: C::Scalar = transcript.challenge_scalar::<C>(b"y");
        let z: C::Scalar = transcript.challenge_scalar::<C>(b"z");
        let mut z2 = z;
        z2.mul_assign(&z);
        let mut z3 = z2;
        z3.mul_assign(&z);
        transcript.append_point(b"T1", &T_1);
        transcript.append_point(b"T2", &T_2);
        let x: C::Scalar = transcript.challenge_scalar::<C>(b"x");
        let mut x2 = x;
        x2.mul_assign(&x);
        // println!("verifier's x = {:?}", x);
        transcript.append_scalar::<C>(b"tx", &tx);
        transcript.append_scalar::<C>(b"tx_tilde", &tx_tilde);
        transcript.append_scalar::<C>(b"e_tilde", &e_tilde);
        let w: C::Scalar = transcript.challenge_scalar::<C>(b"w");
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
        let second: bool = verify_inner_product(transcript, &G, &H_prime, &P_prime, &Q, &ip_proof); // Very expensive
                                                                                                    // println!("Second check = {:?}", second);
        second
    }

    #[allow(non_snake_case)]
    #[test]
    fn test_prove() {
        // Test for nm = 512
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
        let keys = CommitmentKey(B, B_tilde);

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
        let mut transcript = Transcript::new(&[]);
        let (commitments, proof) = prove(&mut transcript, rng, n, m, &v_vec, &gens, &keys);
        assert!(proof.is_some());
        let proof = proof.unwrap();
        let mut transcript = Transcript::new(&[]);
        let b1 = naive_verify(&mut transcript, n, &commitments, &proof, &gens, &keys);

        let mut transcript = Transcript::new(&[]);
        let b2 = verify_efficient(&mut transcript, n, &commitments, &proof, &gens, &keys);

        // Testing the even more efficient verifier:
        let mut transcript = Transcript::new(&[]);
        let b3 = verify_more_efficient(&mut transcript, n, &commitments, &proof, &gens, &keys);
        assert!(b1);
        assert!(b2);
        assert!(b3);
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
        let keys = CommitmentKey(B, B_tilde);

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
        let mut transcript = Transcript::new(&[]);
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
        let mut transcript = Transcript::new(&[]);
        let b1 = verify_efficient(&mut transcript, n, &commitments, &proof, &gens, &keys);
        let mut transcript = Transcript::new(&[]);
        let b2 = verify_more_efficient(&mut transcript, n, &commitments, &proof, &gens, &keys);
        assert!(!b1);
        assert!(!b2);
    }
}
