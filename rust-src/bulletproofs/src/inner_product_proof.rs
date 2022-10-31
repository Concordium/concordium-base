//! Logarithmic sized inner product proof used as base for the other proofs in
//! this crate
use crypto_common::*;
use crypto_common_derive::*;
use curve_arithmetic::{multiexp, Curve};
use ff::Field;
use random_oracle::RandomOracle;

/// Inner product proof
#[derive(Clone, Serialize, Debug)]
pub struct InnerProductProof<C: Curve> {
    #[size_length = 4]
    pub lr_vec: Vec<(C, C)>,
    pub a:      C::Scalar,
    pub b:      C::Scalar,
}

/// This function computes an inner product proof,
/// which is a proof of knowledge that the prover knows vectors a and b such
/// that P'=<a,G>+<b,H>+<a,b>Q.
/// This function is only used for benchmarks and testing, since
/// prove_inner_product_with_scalars is faster when producing the inner product
/// proof inside the range proof. On its own it could be used to produce inner
/// product proofs, though.  The arguments are
/// - G_slice - a slice to the vector G of elliptic curve points
/// - H_slice - a slice to the vector H of elliptic curve points
/// - H_prime_scalars - a slice to the vector c of scalars such that H' = c ∘ H
/// - Q - the elliptic curve point Q
/// - a_slice - a slice to the vector a of scalars
/// - b_slice - a slice to the vector b of scalars
/// Preconditions:
/// G_slice, H_slice, a_slice and b_slice should all be of the same length, and
/// this length must be a power of 2.
#[allow(non_snake_case)]
pub fn prove_inner_product<C: Curve>(
    transcript: &mut RandomOracle,
    G_slice: &[C],
    H_slice: &[C],
    Q: &C,
    a_slice: &[C::Scalar],
    b_slice: &[C::Scalar],
) -> Option<InnerProductProof<C>> {
    let one = C::Scalar::one();
    let H_scalars = vec![one; H_slice.len()];
    prove_inner_product_with_scalars(
        transcript, G_slice, H_slice, &H_scalars, Q, a_slice, b_slice,
    )
}

/// This function computes an inner product proof,
/// which is a proof of knowledge that the prover knows vectors a and b such
/// that P'=<a,G>+<b,H'>+<a,b>Q, but where H' = c ∘ H (pointwise
/// scalarmultiplication) for already known vectors c (of scalars) and H (of
/// elliptic curve points). This is more efficient than calling
/// prove_inner_product with G and H', but the output is a proof of the same
/// statement. The arguments are
/// - G_slice - a slice to the vector G of elliptic curve points
/// - H_slice - a slice to the vector H of elliptic curve points
/// - H_prime_scalars - a slice to the vector c of scalars such that H' = c ∘ H
/// - Q - the elliptic curve point Q
/// - a_slice - a slice to the vector a of scalars
/// - b_slice - a slice to the vector b of scalars
/// Precondictions:
/// G_slice, H_slice, a_slice and b_slice should all be of the same length, and
/// this length must be a power of 2.
#[allow(non_snake_case)]
pub fn prove_inner_product_with_scalars<C: Curve>(
    transcript: &mut RandomOracle,
    G_slice: &[C],
    H_slice: &[C],
    H_prime_scalars: &[C::Scalar],
    Q: &C,
    a_slice: &[C::Scalar],
    b_slice: &[C::Scalar],
) -> Option<InnerProductProof<C>> {
    let mut n = G_slice.len();
    if !n.is_power_of_two() {
        return None;
    }
    let k = n.trailing_zeros() as usize; // This line is also used in Bulletproofs's implementation

    let mut L_R = Vec::with_capacity(k);
    let mut a_vec = a_slice.to_vec();
    let mut b_vec = b_slice.to_vec();
    let mut G_vec = G_slice.to_vec();
    let mut H_vec = H_slice.to_vec();

    for j in 0..k {
        let a_lo = &a_vec[..n / 2];
        let a_hi = &a_vec[n / 2..n];
        let G_lo = &G_vec[..n / 2];
        let G_hi = &G_vec[n / 2..n];
        let b_lo = &b_vec[..n / 2];
        let b_hi = &b_vec[n / 2..n];
        let H_lo = &H_vec[..n / 2];
        let H_hi = &H_vec[n / 2..n];
        let a_lo_G_hi = multiexp(G_hi, a_lo);
        let a_hi_G_lo = multiexp(G_lo, a_hi);
        let b_hi_H_lo: C;
        let b_lo_H_hi: C;
        if j == 0 {
            let scalars_hi = &H_prime_scalars[n / 2..];
            let scalars_lo = &H_prime_scalars[..n / 2];
            let b_hi: Vec<C::Scalar> = b_hi
                .iter()
                .zip(scalars_lo.iter())
                .map(|(&x, y)| {
                    let mut xy = x;
                    xy.mul_assign(y);
                    xy
                })
                .collect();
            let b_lo: Vec<C::Scalar> = b_lo
                .iter()
                .zip(scalars_hi.iter())
                .map(|(&x, y)| {
                    let mut xy = x;
                    xy.mul_assign(y);
                    xy
                })
                .collect();
            b_hi_H_lo = multiexp(H_lo, &b_hi);
            b_lo_H_hi = multiexp(H_hi, &b_lo);
        } else {
            b_hi_H_lo = multiexp(H_lo, b_hi);
            b_lo_H_hi = multiexp(H_hi, b_lo);
        }
        let a_lo_b_hi_Q = Q.mul_by_scalar(&inner_product(a_lo, b_hi));
        let a_hi_b_lo_Q = Q.mul_by_scalar(&inner_product(a_hi, b_lo));

        let Lj = a_lo_G_hi.plus_point(&b_hi_H_lo).plus_point(&a_lo_b_hi_Q);
        let Rj = a_hi_G_lo.plus_point(&b_lo_H_hi).plus_point(&a_hi_b_lo_Q);

        transcript.append_message(b"Lj", &Lj);
        transcript.append_message(b"Rj", &Rj);
        L_R.push((Lj, Rj));
        let u_j: C::Scalar = transcript.challenge_scalar::<C, _>(b"uj");
        // println!("Prover's u_{:?} = {:?}", j, u_j);
        let u_j_inv = match u_j.inverse() {
            Some(inv) => inv,
            _ => return None,
        };

        let G_scalars = [u_j_inv, u_j];
        let mut H_scalars = [u_j, u_j_inv];

        for i in 0..a_lo.len() {
            let a_lo = &a_vec[..n / 2];
            let a_hi = &a_vec[n / 2..];
            let G_lo = &G_vec[..n / 2];
            let G_hi = &G_vec[n / 2..];
            let b_lo = &b_vec[..n / 2];
            let b_hi = &b_vec[n / 2..];
            let H_lo = &H_vec[..n / 2];
            let H_hi = &H_vec[n / 2..];
            let a_lo_len = a_lo.len();
            // Calculating new a vector:
            let mut a_lo_u_j = a_lo[i];
            a_lo_u_j.mul_assign(&u_j);

            let mut u_j_inv_a_hi = a_hi[i];
            u_j_inv_a_hi.mul_assign(&u_j_inv);

            let mut sum = a_lo_u_j;
            sum.add_assign(&u_j_inv_a_hi);
            a_vec[i] = sum;

            // Calculating new b vector:
            let mut b_lo_u_j_inv = b_lo[i];
            b_lo_u_j_inv.mul_assign(&u_j_inv);

            let mut u_j_b_hi = b_hi[i];
            u_j_b_hi.mul_assign(&u_j);

            let mut sum = b_lo_u_j_inv;
            sum.add_assign(&u_j_b_hi);
            b_vec[i] = sum;

            // Calculating new G vector:
            let G_points = [G_lo[i], G_hi[i]];
            let sum = multiexp(&G_points, &G_scalars);
            G_vec[i] = sum;

            // Calculating new H vector:
            let H_points = [H_lo[i], H_hi[i]];
            if j == 0 {
                let mut u_j = u_j;
                let mut u_j_inv = u_j_inv;
                u_j.mul_assign(&H_prime_scalars[i]);
                u_j_inv.mul_assign(&H_prime_scalars[i + a_lo_len]);
                H_scalars = [u_j, u_j_inv];
            }
            let sum = multiexp(&H_points, &H_scalars);
            H_vec[i] = sum;
        }
        n /= 2;
    }

    let a = a_vec[0];
    let b = b_vec[0];

    Some(InnerProductProof { lr_vec: L_R, a, b })
}

/// This struct contains vectors of scalars that are needed for verification.
/// Both u_sq and u_inv_sq have to be of equal length k, and s has to be of
/// length 2^k.
pub struct VerificationScalars<C: Curve> {
    pub u_sq:     Vec<C::Scalar>,
    pub u_inv_sq: Vec<C::Scalar>,
    pub s:        Vec<C::Scalar>,
}

/// This function calculates the verification scalars
/// that are used to verify an inner product proof.
/// The arguments are
/// - proof - a reference to a inner product proof.
/// - n - the number of elements in the vectors (of equal length) that was used
///   to produce the inner product proof. This also means that n = 2^k, where k
///   is the length of proof.lr_vec
#[allow(non_snake_case)]
#[allow(clippy::many_single_char_names)]
pub fn verify_scalars<C: Curve>(
    transcript: &mut RandomOracle,
    n: usize,
    proof: &InnerProductProof<C>,
) -> Option<VerificationScalars<C>> {
    // let n = G_vec.len();
    let L_R = &proof.lr_vec;
    let a = proof.a;
    let b = proof.b;
    let mut ab = a;
    ab.mul_assign(&b);
    let k = L_R.len();
    let mut u_sq = Vec::with_capacity(k);
    let mut u_inv_sq = Vec::with_capacity(k);
    let mut s = Vec::with_capacity(n);
    let mut s_0 = C::Scalar::one();
    for (Lj, Rj) in L_R {
        transcript.append_message(b"Lj", Lj);
        transcript.append_message(b"Rj", Rj);
        let u_j: C::Scalar = transcript.challenge_scalar::<C, _>(b"uj");
        let u_j_inv = match u_j.inverse() {
            Some(inv) => inv,
            _ => return None,
        };
        s_0.mul_assign(&u_j_inv);
        let mut u_j_sq = u_j;
        u_j_sq.mul_assign(&u_j);
        u_sq.push(u_j_sq);

        let mut u_j_inv_sq = u_j_inv;
        u_j_inv_sq.mul_assign(&u_j_inv);
        u_inv_sq.push(u_j_inv_sq);
    }

    s.push(s_0);
    // We calculate entrances s_0, ..., s_n of the vector s, where
    // s_0 = u_k^{-1} ... u_0^{-1}
    // s_1 =  u_k^{-1} ... u_1^{-1} u_0^{1}
    // s_2 =  u_k^{-1} ... u_2^{-1} u_1^{1} u_0^{-1} corresponding to the fact that
    // 2 is 10 in binary ...
    // s_5 =  u_k^{-1} ... u_0^{-1} u_0^{1} u_0^{-1} u_0^{1} corresponding to the
    // fact that 5 is 101 in binary ... and so on.
    // That is, to calculate s_i, the bits of i are distributed among the u_j's
    // exponents but where 0 is replaced with -1.
    for i in 1..n {
        let lg_i = (32 - 1 - (i as u32).leading_zeros()) as usize;
        let k = 1 << lg_i;
        let mut s_i = s[i - k];
        s_i.mul_assign(&u_sq[L_R.len() - 1 - lg_i]);
        s.push(s_i);
    }
    Some(VerificationScalars { u_sq, u_inv_sq, s })
}

/// This function verifies an inner product proof,
/// i.e., a proof of knowledge of vectors `a` and `b` such that
/// `P'=<a,G>+<b,H>+<a,b>Q`.
///
/// Arguments:
/// - `G_vec` - slice `G` of elliptic curve points
/// - `H_vec` - slice `H` of elliptic curve points
/// - `P_prime` - the elliptic curve point `P'`
/// - `Q` - the elliptic curve point `Q`
/// - `proof` - the inner product proof
///
/// Preconditions:
/// `G_vec` and `H_vec` must be of the same length, and this length must a power
/// of 2.
#[allow(non_snake_case)]
pub fn verify_inner_product<C: Curve>(
    transcript: &mut RandomOracle,
    G_vec: &[C],
    H_vec: &[C],
    P_prime: &C,
    Q: &C,
    proof: &InnerProductProof<C>,
) -> bool {
    // call verify_inner_product_with_scalars
    // Since H is directly given, set all exponents for H to 1
    let n = G_vec.len();
    let H_exponents = vec![C::Scalar::one(); n];
    // P_prime is also given directly, so set P_prime_bases to P_prime with exponent
    // 1. Since it is assumed that P_prime_bases starts with G, H and Q, add those
    // first and set the first 2n+1 exponents to 0.
    let mut P_prime_bases = Vec::with_capacity(2 * n + 2);
    P_prime_bases.extend_from_slice(G_vec);
    P_prime_bases.extend_from_slice(H_vec);
    P_prime_bases.push(*Q);
    P_prime_bases.push(*P_prime);
    let mut P_prime_exponents = Vec::with_capacity(2 * n + 2);
    P_prime_exponents.extend(vec![C::Scalar::zero(); 2 * n + 1]);
    P_prime_exponents.push(C::Scalar::one());

    verify_inner_product_with_scalars(
        transcript,
        &H_exponents,
        &P_prime_bases,
        &P_prime_exponents,
        proof,
    )
}

/// This function is the actual verification function used at the core of the
/// function `verify_inner_product`. It is verified whether
/// `P'=<a,G>+<b,H'>+<a,b>Q` for `P' = multiexp(P_prime_bases,
/// P_prime_exponents)` and `H'_i = H_i^H_exponents_i`.
///
/// Arguments:
/// - `transcript` - the proof transcript
/// - `H_exponents` - slice of scalars to whose powers the `H_i` are raised
/// - `P_prime_bases` - slice of points for computing curve point `P'`. It is
///   assumed that the first base points are `G | H, Q`
/// - `P_prime_exponents` - slice of scalars to whose powers the elements
///   `P_prime_bases` are raised
/// - `proof` - the inner product proof
///
/// Preconditions:
/// - `H_exponents` must have length `n`, which is a power of 2.
/// - `P_prime_bases` contains `G` and `H`, each consisting of `n` curve points,
///   followed by a curve point `Q`, and may contain additional curve points.
/// - The length of `P_prime_exponents` is equal to the length of
///   `P_prime_bases`
#[allow(non_snake_case)]
pub(crate) fn verify_inner_product_with_scalars<C: Curve>(
    transcript: &mut RandomOracle,
    H_exponents: &[C::Scalar],
    P_prime_bases: &[C],
    P_prime_exponents: &[C::Scalar],
    proof: &InnerProductProof<C>,
) -> bool {
    let n = H_exponents.len();
    let L_R = &proof.lr_vec;
    let a = proof.a;
    let b = proof.b;
    let mut ab = a;
    ab.mul_assign(&b);

    let verification_scalars = match verify_scalars(transcript, n, proof) {
        None => return false,
        Some(scalars) => scalars,
    };
    let (u_sq, u_inv_sq, s) = (
        verification_scalars.u_sq,
        verification_scalars.u_inv_sq,
        verification_scalars.s,
    );

    // nsum = sum^-1 = prod_j L_R[j].0 ^ -u_sq[j] * L_R[j].1 ^ -u_inv_sq[j]
    let mut nsum_bases = Vec::with_capacity(2 * L_R.len());
    let mut nsum_exps = Vec::with_capacity(2 * L_R.len());
    for j in 0..L_R.len() {
        nsum_bases.push(L_R[j].0);
        nsum_bases.push(L_R[j].1);
        let mut musq = u_sq[j];
        let mut muisq = u_inv_sq[j];
        musq.negate();
        muisq.negate();
        nsum_exps.push(musq);
        nsum_exps.push(muisq);
    }

    // RHS = prod_i G_i^(s_i*a) H_i^(H_exponents_i * s_i^-1 * b) * Q^{ab} * nsum
    let mut s_inv = s.clone();
    s_inv.reverse();
    let mut G_exps = s;
    for ge in &mut G_exps {
        ge.mul_assign(&a);
    }

    // Prepare bases and exponents for computation of RHS and leave space for
    // additional P' computation
    let mut rhs_bases = Vec::with_capacity(nsum_bases.len() + P_prime_bases.len());
    // Add G, H, and Q to rhs_bases
    rhs_bases.extend(&P_prime_bases[0..2 * n + 1]);

    // add further elements to rhs_bases
    rhs_bases.append(&mut nsum_bases);
    rhs_bases.extend(&P_prime_bases[2 * n + 1..]);

    let mut rhs_exps = Vec::with_capacity(rhs_bases.len());
    rhs_exps.append(&mut G_exps);

    // Compute H_exps_i = H_exponents_i * s_i^-1 * b and add to rhs_exps
    for i in 0..H_exponents.len() {
        let mut hi = H_exponents[i];
        hi.mul_assign(&s_inv[i]);
        hi.mul_assign(&b);
        rhs_exps.push(hi);
    }
    rhs_exps.push(ab);
    rhs_exps.append(&mut nsum_exps);

    // check whether P' = RHS <=> 0 = RHS P'^-1
    // add negation of first 2n + 1 exponents to first elements in rhs_exps since
    // they belong to G, H, and Q
    for i in 0..2 * n + 1 {
        rhs_exps[i].sub_assign(&P_prime_exponents[i]);
    }

    // negate remaining elements of P_prime_exponents and append them to rhs_exps
    let mut nppexps = P_prime_exponents[2 * n + 1..].to_vec();
    for nppe in &mut nppexps {
        nppe.negate();
    }
    rhs_exps.append(&mut nppexps);

    // Finally compute RHS P'^-1 and check whether it is 0
    let rhs_p_inv = multiexp(&rhs_bases, &rhs_exps);
    rhs_p_inv.is_zero_point()
}

/// This function calculates the inner product between two vectors over any
/// field F. The arguments are
/// - a - the first vector
/// - b - the second vector
///
/// Precondition:
/// a and b should have the same length. In case they don't have the same length
/// the result is the inner product of the initial segments determined by the
/// length of the shorter vector.
#[allow(non_snake_case)]
pub fn inner_product<F: Field>(a: &[F], b: &[F]) -> F {
    debug_assert_eq!(
        a.len(),
        b.len(),
        "inner_product: lengths of vectors differ."
    );
    let mut sum = F::zero();
    for (a, b) in a.iter().zip(b) {
        let mut ab = *a;
        ab.mul_assign(b);
        sum.add_assign(&ab);
    }
    sum
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve_arithmetic::Curve;
    use pairing::bls12_381::G1;
    use rand::thread_rng;
    type SomeCurve = G1;

    #[test]
    fn testinner() {
        let one = SomeCurve::scalar_from_u64(1);
        let two = SomeCurve::scalar_from_u64(2);
        let three = SomeCurve::scalar_from_u64(3);
        let eleven = SomeCurve::scalar_from_u64(11);

        let v = vec![one, two, three];
        let u = vec![three, one, two];
        let ip = inner_product(&v, &u);
        // Tests that <[1,2,3],[3,1,2]> = 11
        assert!(ip == eleven);
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_inner_product_proof() {
        let rng = &mut thread_rng();
        let n = 32 * 16;
        let mut G_vec = vec![];
        let mut H_vec = vec![];
        let mut a_vec = vec![];
        let mut b_vec = vec![];
        for _ in 0..n {
            let g = SomeCurve::generate(rng);
            let h = SomeCurve::generate(rng);
            let a = SomeCurve::generate_scalar(rng);
            let b = SomeCurve::generate_scalar(rng);

            G_vec.push(g);
            H_vec.push(h);
            a_vec.push(a);
            b_vec.push(b);
        }

        let Q = SomeCurve::generate(rng);
        let P_prime = multiexp(&G_vec, &a_vec)
            .plus_point(&multiexp(&H_vec, &b_vec))
            .plus_point(&Q.mul_by_scalar(&inner_product(&a_vec, &b_vec)));
        let mut transcript = RandomOracle::empty();

        // Producing inner product proof with vector length = n
        let proof = prove_inner_product(&mut transcript, &G_vec, &H_vec, &Q, &a_vec, &b_vec);
        assert!(proof.is_some());
        let proof = proof.unwrap();
        let mut transcript = RandomOracle::empty();

        assert!(verify_inner_product(
            &mut transcript,
            &G_vec,
            &H_vec,
            &P_prime,
            &Q,
            &proof
        ))
    }
}
