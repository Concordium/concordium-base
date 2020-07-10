use crate::transcript::TranscriptProtocol;
use curve_arithmetic::{Curve, multiexp};
use ff::Field;
use crypto_common::*;
use crypto_common_derive::*;
use merlin::Transcript;

#[allow(non_snake_case)]
#[derive(Clone, Serialize)]
pub struct InnerProductProof<C: Curve> {
    pub l_vec: Vec<C>,
    pub r_vec: Vec<C>,
    pub a: C::Scalar,
    pub b: C::Scalar,
}

/// This function computes a inner product proof,
/// which is a proof of knowledge that the prover knows vectors a and b such that P'=<a,G>+<b,H>+<a,b>Q.
/// The arguments are
/// - G_vec - the vector G of elliptic curve points 
/// - H_vec - the vector H of elliptic curve points 
/// - Q - the elliptiv curve point Q
/// - a_vec - the vector a of scalars 
/// - b_vec - the vector b of scalars
/// Precondictions:
/// G_vec, H_vec, a_vec and b_vec should all be of the same length, and this length must a power of 2. 
#[allow(non_snake_case)]
#[allow(dead_code)]
// #[cfg(test)]
pub fn prove_inner_product<C: Curve>(
    transcript: &mut Transcript,
    mut G_vec: Vec<C>,
    mut H_vec: Vec<C>,
    Q: &C,
    mut a_vec: Vec<C::Scalar>,
    mut b_vec: Vec<C::Scalar>,
) -> InnerProductProof<C> {
    let mut n = G_vec.len();
    assert!(n.is_power_of_two());
    let k = n.next_power_of_two().trailing_zeros() as usize; // This line is also used in Bulletproofs's implementation

    let mut L = Vec::with_capacity(k);
    let mut R = Vec::with_capacity(k);

    for _j in 0..k {
        n = G_vec.len();
        let a_lo = &a_vec[..n / 2];
        let a_hi = &a_vec[n / 2..];
        let G_lo = &G_vec[..n / 2];
        let G_hi = &G_vec[n / 2..];
        let b_lo = &b_vec[..n / 2];
        let b_hi = &b_vec[n / 2..];
        let H_lo = &H_vec[..n / 2];
        let H_hi = &H_vec[n / 2..];
        let a_lo_G_hi = multiexp( G_hi, a_lo);
        let a_hi_G_lo = multiexp( G_lo, a_hi);
        let b_hi_H_lo = multiexp( H_lo, b_hi);
        let b_lo_H_hi = multiexp( H_hi, b_lo);
        let a_lo_b_hi_Q = Q.mul_by_scalar(&inner_product(a_lo, b_hi));
        let a_hi_b_lo_Q = Q.mul_by_scalar(&inner_product(a_hi, b_lo));

        let Lj = a_lo_G_hi.plus_point(&b_hi_H_lo).plus_point(&a_lo_b_hi_Q);
        let Rj = a_hi_G_lo.plus_point(&b_lo_H_hi).plus_point(&a_hi_b_lo_Q);

        // Maybe faster:
        // let mut Lj_scalars = Vec::with_capacity(n+1);
        // Lj_scalars.extend_from_slice(a_lo);
        // Lj_scalars.extend_from_slice(b_hi);
        // Lj_scalars.push(inner_product(a_lo, b_hi));
        // let mut Lj_points = Vec::with_capacity(n+1);
        // Lj_points.extend_from_slice(G_hi);
        // Lj_points.extend_from_slice(H_lo);
        // Lj_points.push(*Q);
        // let Lj = multiexp( &Lj_points, &Lj_scalars);
        // let mut Rj_scalars = Vec::with_capacity(n+1);
        // Rj_scalars.extend_from_slice(a_hi);
        // Rj_scalars.extend_from_slice(b_lo);
        // Rj_scalars.push(inner_product(a_hi, b_lo));
        // let mut Rj_points = Vec::with_capacity(n+1);
        // Rj_points.extend_from_slice(G_lo);
        // Rj_points.extend_from_slice(H_hi);
        // Rj_points.push(*Q);
        // let Rj = multiexp( &Rj_points, &Rj_scalars);
        // end maybe faster

        transcript.append_point(b"Lj", &Lj);
        transcript.append_point(b"Rj", &Rj);
        L.push(Lj);
        R.push(Rj);
        let u_j: C::Scalar = transcript.challenge_scalar::<C>(b"uj");
        // println!("Prover's u_{:?} = {:?}", j, u_j);
        let u_j_inv = u_j.inverse().unwrap(); // TODO avoid this

        let mut a = Vec::with_capacity(a_lo.len());
        let mut b = Vec::with_capacity(a_lo.len());
        let mut G = Vec::with_capacity(a_lo.len());
        let mut H = Vec::with_capacity(a_lo.len());
        let G_scalars = [u_j_inv, u_j]; // For faster way
        let H_scalars = [u_j, u_j_inv]; // For faster way
        for i in 0..a_lo.len() {
            // Calculating new a vector:
            let mut a_lo_u_j = a_lo[i];
            a_lo_u_j.mul_assign(&u_j);

            let mut u_j_inv_a_hi = a_hi[i];
            u_j_inv_a_hi.mul_assign(&u_j_inv);

            let mut sum = a_lo_u_j;
            sum.add_assign(&u_j_inv_a_hi);
            a.push(sum);

            // Calculating new b vector:
            let mut b_lo_u_j_inv = b_lo[i];
            b_lo_u_j_inv.mul_assign(&u_j_inv);

            let mut u_j_b_hi = b_hi[i];
            u_j_b_hi.mul_assign(&u_j);

            let mut sum = b_lo_u_j_inv;
            sum.add_assign(&u_j_b_hi);
            b.push(sum);

            // Calculating new G vector:
            // let G_lo_u_j_inv = G_lo[i].mul_by_scalar(&u_j_inv);
            // let u_j_G_hi = G_hi[i].mul_by_scalar(&u_j);
            // let sum = G_lo_u_j_inv.plus_point(&u_j_G_hi);

            // Maybe faster
            let G_points = [G_lo[i], G_hi[i]];
            let sum = multiexp( &G_points, &G_scalars);
            // end maybe faster
            G.push(sum);

            // Calculating new H vector:
            // let H_lo_u_j = H_lo[i].mul_by_scalar(&u_j);
            // let u_j_inv_H_hi = H_hi[i].mul_by_scalar(&u_j_inv);
            // let sum = H_lo_u_j.plus_point(&u_j_inv_H_hi);
            // Maybe faster
            let H_points = [H_lo[i], H_hi[i]];
            let sum = multiexp( &H_points, &H_scalars);
            // end maybe faster
            H.push(sum);
        }
        a_vec = a;
        b_vec = b;
        G_vec = G;
        H_vec = H;
    }

    let a = a_vec[0];
    let b = b_vec[0];

    InnerProductProof { l_vec: L, r_vec: R, a, b }
}

/// This function computes a inner product proof,
/// which is a proof of knowledge that the prover knows vectors a and b such that P'=<a,G>+<b,H'>+<a,b>Q,
/// but where H' = c ∘ H (pointwise scalarmultiplication) for already known vectors c (of scalars) and H (of elliptic curve points).
/// This is more efficient than calling prove_inner_product with G and H', but the output is a proof of the same statement. 
/// The arguments are
/// The arguments are
/// - G_vec - the vector G of elliptic curve points 
/// - H_vec - the vector H of elliptic curve points 
/// - H_prime_scalars - the vector c of scalars such that H' = c ∘ H 
/// - Q - the elliptiv curve point Q
/// - a_vec - the vector a of scalars 
/// - b_vec - the vector b of scalars
/// Precondictions:
/// G_vec, H_vec, a_vec and b_vec should all be of the same length, and this length must a power of 2. 
#[allow(non_snake_case)]
pub fn prove_inner_product_with_scalars<C: Curve>(
    transcript: &mut Transcript,
    mut G_vec: Vec<C>,
    mut H_vec: Vec<C>,
    H_prime_scalars: &[C::Scalar],
    Q: &C,
    mut a_vec: Vec<C::Scalar>,
    mut b_vec: Vec<C::Scalar>,
) -> InnerProductProof<C> {
    let mut n = G_vec.len();
    assert!(n.is_power_of_two());
    let k = n.next_power_of_two().trailing_zeros() as usize; // This line is also used in Bulletproofs's implementation

    let mut L = Vec::with_capacity(k);
    let mut R = Vec::with_capacity(k);

    for j in 0..k {
        n = G_vec.len();
        let a_lo = &a_vec[..n / 2];
        let a_hi = &a_vec[n / 2..];
        let G_lo = &G_vec[..n / 2];
        let G_hi = &G_vec[n / 2..];
        let b_lo = &b_vec[..n / 2];
        let b_hi = &b_vec[n / 2..];
        let H_lo = &H_vec[..n / 2];
        let H_hi = &H_vec[n / 2..];
        let a_lo_G_hi = multiexp( G_hi, a_lo);
        let a_hi_G_lo = multiexp( G_lo, a_hi);
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
            b_hi_H_lo = multiexp( H_lo, &b_hi);
            b_lo_H_hi = multiexp( H_hi, &b_lo);
        } else {
            b_hi_H_lo = multiexp( H_lo, b_hi);
            b_lo_H_hi = multiexp( H_hi, b_lo);
        }
        let a_lo_b_hi_Q = Q.mul_by_scalar(&inner_product(a_lo, b_hi));
        let a_hi_b_lo_Q = Q.mul_by_scalar(&inner_product(a_hi, b_lo));

        let Lj = a_lo_G_hi.plus_point(&b_hi_H_lo).plus_point(&a_lo_b_hi_Q);
        let Rj = a_hi_G_lo.plus_point(&b_lo_H_hi).plus_point(&a_hi_b_lo_Q);

        transcript.append_point(b"Lj", &Lj);
        transcript.append_point(b"Rj", &Rj);
        L.push(Lj);
        R.push(Rj);
        let u_j: C::Scalar = transcript.challenge_scalar::<C>(b"uj");
        // println!("Prover's u_{:?} = {:?}", j, u_j);
        let u_j_inv = u_j.inverse().unwrap(); // TODO avoid unwrap

        let mut a = Vec::with_capacity(a_lo.len());
        let mut b = Vec::with_capacity(a_lo.len());
        let mut G = Vec::with_capacity(a_lo.len());
        let mut H = Vec::with_capacity(a_lo.len());
        let G_scalars = [u_j_inv, u_j]; // For faster way
        let mut H_scalars = [u_j, u_j_inv];

        for i in 0..a_lo.len() {
            // Calculating new a vector:
            let mut a_lo_u_j = a_lo[i];
            a_lo_u_j.mul_assign(&u_j);

            let mut u_j_inv_a_hi = a_hi[i];
            u_j_inv_a_hi.mul_assign(&u_j_inv);

            let mut sum = a_lo_u_j;
            sum.add_assign(&u_j_inv_a_hi);
            a.push(sum);

            // Calculating new b vector:
            let mut b_lo_u_j_inv = b_lo[i];
            b_lo_u_j_inv.mul_assign(&u_j_inv);

            let mut u_j_b_hi = b_hi[i];
            u_j_b_hi.mul_assign(&u_j);

            let mut sum = b_lo_u_j_inv;
            sum.add_assign(&u_j_b_hi);
            b.push(sum);

            // Calculating new G vector:
            // let G_lo_u_j_inv = G_lo[i].mul_by_scalar(&u_j_inv);
            // let u_j_G_hi = G_hi[i].mul_by_scalar(&u_j);
            // let sum = G_lo_u_j_inv.plus_point(&u_j_G_hi);

            // Maybe faster
            let G_points = [G_lo[i], G_hi[i]];
            let sum = multiexp( &G_points, &G_scalars);
            // end maybe faster
            G.push(sum);

            // Calculating new H vector:
            // let H_lo_u_j = H_lo[i].mul_by_scalar(&u_j);
            // let u_j_inv_H_hi = H_hi[i].mul_by_scalar(&u_j_inv);
            // let sum = H_lo_u_j.plus_point(&u_j_inv_H_hi);
            // Maybe faster
            let H_points = [H_lo[i], H_hi[i]];
            if j == 0 {
                let mut u_j = u_j;
                let mut u_j_inv = u_j_inv;
                u_j.mul_assign(&H_prime_scalars[i]);
                u_j_inv.mul_assign(&H_prime_scalars[i + a_lo.len()]);
                H_scalars = [u_j, u_j_inv];
            }
            let sum = multiexp( &H_points, &H_scalars);
            // end maybe faster
            H.push(sum);
        }
        a_vec = a;
        b_vec = b;
        G_vec = G;
        H_vec = H;
    }

    let a = a_vec[0];
    let b = b_vec[0];

    InnerProductProof { l_vec: L, r_vec: R, a, b }
}

/// This struct contains vectors of scalars that are needed for verification.
pub struct VerificationScalars<C: Curve>{
    pub u_sq: Vec<C::Scalar>,
    pub u_inv_sq: Vec<C::Scalar>,
    pub s: Vec<C::Scalar>,
}

/// This function calculates the verification scalars
/// that are used to verify an inner product proof. 
/// The arguments are
/// - proof - a reference to a inner product proof. 
/// - n - the number of elements in the vectors (of equal length) that was used to produce the inner product proof.
#[allow(non_snake_case)]
#[allow(clippy::many_single_char_names)]
pub fn verify_scalars<C: Curve>(
    transcript: &mut Transcript,
    n: usize,
    proof: &InnerProductProof<C>,
) -> VerificationScalars<C> {
    // let n = G_vec.len();
    let L = &proof.l_vec;
    let R = &proof.r_vec;
    let a = proof.a;
    let b = proof.b;
    let mut ab = a;
    ab.mul_assign(&b);

    let mut u_sq = Vec::with_capacity(L.len());
    let mut u_inv_sq = Vec::with_capacity(L.len());
    let mut s = Vec::with_capacity(n);
    let mut s_0 = C::Scalar::one();
    for j in 0..L.len() {
        transcript.append_point(b"Lj", &L[j]);
        transcript.append_point(b"Rj", &R[j]);
        let u_j: C::Scalar = transcript.challenge_scalar::<C>(b"uj");
        let u_j_inv = u_j.inverse().unwrap(); //TODO be careful here
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
    // s_2 =  u_k^{-1} ... u_2^{-1} u_1^{1} u_0^{-1} corresponding to the fact that 2 is 10 in binary
    // ...
    // s_5 =  u_k^{-1} ... u_0^{-1} u_0^{1} u_0^{-1} u_0^{1} corresponding to the fact that 5 is 101 in binary
    // ... and so on.
    // That is, to calculate s_i, the bits of i are distributed among the u_j's exponents but where 0 is replaced with -1.
    for i in 1..n {
        let lg_i = (32 - 1 - (i as u32).leading_zeros()) as usize;
        let k = 1 << lg_i;
        let mut s_i = s[i - k];
        s_i.mul_assign(&u_sq[L.len() - 1 - lg_i]);
        s.push(s_i);
    }
    VerificationScalars{u_sq, u_inv_sq, s}
}

/// This function verifies an inner product proof,
/// i.e. a proof of knowledge of vectors a and b such that P'=<a,G>+<b,H>+<a,b>Q.
/// The arguments are
/// - G_vec - the vector G of elliptic curve points 
/// - H_vec - the vector H of elliptic curve points 
/// - P_prime - the elliptic curve point P'
/// - Q - the elliptic curve point Q
/// - proof - the inner product proof
/// Precondictions:
/// G_vec, H_vec should all be of the same length, and this length must a power of 2. 
#[allow(dead_code)]
#[allow(non_snake_case)]
pub fn verify_inner_product<C: Curve>(
    transcript: &mut Transcript,
    G_vec: Vec<C>,
    H_vec: Vec<C>,
    P_prime: C,
    Q: C,
    proof: &InnerProductProof<C>,
) -> bool {
    let n = G_vec.len();
    let L = &proof.l_vec;
    let R = &proof.r_vec;
    let a = proof.a;
    let b = proof.b;
    let mut ab = a;
    ab.mul_assign(&b);

    let verification_scalars = verify_scalars(transcript, n, &proof);
    let (u_sq, u_inv_sq, s) = (verification_scalars.u_sq, verification_scalars.u_inv_sq, verification_scalars.s);


    let G = multiexp( &G_vec, &s);
    let mut s_inv = s;
    s_inv.reverse();
    let H = multiexp( &H_vec, &s_inv);

    let mut sum = C::zero_point();
    for j in 0..L.len() {
        sum = sum.plus_point(
            &(L[j]
                .mul_by_scalar(&u_sq[j])
                .plus_point(&(R[j].mul_by_scalar(&u_inv_sq[j])))),
        );
    }

    let RHS = G
        .mul_by_scalar(&a)
        .plus_point(&H.mul_by_scalar(&b))
        .plus_point(&Q.mul_by_scalar(&ab))
        .minus_point(&sum);
    P_prime.minus_point(&RHS).is_zero_point()
}

/// This function calculates the inner product between to vectors over any field F.
/// The arguments are
/// - a - the first vector
/// - b - the second vector
/// Precondition: 
/// a and b should have the same length.
#[allow(non_snake_case)]
pub fn inner_product<F: Field>(a: &[F], b: &[F]) -> F {
    let n = a.len();
    if b.len() != n {
        panic!("a and b should have the same length");
    }
    let mut sum = F::zero();
    for (a,b) in a.iter().zip(b) {
        let mut ab = *a;
        ab.mul_assign(b);
        sum.add_assign(&ab);
    }
    sum
}

#[cfg(test)]
mod tests {
    use super::*;
    // use pairing::bls12_381::FqRepr;
    use curve_arithmetic::{
        multiexp_table, multiexp_worker_given_table,
        // multiscalar_multiplication_naive,
    };
    use pairing::bls12_381::{Fr, G1};
    use ff::PrimeField;

    // use pairing::{
    //     bls12_381::{
    //         Bls12, Fq, Fr, FrRepr, G1Affine, G1Compressed, G1Prepared, G2Affine,
    // G2Compressed,         G2Prepared, G1, G2,
    //     },
    //     Engine, PairingCurveAffine,
    // };
    use rand::thread_rng;
    use std::{
        thread,
        time::{Duration, Instant},
    };
    type SomeCurve = G1;
    type SomeField = Fr;

    #[test]
    fn testinner() {
        let one = Fr::from_str("1").unwrap();
        let two = Fr::from_str("2").unwrap();
        let three = Fr::from_str("3").unwrap();
        let eleven = Fr::from_str("11").unwrap();

        let v = vec![one, two, three];
        let u = vec![three, one, two];
        let ip = inner_product(&v, &u);
        // Tests that <[1,2,3],[3,1,2]> = 11
        assert!(ip == eleven);
    }

    #[allow(non_snake_case)]
    #[test]
    fn test_msm_basic() {
        let rng = &mut thread_rng();
        let mut Gis = Vec::new();
        let g1 = SomeCurve::generate(rng);
        let g2 = G1::generate(rng);
        Gis.push(g1);
        Gis.push(g2);
        let mut ais = Vec::new();
        let a1 = SomeCurve::generate_scalar(rng);
        let a2 = SomeCurve::generate_scalar(rng);
        ais.push(a1);
        ais.push(a2);

        println!("Naively with two points and two scalars");
        let now = Instant::now();
        let a1g1 = g1.mul_by_scalar(&a1);
        let a2g2 = g2.mul_by_scalar(&a2);
        let mut sum = a1g1;
        sum = sum.plus_point(&a2g2);
        println!("Done in {} µs", now.elapsed().as_micros());
        println!("sum1: {}", sum);

        println!("Using fast msm with two points and two scalars");
        let now = Instant::now();
        let sum2 = multiexp( &Gis[..], &ais[..]);
        println!("Done in {} µs", now.elapsed().as_micros());
        println!("sum2: {}", sum2);
        assert_eq!(sum, sum2);
    }

    #[allow(non_snake_case)]
    #[test]
    fn test_msm_list() {
        let rng = &mut thread_rng();
        let n = 10000;
        let mut Gis = Vec::with_capacity(n);
        let mut ais = Vec::with_capacity(n);
        for _ in 0..n {
            let g = SomeCurve::generate(rng);
            Gis.push(g);
            let a = SomeCurve::generate_scalar(rng);
            ais.push(a);
        }

        let w = 8;
        let table = multiexp_table(&Gis, w);
        // let sum = multiexp_worker_given_table(&ais, &table, w);
        let mut list: Vec<SomeCurve> = Vec::with_capacity(n);

        println!("Naively creating list");
        let now = Instant::now();
        for i in 0..n {
            list.push(Gis[i].mul_by_scalar(&ais[i]));
        }
        println!("Done in {} ms", now.elapsed().as_millis());

        let mut list2: Vec<SomeCurve> = Vec::with_capacity(n);
        println!("Using fast msm to create list");
        let now = Instant::now();
        for i in 0..n {
            let table_vec = table[i].clone();
            let elem = multiexp_worker_given_table(&[ais[i]], &[table_vec], w);
            // let elem = multiexp( &[Gis[i]], &[ais[i]]);
            list2.push(elem);
        }
        println!("Done in {} ms", now.elapsed().as_millis());
        println!("Equal? {}", list == list2);
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_msm_bench() {
        let rng = &mut thread_rng();
        let n = 100000;
        let mut Gis = Vec::with_capacity(n);
        let mut ais = Vec::with_capacity(n);
        for _ in 0..n {
            let g = SomeCurve::generate(rng);
            Gis.push(g);
            let a = SomeCurve::generate_scalar(rng);
            ais.push(a);
        }

        println!("Doing msm in two go's");
        let now = Instant::now();
        let sum1 = multiexp( &Gis[..n / 2], &ais[..n / 2]);
        let sum2 = multiexp( &Gis[n / 2..], &ais[n / 2..]);
        let sum = sum1.plus_point(&sum2);

        println!("Done in {} ms", now.elapsed().as_millis());
        println!("sum: {}", sum);
        let sleeping_time = Duration::from_millis(3000);
        // let now = time::Instant::now();

        thread::sleep(sleeping_time);

        println!("Doing msm in one go");
        let now = Instant::now();
        let sum = multiexp( &Gis[..], &ais[..]);

        println!("Done in {} ms", now.elapsed().as_millis());
        println!("sum: {}", sum);
    }

    // #[allow(non_snake_case)]
    // #[test]
    // fn test_msm_with_one_vector() {
    //     let rng = &mut thread_rng();
    //     let mut Gis = Vec::new();
    //     // let mut ais = Vec::new();
    //     let n = 100000;
    //     let one = SomeField::one();
    //     let ais = vec![one; n];
    //     for _ in 0..n {
    //         let g = SomeCurve::generate(rng);
    //         Gis.push(g);
    //         // let a = SomeCurve::generate_scalar(rng);
    //         // ais.push(a);
    //     }

    //     println!("Doing msm naively");
    //     let now = Instant::now();
    //     let sum = multiscalar_multiplication_naive(&ais[..], &Gis[..]);

    //     println!("Done in {} ms", now.elapsed().as_millis());
    //     println!("sum: {}", sum);

    //     println!("Doing msm using wnaf stuff");
    //     let now = Instant::now();
    //     let sum = multiexp_worker(&Gis[..], &ais[..], 1); //(&ais[..], &Gis[..]);

    //     println!("Done in {} ms", now.elapsed().as_millis());
    //     println!("sum: {}", sum);
    // }

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
        let P_prime = multiexp( &G_vec, &a_vec)
            .plus_point(&multiexp( &H_vec, &b_vec))
            .plus_point(&Q.mul_by_scalar(&inner_product(&a_vec, &b_vec)));
        let mut transcript = Transcript::new(&[]);

        // Producing inner product proof with vector length = n
        let proof = prove_inner_product(
            &mut transcript,
            G_vec.clone(),
            H_vec.clone(),
            &Q,
            a_vec,
            b_vec,
        );

        let mut transcript = Transcript::new(&[]);            
        
        assert!(verify_inner_product(
            &mut transcript,
            G_vec,
            H_vec,
            P_prime,
            Q,
            &proof
        ))
    }

    #[test]
    #[allow(non_snake_case)]
    fn compare_inner_product_proof() {
        // Testing with n = 4
        let rng = &mut thread_rng();
        let n = 32 * 16;
        let mut G_vec = vec![];
        let mut H_vec = vec![];
        let mut a_vec = vec![];
        let mut b_vec = vec![];
        let y = SomeCurve::generate_scalar(rng);
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
        let H = H_vec.clone();
        let mut H_prime: Vec<SomeCurve> = Vec::with_capacity(n);
        let y_inv = y.inverse().unwrap();
        let mut y_inv_i = SomeField::one();
        let mut H_prime_scalars: Vec<SomeField> = Vec::with_capacity(n);
        for i in 0..n {
            H_prime.push(H[i].mul_by_scalar(&y_inv_i)); // 245 ms vs 126 ms or 625 ms vs 510
            H_prime_scalars.push(y_inv_i);
            y_inv_i.mul_assign(&y_inv);
        }
        let P_prime = multiexp( &G_vec, &a_vec)
            .plus_point(&multiexp( &H_prime, &b_vec))
            .plus_point(&Q.mul_by_scalar(&inner_product(&a_vec, &b_vec)));
        // let P_prime = SomeCurve::zero_point();
        let mut transcript = Transcript::new(&[]);

        println!("Producing inner product proof");
        let now = Instant::now();
        // let proof = prove_inner_product(&mut transcript, G_vec.clone(),
        // H_prime.clone(), &Q, a_vec, b_vec);
        let proof = prove_inner_product_with_scalars(
            &mut transcript,
            G_vec.clone(),
            H_vec.clone(),
            &H_prime_scalars,
            &Q,
            a_vec,
            b_vec,
        );
        println!("Done in {} ms", now.elapsed().as_millis());
        // let P_prime = P_prime_;

        let mut transcript = Transcript::new(&[]);
        println!(
            "{}",
            verify_inner_product(&mut transcript, G_vec, H_prime, P_prime, Q, &proof)
        );
        // assert!(verify_inner_product(&mut transcript, G_vec, H_vec, P_prime,
        // Q, proof));
    }
}
