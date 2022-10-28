#![allow(non_snake_case)]

#[macro_use]
extern crate criterion;

use criterion::Criterion;
use curve_arithmetic::*;
use ff::Field;
use pairing::bls12_381::{Fr, G1};
use pedersen_scheme::*;
use rand::*;
use random_oracle::RandomOracle;

use std::time::Duration;

use bulletproofs::{inner_product_proof::*, range_proof::*, utils::Generators};

type SomeCurve = G1;
type SomeField = Fr;

pub fn prove_verify_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("Range Proof");

    let rng = &mut thread_rng();
    let n: u8 = 32;
    let m: u8 = 16;
    let nm: usize = usize::from(n) * usize::from(m);
    let mut G = Vec::with_capacity(nm);
    let mut H = Vec::with_capacity(nm);
    let mut G_H = Vec::with_capacity(nm);
    let mut randomness = Vec::with_capacity(usize::from(m));
    let mut commitments = Vec::with_capacity(usize::from(m));

    for _ in 0..nm {
        let g = SomeCurve::generate(rng);
        let h = SomeCurve::generate(rng);

        G.push(g);
        H.push(h);
        G_H.push((g, h));
    }
    let B = SomeCurve::generate(rng);
    let B_tilde = SomeCurve::generate(rng);
    let gens = Generators { G_H };
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
    let v_vec_p = v_vec.clone();
    let gens_p = gens.clone();
    let randomness_p = randomness.clone();
    let mut transcript = RandomOracle::empty();
    group.bench_function("Prove", move |b| {
        b.iter(|| {
            prove(
                &mut transcript,
                rng,
                n,
                m,
                &v_vec_p,
                &gens_p,
                &keys,
                &randomness_p,
            );
        })
    });

    let rng = &mut thread_rng();
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
    let proof = proof.unwrap();

    group.bench_function("Verify Efficient", move |b| {
        b.iter(|| {
            let mut transcript = RandomOracle::empty();
            assert!(
                verify_efficient(&mut transcript, n, &commitments, &proof, &gens, &keys).is_ok()
            );
        })
    });
}

#[allow(non_snake_case)]
fn compare_inner_product_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("Inner-Product Proof");

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
    let mut H_prime_scalars: Vec<SomeField> = Vec::with_capacity(n);
    let mut transcript = RandomOracle::empty();
    let G_vec_p = G_vec.clone();
    let H_vec_p = H_vec.clone();
    let a_vec_p = a_vec.clone();
    let b_vec_p = b_vec.clone();
    group.bench_function("Naive inner product proof", move |b| {
        b.iter(|| {
            let mut y_inv_i = SomeField::one();
            for h in H.iter().take(n) {
                H_prime.push(h.mul_by_scalar(&y_inv_i));
                y_inv_i.mul_assign(&y_inv);
            }
            prove_inner_product(&mut transcript, &G_vec, &H_prime, &Q, &a_vec, &b_vec);
        })
    });
    let mut transcript = RandomOracle::empty();
    group.bench_function("Better inner product proof with scalars", move |b| {
        b.iter(|| {
            let mut y_inv_i = SomeField::one();
            for _ in 0..n {
                H_prime_scalars.push(y_inv_i);
                y_inv_i.mul_assign(&y_inv);
            }
            prove_inner_product_with_scalars(
                &mut transcript,
                &G_vec_p,
                &H_vec_p,
                &H_prime_scalars,
                &Q,
                &a_vec_p,
                &b_vec_p,
            );
        })
    });
}

criterion_group!(
    name = benchmarks;
    config = Criterion::default().measurement_time(Duration::from_millis(1000)).sample_size(10);
    targets = prove_verify_benchmarks, compare_inner_product_proof);
criterion_main!(benchmarks);
