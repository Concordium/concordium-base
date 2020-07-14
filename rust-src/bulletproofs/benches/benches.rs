#![allow(non_snake_case)]

#[macro_use]
extern crate criterion;

use criterion::Criterion;
use curve_arithmetic::*;
use merlin::Transcript;
use pairing::bls12_381::G1;
use pedersen_scheme::*;
use rand::*;

use std::time::Duration;

use bulletproofs::range_proof::*;

type SomeCurve = G1;

pub fn prove_verify_benchmarks(c: &mut Criterion) {
    let rng = &mut thread_rng();
    let n: u8 = 32;
    let m: u8 = 16;
    let nm: usize = usize::from(n) * usize::from(m);
    let mut G = Vec::with_capacity(nm);
    let mut H = Vec::with_capacity(nm);
    let mut G_H = Vec::with_capacity(nm);

    for _ in 0..nm {
        let g = SomeCurve::generate(rng);
        let h = SomeCurve::generate(rng);

        G.push(g);
        H.push(h);
        G_H.push((g,h));
    }
    let B = SomeCurve::generate(rng);
    let B_tilde = SomeCurve::generate(rng);
    let gens = Generators{G_H};
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
    let v_vec_p = v_vec.clone();
    let G_p = G.clone();
    let H_p = H.clone();
    let gens_p = gens.clone();
    let mut transcript = Transcript::new(&[]);
    c.bench_function("Prover.", move |b| {
        b.iter(|| {
            prove(
                &mut transcript,
                rng,
                n,
                m,
                &v_vec_p,
                &gens_p,
                &keys,
            );
        })
    });

    let rng = &mut thread_rng();
    let mut transcript = Transcript::new(&[]);
    let (commitments, proof) = prove(
        &mut transcript,
        rng,
        n,
        m,
        &v_vec,
        &gens,
        &keys,
    );

    // c.bench_function("Verifier.", move |b| {
    //     b.iter(|| {
    //         let mut transcript = Transcript::new(&[]);
    //         assert!(verify_efficient(
    //             &mut transcript,
    //             n,
    //             &commitments,
    //             &proof,
    //             &G,
    //             &H,
    //             B,
    //             B_tilde,
    //         ));
    //     })
    // });
}

criterion_group!(
    name = benchmarks;
    config = Criterion::default().measurement_time(Duration::from_millis(1000)).sample_size(10);
    targets = prove_verify_benchmarks);
criterion_main!(benchmarks);
