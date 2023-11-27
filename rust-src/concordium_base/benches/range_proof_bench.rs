#![allow(non_snake_case)]

#[macro_use]
extern crate criterion;

use concordium_base::{
    bulletproofs::{range_proof::*, utils::Generators},
    curve_arithmetic::*,
    id::id_proof_types::ProofVersion,
    pedersen_commitment::*,
    random_oracle::RandomOracle,
};
use criterion::Criterion;
use curve25519_dalek::ristretto::RistrettoPoint;
use pairing::bls12_381::G1;
use pprof::criterion::Output;
use rand::*;
use std::time::Duration;

pub fn prove_verify_benchmarks<SomeCurve: Curve>(c: &mut Criterion) {
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
                ProofVersion::Version1,
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
        ProofVersion::Version1,
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
            assert!(verify_efficient(
                ProofVersion::Version1,
                &mut transcript,
                n,
                &commitments,
                &proof,
                &gens,
                &keys
            )
            .is_ok());
        })
    });
}

criterion_group!(
    name = benchmarks;
    config = Criterion::default().measurement_time(Duration::from_millis(1000)).sample_size(10).with_profiler(
        pprof::criterion::PProfProfiler::new(100, Output::Flamegraph(None))
    );
    targets =
    prove_verify_benchmarks::<G1>,
    prove_verify_benchmarks::<RistrettoPoint>,
);
criterion_main!(benchmarks);
