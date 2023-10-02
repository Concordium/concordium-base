#![allow(non_snake_case)]

use criterion::*;
use rand::*;
use std::time::Duration;


use curve25519_dalek_ng::scalar::Scalar;
use merlin::Transcript;
use bulletproofs::RangeProof;
use bulletproofs::{BulletproofGens, PedersenGens};


pub fn prove_verify_benchmarks(c: &mut Criterion) {
    let n: usize = 32;
    let m: usize = 16;
    let mut group = c.benchmark_group("Range Proof over Dalek Curves");
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(n, m);
    let mut rng = rand::thread_rng();
    let (min, max) = (0u64, ((1u128 << n) - 1) as u64);
    let values: Vec<u64> = (0..m).map(|_| rng.gen_range(min, max)).collect();
    let blindings: Vec<Scalar> = (0..m).map(|_| Scalar::random(&mut rng)).collect();
    let mut transcript = Transcript::new(b"AggregateRangeProofBenchmark");    

    group.bench_function("Prove", move |b| {
        b.iter(|| {
            RangeProof::prove_multiple(
                &bp_gens,
                &pc_gens,
                &mut transcript,
                &values,
                &blindings,
                n,
            )
        })
    });

    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(n, m);
    let mut rng = rand::thread_rng();
    let (min, max) = (0u64, ((1u128 << n) - 1) as u64);
    let values: Vec<u64> = (0..m).map(|_| rng.gen_range(min, max)).collect();
    let blindings: Vec<Scalar> = (0..m).map(|_| Scalar::random(&mut rng)).collect();
    let mut transcript = Transcript::new(b"AggregateRangeProofBenchmark");    let (proof, value_commitments) = RangeProof::prove_multiple(
        &bp_gens,
        &pc_gens,
        &mut transcript,
        &values,
        &blindings,
        n,
    )
    .unwrap();

    group.bench_function("Verify Efficient", move |b| {
        b.iter(|| {
            let mut transcript = Transcript::new(b"AggregateRangeProofBenchmark");
            assert!(proof.verify_multiple(&bp_gens, &pc_gens, &mut transcript, &value_commitments, n)
            .is_ok());
        })
    });
}

criterion_group!(
    name = benchmarks;
    config = Criterion::default().measurement_time(Duration::from_millis(1000)).sample_size(10);
    targets = prove_verify_benchmarks);
criterion_main!(benchmarks);