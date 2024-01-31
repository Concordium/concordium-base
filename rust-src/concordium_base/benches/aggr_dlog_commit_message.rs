use ark_bls12_381::G1Projective;
use concordium_base::{
    curve_arithmetic::{arkworks_instances::ArkGroup, *},
    sigma_protocols::{aggregate_dlog::*, common::*},
};
use criterion::*;
use rand::*;

type G1 = ArkGroup<G1Projective>;

/// Benchmark the aggregate dlog sigma protocol
fn bench_aggr_dlog_commit_message(c: &mut Criterion) {
    let mut csprng = thread_rng();
    let number_of_coeffs = 42;
    let mut coeffs = Vec::with_capacity(number_of_coeffs);
    for _ in 0..number_of_coeffs {
        coeffs.push(G1::generate(&mut csprng));
    }
    let public_key = G1::generate(&mut csprng);
    let dlog = AggregateDlog {
        public: public_key,
        coeff:  coeffs,
    };
    c.bench_function("Aggregate dlog commit message", move |b| {
        b.iter(|| dlog.compute_commit_message(&mut csprng))
    });
}

criterion_group!(commit_point_benchmarks, bench_aggr_dlog_commit_message);
criterion_main!(commit_point_benchmarks);
