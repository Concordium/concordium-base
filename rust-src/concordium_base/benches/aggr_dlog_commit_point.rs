use criterion::*;
use curve_arithmetic::*;
use id::sigma_protocols::{aggregate_dlog::*, common::*};
use pairing::bls12_381::G1;
use rand::*;

/// Benchmark the aggregate dlog sigma protocol
fn bench_aggr_dlog_commit_point(c: &mut Criterion) {
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
    c.bench_function("Aggregate dlog commit point", move |b| {
        b.iter(|| dlog.commit_point(&mut csprng))
    });
}

criterion_group!(commit_point_benchmarks, bench_aggr_dlog_commit_point);
criterion_main!(commit_point_benchmarks);
