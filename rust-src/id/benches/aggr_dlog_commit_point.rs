use criterion::*;
use curve_arithmetic::*;
use id::sigma_protocols::{aggregate_dlog::*, common::*};
use pairing::bls12_381::G1;
use rand::*;
use std::rc::Rc;

/// Benchmark the aggregate dlog sigma protocol
fn bench_aggr_dlog_commit_point(c: &mut Criterion) {
    let mut csprng = thread_rng();
    let number_of_coeffs = 42;
    let mut coeffs = Vec::with_capacity(number_of_coeffs);
    let mut secrets = Vec::with_capacity(number_of_coeffs);
    let mut public_key = G1::zero_point();
    for _ in 0..number_of_coeffs {
        let g = G1::generate(&mut csprng);
        let s = G1::generate_non_zero_scalar(&mut csprng);
        coeffs.push(g);
        secrets.push(Rc::new(s));
        public_key = public_key.plus_point(&g.mul_by_scalar(&s));
    }
    let dlog = AggregateDlog {
        public: public_key,
        coeff:  coeffs,
    };
    c.bench_function("Aggregate dlog commit point", move |b| {
        b.iter(|| dlog.commit_point(&secrets, &mut csprng))
    });
}

criterion_group!(commit_point_benchmarks, bench_aggr_dlog_commit_point);
criterion_main!(commit_point_benchmarks);
