#[macro_use]
extern crate criterion;

use concordium_base::curve_arithmetic::*;
use criterion::Criterion;
use curve25519_dalek::ristretto::RistrettoPoint;
use pairing::bls12_381::G1;
use rand::*;
use std::time::Duration;

pub fn bench_multiexp_bls(c: &mut Criterion) {
    let mut csprng = thread_rng();
    let m = 3;
    let ns = (1..=m).map(|x| x * x);
    let mut gs = Vec::with_capacity(m * m);
    let mut es = Vec::with_capacity(m * m);
    for _ in 0..(m * m) {
        gs.push(G1::generate(&mut csprng));
        es.push(G1::generate_scalar(&mut csprng));
    }

    for i in ns {
        let gsc = gs[..i].to_vec();
        let esc = es[..i].to_vec();
        let mut group = c.benchmark_group(format!("Group({})", i));
        group.bench_function(format!("{}: Baseline for BLS", module_path!()), move |b| {
            b.iter(|| {
                let mut a = G1::zero_point();
                for (g, e) in gsc.iter().zip(esc.iter()) {
                    a = a.plus_point(&g.mul_by_scalar(e))
                }
            })
        });
        for w in 2..=8 {
            let gsc = gs[..i].to_vec();
            let esc = es[..i].to_vec();
            group.bench_function(
                &format!("{}: Multiexp for BLS (window = {w})", module_path!()),
                move |b| b.iter(|| GenericMultiExp::new(&gsc, w).multiexp(&esc)),
            );
        }
        group.finish();
    }
}

// Benchmarking multi-exponentiation over the Ristretto curve. Note that we have
// two multiexp algorithms in our library: one that is tailor-made for the
// Ristretto curve, and one generic algorithm for other curves (e.g., BLS).
// The purpose of this benchmark is to measure the running time of the multiexp
// algorithm for the Ristretto curve.
pub fn bench_multiexp_ristretto(c: &mut Criterion) {
    let mut csprng = thread_rng();
    let m = 3;
    let ns = (1..=m).map(|x| x * x);
    let mut gs: Vec<RistrettoPoint> = Vec::with_capacity(m * m);
    let mut es: Vec<<RistrettoPoint as Curve>::Scalar> = Vec::with_capacity(m * m);
    for _ in 0..(m * m) {
        gs.push(RistrettoPoint::generate(&mut csprng));
        es.push(RistrettoPoint::generate_scalar(&mut csprng));
    }

    for i in ns {
        let gsc = gs[..i].to_vec();
        let esc = es[..i].to_vec();
        let mut group = c.benchmark_group(format!("Group({})", i));
        group.bench_function(
            format!("{}: Baseline for Ristretto", module_path!()),
            move |b| {
                b.iter(|| {
                    let mut a = RistrettoPoint::zero_point();
                    for (g, e) in gsc.iter().zip(esc.iter()) {
                        a = a.plus_point(&g.mul_by_scalar(e))
                    }
                })
            },
        );

        let gsc = gs[..i].to_vec();
        let esc = es[..i].to_vec();
        group.bench_function(
            format!("{}: Multiexp for Ristretto", module_path!()),
            move |b| {
                b.iter(|| {
                    // Create msm algorithm instance with a precomputed point table.
                    // For the Ristretto curve it will use the RistrettoMultiExpNoPrecompute and
                    // our generic implementation for the BLS curve.
                    let msm = RistrettoPoint::new_multiexp(&gsc);
                    msm.multiexp(&esc);
                })
            },
        );

        group.finish();
    }
}

criterion_group!(
    name = multiexp_benchmarks;
    config = Criterion::default().measurement_time(Duration::from_millis(10000)).sample_size(100);
    targets = bench_multiexp_bls, bench_multiexp_ristretto);
criterion_main!(multiexp_benchmarks);
