#[macro_use]
extern crate criterion;

use criterion::Criterion;
use curve_arithmetic::*;
use pairing::bls12_381::G1;
use rand::*;

pub fn bench_multiexp(c: &mut Criterion) {
    let mut csprng = thread_rng();
    let m = 10;
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
        group.bench_function("Baseline", move |b| {
            b.iter(|| {
                let mut a = G1::zero_point();
                for (g, e) in (&gsc).iter().zip((&esc).iter()) {
                    a = a.plus_point(&g.mul_by_scalar(e))
                }
            })
        });
        for w in 2..=8 {
            let gsc = gs[..i].to_vec();
            let esc = es[..i].to_vec();
            group.bench_function(&format!("multiexp({})", w), move |b| {
                b.iter(|| multiexp_worker(&gsc, &esc, w))
            });
        }
        group.finish();
    }
}

criterion_group!(multiexp_benchmarks, bench_multiexp);
criterion_main!(multiexp_benchmarks);
