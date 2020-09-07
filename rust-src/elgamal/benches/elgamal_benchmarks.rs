use rand::*;

#[macro_use]
extern crate criterion;

use criterion::Criterion;

use elgamal::*;

use curve_arithmetic::Curve;
use ff::PrimeField;
use pairing::bls12_381::{Fr, G1};
use std::time::Duration;

pub fn baby_step_giant_step_table_bench(c: &mut Criterion) {
    let mut csprng = thread_rng();
    let x = Fr::from_str("4294967295").unwrap();
    // let x = Fr::from_str("18446744073709551615").unwrap();
    // let x = Fr::from_str("65535").unwrap();
    let h = G1::generate(&mut csprng);
    let hx = h.mul_by_scalar(&x);
    let x = 4294967295;
    let m = 65536;

    c.bench_function("repeat 8 times", move |b| {
        // Takes around 20 sec for sample size = 2
        b.iter(|| {
            assert_eq!(BabyStepGiantStep::discrete_log_full(&h, m, &hx), x);
            assert_eq!(BabyStepGiantStep::discrete_log_full(&h, m, &hx), x);
            assert_eq!(BabyStepGiantStep::discrete_log_full(&h, m, &hx), x);
            assert_eq!(BabyStepGiantStep::discrete_log_full(&h, m, &hx), x);
            assert_eq!(BabyStepGiantStep::discrete_log_full(&h, m, &hx), x);
            assert_eq!(BabyStepGiantStep::discrete_log_full(&h, m, &hx), x);
            assert_eq!(BabyStepGiantStep::discrete_log_full(&h, m, &hx), x);
            assert_eq!(BabyStepGiantStep::discrete_log_full(&h, m, &hx), x);
        })
    });
    c.bench_function("reuse table 8 times, m=k=2^16", move |b| {
        b.iter(|| {
            let bsgs = BabyStepGiantStep::new(&h, m);
            for _ in 0..8 {
                assert_eq!(bsgs.discrete_log(&hx), x);
            }
        })
    });

    // In the following we compute the table once and compute the discrete log using
    // the baby step giant step-algorithm 8 times. In total that is m+8k
    // iterations which (if mk=2^32) is minimal when k = 2^(14,5) and m=2^(17,5).
    // Below we do menchmarks for different choices of (m,k) that are "near"
    // (2^(17,5), 2^(14,5)).

    let m = 262144;
    c.bench_function("reuse table 8 times using m = 2^18, k = 2^14", move |b| {
        b.iter(|| {
            let bsgs = BabyStepGiantStep::new(&h, m);
            for _ in 0..8 {
                assert_eq!(bsgs.discrete_log(&hx), x);
            }
        })
    });

    let m = 185364;
    c.bench_function(
        "reuse table 8 times using m = 185363, k = 23171",
        move |b| {
            b.iter(|| {
                let bsgs = BabyStepGiantStep::new(&h, m);
                for _ in 0..8 {
                    assert_eq!(bsgs.discrete_log(&hx), x);
                }
            })
        },
    );

    let m = 180000;
    c.bench_function(
        "reuse table 8 times using m = 180000, k = 23861",
        move |b| {
            b.iter(|| {
                let bsgs = BabyStepGiantStep::new(&h, m);
                for _ in 0..8 {
                    assert_eq!(bsgs.discrete_log(&hx), x);
                }
            })
        },
    );

    let m = 170000;
    c.bench_function(
        "reuse table 8 times using m = 170000, k = 25265",
        move |b| {
            b.iter(|| {
                let bsgs = BabyStepGiantStep::new(&h, m);
                for _ in 0..8 {
                    assert_eq!(bsgs.discrete_log(&hx), x);
                }
            })
        },
    );
}

pub fn baby_step_giant_step_bench(c: &mut Criterion) {
    let mut csprng = thread_rng();
    let x = Fr::from_str("4294967295").unwrap();
    // let x = Fr::from_str("18446744073709551615").unwrap();
    // let x = Fr::from_str("65535").unwrap();
    let h = G1::generate(&mut csprng);
    let hx = h.mul_by_scalar(&x);

    c.bench_function("baby step giant step m=k=65536", move |b| {
        b.iter(|| {
            assert_eq!(
                BabyStepGiantStep::discrete_log_full(&h, 65536, &hx),
                4294967295
            )
        })
    });
    // c.bench_function("baby step giant step ", move |b| { // This seems to take a
    // lot of time     b.iter(|| assert_eq!(baby_step_giant_step(&hx, &h,
    // 4294967296, 4294967296), 18446744073709551615)) });

    c.bench_function("baby step giant step m=32768, k=131072", move |b| {
        b.iter(|| {
            assert_eq!(
                BabyStepGiantStep::discrete_log_full(&h, 32768, &hx),
                4294967295
            )
        })
    });

    c.bench_function("baby step giant step m=131072, k=32768", move |b| {
        b.iter(|| {
            assert_eq!(
                BabyStepGiantStep::discrete_log_full(&h, 131072, &hx),
                4294967295
            )
        })
    });

    c.bench_function("baby step giant step m=60000, k=71583", move |b| {
        b.iter(|| {
            assert_eq!(
                BabyStepGiantStep::discrete_log_full(&h, 60000, &hx),
                4294967295
            )
        })
    });
    c.bench_function("baby step giant step m=71583, k=60000", move |b| {
        b.iter(|| {
            assert_eq!(
                BabyStepGiantStep::discrete_log_full(&h, 71583, &hx),
                4294967295
            )
        })
    });
}

criterion_group! {
    name = elgamal_benches;
    config = Criterion::default().measurement_time(Duration::from_millis(1000)).sample_size(2);
    targets =
        baby_step_giant_step_table_bench,
        baby_step_giant_step_bench
}

criterion_main!(elgamal_benches);
