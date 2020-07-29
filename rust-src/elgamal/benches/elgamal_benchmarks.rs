use rand::*;

#[macro_use]
extern crate criterion;

use criterion::Criterion;

use elgamal::{elgamal::*, public::*, secret::*};

use curve_arithmetic::Curve;
use ff::PrimeField;
use pairing::bls12_381::{Fr, G1};
use rayon::iter::ParallelIterator;
use std::time::Duration;

// Measure the time to enrypt a 64-bit integer bitwise.
pub fn encrypt_bitwise_bench(c: &mut Criterion) {
    let mut csprng = thread_rng();
    let sk: SecretKey<G1> = SecretKey::generate_all(&mut csprng);
    let pk = PublicKey::from(&sk);
    let n = csprng.next_u64();
    c.bench_function("encryption bitwise", move |b| {
        b.iter(|| encrypt_u64_bitwise_iter(pk, n).count())
    });
}

// Measure the time to decrypt a 64-bit integer bitwise.
pub fn decrypt_bitwise_bench(c: &mut Criterion) {
    let mut csprng = thread_rng();
    let sk: SecretKey<G1> = SecretKey::generate_all(&mut csprng);
    let pk = PublicKey::from(&sk);
    let n = csprng.next_u64();
    let p = encrypt_u64_bitwise(pk, n);
    c.bench_function("decryption bitwise", move |b| {
        b.iter(|| decrypt_u64_bitwise(&sk, &p))
    });
}

pub fn baby_step_giant_step_table_bench(c: &mut Criterion) {
    let mut csprng = thread_rng();
    let x = Fr::from_str("4294967295").unwrap();
    // let x = Fr::from_str("18446744073709551615").unwrap();
    // let x = Fr::from_str("65535").unwrap();
    let h = G1::generate(&mut csprng);
    let hx = h.mul_by_scalar(&x);
    let x = 4294967295;
    let m = 65536;
    let k = 65536;

    c.bench_function("repeat 8 times", move |b| {
        // Takes around 20 sec for sample size = 2
        b.iter(|| {
            assert_eq!(baby_step_giant_step(&hx, &h, m, k), x);
            assert_eq!(baby_step_giant_step(&hx, &h, m, k), x);
            assert_eq!(baby_step_giant_step(&hx, &h, m, k), x);
            assert_eq!(baby_step_giant_step(&hx, &h, m, k), x);
            assert_eq!(baby_step_giant_step(&hx, &h, m, k), x);
            assert_eq!(baby_step_giant_step(&hx, &h, m, k), x);
            assert_eq!(baby_step_giant_step(&hx, &h, m, k), x);
            assert_eq!(baby_step_giant_step(&hx, &h, m, k), x);
        })
    });
    c.bench_function("reuse table 8 times, m=k=2^16", move |b| {
        b.iter(|| {
            let (table, base_m) = baby_step_giant_step_table(&h, m);
            assert_eq!(
                baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                x
            );
            assert_eq!(
                baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                x
            );
            assert_eq!(
                baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                x
            );
            assert_eq!(
                baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                x
            );
            assert_eq!(
                baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                x
            );
            assert_eq!(
                baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                x
            );
            assert_eq!(
                baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                x
            );
            assert_eq!(
                baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                x
            );
        })
    });

    // In the following we compute the table once and compute the discrete log using
    // the baby step giant step-algorithm 8 times. In total that is m+8k
    // iterations which (if mk=2^32) is minimal when k = 2^(14,5) and m=2^(17,5).
    // Below we do menchmarks for different choices of (m,k) that are "near"
    // (2^(17,5), 2^(14,5)).

    let m = 262144;
    let k = 16384;
    c.bench_function("reuse table 8 times using m = 2^18, k = 2^14", move |b| {
        b.iter(|| {
            let (table, base_m) = baby_step_giant_step_table(&h, m);
            assert_eq!(
                baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                x
            );
            assert_eq!(
                baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                x
            );
            assert_eq!(
                baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                x
            );
            assert_eq!(
                baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                x
            );
            assert_eq!(
                baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                x
            );
            assert_eq!(
                baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                x
            );
            assert_eq!(
                baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                x
            );
            assert_eq!(
                baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                x
            );
        })
    });

    let m = 185364;
    let k = 23171;
    c.bench_function(
        "reuse table 8 times using m = 185363, k = 23171",
        move |b| {
            b.iter(|| {
                let (table, base_m) = baby_step_giant_step_table(&h, m);
                assert_eq!(
                    baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                    x
                );
                assert_eq!(
                    baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                    x
                );
                assert_eq!(
                    baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                    x
                );
                assert_eq!(
                    baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                    x
                );
                assert_eq!(
                    baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                    x
                );
                assert_eq!(
                    baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                    x
                );
                assert_eq!(
                    baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                    x
                );
                assert_eq!(
                    baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                    x
                );
            })
        },
    );

    let m = 180000;
    let k = 23861;
    c.bench_function(
        "reuse table 8 times using m = 180000, k = 23861",
        move |b| {
            b.iter(|| {
                let (table, base_m) = baby_step_giant_step_table(&h, m);
                assert_eq!(
                    baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                    x
                );
                assert_eq!(
                    baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                    x
                );
                assert_eq!(
                    baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                    x
                );
                assert_eq!(
                    baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                    x
                );
                assert_eq!(
                    baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                    x
                );
                assert_eq!(
                    baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                    x
                );
                assert_eq!(
                    baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                    x
                );
                assert_eq!(
                    baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                    x
                );
            })
        },
    );

    let m = 170000;
    let k = 25265;
    c.bench_function(
        "reuse table 8 times using m = 170000, k = 25265",
        move |b| {
            b.iter(|| {
                let (table, base_m) = baby_step_giant_step_table(&h, m);
                assert_eq!(
                    baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                    x
                );
                assert_eq!(
                    baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                    x
                );
                assert_eq!(
                    baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                    x
                );
                assert_eq!(
                    baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                    x
                );
                assert_eq!(
                    baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                    x
                );
                assert_eq!(
                    baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                    x
                );
                assert_eq!(
                    baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                    x
                );
                assert_eq!(
                    baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
                    x
                );
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
        b.iter(|| assert_eq!(baby_step_giant_step(&hx, &h, 65536, 65536), 4294967295))
    });
    // c.bench_function("baby step giant step ", move |b| { // This seems to take a
    // lot of time     b.iter(|| assert_eq!(baby_step_giant_step(&hx, &h,
    // 4294967296, 4294967296), 18446744073709551615)) });

    c.bench_function("baby step giant step m=32768, k=131072", move |b| {
        b.iter(|| assert_eq!(baby_step_giant_step(&hx, &h, 32768, 131072), 4294967295))
    });

    c.bench_function("baby step giant step m=131072, k=32768", move |b| {
        b.iter(|| assert_eq!(baby_step_giant_step(&hx, &h, 131072, 32768), 4294967295))
    });

    c.bench_function("baby step giant step m=60000, k=71583", move |b| {
        b.iter(|| assert_eq!(baby_step_giant_step(&hx, &h, 60000, 71583), 4294967295))
    });
    c.bench_function("baby step giant step m=71583, k=60000", move |b| {
        b.iter(|| assert_eq!(baby_step_giant_step(&hx, &h, 71583, 60000), 4294967295))
    });
}

criterion_group! {
    name = elgamal_benches;
    config = Criterion::default().measurement_time(Duration::from_millis(1000)).sample_size(2);
    targets =
        encrypt_bitwise_bench,
        decrypt_bitwise_bench,
        baby_step_giant_step_table_bench,
        baby_step_giant_step_bench
}

criterion_main!(elgamal_benches);
