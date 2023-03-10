#[macro_use]
extern crate criterion;
extern crate curve_arithmetic;

use criterion::Criterion;
use crypto_common::{Deserial, Serial};
use curve_arithmetic::*;
use pairing::bls12_381::{G1, G2};
use rand::*;

pub fn bench_serialize_g1(c: &mut Criterion) {
    let mut csprng = thread_rng();
    let elem = G1::generate(&mut csprng);
    let mut buf = Vec::with_capacity(48);
    c.bench_function("serialize G1 element", move |b| {
        b.iter(|| elem.serial(&mut buf))
    });
}

pub fn bench_deserialize_g1(c: &mut Criterion) {
    let mut csprng = thread_rng();
    let elem = G1::generate(&mut csprng);
    let mut buf = Vec::new();
    elem.serial(&mut buf);
    c.bench_function("deserialize G1 element", move |b| {
        b.iter(|| G1::deserial(&mut std::io::Cursor::new(&buf)).expect("Deserialization succeeds."))
    });
}

pub fn bench_serialize_g2(c: &mut Criterion) {
    let mut csprng = thread_rng();
    let elem = G2::generate(&mut csprng);
    let mut buf = Vec::with_capacity(96);
    c.bench_function("serialize G2 element", move |b| {
        b.iter(|| elem.serial(&mut buf))
    });
}

pub fn bench_deserialize_g2(c: &mut Criterion) {
    let mut csprng = thread_rng();
    let elem = G2::generate(&mut csprng);
    let mut buf = Vec::new();
    elem.serial(&mut buf);
    c.bench_function("deserialize G2 element", move |b| {
        b.iter(|| G2::deserial(&mut std::io::Cursor::new(&buf)).expect("Deserialization succeeds."))
    });
}

// criterion_group!(hash_to_fq, bench_hash_to_fq);
criterion_group!(
    bls_12_serialization,
    bench_serialize_g1,
    bench_deserialize_g1,
    bench_serialize_g2,
    bench_deserialize_g2
);
criterion_main!(bls_12_serialization);
