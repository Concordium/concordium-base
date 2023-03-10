#[macro_use]
extern crate criterion;
extern crate curve_arithmetic;

use criterion::Criterion;
use curve_arithmetic::*;
use pairing::bls12_381::G1;
use rand::*;

macro_rules! rand_m_of_length {
    ($length:expr, $rng:expr) => {{
        let mut m: Vec<u8> = Vec::with_capacity($length);
        for _ in 0..$length {
            m.push($rng.gen::<u8>());
        }
        m
    }};
}

pub fn bench_hash_to_curve(c: &mut Criterion) {
    let mut csprng = thread_rng();
    let msg = rand_m_of_length!(1000, csprng);
    c.bench_function("hash_to_g1", move |b| b.iter(|| G1::hash_to_group(&msg)));
}

// To run this benches do the following:
// - make bls12_381_g1hash pub in lib.rs
// - make hash_bytes_to_fq pub in bls12_381_g1hash.rs
//
// pub fn bench_hash_to_fq(c: &mut Criterion) {
//     let mut csprng = thread_rng();
//     let msg = rand_m_of_length!(1000, csprng);
//     let msg_clone = msg.clone();
//     c.bench_function("hash_to_fq {}", move |b| {
//         b.iter(|| hash_bytes_to_fq(&msg_clone))
//     });
// }

// criterion_group!(hash_to_fq, bench_hash_to_fq);
criterion_group!(hash_to_curve, bench_hash_to_curve);
criterion_main!(hash_to_curve);
