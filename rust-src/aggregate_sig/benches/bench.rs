#[macro_use]
extern crate criterion;
extern crate aggregate_sig;
extern crate rand;

use aggregate_sig::*;
use criterion::Criterion;
use pairing::bls12_381::Bls12;
use rand::{thread_rng, Rng};

macro_rules! rand_m_of_length {
    ($length:expr, $rng:expr) => {{
        let mut m: Vec<u8> = Vec::with_capacity($length);
        for _ in 0..$length {
            m.push($rng.gen::<u8>());
        }
        m
    }};
}

fn bench_sign_and_verify(c: &mut Criterion) {
    let mut csprng = thread_rng();
    let m = rand_m_of_length!(1000, csprng);
    let m_clone = m.clone();

    let sk = SecretKey::<Bls12>::generate(&mut csprng);
    let pk = PublicKey::<Bls12>::from_secret(&sk);
    let sig = sign_message(&sk, m.as_slice());
    c.bench_function("sign {}", move |b| {
        b.iter(|| sign_message(&sk, m.as_slice()))
    });
    c.bench_function("verify {}", move |b| {
        b.iter(|| verify(m_clone.as_slice(), &pk, &sig))
    });
}

// fn bench_aggregate_sig(c: &mut Criterion) {
//     let mut csprng = thread_rng();
//     let m = rand_m_of_length!(1000, csprng);
//
//     (sks, pks) = get_sks_pks!();
//
// }

criterion_group!(benches, bench_sign_and_verify);
criterion_main!(benches);
