#[macro_use]
extern crate criterion;
extern crate ed25519_dalek;
extern crate rand;

use criterion::Criterion;
use ed25519_dalek::*;
use rand::*;

pub fn bench_from_bytes(c: &mut Criterion) {
    let mut csprng = thread_rng();
    let n = 32;
    let mut a: Vec<u8> = Vec::with_capacity(n);
    for _ in 0..n {
        a.push(csprng.gen::<u8>());
    }
    let ca = a.clone();
    c.bench_function("PublicKey::from_bytes {}", move |b| {
        b.iter(|| PublicKey::from_bytes(&a).is_ok())
    });
    c.bench_function("SecretKey::from_bytes {}", move |b| {
        b.iter(|| SecretKey::from_bytes(&ca).is_ok())
    });
}

pub fn bench_sign(c: &mut Criterion) {
    let mut csprng = thread_rng();
    let n = 1000;
    let mut a: Vec<u8> = Vec::with_capacity(n);
    for _ in 0..n {
        a.push(csprng.gen::<u8>());
    }
    let d = a.clone();

    let sk = SecretKey::generate(&mut csprng);
    let pk = PublicKey::from(&sk);
    let expanded_sk = ExpandedSecretKey::from(&sk);
    let sig = expanded_sk.sign(a.as_slice(), &pk);
    c.bench_function("sign {}", move |b| {
        b.iter(|| expanded_sk.sign(a.as_slice(), &pk))
    });
    c.bench_function("verify{}", move |b| {
        b.iter(|| pk.verify(d.as_slice(), &sig))
    });
}

criterion_group! {
    name = eddsa_benches;
    config = Criterion::default();
    targets = bench_sign, bench_from_bytes
}
criterion_main!(eddsa_benches);
