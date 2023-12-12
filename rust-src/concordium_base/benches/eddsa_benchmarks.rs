#[macro_use]
extern crate criterion;
extern crate ed25519_dalek;
extern crate rand;

use criterion::Criterion;
use ed25519_dalek::*;
use rand::*;

pub fn bench_from_bytes(c: &mut Criterion) {
    let mut csprng = thread_rng();
    let mut a = [0u8; 32];
    csprng.fill_bytes(&mut a);
    c.bench_function("VerifyingKey::from_bytes {}", move |b| {
        b.iter(|| VerifyingKey::from_bytes(&a).is_ok())
    });
    c.bench_function("SigningKey::from_bytes {}", move |b| {
        b.iter(|| SigningKey::from_bytes(&a))
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

    let signing = SigningKey::generate(&mut csprng);
    let pk = signing.verifying_key();
    let sig = signing.sign(a.as_slice());
    c.bench_function("sign {}", move |b| b.iter(|| signing.sign(a.as_slice())));
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
