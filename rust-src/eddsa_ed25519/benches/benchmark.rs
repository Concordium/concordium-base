#[macro_use]
extern crate criterion;
extern crate ed25519_dalek;
extern crate rand;

use criterion::Criterion;
use ed25519_dalek::*;
use rand::*;

fn bench_sign(c: &mut Criterion) {
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

criterion_group!(benches, bench_sign);
criterion_main!(benches);
