#[macro_use]
extern crate criterion;
extern crate ed25519_dalek;
extern crate rand;

use criterion::Criterion;
use ed25519_dalek::*;
use rand::*;

fn bench_sign(c: &mut Criterion) {
    let mut csprng = thread_rng();
    let mut a: Vec<u8> = Vec::new();
    for _ in 0..1000 {
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

// fn fuck(sk:ExpandedSecretKey, pk:PublicKey, msg:Vec<u8>){
// sk.sign(msg.as_slice(), &pk);
// }
//
// fn fibonacci(n: u64) -> u64 {
// match n {
// 0 => 1,
// 1 => 1,
// n => fibonacci(n-1) + fibonacci(n-2),
// }
// }
//
// fn criterion_benchmark(c: &mut Criterion) {
// c.bench_function("fib 20", |b| b.iter(|| fibonacci(black_box(20))));
// }

criterion_group!(benches, bench_sign);
criterion_main!(benches);
