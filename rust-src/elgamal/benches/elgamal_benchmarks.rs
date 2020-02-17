use rand::*;

#[macro_use]
extern crate criterion;

use criterion::Criterion;

use elgamal::{elgamal::*, public::*, secret::*};

use pairing::bls12_381::G1;
use rayon::iter::ParallelIterator;

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

criterion_group! {
    name = elgamal_benches;
    config = Criterion::default();
    targets =
        encrypt_bitwise_bench,
        decrypt_bitwise_bench,
}

criterion_main!(elgamal_benches);
