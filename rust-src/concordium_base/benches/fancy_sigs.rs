//! Benchmarks for the set-membership and set-non-membership proofs
#[macro_use]
extern crate criterion;

use bbs::{self, prelude::*};
use criterion::{BenchmarkId, Criterion};
use pairing::bls12_381::Bls12;
use rand::*;
use std::time::Duration;

#[allow(non_snake_case)]
pub fn bench_fancy_sigs(c: &mut Criterion) {
    let mut group = c.benchmark_group("Fancy Signatures");

    let csprng = &mut thread_rng();

    for i in 0..10 {
        let n = 2_usize.pow(i); // number of elements per message

        // PS signatures //
        // generate PS keys for a single message element
        let ps_sk = concordium_base::ps_sig::SecretKey::<Bls12>::generate(n, csprng);
        let ps_pk = concordium_base::ps_sig::PublicKey::from(&ps_sk);

        // generate random message to sign
        let ps_msg = concordium_base::ps_sig::KnownMessage::generate(n, csprng);

        // Generate valid signature for verification
        let ps_sig = ps_sk.sign_known_message(&ps_msg, csprng).unwrap();
        assert!(ps_pk.verify(&ps_sig, &ps_msg));

        // Bench signing message
        group.bench_function(BenchmarkId::new("PS Sign", n), |b| {
            b.iter(|| {
                ps_sk.sign_known_message(&ps_msg, csprng).unwrap();
            })
        });

        // Bench signature verification
        group.bench_function(BenchmarkId::new("PS Verify", n), |b| {
            b.iter(|| {
                ps_pk.verify(&ps_sig, &ps_msg);
            })
        });

        // BBS+ signatures //
        let (bbs_pk, bbs_sk) = bbs::keys::generate(n).unwrap();

        // generate random message to sign
        let mut bbs_msg = Vec::new();
        for _ in 0..n {
            let bbs_msg_i = bbs::SignatureMessage::random();
            bbs_msg.push(bbs_msg_i);
        }

        // Generate valid signature for verification
        let bbs_sig = bbs::signature::Signature::new(bbs_msg.as_slice(), &bbs_sk, &bbs_pk).unwrap();
        assert!(bbs_sig.verify(bbs_msg.as_slice(), &bbs_pk).unwrap());

        // Bench signing message
        group.bench_function(BenchmarkId::new("BBS+ Sign", n), |b| {
            b.iter(|| {
                bbs::signature::Signature::new(bbs_msg.as_slice(), &bbs_sk, &bbs_pk).unwrap();
            })
        });

        // Bench verifying message
        group.bench_function(BenchmarkId::new("BBS+ Verify", n), |b| {
            b.iter(|| {
                bbs_sig.verify(bbs_msg.as_slice(), &bbs_pk).unwrap();
            })
        });
    }
}

criterion_group!(
    name = fancy_sig_bench;
    config = Criterion::default().measurement_time(Duration::from_millis(1000)).sample_size(10);
    targets = bench_fancy_sigs);
criterion_main!(fancy_sig_bench);
