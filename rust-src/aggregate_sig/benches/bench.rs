#[macro_use]
extern crate criterion;
extern crate rand;

extern crate aggregate_sig;
use aggregate_sig::aggregate_sig::*;

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

macro_rules! get_sks_pks {
    ($amt:expr, $rng:expr) => {{
        let sks: Vec<SecretKey<Bls12>> = (0..$amt)
            .map(|_| SecretKey::<Bls12>::generate(&mut $rng))
            .collect();

        let pks: Vec<PublicKey<Bls12>> = sks
            .iter()
            .map(|x| PublicKey::<Bls12>::from_secret(x))
            .collect();

        (sks, pks)
    };};
}

fn bench_sign_and_verify(c: &mut Criterion) {
    let mut csprng = thread_rng();
    let m = rand_m_of_length!(1000, csprng);
    let m_clone = m.clone();

    let sk = SecretKey::<Bls12>::generate(&mut csprng);
    let pk = PublicKey::<Bls12>::from_secret(&sk);
    let sig = sign_message(&sk, m.as_slice());
    c.bench_function("sign", move |b| b.iter(|| sign_message(&sk, m.as_slice())));
    c.bench_function("verify", move |b| {
        b.iter(|| verify(m_clone.as_slice(), &pk, &sig))
    });
}

fn bench_aggregate_sig(c: &mut Criterion) {
    let mut csprng = thread_rng();

    let sk1 = SecretKey::<Bls12>::generate(&mut csprng);
    let sk2 = SecretKey::<Bls12>::generate(&mut csprng);

    let m1 = rand_m_of_length!(1000, csprng);
    let m2 = rand_m_of_length!(1000, csprng);
    let sig1 = sign_message(&sk1, &m1);
    let sig2 = sign_message(&sk2, &m2);
    // TODO, make code below work

    c.bench_function("aggregate_signature", move |b| {
        b.iter(|| aggregate_sig(sig1.clone(), sig2.clone()))
    });
}

fn bench_verify_aggregate_sig(c: &mut Criterion) {
    let mut csprng = thread_rng();
    let n = 200;
    let (sks, pks) = get_sks_pks!(n, csprng);

    let mut ms: Vec<_> = Vec::with_capacity(n);
    for i in 0..n {
        let m = rand_m_of_length!(1000, csprng);
        ms[i] = m;
    }

    let mut m_pk_pairs: Vec<(&[u8], PublicKey<Bls12>)> = Vec::with_capacity(n);
    for i in 0..n {
        let m_pk = (ms[i].as_slice(), pks[i].clone());
        m_pk_pairs.push(m_pk);
    }

    let mut agg_sig = sign_message(&sks[0], &ms[0]);
    for i in 1..n {
        let new_sig = sign_message(&sks[i], &ms[i]);
        agg_sig = aggregate_sig(new_sig, agg_sig);
    }
    let m_pk_pairs_clone = m_pk_pairs.clone();
    let agg_sig_clone = agg_sig.clone();

    c.bench_function("verify_aggregate_v1", move |b| {
        b.iter(|| verify_aggregate_sig_v1(&m_pk_pairs_clone.clone(), agg_sig_clone.clone()))
    });

    let m_pk_pairs_clone = m_pk_pairs.clone();
    let agg_sig_clone = agg_sig.clone();
    c.bench_function("verify_aggregate_v2", move |b| {
        b.iter(|| verify_aggregate_sig_v1(&m_pk_pairs_clone.clone(), agg_sig_clone.clone()))
    });
}

criterion_group!(sign_and_verify, bench_sign_and_verify);
criterion_group!(aggregate, bench_aggregate_sig);
criterion_main!(sign_and_verify, aggregate);
