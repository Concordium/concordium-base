use aggregate_sig::*;

use criterion::*;
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
    ($n:expr, $rng:expr) => {{
        let sks: Vec<SecretKey<Bls12>> = (0..$n)
            .map(|_| SecretKey::<Bls12>::generate(&mut $rng))
            .collect();

        let pks: Vec<PublicKey<Bls12>> = sks.iter().map(PublicKey::<Bls12>::from_secret).collect();

        (sks, pks)
    }};
}

fn bench_sign_and_verify(c: &mut Criterion) {
    let mut csprng = thread_rng();
    let m = rand_m_of_length!(1000, csprng);
    let m_clone = m.clone();

    let sk = SecretKey::<Bls12>::generate(&mut csprng);
    let pk = PublicKey::<Bls12>::from_secret(&sk);
    let sig = sk.sign(m.as_slice());
    c.bench_function("sign", move |b| b.iter(|| sk.sign(m.as_slice())));
    c.bench_function("verify", move |b| {
        b.iter(|| pk.verify(m_clone.as_slice(), sig))
    });
}

fn bench_aggregate_sig(c: &mut Criterion) {
    let mut csprng = thread_rng();

    let sk1 = SecretKey::<Bls12>::generate(&mut csprng);
    let sk2 = SecretKey::<Bls12>::generate(&mut csprng);

    let m1 = rand_m_of_length!(1000, csprng);
    let m2 = rand_m_of_length!(1000, csprng);
    let sig1 = sk1.sign(&m1);
    let sig2 = sk2.sign(&m2);

    c.bench_function("aggregate_signature", move |b| {
        b.iter(|| sig1.aggregate(sig2))
    });
}

macro_rules! n_rand_ms_of_length {
    ($n:expr, $length:expr, $rng:expr) => {{
        let mut ms: Vec<_> = Vec::with_capacity($n);
        for _ in 0..$n {
            let m = rand_m_of_length!($length, $rng);
            ms.push(m);
        }
        ms
    }};
}

fn bench_verify_aggregate_sig(c: &mut Criterion) {
    let mut csprng = thread_rng();
    let n = 200;
    let (sks, pks) = get_sks_pks!(n, csprng);
    let ms: Vec<_> = n_rand_ms_of_length!(n, 1000, csprng);

    let mut agg_sig = sks[0].sign(&ms[0]);
    for i in 1..n {
        let new_sig = sks[i].sign(&ms[i]);
        agg_sig = new_sig.aggregate(agg_sig);
    }

    c.bench_function("verify_aggregate_sig", move |b| {
        let mut m_pk_pairs: Vec<(&[u8], PublicKey<Bls12>)> = Vec::with_capacity(n);
        for i in 0..n {
            let m_pk = (ms[i].as_slice(), pks[i]);
            m_pk_pairs.push(m_pk);
        }
        b.iter(|| verify_aggregate_sig(&m_pk_pairs, agg_sig))
    });
}

fn bench_verify_aggregate_sig_trusted_keys(c: &mut Criterion) {
    let mut csprng = thread_rng();

    let mut group = c.benchmark_group("verify_aggregate_sig_trusted_keys");

    // performance varies from the sequential version to the parallel version around
    // size = 150
    let sizes = vec![50, 100, 150, 200, 250, 300, 350, 400, 600, 1000, 1500, 3000];

    for s in sizes {
        let (sks, pks) = get_sks_pks!(s, csprng);
        let m = rand_m_of_length!(1000, csprng);

        let mut agg_sig = sks[0].sign(&m);
        for i in 1..s {
            let new_sig = sks[i].sign(&m);
            agg_sig = new_sig.aggregate(agg_sig);
        }

        group.bench_function(
            format!("verify_aggregate_sig_trusted_keys_{}", s),
            move |b| b.iter(|| verify_aggregate_sig_trusted_keys(&m, &pks, agg_sig)),
        );
    }

    group.finish();
}

// to bench has_duplicates, expose it in aggregate_sig.rs by making it public
//
// fn bench_has_duplicates(c: &mut Criterion) {
//     let mut csprng = thread_rng();
//     let n = 200;
//     let mut ms: Vec<_> = Vec::new();
//     for _ in 0..n {
//         let m = rand_m_of_length!(n, csprng);
//         ms.push(m);
//     }
//
//     c.bench_function("has_duplicates", move |b| {
//         let ms: Vec<&[u8]> = ms.iter().map(|x| x.as_slice()).collect();
//         b.iter(|| has_duplicates(ms.clone()))
//     });
// }

criterion_group!(sign_and_verify, bench_sign_and_verify);
criterion_group!(aggregate, bench_aggregate_sig);
criterion_group!(verify_aggregate, bench_verify_aggregate_sig);
criterion_group!(
    verify_aggregate_trusted_keys,
    bench_verify_aggregate_sig_trusted_keys
);
// criterion_group!(has_dups, bench_has_duplicates);
criterion_main!(
    // sign_and_verify,
    // aggregate,
    // verify_aggregate,
    verify_aggregate_trusted_keys
);
