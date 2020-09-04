use rand::*;

#[macro_use]
extern crate criterion;

use criterion::Criterion;
use crypto_common::types::Amount;
use curve_arithmetic::Value;
use elgamal::{PublicKey, SecretKey};
use encrypted_transfers::proofs::generate_proofs::*;
use id::types::GlobalContext;
use merlin::Transcript;
use pairing::bls12_381::G1;
use random_oracle::*;
use std::time::Duration;

pub fn generate_challenge_prefix<R: rand::Rng>(csprng: &mut R) -> Vec<u8> {
    // length of the challenge
    let l = csprng.gen_range(0, 1000);
    let mut challenge_prefix = vec![0; l];
    for v in challenge_prefix.iter_mut() {
        *v = csprng.gen();
    }
    challenge_prefix
}

#[allow(non_snake_case)]
pub fn enc_trans_bench(c: &mut Criterion) {
    type SomeCurve = G1;
    let mut csprng = thread_rng();
    let sk_sender: SecretKey<G1> = SecretKey::generate_all(&mut csprng);
    let pk_sender = PublicKey::from(&sk_sender);
    let sk_receiver: SecretKey<G1> = SecretKey::generate(&pk_sender.generator, &mut csprng);
    let pk_receiver = PublicKey::from(&sk_receiver);
    let s = csprng.gen(); // amount on account.

    let a = csprng.gen_range(0, s); // amount to send

    let m = 2; // 2 chunks
    let n = 32;
    let nm = n * m;

    let context = GlobalContext::<SomeCurve>::generate_size(nm);
    let generator = context.encryption_in_exponent_generator(); // h
    let s_value = Value::from_u64(s);
    let S = pk_sender.encrypt_exponent_given_generator(&mut csprng, &s_value, generator);

    let challenge_prefix = generate_challenge_prefix(&mut csprng);
    let ro = RandomOracle::domain(&challenge_prefix);

    let mut transcript = Transcript::new(&[]);
    let index = csprng.gen();

    let context_clone = context.clone();
    let sk_clone = sk_sender.clone();
    c.bench_function("Create transaction with proofs", move |b| {
        b.iter(|| {
            gen_enc_trans(
                &context_clone,
                ro.split(),
                &mut transcript,
                &pk_sender,
                &sk_clone,
                &pk_receiver,
                index,
                &S,
                Amount::from(s),
                Amount::from(a),
                &mut csprng,
            )
            .expect("Could not produce proof.");
        })
    });

    let challenge_prefix = generate_challenge_prefix(&mut csprng);
    let ro = RandomOracle::domain(&challenge_prefix);
    let ro_copy = ro.split();

    let mut transcript = Transcript::new(&[]);
    let index = csprng.gen();
    let transaction = gen_enc_trans(
        &context,
        ro_copy,
        &mut transcript,
        &pk_sender,
        &sk_sender,
        &pk_receiver,
        index,
        &S,
        Amount::from(s),
        Amount::from(a),
        &mut csprng,
    )
    .expect("Could not produce proof.");
    c.bench_function("Verify transaction and proofs", move |b| {
        b.iter(|| {
            let ro = RandomOracle::domain(&challenge_prefix);
            let mut transcript = Transcript::new(&[]);
            assert_eq!(
                verify_enc_trans(
                    &context,
                    ro,
                    &mut transcript,
                    &transaction,
                    &pk_sender,
                    &pk_receiver,
                    &S,
                ),
                Ok(())
            )
        })
    });
}

#[allow(non_snake_case)]
pub fn sec_to_pub_bench(c: &mut Criterion) {
    type SomeCurve = G1;
    let mut csprng = thread_rng();
    let sk: SecretKey<G1> = SecretKey::generate_all(&mut csprng);
    let pk = PublicKey::from(&sk);
    let s = csprng.gen(); // amount on account.

    let a = csprng.gen_range(0, s); // amount to send

    let m = 2; // 2 chunks
    let n = 32;
    let nm = n * m;

    let context = GlobalContext::<SomeCurve>::generate_size(nm);
    let generator = context.encryption_in_exponent_generator(); // h
    let s_value = Value::from_u64(s);
    let S = pk.encrypt_exponent_given_generator(&mut csprng, &s_value, generator);

    let challenge_prefix = generate_challenge_prefix(&mut csprng);
    let ro = RandomOracle::domain(&challenge_prefix);

    let mut transcript = Transcript::new(&[]);
    let index = csprng.gen();

    let context_clone = context.clone();
    let sk_clone = sk.clone();
    c.bench_function("Create sec to pub transaction with proofs", move |b| {
        b.iter(|| {
            gen_sec_to_pub_trans(
                &context_clone,
                ro.split(),
                &mut transcript,
                &pk,
                &sk_clone,
                index,
                &S,
                Amount::from(s),
                Amount::from(a),
                &mut csprng,
            )
            .expect("Could not produce proof.");
        })
    });

    let challenge_prefix = generate_challenge_prefix(&mut csprng);
    let ro = RandomOracle::domain(&challenge_prefix);
    let ro_copy = ro.split();

    let mut transcript = Transcript::new(&[]);
    let index = csprng.gen();
    let transaction = gen_sec_to_pub_trans(
        &context,
        ro_copy,
        &mut transcript,
        &pk,
        &sk,
        index,
        &S,
        Amount::from(s),
        Amount::from(a),
        &mut csprng,
    )
    .expect("Could not produce proof.");
    c.bench_function("Verify sec to pub transaction and proofs", move |b| {
        b.iter(|| {
            let ro = RandomOracle::domain(&challenge_prefix);
            let mut transcript = Transcript::new(&[]);
            assert_eq!(
                verify_sec_to_pub_trans(&context, ro, &mut transcript, &transaction, &pk, &S,),
                Ok(())
            )
        })
    });
}

criterion_group! {
    name = elgamal_benches;
    config = Criterion::default().measurement_time(Duration::from_millis(1000)).sample_size(10);
    targets =
        enc_trans_bench, sec_to_pub_bench
}

criterion_main!(elgamal_benches);
