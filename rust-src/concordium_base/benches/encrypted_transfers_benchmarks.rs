use ark_bls12_381::G1Projective;
use rand::*;

#[macro_use]
extern crate criterion;

use concordium_base::{
    common::types::Amount,
    curve_arithmetic::{arkworks_instances::ArkGroup, Value},
    elgamal::{PublicKey, SecretKey},
    encrypted_transfers::proofs::*,
    id::types::GlobalContext,
    random_oracle::*,
};
use criterion::Criterion;
use std::time::Duration;

type G1 = ArkGroup<G1Projective>;

pub fn generate_challenge_prefix<R: rand::Rng>(csprng: &mut R) -> Vec<u8> {
    // length of the challenge
    let l = csprng.gen_range(0..1000);
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
    let s = csprng.gen::<u64>(); // amount on account.

    let a = csprng.gen_range(0..s); // amount to send

    let m = 2; // 2 chunks
    let n = 32;
    let nm = n * m;

    let context = GlobalContext::<SomeCurve>::generate_size(String::from("genesis_string"), nm);
    let generator = context.encryption_in_exponent_generator(); // h
    let s_value = Value::from(s);
    let S = pk_sender.encrypt_exponent_given_generator(&s_value, generator, &mut csprng);

    let challenge_prefix = generate_challenge_prefix(&mut csprng);
    let ro = RandomOracle::domain(challenge_prefix);

    let index = csprng.gen::<u64>().into();

    let context_clone = context.clone();
    let sk_clone = sk_sender.clone();
    let mut csprng_clone = csprng.clone();
    c.bench_function(
        &format!("{}: Create transaction with proofs", module_path!()),
        move |b| {
            b.iter(|| {
                gen_enc_trans(
                    &context_clone,
                    &mut ro.split(),
                    &pk_sender,
                    &sk_clone,
                    &pk_receiver,
                    index,
                    &S,
                    Amount::from_micro_ccd(s),
                    Amount::from_micro_ccd(a),
                    &mut csprng_clone,
                )
                .expect("Could not produce proof.");
            })
        },
    );

    let challenge_prefix = generate_challenge_prefix(&mut csprng);
    let ro = RandomOracle::domain(&challenge_prefix);
    let mut ro_copy = ro.split();

    let index = csprng.gen::<u64>().into();
    let transaction = gen_enc_trans(
        &context,
        &mut ro_copy,
        &pk_sender,
        &sk_sender,
        &pk_receiver,
        index,
        &S,
        Amount::from_micro_ccd(s),
        Amount::from_micro_ccd(a),
        &mut csprng,
    )
    .expect("Could not produce proof.");
    c.bench_function(
        &format!("{}: Verify transaction and proofs", module_path!()),
        move |b| {
            b.iter(|| {
                let mut ro = RandomOracle::domain(&challenge_prefix);
                assert_eq!(
                    verify_enc_trans(
                        &context,
                        &mut ro,
                        &transaction,
                        &pk_sender,
                        &pk_receiver,
                        &S,
                    ),
                    Ok(())
                )
            })
        },
    );
}

#[allow(non_snake_case)]
pub fn sec_to_pub_bench(c: &mut Criterion) {
    type SomeCurve = G1;
    let mut csprng = thread_rng();
    let sk: SecretKey<G1> = SecretKey::generate_all(&mut csprng);
    let pk = PublicKey::from(&sk);
    let s = csprng.gen::<u64>(); // amount on account.

    let a = csprng.gen_range(0..s); // amount to send

    let m = 2; // 2 chunks
    let n = 32;
    let nm = n * m;

    let context = GlobalContext::<SomeCurve>::generate_size(String::from("genesis_string"), nm);
    let generator = context.encryption_in_exponent_generator(); // h
    let s_value = Value::from(s);
    let S = pk.encrypt_exponent_given_generator(&s_value, generator, &mut csprng);

    let challenge_prefix = generate_challenge_prefix(&mut csprng);
    let ro = RandomOracle::domain(challenge_prefix);

    let index = csprng.gen::<u64>().into();

    let context_clone = context.clone();
    let sk_clone = sk.clone();
    let mut csprng_clone = csprng.clone();
    c.bench_function(
        &format!(
            "{}: Create sec to pub transaction with proofs",
            module_path!()
        ),
        move |b| {
            b.iter(|| {
                gen_sec_to_pub_trans(
                    &context_clone,
                    &mut ro.split(),
                    &pk,
                    &sk_clone,
                    index,
                    &S,
                    Amount::from_micro_ccd(s),
                    Amount::from_micro_ccd(a),
                    &mut csprng_clone,
                )
                .expect("Could not produce proof.");
            })
        },
    );

    let challenge_prefix = generate_challenge_prefix(&mut csprng);
    let ro = RandomOracle::domain(&challenge_prefix);
    let mut ro_copy = ro.split();

    let index = csprng.gen::<u64>().into();
    let transaction = gen_sec_to_pub_trans(
        &context,
        &mut ro_copy,
        &pk,
        &sk,
        index,
        &S,
        Amount::from_micro_ccd(s),
        Amount::from_micro_ccd(a),
        &mut csprng,
    )
    .expect("Could not produce proof.");
    c.bench_function(
        &format!(
            "{}: Verify sec to pub transaction and proofs",
            module_path!()
        ),
        move |b| {
            b.iter(|| {
                let mut ro = RandomOracle::domain(&challenge_prefix);
                assert_eq!(
                    verify_sec_to_pub_trans(&context, &mut ro, &transaction, &pk, &S,),
                    Ok(())
                )
            })
        },
    );
}

criterion_group! {
    name = encrypted_transfer_benches;
    config = Criterion::default().measurement_time(Duration::from_millis(100000)).sample_size(20);
    targets =
        enc_trans_bench
}

criterion_main!(encrypted_transfer_benches);
