#[macro_use]
extern crate criterion;

use std::time::Duration;
use bulletproofs::{set_membership_proof::*, utils::Generators};
use criterion::{BenchmarkId, Criterion};
use curve_arithmetic::*;
use pairing::bls12_381::G1;
use pedersen_scheme::{CommitmentKey, Randomness};
use rand::*;
use random_oracle::RandomOracle;

#[allow(non_snake_case)]
pub fn bench_set_membership_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("Set Membership Proof");

    for i in 0..13 {
        let rng = &mut thread_rng();
        // Instance
        let n = 2_usize.pow(i);
        let mut the_set = Vec::<u64>::with_capacity(n);
        // Technically generates a multi-set, but this is fine
        for _ in 0..n {
            the_set.push(rng.next_u64())
        }
        let v_index = rng.gen_range(0, n);
        let v = the_set[v_index];

        // Commit to v
        let B = G1::generate(rng);
        let B_tilde = G1::generate(rng);
        let v_keys = CommitmentKey { g: B, h: B_tilde };
        let v_rand = Randomness::generate(rng);
        let v_scalar = G1::scalar_from_u64(v);
        let v_value = Value::<G1>::new(v_scalar);
        let v_com = v_keys.hide(&v_value, &v_rand);

        // Get some generators
        let mut gh = Vec::with_capacity(n);
        for _ in 0..n {
            let x = G1::generate(rng);
            let y = G1::generate(rng);
            gh.push((x, y));
        }
        let gens = Generators { G_H: gh };

        // Bench prover
        let the_set_p = the_set.clone();
        let gens_p = gens.clone();
        let v_keys_p = v_keys.clone();
        let v_rand_p = v_rand.clone();
        group.bench_function(BenchmarkId::new("Prover", n), move |b| {
            b.iter(|| {
                let rng = &mut thread_rng();
                let mut transcript = RandomOracle::empty();
                prove(
                    &mut transcript,
                    rng,
                    &the_set_p,
                    v,
                    &gens_p,
                    &v_keys_p,
                    &v_rand_p,
                )
                .unwrap();
            })
        });

        // The proof for verification
        let mut transcript = RandomOracle::empty();
        let proof = prove(&mut transcript, rng, &the_set, v, &gens, &v_keys, &v_rand);
        assert!(proof.is_ok());
        let proof = proof.unwrap();

        // Bench verification
        let the_set_p = the_set.clone();
        let v_com_p = v_com.clone();
        let gens_p = gens.clone();
        let v_keys_p = v_keys.clone();
        let proof_p = proof.clone();
        group.bench_function(BenchmarkId::new("BP Verification", n), move |b| {
            b.iter(|| {
                let mut transcript = RandomOracle::empty();
                verify(
                    &mut transcript,
                    &the_set_p,
                    &v_com_p,
                    &proof_p,
                    &gens_p,
                    &v_keys_p,
                )
                .unwrap();
            })
        });        

        // Bench ultra verification
        group.bench_function(BenchmarkId::new("Ultra Verification", n), move |b| {
            b.iter(|| {
                let mut transcript = RandomOracle::empty();
                verify_ultra_efficient(
                    &mut transcript,
                    rng,
                    &the_set,
                    &v_com,
                    &proof,
                    &gens,
                    &v_keys,
                )
                .unwrap();
            })
        });
    }
}

criterion_group!(
    name = smp_bench; 
    config = Criterion::default().measurement_time(Duration::from_millis(1000)).sample_size(10);
    targets = bench_set_membership_proof);
criterion_main!(smp_bench);
