//! Benchmarks for the set-membership and set-non-membership proofs
#[macro_use]
extern crate criterion;

use bulletproofs::{set_membership_proof, set_non_membership_proof, utils::Generators};
use criterion::{BenchmarkId, Criterion};
use curve_arithmetic::*;
use pairing::bls12_381::G1;
use pedersen_scheme::{CommitmentKey, Randomness};
use rand::*;
use random_oracle::RandomOracle;
use std::time::Duration;

#[allow(non_snake_case)]
pub fn bench_set_proofs(c: &mut Criterion) {
    let mut group = c.benchmark_group("Set Proofs");

    for i in 0..13 {
        let rng = &mut thread_rng();
        // Instance
        let n = 2_usize.pow(i);
        let mut the_set = Vec::<<G1 as Curve>::Scalar>::with_capacity(n);
        let v = G1::generate_scalar(rng); // random element

        // Generate (multi)set with n elements not containing v
        while the_set.len() < n {
            let elem = G1::generate_scalar(rng);
            if elem != v {
                the_set.push(elem);
            }
        }

        // Let w be an element in the set
        let w_index = rng.gen_range(0, n);
        let w = the_set[w_index];

        // Commit to v
        let B = G1::generate(rng);
        let B_tilde = G1::generate(rng);
        let v_keys = CommitmentKey { g: B, h: B_tilde };
        let v_rand = Randomness::generate(rng);
        let v_value = Value::<G1>::new(v);
        let v_com = v_keys.hide(&v_value, &v_rand);

        // Commit to w
        let w_rand = Randomness::generate(rng);
        let w_value = Value::<G1>::new(w);
        let w_com = v_keys.hide(&w_value, &w_rand);

        // Get some generators
        let mut gh = Vec::with_capacity(n);
        for _ in 0..n {
            let x = G1::generate(rng);
            let y = G1::generate(rng);
            gh.push((x, y));
        }
        let gens = Generators { G_H: gh };

        // Bench prover for set membership
        let the_set_p = the_set.clone();
        let gens_p = gens.clone();
        let v_keys_p = v_keys.clone();
        let w_rand_p = v_rand.clone();
        group.bench_function(BenchmarkId::new("SM Prove", n), move |b| {
            b.iter(|| {
                let rng = &mut thread_rng();
                let mut transcript = RandomOracle::empty();
                set_membership_proof::prove(
                    &mut transcript,
                    rng,
                    &the_set_p,
                    w,
                    &gens_p,
                    &v_keys_p,
                    &w_rand_p,
                )
                .unwrap();
            })
        });

        // Bench prover for set non-membership
        let the_set_p = the_set.clone();
        let gens_p = gens.clone();
        let v_keys_p = v_keys.clone();
        let v_rand_p = v_rand.clone();
        group.bench_function(BenchmarkId::new("SNM Prove", n), move |b| {
            b.iter(|| {
                let rng = &mut thread_rng();
                let mut transcript = RandomOracle::empty();
                set_non_membership_proof::prove(
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

        // Generate valid proofs for verification
        let mut transcript = RandomOracle::empty();
        let snm_proof = set_non_membership_proof::prove(
            &mut transcript,
            rng,
            &the_set,
            v,
            &gens,
            &v_keys,
            &v_rand,
        );
        assert!(snm_proof.is_ok());
        let snm_proof = snm_proof.unwrap();
        let mut transcript = RandomOracle::empty();
        let sm_proof =
            set_membership_proof::prove(&mut transcript, rng, &the_set, w, &gens, &v_keys, &w_rand);
        assert!(sm_proof.is_ok());
        let sm_proof = sm_proof.unwrap();

        // Bench verification for set membership
        let the_set_p = the_set.clone();
        let w_com_p = w_com.clone();
        let gens_p = gens.clone();
        let v_keys_p = v_keys.clone();
        let sm_proof_p = sm_proof.clone();
        group.bench_function(BenchmarkId::new("SM Verify", n), move |b| {
            b.iter(|| {
                let mut transcript = RandomOracle::empty();
                set_membership_proof::verify(
                    &mut transcript,
                    &the_set_p,
                    &w_com_p,
                    &sm_proof_p,
                    &gens_p,
                    &v_keys_p,
                )
                .unwrap();
            })
        });

        // Bench verification for set non-membership
        let the_set_p = the_set.clone();
        let v_com_p = v_com.clone();
        let gens_p = gens.clone();
        let v_keys_p = v_keys.clone();
        let snm_proof_p = snm_proof.clone();
        group.bench_function(BenchmarkId::new("SNM Verify", n), move |b| {
            b.iter(|| {
                let mut transcript = RandomOracle::empty();
                set_non_membership_proof::verify(
                    &mut transcript,
                    &the_set_p,
                    &v_com_p,
                    &snm_proof_p,
                    &gens_p,
                    &v_keys_p,
                )
                .unwrap();
            })
        });
    }
}

criterion_group!(
    name = set_proof_bench;
    config = Criterion::default().measurement_time(Duration::from_millis(1000)).sample_size(10);
    targets = bench_set_proofs);
criterion_main!(set_proof_bench);
