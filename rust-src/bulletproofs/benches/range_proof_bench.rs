//! Testing range proofs over curves used in the dalek library e.g., curve25519-dalek (https://doc.dalek.rs/curve25519_dalek/index.html=)

extern crate curve25519_dalek;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::CompressedRistretto;

use bulletproofs::utils::Generators;
 use curve_arithmetic::{Curve, Value};
use pedersen_scheme::*;
use rand::*;
use random_oracle::RandomOracle;
use std::time::Instant;

#[cfg(test)]
mod tests {
    use super::*;
    use bulletproofs::range_proof::{prove, verify_efficient};
    use pairing::bls12_381::G1;
    type SomeCurve = G1;
    
    #[allow(non_snake_case)]
    #[test]
    fn test_single_value() {
        let rng = &mut thread_rng();
        let n = 64;
        let m = 1;
        let nm = (usize::from(n)) * (usize::from(m));
        let mut G = Vec::with_capacity(nm);
        let mut H = Vec::with_capacity(nm);
        let mut G_H = Vec::with_capacity(nm);
        let mut randomness = Vec::with_capacity(usize::from(m));
        let mut commitments = Vec::with_capacity(usize::from(m));

        for _i in 0..(nm) {
            let g = SomeCurve::generate(rng);
            let h = SomeCurve::generate(rng);
            G.push(g);
            H.push(h);
            G_H.push((g, h)); 
        }

        let gens = Generators { G_H };
        let B = SomeCurve::generate(rng);
        let B_tilde = SomeCurve::generate(rng);
        let keys = CommitmentKey { g: B, h: B_tilde };

        // Some numbers in [0, 2^n):
        let v_vec: Vec<u64> = vec![
            4294967295
        ];

        for &v in v_vec.iter().take(m.into()) {
            let r = Randomness::generate(rng);
            let v_scalar = SomeCurve::scalar_from_u64(v);
            let v_value = Value::<SomeCurve>::new(v_scalar);
            let com = keys.hide(&v_value, &r);
            randomness.push(r);
            commitments.push(com);
        }
        let mut transcript = RandomOracle::empty();
        let start = Instant::now();
        let proof = prove(
            &mut transcript,
            rng,
            n,
            m,
            &v_vec,
            &gens,
            &keys,
            &randomness,
        );
        
        println!(
            "proving time: {} ms",
            start.elapsed().as_millis() as u128
        );
        assert!(proof.is_some());
        let proof = proof.unwrap();

        let mut transcript = RandomOracle::empty();
        let start = Instant::now();
        let result = verify_efficient(&mut transcript, n, &commitments, &proof, &gens, &keys);
        assert!(result.is_ok());
        println!(
            "verification time: {} ms",
            start.elapsed().as_millis() as u128
        );
    }
}