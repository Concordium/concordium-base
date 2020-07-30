//! This is a temporary runner to benchmark decryption performance on various
//! devices.
use rand::*;

use elgamal::secret::*;

use curve_arithmetic::Curve;
use ff::PrimeField;
use pairing::bls12_381::{Fr, G1};
use std::time::SystemTime;

pub fn baby_step_giant_step_table_bench() {
    let mut csprng = thread_rng();
    let x = Fr::from_str("4294967295").unwrap();
    // let x = Fr::from_str("18446744073709551615").unwrap();
    // let x = Fr::from_str("65535").unwrap();
    let h = G1::generate(&mut csprng);
    let hx = h.mul_by_scalar(&x);
    let x = 4294967295;
    let m = 65536;
    let k = 65536;

    println!("Running baby-step giant-step with table.");
    println!("Repeat single decryption 10 times.");
    let now = SystemTime::now();
    for _ in 0..10 {
        assert_eq!(baby_step_giant_step(&hx, &h, m, k), x);
    }
    println!("Time elapsed: {}ms", now.elapsed().unwrap().as_millis());

    println!("Running benchmark with precomputed table.");
    println!("Computing table.");
    let now = SystemTime::now();
    let (table, base_m) = baby_step_giant_step_table(&h, m);
    println!("Time elapsed: {}ms", now.elapsed().unwrap().as_millis());
    println!("Decrypting with table 10 times.");
    let now = SystemTime::now();
    for _ in 0..10 {
        assert_eq!(
            baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
            x
        );
    }
    println!("Time elapsed: {}ms", now.elapsed().unwrap().as_millis());

    println!("Running benchmark with precomputed table with m = 2^18, k = 2^14.");
    let m = 1 << 18;
    let k = 1 << 14;
    println!("Computing table.");
    let now = SystemTime::now();
    let (table, base_m) = baby_step_giant_step_table(&h, m);
    println!("Time elapsed: {}ms", now.elapsed().unwrap().as_millis());
    println!("Decrypting with table 10 times.");
    let now = SystemTime::now();
    for _ in 0..10 {
        assert_eq!(
            baby_step_giant_step_given_table(&hx, &base_m, m, k, &table),
            x
        );
    }
    println!("Time elapsed: {}ms", now.elapsed().unwrap().as_millis());
}

pub fn main() { baby_step_giant_step_table_bench() }
