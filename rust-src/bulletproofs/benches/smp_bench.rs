#[macro_use]
extern crate criterion;

use bulletproofs::{
    inner_product_proof::verify_scalars,
    set_membership_proof::*,
    utils::{get_set_vector, z_vec, Generators},
};
use criterion::{BenchmarkId, Criterion};
use curve_arithmetic::*;
use ff::Field;
use pairing::bls12_381::G1;
use pedersen_scheme::{Commitment, CommitmentKey, Randomness};
use rand::*;
use random_oracle::RandomOracle;
use std::time::Duration;

#[derive(Debug, PartialEq, Eq)]
pub enum UltraVerificationError {
    /// The length of G_H was less than |S|, which is too small
    NotEnoughGenerators,
    /// Could not compute the inner product scalars
    IpScalarCheckFailed,
    /// Could not invert the given y
    DivisionError,
    /// Verification sum non-zero
    VerificationSumNonZero,
}

#[allow(non_snake_case)]
pub fn verify_ultra_efficient<C: Curve, R: Rng>(
    transcript: &mut RandomOracle,
    csprng: &mut R,
    the_set: &[u64],
    V: &Commitment<C>,
    proof: &SetMembershipProof<C>,
    gens: &Generators<C>,
    v_keys: &CommitmentKey<C>,
) -> Result<(), UltraVerificationError> {
    // Domain separation
    transcript.add_bytes(b"SetMembershipProof");
    transcript.append_message(b"V", &V.0);
    // Convert the u64 set into a field element vector
    let set_vec = get_set_vector::<C>(the_set);
    let n = set_vec.len();
    // Append the set to the transcript
    transcript.append_message(b"theSet", &set_vec);

    // Check that we have enough generators for vector commitments
    if gens.G_H.len() < n {
        return Err(UltraVerificationError::NotEnoughGenerators);
    }
    // Define generators
    let (G, H): (Vec<_>, Vec<_>) = gens.G_H.iter().take(n).cloned().unzip();
    let B = v_keys.g;
    let B_tilde = v_keys.h;

    let A = proof.A;
    let S = proof.S;
    transcript.append_message(b"A", &A);
    transcript.append_message(b"S", &S);
    let y: C::Scalar = transcript.challenge_scalar::<C, _>(b"y");
    let z: C::Scalar = transcript.challenge_scalar::<C, _>(b"z");
    let mut z2 = z;
    z2.mul_assign(&z);
    let mut z3 = z2;
    z3.mul_assign(&z);

    let T_1 = proof.T_1;
    let T_2 = proof.T_2;
    transcript.append_message(b"T1", &T_1);
    transcript.append_message(b"T2", &T_2);
    let x: C::Scalar = transcript.challenge_scalar::<C, _>(b"x");
    let mut x2 = x;
    x2.mul_assign(&x);

    let tx = proof.tx;
    let tx_tilde = proof.tx_tilde;
    let e_tilde = proof.e_tilde;
    transcript.append_message(b"tx", &tx);
    transcript.append_message(b"tx_tilde", &tx_tilde);
    transcript.append_message(b"e_tilde", &e_tilde);
    let w: C::Scalar = transcript.challenge_scalar::<C, _>(b"w");
    // Calculate delta(x,y) <- z^3(1-zn-<1,s>)+(z-z^2)*<1,y^n>
    //<1,y^n>
    let mut ip_1_y = C::Scalar::zero();
    let mut yi = C::Scalar::one();
    for _ in 0..n {
        ip_1_y.add_assign(&yi);
        yi.mul_assign(&y);
    }
    //<1,s>
    let mut ip_1_s = C::Scalar::zero();
    for s_i in &set_vec {
        ip_1_s.add_assign(s_i);
    }
    let mut zn = C::scalar_from_u64(n as u64);
    zn.mul_assign(&z);
    // z^3(1-zn-<1,s>)
    let mut z3_term = C::Scalar::one();
    z3_term.sub_assign(&zn);
    z3_term.sub_assign(&ip_1_s);
    z3_term.mul_assign(&z3);
    let mut yn_term = z;
    yn_term.sub_assign(&z2);
    yn_term.mul_assign(&ip_1_y);
    let mut delta_yz = z3_term;
    delta_yz.add_assign(&yn_term);

    // Get ip scalars
    let ip_proof = &proof.ip_proof;
    let verification_scalars = verify_scalars(transcript, n, ip_proof);
    if verification_scalars.is_none() {
        return Err(UltraVerificationError::IpScalarCheckFailed);
    }
    let verification_scalars = verification_scalars.unwrap();
    let (u_sq, u_inv_sq, s) = (
        verification_scalars.u_sq,
        verification_scalars.u_inv_sq,
        verification_scalars.s,
    );

    let a = ip_proof.a;
    let b = ip_proof.b;
    let (L, R): (Vec<_>, Vec<_>) = ip_proof.lr_vec.iter().cloned().unzip();
    let mut s_inv = s.clone();
    s_inv.reverse();
    let y_inv = match y.inverse() {
        Some(inv) => inv,
        None => return Err(UltraVerificationError::DivisionError),
    };
    let y_n_inv = z_vec(y_inv, 0, n);

    // Select random c
    let c = C::generate_scalar(csprng);

    // Compute scalars
    let A_scalar = C::Scalar::one();
    let S_scalar = x;
    let mut V_scalar = c;
    V_scalar.mul_assign(&z2);
    let mut T_1_scalar = c;
    T_1_scalar.mul_assign(&x);
    let mut T_2_scalar = T_1_scalar;
    T_2_scalar.mul_assign(&x);
    // B_scalar <- w(tx-ab)+c(delta_yz-tx)
    let mut ab = a;
    ab.mul_assign(&b);
    let mut c_delta_minus_tx = delta_yz;
    c_delta_minus_tx.sub_assign(&tx);
    c_delta_minus_tx.mul_assign(&c);
    let mut B_scalar = tx;
    B_scalar.sub_assign(&ab);
    B_scalar.mul_assign(&w);
    B_scalar.add_assign(&c_delta_minus_tx);
    // B_tilde_scalar <- -e_tilde-c*tx_tilde
    let mut minus_e_tilde = e_tilde;
    minus_e_tilde.negate();
    let mut ctx_tilde = tx_tilde;
    ctx_tilde.mul_assign(&c);
    let mut B_tilde_scalar = minus_e_tilde;
    B_tilde_scalar.sub_assign(&ctx_tilde);
    // G_scalars g_i <- -z-a*s_i
    let mut G_scalars = Vec::with_capacity(n);
    for si in s {
        let mut G_scalar = z;
        G_scalar.negate();
        let mut sa = si;
        sa.mul_assign(&a);
        G_scalar.sub_assign(&sa);
        G_scalars.push(G_scalar);
    }
    // H_scalars h_i <- y^-i * (z^2set_i-b*s_inv_i+z^3) + z
    let mut H_scalars = Vec::with_capacity(n);
    for i in 0..n {
        let mut H_scalar = set_vec[i];
        H_scalar.mul_assign(&z2);
        let mut bs_inv = b;
        bs_inv.mul_assign(&s_inv[i]);
        H_scalar.sub_assign(&bs_inv);
        H_scalar.add_assign(&z3);
        H_scalar.mul_assign(&y_n_inv[i]);
        H_scalar.add_assign(&z);
        H_scalars.push(H_scalar);
    }
    // L and R scalars
    let mut L_scalars = u_sq;
    let mut R_scalars = u_inv_sq;

    // Combine scalar vectors
    let mut all_scalars = vec![A_scalar];
    all_scalars.push(S_scalar);
    all_scalars.push(T_1_scalar);
    all_scalars.push(T_2_scalar);
    all_scalars.push(B_scalar);
    all_scalars.push(B_tilde_scalar);
    all_scalars.push(V_scalar);
    all_scalars.append(&mut G_scalars);
    all_scalars.append(&mut H_scalars);
    all_scalars.append(&mut L_scalars);
    all_scalars.append(&mut R_scalars);
    // Combine generator vectors
    let mut all_points = vec![A];
    all_points.push(S);
    all_points.push(T_1);
    all_points.push(T_2);
    all_points.push(B);
    all_points.push(B_tilde);
    all_points.push(V.0);
    all_points.extend_from_slice(&G);
    all_points.extend_from_slice(&H);
    all_points.extend_from_slice(&L);
    all_points.extend_from_slice(&R);

    let sum = multiexp(&all_points, &all_scalars);

    if !sum.is_zero_point() {
        return Err(UltraVerificationError::VerificationSumNonZero);
    }

    Ok(())
}

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
