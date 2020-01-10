//! The module provides the implementation of the `com_eq` sigma protocol.
//! This protocol enables one to prove knowledge of discrete logarithms $a_1 ...
//! a_n$ together with randomnesses $r_1 ... r_n$ corresponding to public values
//! $ y = \prod G_i^{a_i} $ and commitments $C_i = commit(a_i, r_i)$.
use curve_arithmetic::curve_arithmetic::Curve;
use ff::Field;
use rand::*;

use failure::Error;
use random_oracle::RandomOracle;
use std::io::Cursor;

use pedersen_scheme::{Commitment, CommitmentKey, Randomness, Value};

use curve_arithmetic::serialization::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComEqProof<T: Curve> {
    /// The challenge computed by the prover.
    challenge: T::Scalar,
    /// The list of pairs $(s_i, t_i)$ where
    /// * $s_i = \alpha_i - c a_i$
    /// * $t_i = R_i - c r_i$
    /// where $c$ is the challenge and $\alpha_i$ and $R_i$ are prover chosen
    /// random scalars.
    witness: Vec<(T::Scalar, T::Scalar)>,
}

impl<T: Curve> ComEqProof<T> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let witness_len = self.witness.len();
        // the +4 is for the length information of the witness vector
        let bytes_len = 4 + T::SCALAR_LENGTH + (2 * witness_len) * T::SCALAR_LENGTH;
        let mut bytes = Vec::with_capacity(bytes_len);
        write_curve_scalar::<T>(&self.challenge, &mut bytes);
        write_length(&self.witness, &mut bytes);
        for (x, y) in self.witness.iter() {
            write_curve_scalar::<T>(x, &mut bytes);
            write_curve_scalar::<T>(y, &mut bytes);
        }
        bytes
    }

    pub fn from_bytes(bytes: &mut Cursor<&[u8]>) -> Result<Self, Error> {
        let challenge = read_curve_scalar::<T>(bytes)?;
        let len = read_length(bytes)?;
        let mut witness = common::safe_with_capacity(len);
        for _ in 0..len {
            let w1 = read_curve_scalar::<T>(bytes)?;
            let w2 = read_curve_scalar::<T>(bytes)?;
            witness.push((w1, w2));
        }
        Ok(ComEqProof { challenge, witness })
    }
}
/// Construct a proof of knowledge of secret values. The arguments are as
/// follows.
/// * `ro` - Random oracle used in the challenge computation. This can be used
///   to make sure that the proof is only valid in a certain context.
/// * `commitments` - The list of commitments.
/// * `y` - The evaluation $y$ (see above for notation).
/// * `cmm_key` - The commitment key with which all the commitments are
///   generated
/// * `gxs` - The list of generators for discrete log proofs.
/// * `secret` - The list of pairs $(r_i, a_i)$ where $r_i$ is the commitment
///   randomness, and $a_i$ the commited to value.
/// * `csprng` - A cryptographically secure random number generator.
#[allow(non_snake_case)]
pub fn prove_com_eq<T: Curve, R: Rng>(
    ro: RandomOracle,
    commitments: &[Commitment<T>],
    y: &T,
    cmm_key: &CommitmentKey<T>,
    gxs: &[T],
    secret: &[(&Randomness<T>, &Value<T>)],
    csprng: &mut R,
) -> ComEqProof<T> {
    let n = commitments.len();
    // FIXME: This should be handled better by returning an Option(Proof).
    // Or at the very least stating the precondition.
    assert_eq!(secret.len(), n);
    assert_eq!(gxs.len(), n);

    let mut rands = Vec::with_capacity(n);

    let hasher = ro
        .append("com_eq")
        .extend_from(commitments.iter().map(Commitment::to_bytes))
        .append(&y.curve_to_bytes())
        .append(&cmm_key.to_bytes())
        .extend_from(gxs.iter().map(Curve::curve_to_bytes));

    loop {
        // For each iteration of the loop we need to recompute the challenge,
        // but we reuse the prefix computation from above.
        let mut hasher2 = hasher.split();
        let mut tmp_u = T::zero_point();
        // clear the vector of randoms for the current iteration.
        // Doing it this way avoids reallocating a whole new vector on each iteration.
        rands.clear();
        for g in gxs {
            let alpha_i = Value::<T>::generate_non_zero(csprng);
            // This cR_i is R_i from the specification.
            let (v_i, cR_i) = cmm_key.commit(&alpha_i, csprng);
            tmp_u = tmp_u.plus_point(&g.mul_by_scalar(&alpha_i));
            hasher2.add(&v_i.curve_to_bytes());
            rands.push((alpha_i, cR_i));
        }
        hasher2.add(tmp_u.curve_to_bytes());
        let challenge = hasher2.result_to_scalar::<T>();
        match challenge {
            None => {} // loop again
            Some(challenge) => {
                // In the unlikely case that the challenge is 0 we try with a
                // different randomness. The reason for this is that in such a
                // case the proof will not be valid. This should not happen in
                // practice though.
                if challenge != T::Scalar::zero() {
                    let mut witness = Vec::with_capacity(n);
                    for ((r_i, a_i), (ref alpha_i, ref cR_i)) in izip!(secret, rands) {
                        // compute alpha_i - a_i * c
                        let mut s_i = challenge;
                        s_i.mul_assign(a_i);
                        s_i.negate();
                        s_i.add_assign(alpha_i);
                        // compute R_i - r_i * c
                        let mut t_i = challenge;
                        t_i.mul_assign(r_i);
                        t_i.negate();
                        t_i.add_assign(cR_i);
                        witness.push((s_i, t_i))
                    }
                    let proof = ComEqProof { challenge, witness };
                    return proof;
                }
            }
        }
    }
}

/// Specialization of the above for when we only have a single commitment.
pub fn prove_com_eq_single<T: Curve, R: Rng>(
    ro: RandomOracle,
    commitment: &Commitment<T>,
    y: &T,
    cmm_key: &CommitmentKey<T>,
    gx: &T,
    secret: (&Randomness<T>, &Value<T>),
    csprng: &mut R,
) -> ComEqProof<T> {
    prove_com_eq(ro, &[*commitment], y, cmm_key, &[*gx], &[secret], csprng)
}

#[allow(clippy::many_single_char_names)]
/// Verify a proof of knowledge. The arguments are as follows.
/// * `ro` - Random oracle used in the challenge computation. This can be used
///   to make sure that the proof is only valid in a certain context.
/// * `commitments` - The list of commitments.
/// * `y` - The evaluation $y$ (see above for notation).
/// * `cmm_key` - The commitment key with which all the commitments are
///   generated
/// * `gxs` - The list of generators for discrete log proofs.
/// * `proof` - Proposed proof.
pub fn verify_com_eq<T: Curve>(
    ro: RandomOracle,
    commitments: &[Commitment<T>],
    y: &T,
    cmm_key: &CommitmentKey<T>,
    gxs: &[T],
    proof: &ComEqProof<T>,
) -> bool {
    if commitments.len() != proof.witness.len() {
        return false;
    }

    let challenge = &proof.challenge;

    let mut u = y.mul_by_scalar(challenge);
    for (g, (s_i, _)) in izip!(gxs, &proof.witness) {
        u = u.plus_point(&g.mul_by_scalar(&s_i));
    }

    let mut hasher = ro
        .append("com_eq")
        .extend_from(commitments.iter().map(Commitment::to_bytes))
        .append(&y.curve_to_bytes())
        .append(&cmm_key.to_bytes())
        .extend_from(gxs.iter().map(Curve::curve_to_bytes));

    for (c, (s_i, t_i)) in izip!(commitments.iter(), &proof.witness) {
        let v = c
            .mul_by_scalar(challenge)
            .plus_point(&cmm_key.hide(Value::view_scalar(s_i), Randomness::view_scalar(t_i)));
        hasher.add(&v.curve_to_bytes());
    }
    hasher.add(&u.curve_to_bytes());

    let computed_challenge = hasher.result_to_scalar::<T>();
    match computed_challenge {
        None => false,
        Some(computed_challenge) => computed_challenge == proof.challenge,
    }
}

/// Specialization of the above when only a single commitment is given.
pub fn verify_com_eq_single<T: Curve>(
    ro: RandomOracle,
    commitment: &Commitment<T>,
    y: &T,
    cmm_key: &CommitmentKey<T>,
    gx: &T,
    proof: &ComEqProof<T>,
) -> bool {
    verify_com_eq(ro, &[*commitment], y, cmm_key, &[*gx], proof)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::sigma_protocols::common::*;
    use pairing::bls12_381::G1Affine;

    #[test]
    pub fn test_com_eq_correctness() {
        let mut csprng = thread_rng();
        let mut secret: Vec<(&Randomness<_>, &Value<_>)> = Vec::with_capacity(20);
        let mut cxs = Vec::with_capacity(20);
        let mut gxs = Vec::with_capacity(20);
        for i in 1..20 {
            secret.clear();
            cxs.clear();
            gxs.clear();
            let g = G1Affine::generate(&mut csprng);
            let h = G1Affine::generate(&mut csprng);
            let mut y = G1Affine::zero_point();
            let comm_key = CommitmentKey(g, h);
            for _ in 0..i {
                let a = Value::generate_non_zero(&mut csprng);
                let (c, randomness) = comm_key.commit(&a, &mut csprng);
                let g_i = G1Affine::generate(&mut csprng);
                y = y.plus_point(&g_i.mul_by_scalar(&a));
                secret.push((Box::leak(Box::new(randomness)), Box::leak(Box::new(a))));
                cxs.push(c);
                gxs.push(g_i);
            }
            let challenge_prefix = generate_challenge_prefix(&mut csprng);
            let ro = RandomOracle::domain(&challenge_prefix);
            let proof = prove_com_eq(ro.split(), &cxs, &y, &comm_key, &gxs, &secret, &mut csprng);
            let res = verify_com_eq(ro, &cxs, &y, &comm_key, &gxs, &proof);
            assert!(res, "Verification of produced proof.");
        }
    }

    #[test]
    pub fn test_com_eq_soundness() {
        let mut csprng = thread_rng();
        let mut secret: Vec<(&Randomness<_>, &Value<_>)> = Vec::with_capacity(20);
        let mut cxs = Vec::with_capacity(20);
        let mut gxs = Vec::with_capacity(20);
        for i in 1..20 {
            // Generate proof
            secret.clear();
            cxs.clear();
            gxs.clear();
            let g = G1Affine::generate(&mut csprng);
            let h = G1Affine::generate(&mut csprng);
            let mut y = G1Affine::zero_point();
            let comm_key = CommitmentKey(g, h);
            for _ in 0..i {
                let a = Value::generate_non_zero(&mut csprng);
                let (c, randomness) = comm_key.commit(&a, &mut csprng);
                let g_i = G1Affine::generate(&mut csprng);
                y = y.plus_point(&g_i.mul_by_scalar(&a));
                secret.push((Box::leak(Box::new(randomness)), Box::leak(Box::new(a))));
                cxs.push(c);
                gxs.push(g_i);
            }
            let challenge_prefix = generate_challenge_prefix(&mut csprng);
            let ro = RandomOracle::domain(&challenge_prefix);
            let proof = prove_com_eq(ro.split(), &cxs, &y, &comm_key, &gxs, &secret, &mut csprng);

            // Construct invalid parameters
            let mut rng = thread_rng();
            let index_wrong_cx: usize = rng.gen_range(0, i);
            let index_wrong_gx: usize = rng.gen_range(0, i);

            let wrong_ro = RandomOracle::domain(generate_challenge_prefix(&mut csprng));
            let mut wrong_cxs = cxs.to_owned();
            wrong_cxs[index_wrong_cx].0 = wrong_cxs[index_wrong_cx].0.double_point();
            let wrong_y = y.double_point();
            let mut wrong_comm_key_0 = comm_key;
            wrong_comm_key_0.0 = wrong_comm_key_0.0.double_point();
            let mut wrong_comm_key_1 = comm_key;
            wrong_comm_key_1.1 = wrong_comm_key_1.1.double_point();
            let mut wrong_gxs = gxs.to_owned();
            wrong_gxs[index_wrong_gx] = wrong_gxs[index_wrong_gx].double_point();

            // Verify failure for invalid parameters
            assert!(!verify_com_eq(wrong_ro, &cxs, &y, &comm_key, &gxs, &proof));
            assert!(!verify_com_eq(
                ro.split(),
                &wrong_cxs,
                &y,
                &comm_key,
                &gxs,
                &proof
            ));
            assert!(!verify_com_eq(
                ro.split(),
                &cxs,
                &wrong_y,
                &comm_key,
                &gxs,
                &proof
            ));
            assert!(!verify_com_eq(
                ro.split(),
                &cxs,
                &y,
                &wrong_comm_key_0,
                &gxs,
                &proof
            ));
            assert!(!verify_com_eq(
                ro.split(),
                &cxs,
                &y,
                &wrong_comm_key_1,
                &gxs,
                &proof
            ));
            assert!(!verify_com_eq(
                ro.split(),
                &cxs,
                &y,
                &comm_key,
                &wrong_gxs,
                &proof
            ));
        }
    }

    #[test]
    pub fn test_com_eq_proof_serialization() {
        let mut csprng = thread_rng();
        for _ in 1..100 {
            let challenge = G1Affine::generate_scalar(&mut csprng);
            let lrp1 = csprng.gen_range(1, 30);
            let mut rp1 = Vec::with_capacity(lrp1);
            for _ in 0..lrp1 {
                rp1.push(G1Affine::generate(&mut csprng));
            }
            let lw = csprng.gen_range(1, 87);
            let mut witness = Vec::with_capacity(lw);
            for _ in 0..lw {
                let a = G1Affine::generate_scalar(&mut csprng);
                let b = G1Affine::generate_scalar(&mut csprng);
                witness.push((a, b));
            }
            let cep = ComEqProof::<G1Affine> { challenge, witness };
            let bytes = cep.to_bytes();
            let cepp = ComEqProof::from_bytes(&mut Cursor::new(&bytes));
            assert!(cepp.is_ok());
            assert_eq!(cep, cepp.unwrap());
        }
    }
}
