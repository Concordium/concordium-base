//! The module provides the implementation of the `com_eq` sigma protocol.
//! This protocol enables one to prove knowledge of discrete logarithms $a_1 ...
//! a_n$ together with randomnesses $r_1 ... r_n$ corresponding to public values
//! $ y = \prod G_i^{a_i} $ and commitments $C_i = commit(a_i, r_i)$.
//! The product y and commitments can be in different groups, but they have to
//! be of the same prime order, and for the implementation the field of scalars
//! must be the same type for both groups.

use curve_arithmetic::curve_arithmetic::Curve;
use ff::Field;
use rand::*;

use random_oracle::RandomOracle;

use crypto_common::*;
use crypto_common_derive::*;
use pedersen_scheme::{Commitment, CommitmentKey, Randomness, Value};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, SerdeBase16Serialize)]
pub struct ComEqProof<T: Curve> {
    /// The challenge computed by the prover.
    challenge: T::Scalar,
    /// The list of pairs $(s_i, t_i)$ where
    /// * $s_i = \alpha_i - c a_i$
    /// * $t_i = R_i - c r_i$
    /// where $c$ is the challenge and $\alpha_i$ and $R_i$ are prover chosen
    /// random scalars.
    #[size_length = 4]
    witness: Vec<(T::Scalar, T::Scalar)>,
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
pub fn prove_com_eq<C: Curve, T: Curve<Scalar = C::Scalar>, R: Rng>(
    ro: RandomOracle,
    commitments: &[Commitment<C>],
    y: &T,
    cmm_key: &CommitmentKey<C>,
    gxs: &[T],
    secret: &[(&Randomness<C>, &Value<C>)],
    csprng: &mut R,
) -> ComEqProof<C> {
    let n = commitments.len();
    // FIXME: This should be handled better by returning an Option(Proof).
    // Or at the very least stating the precondition.
    assert_eq!(secret.len(), n);
    assert_eq!(gxs.len(), n);

    let mut rands = Vec::with_capacity(n);

    let hasher = ro
        .append_bytes("com_eq")
        .extend_from(commitments.iter())
        .append(y)
        .append(cmm_key)
        .extend_from(gxs.iter());

    // For each iteration of the loop we need to recompute the challenge,
    // but we reuse the prefix computation from above.
    let mut hasher2 = hasher.split();
    let mut tmp_u = T::zero_point();
    // clear the vector of randoms for the current iteration.
    // Doing it this way avoids reallocating a whole new vector on each iteration.
    rands.clear();
    for g in gxs {
        let alpha_i = Value::<C>::generate_non_zero(csprng);
        // This cR_i is R_i from the specification.
        let (v_i, cR_i) = cmm_key.commit(&alpha_i, csprng);
        tmp_u = tmp_u.plus_point(&g.mul_by_scalar(&alpha_i));
        hasher2.add(&v_i);
        rands.push((alpha_i, cR_i));
    }
    hasher2.add(&tmp_u);
    let challenge = hasher2.result_to_scalar::<T>();
    // In the unlikely case that the challenge is 0 the proof will not be valid.
    // But that is exceedingly unlikely.
    let mut witness = Vec::with_capacity(n);
    for ((r_i, a_i), (ref alpha_i, ref cR_i)) in izip!(secret, rands) {
        // compute alpha_i - a_i * c
        let mut s_i = challenge;
        s_i.mul_assign(a_i);
        s_i.negate();
        s_i.add_assign(alpha_i);
        // compute R_i - r_i * c
        let mut t_i: C::Scalar = challenge;
        t_i.mul_assign(r_i);
        t_i.negate();
        t_i.add_assign(cR_i);
        witness.push((s_i, t_i))
    }
    ComEqProof { challenge, witness }
}

/// Specialization of the above for when we only have a single commitment.
pub fn prove_com_eq_single<C: Curve, T: Curve<Scalar = C::Scalar>, R: Rng>(
    ro: RandomOracle,
    commitment: &Commitment<C>,
    y: &T,
    cmm_key: &CommitmentKey<C>,
    gx: &T,
    secret: (&Randomness<C>, &Value<C>),
    csprng: &mut R,
) -> ComEqProof<C> {
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
pub fn verify_com_eq<C: Curve, T: Curve<Scalar = C::Scalar>>(
    ro: RandomOracle,
    commitments: &[Commitment<C>],
    y: &T,
    cmm_key: &CommitmentKey<C>,
    gxs: &[T],
    proof: &ComEqProof<C>,
) -> bool {
    if commitments.len() != proof.witness.len() {
        return false;
    }
    if gxs.len() != proof.witness.len() {
        return false;
    }

    let challenge = &proof.challenge;

    let mut u = y.mul_by_scalar(challenge);
    for (g, (s_i, _)) in izip!(gxs, &proof.witness) {
        u = u.plus_point(&g.mul_by_scalar(&s_i));
    }

    let mut hasher = ro
        .append_bytes("com_eq")
        .extend_from(commitments.iter())
        .append(y)
        .append(cmm_key)
        .extend_from(gxs.iter());

    for (c, (s_i, t_i)) in izip!(commitments.iter(), &proof.witness) {
        let v = c
            .mul_by_scalar(challenge)
            .plus_point(&cmm_key.hide(Value::view_scalar(s_i), Randomness::view_scalar(t_i)));
        hasher.add(&v);
    }
    hasher.add(&u);

    let computed_challenge = hasher.result_to_scalar::<T>();
    computed_challenge == proof.challenge
}

/// Specialization of the above when only a single commitment is given.
pub fn verify_com_eq_single<C: Curve, T: Curve<Scalar = C::Scalar>>(
    ro: RandomOracle,
    commitment: &Commitment<C>,
    y: &T,
    cmm_key: &CommitmentKey<C>,
    gx: &T,
    proof: &ComEqProof<C>,
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
            let index_wrong_cx: usize = csprng.gen_range(0, i);
            let index_wrong_gx: usize = csprng.gen_range(0, i);

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
            let cepp = serialize_deserialize(&cep);
            assert!(cepp.is_ok());
            assert_eq!(cep, cepp.unwrap());
        }
    }
}
