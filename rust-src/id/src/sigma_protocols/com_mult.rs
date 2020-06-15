//! The module provides the implementation of the `com_mult` sigma protocol.
//! This protocol enables one to prove that the the product of two commited
//! values is equal to the third commited value, without revealing the values
//! themselves.
use curve_arithmetic::curve_arithmetic::Curve;
use ff::Field;
use rand::*;

use crypto_common::*;
use pedersen_scheme::{Commitment, CommitmentKey, Randomness, Value};
use random_oracle::RandomOracle;

pub struct ComMultSecret<'a, T: Curve> {
    pub values: &'a [Value<T>; 3],
    pub rands:  &'a [Randomness<T>; 3],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ComMultProof<T: Curve> {
    /// Computed challenge.
    challenge: T::Scalar,
    /// The witness, expanded using the same notation as in the specification.
    ss: [T::Scalar; 3],
    ts: [T::Scalar; 3],
    t: T::Scalar,
}

/// Construct a proof of knowledge of multiplicative relationship. The arguments
/// are as follows.
/// * `ro` - Random oracle used in the challenge computation. This can be used
///   to make sure that the proof is only valid in a certain context.
/// * `cmm_{1,2,3}` - The triple of commitments (the product of the first two
///   commited values should be equal to the last)
/// * `cmm_key` - The commitment key with which all the commitments are
///   generated.
/// * `secret` - The list of pairs $(a_i, r_i)$ where $r_i$ is the commitment
///   randomness, and $a_i$ the commited to value.
/// * `csprng` - A cryptographically secure random number generator.
#[allow(non_snake_case)]
pub fn prove_com_mult<T: Curve, R: Rng>(
    ro: RandomOracle,
    cmm_1: &Commitment<T>,
    cmm_2: &Commitment<T>,
    cmm_3: &Commitment<T>,
    cmm_key: &CommitmentKey<T>,
    secret: &ComMultSecret<T>,
    csprng: &mut R,
) -> ComMultProof<T> {
    let hasher = ro
        .append_bytes("com_mult")
        .append(cmm_1)
        .append(cmm_2)
        .append(cmm_3)
        .append(cmm_key);

    let alpha_1 = Value::generate_non_zero(csprng);
    let alpha_2 = Value::generate_non_zero(csprng);
    let alpha_3 = Value::generate_non_zero(csprng);

    let (v_1, cR_1) = cmm_key.commit(&alpha_1, csprng);
    let (v_2, cR_2) = cmm_key.commit(&alpha_2, csprng);
    let (v_3, cR_3) = cmm_key.commit(&alpha_3, csprng);

    let cmm_key_1 = CommitmentKey(cmm_1.0, cmm_key.1);
    let (v, cR) = cmm_key_1.commit(&alpha_2, csprng);

    let challenge = hasher
        .append(&v_1)
        .append(&v_2)
        .append(&v_3)
        .finish_to_scalar::<T, _>(&v);

    // If challenge is zero the proof is very unlikely to be valid.
    // But that is exceedingly unlikely.
    let mut ss = [challenge; 3];
    let mut ts = [challenge; 3];
    let alphas = [alpha_1, alpha_2, alpha_3];
    let rands = [cR_1, cR_2, cR_3];
    for i in 0..3 {
        ss[i].mul_assign(&secret.values[i]);
        ss[i].negate();
        ss[i].add_assign(&alphas[i]);

        ts[i].mul_assign(&secret.rands[i]);
        ts[i].negate();
        ts[i].add_assign(&rands[i]);
    }

    // compute r_3 - r_1a_2
    let mut r = secret.rands[0].randomness; // r_1
    r.mul_assign(&secret.values[1]); // r_1 * a_2
    r.negate();
    r.add_assign(&secret.rands[2]);

    let mut t = challenge;
    t.mul_assign(&r);
    t.negate();
    t.add_assign(&cR);
    ComMultProof {
        challenge,
        ss,
        ts,
        t,
    }
}

/// Verify proof of knowledge of multiplicative relationship. The arguments are
/// as follows.
/// * `ro` - Random oracle used in the challenge computation. This can be used
///   to make sure that the proof is only valid in a certain context.
/// * `cmm_{1,2,3}` - The triple of commitments (the product of the first two
///   commited values should be equal to the last)
/// * `cmm_key` - The commitment key with which all the commitments are
///   generated.
#[allow(non_snake_case)]
pub fn verify_com_mult<T: Curve>(
    ro: RandomOracle,
    cmm_1: &Commitment<T>,
    cmm_2: &Commitment<T>,
    cmm_3: &Commitment<T>,
    cmm_key: &CommitmentKey<T>,
    proof: &ComMultProof<T>,
) -> bool {
    let mut hasher = ro
        .append_bytes("com_mult")
        .append(cmm_1)
        .append(cmm_2)
        .append(cmm_3)
        .append(cmm_key);

    for (c_i, s_i, t_i) in izip!(
        [cmm_1, cmm_2, cmm_3].iter(),
        proof.ss.iter(),
        proof.ts.iter()
    ) {
        let v_i = c_i
            .mul_by_scalar(&proof.challenge)
            .plus_point(&cmm_key.hide(Value::view_scalar(s_i), Randomness::view_scalar(t_i)));
        hasher.add(&v_i);
    }

    let h = cmm_key.1;
    let s_2 = proof.ss[1];
    let cC_3 = cmm_3;
    let cC_1 = cmm_1;
    let v = cC_3
        .mul_by_scalar(&proof.challenge)
        .plus_point(&cC_1.mul_by_scalar(&s_2))
        .plus_point(&h.mul_by_scalar(&proof.t));

    let computed_challenge = hasher.finish_to_scalar::<T, _>(&v);
    computed_challenge == proof.challenge
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigma_protocols::common::*;
    use pairing::bls12_381::G1;

    #[test]
    pub fn test_com_mult_correctness() {
        let mut csprng = thread_rng();
        for _ in 0..100 {
            let cmm_key = CommitmentKey::generate(&mut csprng);
            let a_1 = Value::<G1>::generate_non_zero(&mut csprng);
            let a_2 = Value::<G1>::generate_non_zero(&mut csprng);
            let mut a_3 = a_1.value;
            a_3.mul_assign(&a_2);

            let a_3 = Value::new(a_3);

            let (c_1, r_1) = cmm_key.commit(&a_1, &mut csprng);
            let (c_2, r_2) = cmm_key.commit(&a_2, &mut csprng);
            let (c_3, r_3) = cmm_key.commit(&a_3, &mut csprng);

            let secret = ComMultSecret {
                values: &[a_1, a_2, a_3],
                rands:  &[r_1, r_2, r_3],
            };

            let challenge_prefix = generate_challenge_prefix(&mut csprng);
            let ro = RandomOracle::domain(&challenge_prefix);
            let proof =
                prove_com_mult(ro.split(), &c_1, &c_2, &c_3, &cmm_key, &secret, &mut csprng);
            assert!(verify_com_mult(
                ro.split(),
                &c_1,
                &c_2,
                &c_3,
                &cmm_key,
                &proof
            ));
        }
    }

    #[test]
    pub fn test_com_mult_soundness() {
        let mut csprng = thread_rng();
        for _ in 0..100 {
            // Generate proof
            let cmm_key = CommitmentKey::generate(&mut csprng);
            let a_1 = Value::<G1>::generate_non_zero(&mut csprng);
            let a_2 = Value::<G1>::generate_non_zero(&mut csprng);
            let mut a_3 = a_1.value;
            a_3.mul_assign(&a_2);

            let a_3 = Value::new(a_3);

            let (c_1, r_1) = cmm_key.commit(&a_1, &mut csprng);
            let (c_2, r_2) = cmm_key.commit(&a_2, &mut csprng);
            let (c_3, r_3) = cmm_key.commit(&a_3, &mut csprng);

            let secret = ComMultSecret {
                values: &[a_1, a_2, a_3],
                rands:  &[r_1, r_2, r_3],
            };

            let challenge_prefix = generate_challenge_prefix(&mut csprng);
            let ro = RandomOracle::domain(&challenge_prefix);
            let proof =
                prove_com_mult(ro.split(), &c_1, &c_2, &c_3, &cmm_key, &secret, &mut csprng);
            assert!(verify_com_mult(
                ro.split(),
                &c_1,
                &c_2,
                &c_3,
                &cmm_key,
                &proof
            ));

            // Construct invalid parameters
            let wrong_ro = RandomOracle::domain(generate_challenge_prefix(&mut csprng));
            let wrong_c1 = pedersen_scheme::commitment::Commitment(c_1.double_point());
            let wrong_c2 = pedersen_scheme::commitment::Commitment(c_2.double_point());
            let wrong_c3 = pedersen_scheme::commitment::Commitment(c_3.double_point());
            let mut wrong_cmm_key_0 = cmm_key;
            wrong_cmm_key_0.0 = wrong_cmm_key_0.0.double_point();
            let mut wrong_cmm_key_1 = cmm_key;
            wrong_cmm_key_1.1 = wrong_cmm_key_1.1.double_point();

            // Verify failure for invalid parameters
            assert!(!verify_com_mult(
                wrong_ro, &c_1, &c_2, &c_3, &cmm_key, &proof
            ));
            assert!(!verify_com_mult(
                ro.split(),
                &wrong_c1,
                &c_2,
                &c_3,
                &cmm_key,
                &proof
            ));
            assert!(!verify_com_mult(
                ro.split(),
                &c_1,
                &wrong_c2,
                &c_3,
                &cmm_key,
                &proof
            ));
            assert!(!verify_com_mult(
                ro.split(),
                &c_1,
                &c_2,
                &wrong_c3,
                &cmm_key,
                &proof
            ));
            assert!(!verify_com_mult(
                ro.split(),
                &c_1,
                &c_2,
                &c_3,
                &wrong_cmm_key_0,
                &proof
            ));
            assert!(!verify_com_mult(
                ro.split(),
                &c_1,
                &c_2,
                &c_3,
                &wrong_cmm_key_1,
                &proof
            ));
        }
    }

    #[test]
    pub fn test_com_mult_proof_serialization() {
        let mut csprng = thread_rng();
        let challenge = G1::generate_scalar(&mut csprng);
        let ss = [
            G1::generate_scalar(&mut csprng),
            G1::generate_scalar(&mut csprng),
            G1::generate_scalar(&mut csprng),
        ];
        let ts = [
            G1::generate_scalar(&mut csprng),
            G1::generate_scalar(&mut csprng),
            G1::generate_scalar(&mut csprng),
        ];
        let t = G1::generate_scalar(&mut csprng);
        let cp = ComMultProof::<G1> {
            challenge,
            ss,
            ts,
            t,
        };
        let cpp = serialize_deserialize(&cp);
        assert!(cpp.is_ok());
        assert_eq!(cp, cpp.unwrap());
    }
}
