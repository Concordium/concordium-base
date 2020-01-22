//! The module provides the implementation of the `aggregate_dlog` sigma
//! protocol. This protocol enables one to prove knowledge of discrete
//! logarithms $a_1 ... a_n$ public values $ y = \prod G_i^{a_i} $.
//! This is a specialization of `com_eq` protocol where we do not require
//! commitments.
use curve_arithmetic::curve_arithmetic::Curve;
use ff::Field;
use rand::*;

use crypto_common::*;
use random_oracle::RandomOracle;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AggregateDlogProof<T: Curve> {
    /// The challenge computed by the prover.
    challenge: T::Scalar,
    /// The list of $s_i$ where
    /// * $s_i = \alpha_i - c a_i$
    /// where $c$ is the challenge and $\alpha_i$ are prover chosen
    /// random scalars, and $a_i$ are the secret values.
    #[size_length = 4]
    witness: Vec<T::Scalar>,
}

/// Construct a proof of knowledge of secret values. The arguments are as
/// follows.
/// * `ro` - Random oracle used in the challenge computation. This can be used
///   to make sure that the proof is only valid in a certain context.
/// * `evaluation` - The evaluation $y$ (see above for notation).
/// * `coeff` - The list of generators for discrete log proofs.
/// * `secret` - The list of secret values $a_i$. The length of this list must
///   be the
/// same as the lenght of `coeff`.
/// * `csprng` - A cryptographically secure random number generator.
pub fn prove_aggregate_dlog<T: Curve, R: Rng>(
    ro: RandomOracle,
    public: &T,
    coeff: &[T],
    secret: &[T::Scalar],
    csprng: &mut R,
) -> AggregateDlogProof<T> {
    let n = secret.len();
    // FIXME: Likely the return value should be an option type (or Result type).
    assert_eq!(coeff.len(), n);

    let hasher = ro
        .append_bytes("aggregate_dlog")
        .append(public)
        .extend_from(coeff.iter());

    // Only allocate the vector once and just reset it each iteration. The vector
    // can be big, and there is no reason to allocate a new one each iteration.
    let mut rands = Vec::with_capacity(n);
    loop {
        rands.clear();
        let mut point = T::zero_point();

        for g in coeff.iter() {
            let rand = T::generate_non_zero_scalar(csprng);
            point = point.plus_point(&g.mul_by_scalar(&rand));
            rands.push(rand);
        }
        let maybe_challenge = hasher.append_fresh(&point).result_to_scalar::<T>();
        match maybe_challenge {
            None => {} // loop again
            Some(challenge) => {
                if challenge != T::Scalar::zero() {
                    let mut witness = Vec::with_capacity(n);
                    for (ref s, ref r) in izip!(secret, rands) {
                        let mut wit = challenge;
                        wit.mul_assign(s);
                        wit.negate();
                        wit.add_assign(r);
                        witness.push(wit);
                    }
                    let proof = AggregateDlogProof { challenge, witness };
                    return proof;
                }
            }
        }
    }
}

/// Verify a proof of knowledge of secret values. The arguments are as
/// follows.
/// * `ro` - Random oracle used in the challenge computation. This can be used
///   to make sure that the proof is only valid in a certain context.
/// * `evaluation` - The evaluation $y$ (see above for notation).
/// * `coeff` - THe list of generators for discrete log proofs.
pub fn verify_aggregate_dlog<T: Curve>(
    ro: RandomOracle,
    public: &T,
    coeff: &[T],
    proof: &AggregateDlogProof<T>,
) -> bool {
    let hasher = ro
        .append_bytes("aggregate_dlog")
        .append(public)
        .extend_from(coeff.iter());

    let mut point = public.mul_by_scalar(&proof.challenge);
    if proof.witness.len() != coeff.len() {
        return false;
    }
    for (ref w, ref g) in izip!(&proof.witness, coeff) {
        point = point.plus_point(&g.mul_by_scalar(w));
    }
    let computed_challenge = hasher.finish_to_scalar::<T, _>(&point);
    match computed_challenge {
        None => false,
        Some(computed_challenge) => proof.challenge == computed_challenge,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigma_protocols::common::*;
    use pairing::bls12_381::G1Affine;

    #[test]
    pub fn test_aggregate_dlog_correctness() {
        let mut csprng = thread_rng();
        for i in 1..20 {
            let mut secret = Vec::with_capacity(i);
            let mut coeff = Vec::with_capacity(i);
            let mut public = <G1Affine as Curve>::zero_point();
            for _ in 0..i {
                let s = G1Affine::generate_scalar(&mut csprng);
                let g = G1Affine::generate(&mut csprng);
                public = public.plus_point(&g.mul_by_scalar(&s));
                secret.push(s);
                coeff.push(g);
            }
            let challenge_prefix = generate_challenge_prefix(&mut csprng);
            let ro = RandomOracle::domain(&challenge_prefix);
            let proof = prove_aggregate_dlog::<G1Affine, ThreadRng>(
                ro.split(),
                &public,
                &coeff,
                &secret,
                &mut csprng,
            );
            assert!(verify_aggregate_dlog(ro, &public, &coeff, &proof));
        }
    }

    #[test]
    pub fn test_aggregate_dlog_soundness() {
        let mut csprng = thread_rng();
        for i in 1..20 {
            // Generate proof
            let mut secret = Vec::with_capacity(i);
            let mut coeff = Vec::with_capacity(i);
            let mut public = <G1Affine as Curve>::zero_point();
            for _ in 0..i {
                let s = G1Affine::generate_scalar(&mut csprng);
                let g = G1Affine::generate(&mut csprng);
                public = public.plus_point(&g.mul_by_scalar(&s));
                secret.push(s);
                coeff.push(g);
            }
            let challenge_prefix = generate_challenge_prefix(&mut csprng);
            let ro = RandomOracle::domain(&challenge_prefix);
            let proof = prove_aggregate_dlog::<G1Affine, ThreadRng>(
                ro.split(),
                &public,
                &coeff,
                &secret,
                &mut csprng,
            );

            // Construct invalid parameters
            let index_wrong_coeff: usize = csprng.gen_range(0, i);

            let wrong_ro = RandomOracle::domain(generate_challenge_prefix(&mut csprng));
            let wrong_public = public.double_point();
            let mut wrong_coeff = coeff.to_owned();
            wrong_coeff[index_wrong_coeff] = wrong_coeff[index_wrong_coeff].double_point();

            // Verify failure for invalid parameters
            assert!(!verify_aggregate_dlog(wrong_ro, &public, &coeff, &proof));
            assert!(!verify_aggregate_dlog(
                ro.split(),
                &wrong_public,
                &coeff,
                &proof
            ));
            assert!(!verify_aggregate_dlog(
                ro.split(),
                &public,
                &wrong_coeff,
                &proof
            ));
        }
    }

    #[test]
    pub fn test_serialization() {
        let mut csprng = thread_rng();
        for i in 1..20 {
            let mut witness = vec![<G1Affine as Curve>::Scalar::zero(); i];
            let challenge: <G1Affine as Curve>::Scalar = G1Affine::generate_scalar(&mut csprng);
            for j in 0..i {
                witness[j] = G1Affine::generate_scalar(&mut csprng);
            }
            let ap = AggregateDlogProof::<G1Affine> { challenge, witness };
            let app = serialize_deserialize(&ap);
            assert!(app.is_ok());
            assert_eq!(ap, app.unwrap());
        }
    }
}
