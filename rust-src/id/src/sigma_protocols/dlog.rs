//! This module provides the implementation of the discrete log sigma protocol
//! which enables one to prove knowledge of the discrete logarithm without
//! revealing it.
use curve_arithmetic::curve_arithmetic::Curve;
use ff::Field;
use rand::*;
use random_oracle::RandomOracle;

use crypto_common::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct DlogProof<T: Curve> {
    challenge: T::Scalar,
    witness:   T::Scalar,
    _phantom:  std::marker::PhantomData<T>,
}

pub fn prove_dlog<T: Curve, R: Rng>(
    csprng: &mut R,
    ro: RandomOracle,
    public: &T,
    secret: &T::Scalar,
    base: &T,
) -> DlogProof<T> {
    let hasher = ro.append_bytes("dlog").append(public).append(base);

    loop {
        let rand_scalar = T::generate_non_zero_scalar(csprng);
        let randomised_point = base.mul_by_scalar(&rand_scalar);

        let maybe_challenge = hasher
            .append_fresh(&randomised_point)
            .result_to_scalar::<T>();
        match maybe_challenge {
            None => {} // loop again
            Some(challenge) => {
                // The proof is not going to be valid unless alpha (randomised
                // point) is also zero in such a case.
                // So we resample in such a case.
                if challenge != T::Scalar::zero() {
                    let mut witness = *secret;
                    witness.mul_assign(&challenge);
                    witness.add_assign(&rand_scalar);

                    let proof = DlogProof {
                        challenge,
                        witness,
                        _phantom: Default::default(),
                    };
                    return proof;
                } // else loop again
            }
        }
    }
}

pub fn verify_dlog<T: Curve>(ro: RandomOracle, base: &T, public: &T, proof: &DlogProof<T>) -> bool {
    let hasher = ro.append_bytes("dlog").append(public).append(base);
    let mut c = proof.challenge;
    c.negate();
    let randomised_point = public
        .mul_by_scalar(&c)
        .plus_point(&base.mul_by_scalar(&proof.witness));

    // FIXME: Likely we should check here that alpha was chosen to be non-zero
    // i.e., that randomised_point is not the group unit.
    // Or we should not require it to be non-zero if this is never checked, unless
    // it can be used to leak secrets.
    let computed_challenge = hasher.finish_to_scalar::<T, _>(&randomised_point);
    match computed_challenge {
        None => false,
        Some(computed_challenge) => computed_challenge == proof.challenge,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigma_protocols::common::*;
    use pairing::bls12_381::G1Affine;
    use rand::rngs::ThreadRng;

    #[test]
    pub fn test_dlog_correctness() {
        let mut csprng = thread_rng();
        for _ in 0..1000 {
            let secret = G1Affine::generate_scalar(&mut csprng);
            let base = G1Affine::generate(&mut csprng);
            let public = &base.mul_by_scalar(&secret);
            let challenge_prefix = generate_challenge_prefix(&mut csprng);
            let ro = RandomOracle::domain(&challenge_prefix);
            let proof =
                prove_dlog::<G1Affine, ThreadRng>(&mut csprng, ro.split(), &public, &secret, &base);
            assert!(verify_dlog(ro, &base, &public, &proof));
        }
    }

    #[test]
    pub fn test_dlog_soundness() {
        let mut csprng = thread_rng();
        for _ in 0..100 {
            // Generate proof
            let secret = G1Affine::generate_scalar(&mut csprng);
            let base = G1Affine::generate(&mut csprng);
            let public = &base.mul_by_scalar(&secret);
            let challenge_prefix = generate_challenge_prefix(&mut csprng);
            let ro = RandomOracle::domain(&challenge_prefix);
            let proof =
                prove_dlog::<G1Affine, ThreadRng>(&mut csprng, ro.split(), &public, &secret, &base);

            // Construct invalid parameters
            let wrong_ro = RandomOracle::domain(generate_challenge_prefix(&mut csprng));
            let wrong_base = base.double_point();
            let wrong_public = public.double_point();
            let mut wrong_proof_challenge = proof;
            wrong_proof_challenge.challenge.add_assign(&secret);
            let mut wrong_proof_witness = proof;
            wrong_proof_witness.witness.add_assign(&secret);

            // Verify failure for invalid parameters
            assert!(!verify_dlog(wrong_ro, &base, &public, &proof));
            assert!(!verify_dlog(ro.split(), &wrong_base, &public, &proof));
            assert!(!verify_dlog(ro.split(), &base, &wrong_public, &proof));
            assert!(!verify_dlog(
                ro.split(),
                &base,
                &public,
                &wrong_proof_challenge
            ));
            assert!(!verify_dlog(
                ro.split(),
                &base,
                &public,
                &wrong_proof_witness
            ));
        }
    }

    #[test]
    pub fn test_dlog_proof_serialization() {
        let mut csprng = thread_rng();
        for _ in 0..1000 {
            let challenge = G1Affine::generate_scalar(&mut csprng);
            let witness = G1Affine::generate_scalar(&mut csprng);

            let dp = DlogProof::<G1Affine> {
                challenge,
                witness,
                _phantom: Default::default(),
            };
            let dpp = serialize_deserialize(&dp);
            assert!(dpp.is_ok());
            assert_eq!(dp, dpp.unwrap());
        }
    }
}
