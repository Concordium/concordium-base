//! This module provides the implementation of the discrete log sigma protocol
//! which enables one to prove knowledge of the discrete logarithm without
//! revealing it.
use crate::sigma_protocols::common::*;
use crypto_common::*;
use crypto_common_derive::*;
use curve_arithmetic::{Curve, Value};
use ff::Field;
use random_oracle::{Challenge, RandomOracle};

pub struct Dlog<C: Curve> {
    /// Evaluated point.
    pub public: C,
    /// The base point.
    pub coeff:  C,
}

pub struct DlogSecret<C: Curve> {
    pub secret: Value<C>,
}

/// Dlog witness. We deliberately make it opaque.
/// We implement Copy to make the interface easier to use.
#[derive(Debug, Serialize, Clone, Copy, Eq, PartialEq)]
pub struct Witness<C: Curve> {
    witness: C::Scalar,
}

/// Convenient alias for aggregate dlog proof
pub type Proof<C> = SigmaProof<Witness<C>>;

impl<C: Curve> SigmaProtocol for Dlog<C> {
    type CommitMessage = C;
    type ProtocolChallenge = C::Scalar;
    type ProverState = C::Scalar;
    type ProverWitness = Witness<C>;
    type SecretData = DlogSecret<C>;

    fn public(&self, ro: &mut RandomOracle) {
        ro.append_message("public", &self.public);
        ro.append_message("coeff", &self.coeff)
    }

    fn get_challenge(&self, challenge: &Challenge) -> Self::ProtocolChallenge {
        C::scalar_from_bytes(challenge)
    }

    fn commit_point<R: rand::Rng>(
        &self,
        csprng: &mut R,
    ) -> Option<(Self::CommitMessage, Self::ProverState)> {
        let rand_scalar = C::generate_non_zero_scalar(csprng);
        let randomised_point = self.coeff.mul_by_scalar(&rand_scalar);
        Some((randomised_point, rand_scalar))
    }

    fn generate_witness(
        &self,
        secret: Self::SecretData,
        state: Self::ProverState,
        challenge: &Self::ProtocolChallenge,
    ) -> Option<Self::ProverWitness> {
        // If the challenge is zero, the proof is not going to be valid unless alpha
        // (randomised point) is also zero.
        let mut witness = *challenge;
        witness.mul_assign(&secret.secret);
        witness.add_assign(&state);
        Some(Witness { witness })
    }

    fn extract_point(
        &self,
        challenge: &Self::ProtocolChallenge,
        witness: &Self::ProverWitness,
    ) -> Option<Self::CommitMessage> {
        let randomised_point = self
            .coeff
            .mul_by_scalar(&witness.witness)
            .minus_point(&self.public.mul_by_scalar(challenge));
        Some(randomised_point)
    }

    #[cfg(test)]
    fn with_valid_data<R: rand::Rng>(
        _data_size: usize,
        csprng: &mut R,
        f: impl FnOnce(Dlog<C>, Self::SecretData, &mut R),
    ) {
        let secret = Value::generate(csprng);
        let base = C::generate(csprng);
        let public = base.mul_by_scalar(&secret);
        let dlog = Dlog {
            public,
            coeff: base,
        };
        f(dlog, DlogSecret { secret }, csprng);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::G1;

    #[test]
    pub fn test_dlog_correctness() {
        let mut csprng = rand::thread_rng();
        for _ in 0..1000 {
            Dlog::with_valid_data(0, &mut csprng, |dlog: Dlog<G1>, secret, csprng| {
                let challenge_prefix = generate_challenge_prefix(csprng);
                let mut ro = RandomOracle::domain(&challenge_prefix);
                let proof =
                    prove(&mut ro.split(), &dlog, secret, csprng).expect("Proving should succeed.");
                assert!(verify(&mut ro, &dlog, &proof));
            })
        }
    }

    #[test]
    pub fn test_dlog_soundness() {
        let mut csprng = rand::thread_rng();
        for _ in 0..100 {
            Dlog::with_valid_data(0, &mut csprng, |dlog, secret, csprng| {
                // Generate proof
                let challenge_prefix = generate_challenge_prefix(csprng);
                let mut ro = RandomOracle::domain(&challenge_prefix);
                let proof =
                    prove(&mut ro.split(), &dlog, secret, csprng).expect("Proving should succeed.");

                // Construct invalid parameters
                let mut wrong_ro = RandomOracle::domain(generate_challenge_prefix(csprng));
                let wrong_base = G1::generate(csprng);
                let wrong_public = G1::generate(csprng);

                let wrong_proof_challenge = SigmaProof {
                    challenge: RandomOracle::domain(&generate_challenge_prefix(csprng))
                        .get_challenge(),
                    ..proof
                };
                let wrong_proof_witness = SigmaProof {
                    witness: Witness {
                        witness: G1::generate_scalar(csprng),
                    },
                    ..proof
                };

                // Verify failure for invalid parameters
                if verify(&mut wrong_ro, &dlog, &proof) {
                    assert_eq!(wrong_ro, ro);
                }
                let dlog_wrong_base = Dlog {
                    coeff: wrong_base,
                    ..dlog
                };
                let dlog_wrong_public = Dlog {
                    public: wrong_public,
                    ..dlog
                };
                assert!(!verify(&mut ro.split(), &dlog_wrong_base, &proof));
                assert!(!verify(&mut ro.split(), &dlog_wrong_public, &proof));
                assert!(!verify(&mut ro.split(), &dlog, &wrong_proof_challenge));
                assert!(!verify(&mut ro, &dlog, &wrong_proof_witness));
            })
        }
    }
}
