//! This module provides the implementation of the `dlog` sigma protocol
//! (cf. "Proof of Knowledge of Discrete Logarithm" Section 9.2.1, Bluepaper
//! v1.2.5) which enables one to prove knowledge of the discrete logarithm
//! without revealing it.
use super::common::*;
use crate::{
    common::*,
    curve_arithmetic::{Curve, Field, Value},
    random_oracle::{Challenge, RandomOracle},
};

pub struct Dlog<C: Curve> {
    /// Evaluated point.
    pub public: C,
    /// The base point.
    pub coeff:  C,
}

pub struct DlogSecret<C: Curve> {
    pub secret: Value<C>,
}

/// Response for Dlog proof. We deliberately make it opaque.
/// We implement Copy to make the interface easier to use.
#[derive(Debug, Serialize, Clone, Copy, Eq, PartialEq)]
pub struct Response<C: Curve> {
    response: C::Scalar,
}

/// Convenient alias for aggregate dlog proof
pub type Proof<C> = SigmaProof<Response<C>>;

impl<C: Curve> SigmaProtocol for Dlog<C> {
    type CommitMessage = C;
    type ProtocolChallenge = C::Scalar;
    type ProverState = C::Scalar;
    type Response = Response<C>;
    type SecretData = DlogSecret<C>;

    fn public(&self, ro: &mut RandomOracle) {
        ro.append_message("public", &self.public);
        ro.append_message("coeff", &self.coeff)
    }

    fn compute_commit_message<R: rand::Rng>(
        &self,
        csprng: &mut R,
    ) -> Option<(Self::CommitMessage, Self::ProverState)> {
        let rand_scalar = C::generate_non_zero_scalar(csprng);
        let commit_message = self.coeff.mul_by_scalar(&rand_scalar);
        Some((commit_message, rand_scalar))
    }

    fn get_challenge(&self, challenge: &Challenge) -> Self::ProtocolChallenge {
        C::scalar_from_bytes(challenge)
    }

    fn compute_response(
        &self,
        secret: Self::SecretData,
        state: Self::ProverState,
        challenge: &Self::ProtocolChallenge,
    ) -> Option<Self::Response> {
        // If the challenge is zero, the proof is not going to be valid unless alpha
        // (randomised point) is also zero.
        let mut response = *challenge;
        response.mul_assign(&secret.secret);
        response.add_assign(&state);
        Some(Response { response })
    }

    fn extract_commit_message(
        &self,
        challenge: &Self::ProtocolChallenge,
        response: &Self::Response,
    ) -> Option<Self::CommitMessage> {
        let randomised_point = self
            .coeff
            .mul_by_scalar(&response.response)
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
    use crate::curve_arithmetic::arkworks_instances::ArkGroup;

    use super::*;
    use ark_bls12_381::G1Projective;

    type G1 = ArkGroup<G1Projective>;

    #[test]
    pub fn test_dlog_correctness() {
        let mut csprng = rand::thread_rng();
        for _ in 0..1000 {
            Dlog::with_valid_data(0, &mut csprng, |dlog: Dlog<G1>, secret, csprng| {
                let challenge_prefix = generate_challenge_prefix(csprng);
                let mut ro = RandomOracle::domain(challenge_prefix);
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
                let mut ro = RandomOracle::domain(challenge_prefix);
                let proof =
                    prove(&mut ro.split(), &dlog, secret, csprng).expect("Proving should succeed.");

                // Construct invalid parameters
                let mut wrong_ro = RandomOracle::domain(generate_challenge_prefix(csprng));
                let wrong_base = G1::generate(csprng);
                let wrong_public = G1::generate(csprng);

                let wrong_proof_challenge = SigmaProof {
                    challenge: RandomOracle::domain(generate_challenge_prefix(csprng))
                        .get_challenge(),
                    ..proof
                };
                let wrong_proof_response = SigmaProof {
                    response: Response {
                        response: G1::generate_scalar(csprng),
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
                assert!(!verify(&mut ro, &dlog, &wrong_proof_response));
            })
        }
    }
}
