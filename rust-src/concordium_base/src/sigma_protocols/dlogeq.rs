//! This sigma protocol can be used to prove knowledge of x such that y_1 =
//! g_1^x and y_2=g_2^x
//!
//! NB: This module is not used by the rest of the project and is only here for
//! demonstration purposes.
//! If it becomes necessary to use it, the code needs to be thoroughly reviewed.
use crate::{
    curve_arithmetic::Curve,
    random_oracle::{Challenge, RandomOracle},
    sigma_protocols::{
        common::*,
        dlog::{Response as DlogResponse, *},
    },
};

struct DlogEqual<C: Curve> {
    dlog1: Dlog<C>,
    dlog2: Dlog<C>,
}

impl<C: Curve> SigmaProtocol for DlogEqual<C> {
    type CommitMessage = (C, C);
    type ProtocolChallenge = C::Scalar;
    type ProverState = C::Scalar;
    type Response = DlogResponse<C>;
    type SecretData = DlogSecret<C>;

    fn public(&self, ro: &mut RandomOracle) {
        self.dlog1.public(ro);
        self.dlog2.public(ro)
    }

    fn get_challenge(&self, challenge: &Challenge) -> Self::ProtocolChallenge {
        C::scalar_from_bytes(challenge)
    }

    fn compute_commit_message<R: rand::Rng>(
        &self,
        csprng: &mut R,
    ) -> Option<(Self::CommitMessage, Self::ProverState)> {
        let rand_scalar = C::generate_non_zero_scalar(csprng);
        let randomized_point_1 = self.dlog1.coeff.mul_by_scalar(&rand_scalar);
        let randomized_point_2 = self.dlog2.coeff.mul_by_scalar(&rand_scalar);
        let commit = (randomized_point_1, randomized_point_2);
        Some((commit, rand_scalar))
    }

    fn compute_response(
        &self,
        secret: Self::SecretData,
        state: Self::ProverState,
        challenge: &Self::ProtocolChallenge,
    ) -> Option<Self::Response> {
        let w1 = self.dlog1.compute_response(secret, state, challenge)?;
        Some(w1)
    }

    fn extract_commit_message(
        &self,
        challenge: &Self::ProtocolChallenge,
        response: &Self::Response,
    ) -> Option<Self::CommitMessage> {
        let p1 = self.dlog1.extract_commit_message(challenge, response)?;
        let p2 = self.dlog2.extract_commit_message(challenge, response)?;
        Some((p1, p2))
    }

    #[cfg(test)]
    fn with_valid_data<R: rand::Rng>(
        _data_size: usize,
        _csprng: &mut R,
        _f: impl FnOnce(Self, Self::SecretData, &mut R),
    ) {
        unimplemented!("Tested in a different way.")
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::curve_arithmetic::{
        arkworks_instances::{ArkField, ArkGroup},
        Value,
    };
    use rand::*;

    use ark_bls12_381::G1Projective;
    use std::str::FromStr;

    type G1 = ArkGroup<G1Projective>;
    type Fr = ArkField<ark_bls12_381::Fr>;

    pub fn generate_challenge_prefix<R: rand::Rng>(csprng: &mut R) -> Vec<u8> {
        // length of the challenge
        let l = csprng.gen_range(0, 1000);
        let mut challenge_prefix = vec![0; l];
        for v in challenge_prefix.iter_mut() {
            *v = csprng.gen();
        }
        challenge_prefix
    }

    #[allow(non_snake_case)]
    #[test]
    fn test_gen_eq() {
        let mut csprng = thread_rng();
        let x = Fr::from_str("3").unwrap();
        let x_secret = Value::<G1>::new(x);
        let g1 = G1::generate(&mut csprng);
        let g2 = G1::generate(&mut csprng);
        let g1x = g1.mul_by_scalar(&x);
        let g2x = g2.mul_by_scalar(&x);
        let dlog1 = Dlog {
            public: g1x,
            coeff:  g1,
        };
        let dlog2 = Dlog {
            public: g2x,
            coeff:  g2,
        };
        let equal = DlogEqual { dlog1, dlog2 };
        let secret = DlogSecret { secret: x_secret };
        let challenge_prefix = generate_challenge_prefix(&mut csprng);
        let mut ro = RandomOracle::domain(challenge_prefix);
        let proof = prove(&mut ro.split(), &equal, secret, &mut csprng).unwrap();
        assert!(verify(&mut ro, &equal, &proof));
    }
}
