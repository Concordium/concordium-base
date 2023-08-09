//! The module provides the implementation of the `aggregate_dlog` sigma
//! protocol. This protocol enables one to prove knowledge of discrete
//! logarithms $a_1 ... a_n$ public values $ y = \prod G_i^{a_i} $.
//! This is a specialization of `com_eq` protocol where we do not require
//! commitments.
use super::common::*;
use crate::{
    common::*,
    curve_arithmetic::{multiexp, Curve},
    random_oracle::{Challenge, RandomOracle},
};
use ff::Field;
use itertools::izip;
use std::rc::Rc;

pub struct AggregateDlog<C: Curve> {
    /// Evaluated point.
    pub public: C,
    /// The points G_i references in the module description, in the given order.
    pub coeff:  Vec<C>,
}

/// Aggregate dlog response. We deliberately make it opaque.
#[derive(Debug, Serialize)]
pub struct Response<C: Curve> {
    #[size_length = 4]
    response: Vec<C::Scalar>,
}

/// Convenient alias for aggregate dlog proof
pub type Proof<C> = SigmaProof<Response<C>>;

impl<C: Curve> SigmaProtocol for AggregateDlog<C> {
    type CommitMessage = C;
    type ProtocolChallenge = C::Scalar;
    type ProverState = Vec<C::Scalar>;
    type Response = Response<C>;
    type SecretData = Vec<Rc<C::Scalar>>;

    fn public(&self, ro: &mut RandomOracle) {
        ro.append_message(b"public", &self.public);
        ro.extend_from(b"coeff", &self.coeff)
    }

    fn compute_commit_message<R: rand::Rng>(
        &self,
        csprng: &mut R,
    ) -> Option<(Self::CommitMessage, Self::ProverState)> {
        // Make sure our data is consistent.
        let n = self.coeff.len();
        let mut rands = Vec::with_capacity(n);
        for _ in 0..n {
            let rand = C::generate_non_zero_scalar(csprng);
            rands.push(rand);
        }
        Some((multiexp(&self.coeff, &rands), rands))
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
        let n = secret.len();
        if state.len() != n {
            return None;
        }
        let mut response = Vec::with_capacity(n);
        for (ref s, ref r) in izip!(secret, state) {
            let mut res = *challenge;
            res.mul_assign(s);
            res.negate();
            res.add_assign(r);
            response.push(res);
        }
        Some(Response { response })
    }

    fn extract_commit_message(
        &self,
        challenge: &Self::ProtocolChallenge,
        response: &Self::Response,
    ) -> Option<Self::CommitMessage> {
        if response.response.len() != self.coeff.len() {
            return None;
        }
        let mut point = self.public.mul_by_scalar(challenge);
        for (w, g) in izip!(response.response.iter(), self.coeff.iter()) {
            point = point.plus_point(&g.mul_by_scalar(w));
        }
        Some(point)
    }

    #[cfg(test)]
    fn with_valid_data<R: rand::Rng>(
        data_size: usize,
        csprng: &mut R,
        f: impl FnOnce(Self, Self::SecretData, &mut R),
    ) {
        let mut secret = Vec::with_capacity(data_size);
        let mut coeff = Vec::with_capacity(data_size);
        let mut public = C::zero_point();
        for _ in 0..data_size {
            let s = C::generate_scalar(csprng);
            let g = C::generate(csprng);
            public = public.plus_point(&g.mul_by_scalar(&s));
            secret.push(Rc::new(s));
            coeff.push(g);
        }
        let agg = AggregateDlog { public, coeff };
        f(agg, secret, csprng)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::G1;
    use rand::{thread_rng, Rng};

    #[test]
    pub fn test_aggregate_dlog_correctness() {
        let mut csprng = thread_rng();
        for i in 1..20 {
            AggregateDlog::with_valid_data(
                i,
                &mut csprng,
                |agg: AggregateDlog<G1>, secret, csprng| {
                    let challenge_prefix = generate_challenge_prefix(csprng);
                    let mut ro = RandomOracle::domain(challenge_prefix);
                    let proof =
                        prove(&mut ro.split(), &agg, secret, csprng).expect("Input data is valid.");
                    assert!(verify(&mut ro, &agg, &proof));
                },
            )
        }
    }

    #[test]
    pub fn test_aggregate_dlog_soundness() {
        let mut csprng = thread_rng();
        for i in 1..20 {
            AggregateDlog::with_valid_data(i, &mut csprng, |agg, secret, csprng| {
                let challenge_prefix = generate_challenge_prefix(csprng);
                let ro = RandomOracle::domain(challenge_prefix);
                let proof =
                    prove(&mut ro.split(), &agg, secret, csprng).expect("Input data is valid.");

                // Construct invalid parameters
                let index_wrong_coeff: usize = csprng.gen_range(0, i);

                let mut wrong_ro = RandomOracle::domain(generate_challenge_prefix(csprng));
                let wrong_public = G1::generate(csprng);
                let mut wrong_coeff = agg.coeff.clone();
                wrong_coeff[index_wrong_coeff] = G1::generate(csprng);

                // Verify failure for invalid parameters
                // Incorrect context string
                if verify(&mut wrong_ro, &agg, &proof) {
                    assert_eq!(wrong_ro, ro);
                }
                let wrong_agg = AggregateDlog {
                    public: wrong_public,
                    ..agg
                };
                // Incorrect public data: incorrect evaluation.
                assert!(!verify(&mut ro.split(), &wrong_agg, &proof));

                let wrong_agg_coeff = AggregateDlog {
                    coeff: wrong_coeff,
                    ..agg
                };
                // Incorrect public data: incorrect coefficient.
                assert!(!verify(&mut ro.split(), &wrong_agg_coeff, &proof));
            })
        }
    }
}
