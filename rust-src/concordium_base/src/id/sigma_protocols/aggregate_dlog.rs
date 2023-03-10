//! The module provides the implementation of the `aggregate_dlog` sigma
//! protocol. This protocol enables one to prove knowledge of discrete
//! logarithms $a_1 ... a_n$ public values $ y = \prod G_i^{a_i} $.
//! This is a specialization of `com_eq` protocol where we do not require
//! commitments.
use crate::sigma_protocols::common::*;
use crypto_common::*;
use curve_arithmetic::{multiexp, Curve};
use ff::Field;
use random_oracle::{Challenge, RandomOracle};
use std::rc::Rc;

pub struct AggregateDlog<C: Curve> {
    /// Evaluated point.
    pub public: C,
    /// The points G_i references in the module description, in the given order.
    pub coeff:  Vec<C>,
}

/// Aggregate dlog witness. We deliberately make it opaque.
#[derive(Debug, Serialize)]
pub struct Witness<C: Curve> {
    #[size_length = 4]
    witness: Vec<C::Scalar>,
}

/// Convenient alias for aggregate dlog proof
pub type Proof<C> = SigmaProof<Witness<C>>;

impl<C: Curve> SigmaProtocol for AggregateDlog<C> {
    type CommitMessage = C;
    type ProtocolChallenge = C::Scalar;
    type ProverState = Vec<C::Scalar>;
    type ProverWitness = Witness<C>;
    type SecretData = Vec<Rc<C::Scalar>>;

    fn public(&self, ro: &mut RandomOracle) {
        ro.append_message(b"public", &self.public);
        ro.extend_from(b"coeff", &self.coeff)
    }

    fn get_challenge(&self, challenge: &Challenge) -> Self::ProtocolChallenge {
        C::scalar_from_bytes(challenge)
    }

    fn commit_point<R: rand::Rng>(
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

    fn generate_witness(
        &self,
        secret: Self::SecretData,
        state: Self::ProverState,
        challenge: &Self::ProtocolChallenge,
    ) -> Option<Self::ProverWitness> {
        let n = secret.len();
        if state.len() != n {
            return None;
        }
        let mut witness = Vec::with_capacity(n);
        for (ref s, ref r) in izip!(secret, state) {
            let mut wit = *challenge;
            wit.mul_assign(s);
            wit.negate();
            wit.add_assign(r);
            witness.push(wit);
        }
        Some(Witness { witness })
    }

    fn extract_point(
        &self,
        challenge: &Self::ProtocolChallenge,
        witness: &Self::ProverWitness,
    ) -> Option<Self::CommitMessage> {
        if witness.witness.len() != self.coeff.len() {
            return None;
        }
        let mut point = self.public.mul_by_scalar(challenge);
        for (w, g) in izip!(witness.witness.iter(), self.coeff.iter()) {
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
                    let mut ro = RandomOracle::domain(&challenge_prefix);
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
                let ro = RandomOracle::domain(&challenge_prefix);
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
