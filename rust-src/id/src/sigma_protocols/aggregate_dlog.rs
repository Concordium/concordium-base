//! The module provides the implementation of the `aggregate_dlog` sigma
//! protocol. This protocol enables one to prove knowledge of discrete
//! logarithms $a_1 ... a_n$ public values $ y = \prod G_i^{a_i} $.
//! This is a specialization of `com_eq` protocol where we do not require
//! commitments.
use curve_arithmetic::Curve;
use ff::Field;

use crypto_common::*;
use random_oracle::{Challenge, RandomOracle};

use crate::sigma_protocols::common::*;

pub struct AggregateDlog<'a, C: Curve> {
    /// Evaluated point.
    public: &'a C,
    /// The points G_i references in the module description, in the given order.
    coeff: &'a [C],
}

/// Aggregate dlog witness. We deliberately make it opaque.
#[derive(Debug, Serialize)]
pub struct Witness<C: Curve> {
    #[size_length = 4]
    witness: Vec<C::Scalar>,
}

/// Convenient alias for aggregate dlog proof
pub type Proof<C> = SigmaProof<Witness<C>>;

impl<'a, C: Curve> SigmaProtocolCommon for AggregateDlog<'a, C> {
    type CommitMessage = C;
    type ProtocolChallenge = C::Scalar;
    type ProverWitness = Witness<C>;

    fn public(&self, ro: RandomOracle) -> RandomOracle {
        ro.append(self.public).extend_from(self.coeff)
    }

    fn get_challenge(&self, challenge: &Challenge) -> Self::ProtocolChallenge {
        C::scalar_from_bytes_mod(challenge)
    }
}

impl<'a, C: Curve> SigmaProtocolProver for AggregateDlog<'a, C> {
    type ProverState = Vec<C::Scalar>;
    type SecretData = &'a [C::Scalar];

    fn commit_point<R: rand::Rng>(
        &self,
        secret: Self::SecretData,
        csprng: &mut R,
    ) -> Option<(Self::CommitMessage, Self::ProverState)> {
        // Make sure our data is consistent.
        let n = secret.len();
        if self.coeff.len() != n {
            return None;
        }

        let mut rands = Vec::with_capacity(n);
        let mut point = C::zero_point();
        for g in self.coeff.iter() {
            let rand = C::generate_non_zero_scalar(csprng);
            // FIXME: Multiexponentiation would be useful in this case.
            point = point.plus_point(&g.mul_by_scalar(&rand));
            rands.push(rand);
        }
        Some((point, rands))
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
}

impl<'a, C: Curve> SigmaProtocolVerifier for AggregateDlog<'a, C> {
    fn extract_point(
        &self,
        challenge: &Self::ProtocolChallenge,
        witness: &Self::ProverWitness,
    ) -> Option<Self::CommitMessage> {
        if witness.witness.len() != self.coeff.len() {
            return None;
        }
        let mut point = self.public.mul_by_scalar(challenge);
        for (ref w, ref g) in izip!(witness.witness.iter(), self.coeff) {
            point = point.plus_point(&g.mul_by_scalar(w));
        }
        Some(point)
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
            let mut secret = Vec::with_capacity(i);
            let mut coeff = Vec::with_capacity(i);
            let mut public = <G1 as Curve>::zero_point();
            for _ in 0..i {
                let s = G1::generate_scalar(&mut csprng);
                let g = G1::generate(&mut csprng);
                public = public.plus_point(&g.mul_by_scalar(&s));
                secret.push(s);
                coeff.push(g);
            }
            let agg = AggregateDlog {
                public: &public,
                coeff:  &coeff,
            };
            let challenge_prefix = generate_challenge_prefix(&mut csprng);
            let ro = RandomOracle::domain(&challenge_prefix);
            let proof =
                prove(ro.split(), &agg, &secret, &mut csprng).expect("Input data is valid.");
            assert!(verify(ro, &agg, &proof));
        }
    }

    #[test]
    pub fn test_aggregate_dlog_soundness() {
        let mut csprng = thread_rng();
        for i in 1..20 {
            // Generate proof
            let mut secret = Vec::with_capacity(i);
            let mut coeff = Vec::with_capacity(i);
            let mut public = G1::zero_point();
            for _ in 0..i {
                let s = G1::generate_scalar(&mut csprng);
                let g = G1::generate(&mut csprng);
                public = public.plus_point(&g.mul_by_scalar(&s));
                secret.push(s);
                coeff.push(g);
            }
            let challenge_prefix = generate_challenge_prefix(&mut csprng);
            let ro = RandomOracle::domain(&challenge_prefix);
            let agg = AggregateDlog {
                public: &public,
                coeff:  &coeff,
            };
            let proof =
                prove(ro.split(), &agg, &secret, &mut csprng).expect("Input data is valid.");

            // Construct invalid parameters
            let index_wrong_coeff: usize = csprng.gen_range(0, i);

            let wrong_ro = RandomOracle::domain(generate_challenge_prefix(&mut csprng));
            let wrong_public = G1::generate(&mut csprng);
            let mut wrong_coeff = coeff.clone();
            wrong_coeff[index_wrong_coeff] = G1::generate(&mut csprng);

            // Verify failure for invalid parameters
            // Incorrect context string
            assert!(!verify(wrong_ro, &agg, &proof));
            let wrong_agg = AggregateDlog {
                public: &wrong_public,
                ..agg
            };
            // Incorrect public data: incorrect evaluation.
            assert!(!verify(ro.split(), &wrong_agg, &proof));

            let wrong_agg_coeff = AggregateDlog {
                coeff: &wrong_coeff,
                ..agg
            };
            // Incorrect public data: incorrect coefficient.
            assert!(!verify(ro.split(), &wrong_agg_coeff, &proof));
        }
    }
}
