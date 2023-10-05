//! The module provides the implementation of the `com-dlog-eq` sigma protocol
//! for the special case of one commitment (cf. "Proof of Equality for
//! Aggregated Discrete Logarithms and Commitments" Section 9.2.5, Bluepaper
//! v1.2.5). This protocol enables one to prove knowledge of discrete logarithm
//! $a_1$ together with randomnesses $r_1$ corresponding to the public value $ y
//! = \prod G_i^{a_i} $ and the commitment $C = commit(a_1, r_1)$. The product y
//! and commitments can be in different groups, but they have to be of the same
//! prime order, and for the implementation the field of scalars must be the
//! same type for both groups.

use super::common::*;
use crate::{
    common::*,
    curve_arithmetic::{multiexp, Curve, Field},
    pedersen_commitment::{Commitment, CommitmentKey, Randomness, Value},
    random_oracle::RandomOracle,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, SerdeBase16Serialize)]
pub struct Response<T: Curve> {
    /// The pair $(s, t)$ where
    /// * $s = \alpha - c a$
    /// * $t = R - c r$
    /// where $c$ is the challenge and $\alpha$ and $R$ are prover chosen
    /// random scalars.
    pub response: (T::Scalar, T::Scalar),
}

#[derive(Debug, Serialize)]
pub struct CommittedMessages<C: Curve, D: Curve> {
    pub u: C,
    pub v: Commitment<D>,
}

pub struct ComEq<C: Curve, D: Curve<Scalar = C::Scalar>> {
    /// The list of commitments.
    pub commitment: Commitment<D>,
    /// The evaluation $y$ (see above for notation).
    pub y:          C,
    /// The commitment key with which all the commitments are
    /// generated
    pub cmm_key:    CommitmentKey<D>,
    /// The generator for discrete log.
    pub g:          C,
}

pub struct ComEqSecret<C: Curve> {
    pub r: Randomness<C>,
    pub a: Value<C>,
}

#[allow(non_snake_case)]
impl<C: Curve, D: Curve<Scalar = C::Scalar>> SigmaProtocol for ComEq<C, D> {
    type CommitMessage = CommittedMessages<C, D>;
    type ProtocolChallenge = C::Scalar;
    // Vector of pairs (alpha_i, R_i).
    type ProverState = (Value<D>, Randomness<D>);
    type Response = Response<C>;
    type SecretData = ComEqSecret<D>;

    fn public(&self, ro: &mut RandomOracle) {
        ro.append_message("commitment", &self.commitment);
        ro.append_message("y", &self.y);
        ro.append_message("cmm_key", &self.cmm_key);
        ro.append_message("g", &self.g)
    }

    fn compute_commit_message<R: rand::Rng>(
        &self,
        csprng: &mut R,
    ) -> Option<(Self::CommitMessage, Self::ProverState)> {
        let mut u = C::zero_point();

        let alpha = Value::<D>::generate_non_zero(csprng);
        // This cR_i is R_i from the specification.
        let (v, cR) = self.cmm_key.commit(&alpha, csprng);
        u = u.plus_point(&self.g.mul_by_scalar(&alpha));
        Some((CommittedMessages { u, v }, (alpha, cR)))
    }

    fn get_challenge(
        &self,
        challenge: &crate::random_oracle::Challenge,
    ) -> Self::ProtocolChallenge {
        C::scalar_from_bytes(challenge)
    }

    fn compute_response(
        &self,
        secret: Self::SecretData,
        state: Self::ProverState,
        challenge: &Self::ProtocolChallenge,
    ) -> Option<Self::Response> {
        let (ref alpha, ref cR) = state;
        // compute alpha_i - a_i * c
        let mut s = *challenge;
        s.mul_assign(&secret.a);
        s.negate();
        s.add_assign(alpha);
        // compute R_i - r_i * c
        let mut t: C::Scalar = *challenge;
        t.mul_assign(&secret.r);
        t.negate();
        t.add_assign(cR);
        Some(Response { response: (s, t) })
    }

    fn extract_commit_message(
        &self,
        challenge: &Self::ProtocolChallenge,
        response: &Self::Response,
    ) -> Option<Self::CommitMessage> {
        // let mut u = self.y.mul_by_scalar(challenge);
        // FIXME: Could benefit from multiexponentiation
        // u = u.plus_point(&self.g.mul_by_scalar(&response.response.0));

        let u = multiexp(&[self.y, self.g], &[*challenge, response.response.0]);

        let v = self.commitment.mul_by_scalar(challenge).plus_point(
            &self
                .cmm_key
                .hide_worker(&response.response.0, &response.response.1),
        );
        Some(CommittedMessages {
            u,
            v: Commitment(v),
        })
    }

    #[cfg(test)]
    #[allow(clippy::many_single_char_names)]
    fn with_valid_data<R: rand::Rng>(
        _data_size: usize,
        csprng: &mut R,
        f: impl FnOnce(Self, Self::SecretData, &mut R),
    ) {
        let comm_key = CommitmentKey::generate(csprng);
        let a = Value::<D>::generate_non_zero(csprng);
        let (c, randomness) = comm_key.commit(&a, csprng);
        let g = C::generate(csprng);
        let mut y = C::zero_point();
        y = y.plus_point(&g.mul_by_scalar(&a));
        let com_eq = ComEq {
            commitment: c,
            y,
            cmm_key: comm_key,
            g,
        };
        let secret = ComEqSecret { r: randomness, a };
        f(com_eq, secret, csprng)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use pairing::bls12_381::{G1, G2};

    #[test]
    pub fn test_com_eq_correctness() {
        let mut csprng = rand::thread_rng();
        for _i in 1..20 {
            ComEq::<G1, G2>::with_valid_data(0, &mut csprng, |com_eq, secret, csprng| {
                let challenge_prefix = generate_challenge_prefix(csprng);
                let mut ro = RandomOracle::domain(challenge_prefix);
                let proof = prove(&mut ro.split(), &com_eq, secret, csprng)
                    .expect("Proving should succeed.");
                let res = verify(&mut ro, &com_eq, &proof);
                assert!(res, "Verification of produced proof.");
            })
        }
    }

    #[test]
    pub fn test_com_eq_soundness() {
        let mut csprng = rand::thread_rng();
        for i in 1..20 {
            ComEq::<G1, G2>::with_valid_data(i, &mut csprng, |com_eq, secret, csprng| {
                let challenge_prefix = generate_challenge_prefix(csprng);
                let ro = RandomOracle::domain(challenge_prefix);
                let proof = prove(&mut ro.split(), &com_eq, secret, csprng)
                    .expect("Proving should succeed.");

                let mut wrong_ro = RandomOracle::domain(generate_challenge_prefix(csprng));
                if verify(&mut wrong_ro, &com_eq, &proof) {
                    assert_eq!(wrong_ro, ro);
                }
                let mut wrong_com_eq = com_eq;
                {
                    let tmp = wrong_com_eq.commitment;
                    let v = Value::<G1>::generate(csprng);
                    wrong_com_eq.commitment = wrong_com_eq.cmm_key.commit(&v, csprng).0;
                    assert!(!verify(&mut ro.split(), &wrong_com_eq, &proof));
                    wrong_com_eq.commitment = tmp;
                }

                {
                    let tmp = wrong_com_eq.y;
                    wrong_com_eq.y = G1::generate(csprng);
                    assert!(!verify(&mut ro.split(), &wrong_com_eq, &proof));
                    wrong_com_eq.y = tmp;
                }

                {
                    let tmp = wrong_com_eq.cmm_key;
                    wrong_com_eq.cmm_key = CommitmentKey::generate(csprng);
                    assert!(!verify(&mut ro.split(), &wrong_com_eq, &proof));
                    wrong_com_eq.cmm_key = tmp;
                }

                {
                    let tmp = wrong_com_eq.g;
                    wrong_com_eq.g = G1::generate(csprng);
                    assert!(!verify(&mut ro.split(), &wrong_com_eq, &proof));
                    wrong_com_eq.g = tmp;
                }
            })
        }
    }
}
