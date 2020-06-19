//! The module provides the implementation of the `com_eq` sigma protocol.
//! This protocol enables one to prove knowledge of discrete logarithms $a_1 ...
//! a_n$ together with randomnesses $r_1 ... r_n$ corresponding to public values
//! $ y = \prod G_i^{a_i} $ and commitments $C_i = commit(a_i, r_i)$.
//! The product y and commitments can be in different groups, but they have to
//! be of the same prime order, and for the implementation the field of scalars
//! must be the same type for both groups.

use curve_arithmetic::Curve;
use ff::Field;

use random_oracle::RandomOracle;

use crypto_common::*;
use crypto_common_derive::*;
use pedersen_scheme::{Commitment, CommitmentKey, Randomness, Value};

use crate::sigma_protocols::common::*;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, SerdeBase16Serialize)]
pub struct Witness<T: Curve> {
    /// The list of pairs $(s_i, t_i)$ where
    /// * $s_i = \alpha_i - c a_i$
    /// * $t_i = R_i - c r_i$
    /// where $c$ is the challenge and $\alpha_i$ and $R_i$ are prover chosen
    /// random scalars.
    #[size_length = 4]
    witness: Vec<(T::Scalar, T::Scalar)>,
}

type Proof<C> = SigmaProof<Witness<C>>;

#[derive(Debug, Serialize)]
struct CommittedPoints<C: Curve> {
    pub(crate) u: C,
    #[size_length = 4]
    pub(crate) vs: Vec<Commitment<C>>,
}

pub struct ComEq<'a, C: Curve> {
    /// The list of commitments.
    commitments: &'a [Commitment<C>],
    /// The evaluation $y$ (see above for notation).
    y: &'a C,
    /// The commitment key with which all the commitments are
    ///   generated
    cmm_key: &'a CommitmentKey<C>,
    /// The list of generators for discrete log proofs.
    gxs: &'a [C],
}

impl<'a, C: Curve> SigmaProtocol for ComEq<'a, C> {
    type CommitMessage = CommittedPoints<C>;
    type SecretData = &'a [(Randomness<C>, Value<C>)];
    // Vector of pairs (alpha_i, R_i).
    type ProverState = Vec<(Value<C>, Randomness<C>)>;
    type ProverWitness = Witness<C>;
    type ProtocolChallenge = C::Scalar;

    fn public(&self, ro: RandomOracle) -> RandomOracle {
        ro.extend_from(self.commitments.iter())
            .append(self.y)
            .append(self.cmm_key)
            .extend_from(self.gxs.iter())
    }

    fn commit_point<R: rand::Rng>(
        &self,
        csprng: &mut R,
    ) -> Option<(Self::CommitMessage, Self::ProverState)> {
        let n = self.commitments.len();
        if self.gxs.len() != n {
            return None;
        };

        let mut rands = Vec::with_capacity(n);

        let mut u = C::zero_point();

        let mut vs = Vec::with_capacity(n);
        for g in self.gxs {
            let alpha_i = Value::<C>::generate_non_zero(csprng);
            // This cR_i is R_i from the specification.
            let (v_i, cR_i) = self.cmm_key.commit(&alpha_i, csprng);
            u = u.plus_point(&g.mul_by_scalar(&alpha_i));
            rands.push((alpha_i, cR_i));
            vs.push(v_i)
        }
        Some((CommittedPoints { u, vs }, rands))
    }
    fn get_challenge(&self, challenge: &random_oracle::Challenge) -> Self::ProtocolChallenge {
        C::scalar_from_bytes_mod(&challenge)
    }

    fn generate_witness(
        &self,
        secret: Self::SecretData,
        state: Self::ProverState,
        challenge: &Self::ProtocolChallenge,
    ) -> Option<Self::ProverWitness> {
        if secret.len() != state.len() {
            return None;
        }
        let mut witness = Vec::with_capacity(secret.len());
        for ((r_i, a_i), (ref alpha_i, ref cR_i)) in izip!(secret, state) {
            // compute alpha_i - a_i * c
            let mut s_i = *challenge;
            s_i.mul_assign(a_i);
            s_i.negate();
            s_i.add_assign(alpha_i);
            // compute R_i - r_i * c
            let mut t_i: C::Scalar = *challenge;
            t_i.mul_assign(r_i);
            t_i.negate();
            t_i.add_assign(cR_i);
            witness.push((s_i, t_i));
        }
        Some(Witness { witness })
    }

    fn extract_point(
        &self,
        challenge: &Self::ProtocolChallenge,
        witness: &Self::ProverWitness,
    ) -> Option<Self::CommitMessage> {
        let n = self.commitments.len();
        if witness.witness.len() != n {
            return None;
        }
        if self.gxs.len() != n {
            return None;
        }

        let mut u = self.y.mul_by_scalar(challenge);
        // FIXME: Could benefit from multiexponentiation
        for (g, (s_i, _)) in izip!(self.gxs, &witness.witness) {
            u = u.plus_point(&g.mul_by_scalar(&s_i));
        }
        let mut vs = Vec::with_capacity(n);
        for (c, (s_i, t_i)) in izip!(self.commitments.iter(), &witness.witness) {
            let v = c.mul_by_scalar(challenge).plus_point(
                &self
                    .cmm_key
                    .hide(Value::view_scalar(s_i), Randomness::view_scalar(t_i)),
            );
            vs.push(Commitment(v));
        }
        Some(CommittedPoints { u, vs })
    }

    #[cfg(test)]
    fn with_valid_data<R: rand::Rng>(
        data_size: usize,
        csprng: &mut R,
        f: impl FnOnce(Self, Self::SecretData) -> (),
    ) {
        let mut secret = Vec::with_capacity(data_size);
        let mut cxs = Vec::with_capacity(data_size);
        let mut gxs = Vec::with_capacity(data_size);
        let g = C::generate(&mut csprng);
        let h = C::generate(&mut csprng);
        let mut y = C::zero_point();
        let comm_key = CommitmentKey(g, h);
        for _ in 0..data_size {
            let a = Value::generate_non_zero(&mut csprng);
            let (c, randomness) = comm_key.commit(&a, &mut csprng);
            let g_i = C::generate(&mut csprng);
            y = y.plus_point(&g_i.mul_by_scalar(&a));
            secret.push((randomness, a));
            cxs.push(c);
            gxs.push(g_i);
        }
        let com_eq = ComEq {
            commitments: &cxs,
            y: &y,
            cmm_key: &comm_key,
            gxs: &gxs,
        };
        f(com_eq, &secret)
    }
}

/* /// Specialization of the above for when we only have a single commitment.
pub fn prove_com_eq_single<C: Curve, T: Curve<Scalar = C::Scalar>, R: Rng>(
    ro: RandomOracle,
    commitment: &Commitment<C>,
    y: &T,
    cmm_key: &CommitmentKey<C>,
    gx: &T,
    secret: (&Randomness<C>, &Value<C>),
    csprng: &mut R,
) -> ComEqProof<C> {
    prove_com_eq(ro, &[*commitment], y, cmm_key, &[*gx], &[secret], csprng)
}

/// Specialization of the above when only a single commitment is given.
pub fn verify_com_eq_single<C: Curve, T: Curve<Scalar = C::Scalar>>(
    ro: RandomOracle,
    commitment: &Commitment<C>,
    y: &T,
    cmm_key: &CommitmentKey<C>,
    gx: &T,
    proof: &ComEqProof<C>,
) -> bool {
    verify_com_eq(ro, &[*commitment], y, cmm_key, &[*gx], proof)
} */

#[cfg(test)]
mod test {
    use super::*;
    use pairing::bls12_381::G1;
    use rand::Rng;

    #[test]
    pub fn test_com_eq_correctness() {
        let mut csprng = rand::thread_rng();
        for i in 1..20 {
            ComEq::<G1>::with_valid_data(i, &mut csprng, |com_eq, secret| {
                let challenge_prefix = generate_challenge_prefix(&mut csprng);
                let ro = RandomOracle::domain(&challenge_prefix);
                let proof = prove(ro.split(), &com_eq, secret, &mut csprng)
                    .expect("Proving should succeed.");
                let res = verify(ro, &com_eq, &proof);
                assert!(res, "Verification of produced proof.");
            })
        }
    }

    #[test]
    pub fn test_com_eq_soundness() {
        let mut csprng = rand::thread_rng();
        for i in 1..20 {
            ComEq::<G1>::with_valid_data(i, &mut csprng, |com_eq, secret| {
                let challenge_prefix = generate_challenge_prefix(&mut csprng);
                let ro = RandomOracle::domain(&challenge_prefix);
                let proof = prove(ro.split(), &com_eq, secret, &mut csprng)
                    .expect("Proving should succeed.");

                // Construct invalid parameters
                let index_wrong_cx: usize = csprng.gen_range(0, i);
                let index_wrong_gx: usize = csprng.gen_range(0, i);

                let wrong_ro = RandomOracle::domain(generate_challenge_prefix(&mut csprng));
                assert!(!verify(wrong_ro, &com_eq, &proof));
                let mut wrong_com_eq = com_eq;
                {
                    let tmp = wrong_com_eq.commitments[index_wrong_cx];
                    wrong_com_eq.commitments[index_wrong_cx] = com_eq
                        .cmm_key
                        .commit(&Value::generate(&mut csprng), &mut csprng)
                        .0;
                    assert!(!verify(ro.split(), &wrong_com_eq, &proof));
                    wrong_com_eq.commitments[index_wrong_cx] = tmp;
                }

                {
                    let mut tmp = com_eq.y;
                    wrong_com_eq.y = &G1::generate(&mut csprng);
                    assert!(!verify(ro.split(), &wrong_com_eq, &proof));
                    wrong_com_eq.y = tmp;
                }

                {
                    let mut tmp = com_eq.cmm_key;
                    wrong_com_eq.cmm_key = &CommitmentKey::generate(&mut csprng);
                    assert!(!verify(ro.split(), &wrong_com_eq, &proof));
                    wrong_com_eq.cmm_key = tmp;
                }

                {
                    let mut tmp = wrong_com_eq.gxs[index_wrong_gx];
                    wrong_com_eq.gxs[index_wrong_gx] = G1::generate(&mut csprng);
                    assert!(!verify(ro.split(), &wrong_com_eq, &proof));
                    wrong_com_eq.gxs[index_wrong_gx] = tmp;
                }
            })
        }
    }
}
