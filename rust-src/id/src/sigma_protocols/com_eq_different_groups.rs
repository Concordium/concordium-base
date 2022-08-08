//! The module provides the implementation of the `com_eq_diff_groups` sigma
//! protocol. This protocol enables one to prove that the value committed to in
//! two commitments $C_1$ and $C_2$ in (potentially) two different groups (of
//! the same order) is the same.
use crate::sigma_protocols::common::*;
use crypto_common::*;
use crypto_common_derive::*;
use curve_arithmetic::{multiexp, Curve};
use ff::Field;
use pedersen_scheme::{Commitment, CommitmentKey, Randomness, Value};
use rand::*;
use random_oracle::RandomOracle;

#[derive(Debug)]
pub struct ComEqDiffGroupsSecret<C1: Curve, C2: Curve<Scalar = C1::Scalar>> {
    pub value:      Value<C2>,
    pub rand_cmm_1: Randomness<C1>,
    pub rand_cmm_2: Randomness<C2>,
}

#[derive(Clone, Debug, Eq, PartialEq, Copy, Serialize, SerdeBase16Serialize)]
pub struct Witness<C1: Curve, C2: Curve<Scalar = C1::Scalar>> {
    /// The triple (s_1, s_2, t).
    witness: (C1::Scalar, C1::Scalar, C2::Scalar),
}

pub struct ComEqDiffGroups<C1: Curve, C2: Curve> {
    /// A pair of commitments to the same value in different
    ///   groups.
    pub commitment_1: Commitment<C1>,
    pub commitment_2: Commitment<C2>,
    /// A pair of commitment keys (for the first and second
    /// commitment, respectively)
    pub cmm_key_1:    CommitmentKey<C1>,
    pub cmm_key_2:    CommitmentKey<C2>,
}

#[allow(non_snake_case)]
impl<C1: Curve, C2: Curve<Scalar = C1::Scalar>> SigmaProtocol for ComEqDiffGroups<C1, C2> {
    type CommitMessage = (Commitment<C1>, Commitment<C2>);
    type ProtocolChallenge = C1::Scalar;
    // The triple alpha_1, alpha_2, R
    type ProverState = (Value<C1>, Randomness<C1>, Randomness<C2>);
    type ProverWitness = Witness<C1, C2>;
    type SecretData = ComEqDiffGroupsSecret<C1, C2>;

    #[inline]
    fn public(&self, ro: &mut RandomOracle) {
        ro.append_message("commitment_1", &self.commitment_1);
        ro.append_message("commitment_2", &self.commitment_2);
        ro.append_message("cmm_key_1", &self.cmm_key_1);
        ro.append_message("cmm_key_2", &self.cmm_key_2)
    }

    #[inline]
    fn get_challenge(&self, challenge: &random_oracle::Challenge) -> Self::ProtocolChallenge {
        C1::scalar_from_bytes(challenge)
    }

    #[inline]
    fn commit_point<R: Rng>(
        &self,
        csprng: &mut R,
    ) -> Option<(Self::CommitMessage, Self::ProverState)> {
        let alpha_1 = Value::generate_non_zero(csprng);
        let (u, alpha_2) = self.cmm_key_1.commit(&alpha_1, csprng);
        let (v, cR) = self.cmm_key_2.commit(&alpha_1, csprng);
        Some(((u, v), (alpha_1, alpha_2, cR)))
    }

    #[inline]
    fn generate_witness(
        &self,
        secret: Self::SecretData,
        state: Self::ProverState,
        challenge: &Self::ProtocolChallenge,
    ) -> Option<Self::ProverWitness> {
        let mut s_1 = *challenge;
        s_1.mul_assign(&secret.value);
        s_1.negate();
        s_1.add_assign(&state.0);

        let mut s_2 = *challenge;
        s_2.mul_assign(&secret.rand_cmm_1);
        s_2.negate();
        s_2.add_assign(&state.1);

        let mut t = *challenge;
        t.mul_assign(&secret.rand_cmm_2);
        t.negate();
        t.add_assign(&state.2);
        Some(Witness {
            witness: (s_1, s_2, t),
        })
    }

    #[inline]
    #[allow(clippy::many_single_char_names)]
    fn extract_point(
        &self,
        challenge: &Self::ProtocolChallenge,
        witness: &Self::ProverWitness,
    ) -> Option<Self::CommitMessage> {
        let y = self.commitment_1;
        let cC = self.commitment_2;

        let CommitmentKey { g: cG1, h: cG2 } = self.cmm_key_1;
        let CommitmentKey { g, h } = self.cmm_key_2;

        let (s_1, s_2, t) = witness.witness;

        let u = {
            let bases = [y.0, cG1, cG2];
            let powers = [*challenge, s_1, s_2];
            multiexp(&bases, &powers)
        };
        // y
        //     .mul_by_scalar(challenge)
        //     .plus_point(&cG1.mul_by_scalar(&s_1))
        //     .plus_point(&cG2.mul_by_scalar(&s_2));
        let v = {
            let bases = [cC.0, g, h];
            let powers = [*challenge, s_1, t];
            multiexp(&bases, &powers)
        };
        // cC
        //     .mul_by_scalar(challenge)
        //     .plus_point(&g.mul_by_scalar(&s_1))
        //     .plus_point(&h.mul_by_scalar(&t));
        Some((Commitment(u), Commitment(v)))
    }

    #[cfg(test)]
    #[allow(clippy::many_single_char_names)]
    fn with_valid_data<R: Rng>(
        _data_size: usize,
        csprng: &mut R,
        f: impl FnOnce(Self, Self::SecretData, &mut R),
    ) {
        let a_1: Value<C2> = Value::generate_non_zero(csprng);
        let cmm_key_1: CommitmentKey<C1> = CommitmentKey::generate(csprng);
        let cmm_key_2: CommitmentKey<C2> = CommitmentKey::generate(csprng);

        let (u, a_2) = cmm_key_1.commit(&a_1, csprng);
        let (v, r) = cmm_key_2.commit(&a_1, csprng);
        let cdg = ComEqDiffGroups {
            cmm_key_1,
            cmm_key_2,
            commitment_1: u,
            commitment_2: v,
        };
        let secret = ComEqDiffGroupsSecret {
            value:      a_1,
            rand_cmm_1: a_2,
            rand_cmm_2: r,
        };
        f(cdg, secret, csprng)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::{G1, G2};

    #[test]
    pub fn test_com_eq_diff_grps_correctness() {
        let mut csprng = thread_rng();
        for _i in 0..100 {
            ComEqDiffGroups::<G1, G2>::with_valid_data(0, &mut csprng, |cdg, secret, csprng| {
                let challenge_prefix = generate_challenge_prefix(csprng);
                let mut ro = RandomOracle::domain(&challenge_prefix);

                let proof =
                    prove(&mut ro.split(), &cdg, secret, csprng).expect("Proving should succeed.");
                assert!(verify(&mut ro, &cdg, &proof))
            })
        }
    }

    #[test]
    pub fn test_com_eq_diff_grps_soundness() {
        let mut csprng = thread_rng();
        for _i in 0..100 {
            ComEqDiffGroups::<G1, G2>::with_valid_data(0, &mut csprng, |cdg, secret, csprng| {
                let challenge_prefix = generate_challenge_prefix(csprng);
                let ro = RandomOracle::domain(&challenge_prefix);

                let proof =
                    prove(&mut ro.split(), &cdg, secret, csprng).expect("Proving should succeed.");

                // Construct invalid parameters
                let mut wrong_ro = RandomOracle::domain(generate_challenge_prefix(csprng));
                if verify(&mut wrong_ro, &cdg, &proof) {
                    assert_eq!(wrong_ro, ro);
                }
                let mut wrong_cdg = cdg;
                {
                    let tmp = wrong_cdg.cmm_key_1;
                    wrong_cdg.cmm_key_1 = CommitmentKey::generate(csprng);
                    assert!(!verify(&mut ro.split(), &wrong_cdg, &proof));
                    wrong_cdg.cmm_key_1 = tmp;
                }
                {
                    let tmp = wrong_cdg.cmm_key_2;
                    wrong_cdg.cmm_key_1 = CommitmentKey::generate(csprng);
                    assert!(!verify(&mut ro.split(), &wrong_cdg, &proof));
                    wrong_cdg.cmm_key_2 = tmp;
                }

                {
                    let tmp = wrong_cdg.commitment_1;
                    wrong_cdg.commitment_1 = wrong_cdg
                        .cmm_key_1
                        .commit(&Value::<G1>::generate(csprng), csprng)
                        .0;
                    assert!(!verify(&mut ro.split(), &wrong_cdg, &proof));
                    wrong_cdg.commitment_1 = tmp;
                }

                {
                    let tmp = wrong_cdg.commitment_2;
                    wrong_cdg.commitment_2 = wrong_cdg
                        .cmm_key_2
                        .commit(&Value::<G2>::generate(csprng), csprng)
                        .0;
                    assert!(!verify(&mut ro.split(), &wrong_cdg, &proof));
                    wrong_cdg.commitment_2 = tmp;
                }
            })
        }
    }
}
