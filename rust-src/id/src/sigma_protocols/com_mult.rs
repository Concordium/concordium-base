//! The module provides the implementation of the `com_mult` sigma protocol.
//! This protocol enables one to prove that the the product of two commited
//! values is equal to the third commited value, without revealing the values
//! themselves.
use crate::sigma_protocols::common::*;
use crypto_common::*;
use curve_arithmetic::{multiexp, Curve};
use ff::Field;
use pedersen_scheme::{Commitment, CommitmentKey, Randomness, Value};
use random_oracle::{Challenge, RandomOracle};

pub struct ComMultSecret<T: Curve> {
    pub values: [Value<T>; 2],
    pub rands:  [Randomness<T>; 3],
}

/// The ComMult sigma proof instance.
/// * `cmm_{1,2,3}` - The triple of commitments (the product of the first two
///   commited values should be equal to the last)
/// * `cmm_key` - The commitment key with which all the commitments are
///   generated.
pub struct ComMult<C: Curve> {
    pub cmms:    [Commitment<C>; 3],
    pub cmm_key: CommitmentKey<C>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct Witness<C: Curve> {
    /// The witness, expanded using the same notation as in the specification.
    ss: [C::Scalar; 2],
    ts: [C::Scalar; 2],
    t:  C::Scalar,
}

#[allow(non_snake_case)]
impl<C: Curve> SigmaProtocol for ComMult<C> {
    type CommitMessage = ([Commitment<C>; 2], Commitment<C>);
    type ProtocolChallenge = C::Scalar;
    // alpha's, R_i's, R's
    type ProverState = ([Value<C>; 2], [Randomness<C>; 2], Randomness<C>);
    type ProverWitness = Witness<C>;
    type SecretData = ComMultSecret<C>;

    #[inline]
    fn public(&self, ro: &mut RandomOracle) {
        ro.extend_from(b"cmms", self.cmms.iter());
        ro.append_message(b"cmm_key", &self.cmm_key)
    }

    #[inline]
    fn get_challenge(&self, challenge: &Challenge) -> Self::ProtocolChallenge {
        C::scalar_from_bytes(challenge)
    }

    #[inline]
    fn commit_point<R: rand::Rng>(
        &self,
        csprng: &mut R,
    ) -> Option<(Self::CommitMessage, Self::ProverState)> {
        let alpha_1 = Value::generate_non_zero(csprng);
        let alpha_2 = Value::generate_non_zero(csprng);

        let (v_1, cR_1) = self.cmm_key.commit(&alpha_1, csprng);
        let (v_2, cR_2) = self.cmm_key.commit(&alpha_2, csprng);

        let cmm_key_1 = CommitmentKey {
            g: self.cmms[0].0,
            h: self.cmm_key.h,
        };
        let (v, cR) = cmm_key_1.commit(&alpha_2, csprng);
        Some((([v_1, v_2], v), ([alpha_1, alpha_2], [cR_1, cR_2], cR)))
    }

    #[inline]
    fn generate_witness(
        &self,
        secret: Self::SecretData,
        state: Self::ProverState,
        challenge: &Self::ProtocolChallenge,
    ) -> Option<Self::ProverWitness> {
        let mut ss = [*challenge; 2];
        let mut ts = [*challenge; 2];

        let alphas = state.0;
        let rands = state.1;
        let cR = state.2;
        for i in 0..2 {
            ss[i].mul_assign(&secret.values[i]); // c * x_i
            ss[i].negate(); // - c * x_i
            ss[i].add_assign(&alphas[i]); // alpha - c * x_i

            ts[i].mul_assign(&secret.rands[i]); // c * r_i
            ts[i].negate(); // - c * r_i
            ts[i].add_assign(&rands[i]); // rTilde_i - c * r_i
        }

        // compute r_3 - r_1 * x_2
        let mut r = C::Scalar::one();
        r.mul_assign(&secret.rands[0]); // r_1
        r.mul_assign(&secret.values[1]); // r_1 * x_2
        r.negate();
        r.add_assign(&secret.rands[2]); // r_3 - r_1 * x_2

        let mut t = r;
        t.mul_assign(challenge);
        t.negate();
        t.add_assign(&cR);

        Some(Witness { ss, ts, t })
    }

    #[inline]
    fn extract_point(
        &self,
        challenge: &Self::ProtocolChallenge,
        witness: &Self::ProverWitness,
    ) -> Option<Self::CommitMessage> {
        let mut points = [Commitment(C::zero_point()); 2];
        for (i, (s_i, t_i)) in izip!(witness.ss.iter(), witness.ts.iter()).enumerate() {
            points[i] = {
                let bases = [self.cmms[i].0, self.cmm_key.g, self.cmm_key.h];
                let powers = [*challenge, *s_i, *t_i];
                let cmm = multiexp(&bases, &powers);
                Commitment(cmm) // g^s_i * h^t_i * C_i^c
            }
        }
        let h = &self.cmm_key.h;
        let s_2 = &witness.ss[1];
        let cC_3 = self.cmms[2];
        let cC_1 = self.cmms[0];
        let v = {
            let bases = [cC_1.0, *h, cC_3.0];
            let powers = [*s_2, witness.t, *challenge];
            multiexp(&bases, &powers) // C_1^s_2 * h^t * C_3^c
        };
        Some((points, Commitment(v)))
    }

    #[cfg(test)]
    fn with_valid_data<R: rand::Rng>(
        _data_size: usize,
        csprng: &mut R,
        f: impl FnOnce(Self, Self::SecretData, &mut R),
    ) {
        let cmm_key = CommitmentKey::generate(csprng);
        let a_1 = Value::<C>::generate_non_zero(csprng);
        let a_2 = Value::<C>::generate_non_zero(csprng);
        let mut a_3 = C::Scalar::one();
        a_3.mul_assign(&a_1);
        a_3.mul_assign(&a_2);
        let a_3: Value<C> = Value::new(a_3);

        let (cmm_1, r_1) = cmm_key.commit(&a_1, csprng);
        let (cmm_2, r_2) = cmm_key.commit(&a_2, csprng);
        let (cmm_3, r_3) = cmm_key.commit(&a_3, csprng);

        let secret = ComMultSecret {
            values: [a_1, a_2],
            rands:  [r_1, r_2, r_3],
        };

        let com_mult = ComMult {
            cmms: [cmm_1, cmm_2, cmm_3],
            cmm_key,
        };
        f(com_mult, secret, csprng)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::G1;
    use rand::thread_rng;

    #[test]
    pub fn test_com_mult_correctness() {
        let mut csprng = thread_rng();
        for _ in 0..100 {
            ComMult::<G1>::with_valid_data(0, &mut csprng, |com_mult, secret, csprng| {
                let challenge_prefix = generate_challenge_prefix(csprng);
                let mut ro = RandomOracle::domain(&challenge_prefix);
                let proof = prove(&mut ro.split(), &com_mult, secret, csprng)
                    .expect("Proving should succeed.");
                assert!(verify(&mut ro, &com_mult, &proof));
            })
        }
    }

    #[test]
    pub fn test_com_mult_soundness() {
        let mut csprng = thread_rng();
        for _ in 0..100 {
            ComMult::<G1>::with_valid_data(0, &mut csprng, |com_mult, secret, csprng| {
                let challenge_prefix = generate_challenge_prefix(csprng);
                let ro = RandomOracle::domain(&challenge_prefix);
                let proof = prove(&mut ro.split(), &com_mult, secret, csprng)
                    .expect("Proving should succeed.");
                assert!(verify(&mut ro.split(), &com_mult, &proof));

                // Construct invalid parameters
                let mut wrong_ro = RandomOracle::domain(generate_challenge_prefix(csprng));

                // Verify failure for invalid parameters, or that the same RO state has been
                // sampled
                if verify(&mut wrong_ro, &com_mult, &proof) {
                    assert_eq!(ro, wrong_ro)
                }
                let mut wrong_cmm = com_mult;
                for i in 0..3 {
                    let tmp = wrong_cmm.cmms[i];
                    let v = pedersen_scheme::Value::<G1>::generate(csprng);
                    wrong_cmm.cmms[i] = wrong_cmm.cmm_key.commit(&v, csprng).0;
                    assert!(!verify(&mut ro.split(), &wrong_cmm, &proof));
                    wrong_cmm.cmms[i] = tmp;
                }

                wrong_cmm.cmm_key = pedersen_scheme::CommitmentKey::generate(csprng);

                assert!(!verify(&mut ro.split(), &wrong_cmm, &proof))
            })
        }
    }
}
