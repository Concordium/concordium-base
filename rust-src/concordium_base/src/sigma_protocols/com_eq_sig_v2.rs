//! This module implements the proof of knowledge of signature sigma protocol.
//! This protocol allows a user to prove knowledge of a PS signature without
//! revealing the original signature, or the message, but they have to reveal
//! the blinded version of the signature, and commitments to the values that
//! were signed. The protocol is a essentially `com-dlog-eq` from "Proof of
//! Equality for Aggregated Discrete Logarithms and Commitments" Section 9.2.5,
//! Bluepaper v1.2.5 where the blinded signature is the aggregated dlog (cf.
//! "Proof of Knowledge of a Signature" Section 5.3.5, Bluepaper v1.2.5")

use super::common::*;
use crate::{
    common::*,
    curve_arithmetic::*,
    pedersen_commitment::{Commitment, CommitmentKey, Randomness, Value},
    ps_sig::{BlindedSignature, BlindingRandomness, PublicKey as PsSigPublicKey},
    random_oracle::RandomOracle,
};
use itertools::izip;
use rand::*;

#[derive(Clone, Debug, Serialize)]
pub struct Response<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// The response that the prover knows $r'$ (see specification)
    r_prime: P::ScalarField,
    /// List of responses $(res_m_i, res_R_i)$ that the user knows the messages
    /// m_i and randomness R_i that combine to commitments and the public
    /// randomized signature.
    #[size_length = 4]
    ms_rs: Vec<(P::ScalarField, C::Scalar)>,
}

/// How to handle a signed message
#[derive(Clone)]
pub enum MessageHandling<C: Curve> {
    /// The message is proven known and equal to a commitment to the value
    EqualToCommitment(Commitment<C>),
    /// The value is revealed
    Revealed(Value<C>),
    // /// The value is proven known
    // Known
}

impl<C: Curve> Serial for MessageHandling<C> {
    fn serial<B: Buffer>(&self, out: &mut B) {
        match &self {
            MessageHandling::EqualToCommitment(cmm) => {
                out.put(&0u8);
                out.put(cmm);
            }
            MessageHandling::Revealed(value) => {
                out.put(&1u8);
                out.put(value);
            }
        }
    }
}

/// How to handle a signed message
#[derive(Clone)]
pub enum MessageSecret<C: Curve> {
    /// The message is proven known and equal to a commitment to the value
    EqualToCommitment(Value<C>, Randomness<C>),
    /// The value is revealed
    Revealed(Value<C>),
    // /// The value is proven known
    // Known
}

pub struct ComEqSig<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// The blinded signature
    pub blinded_sig: BlindedSignature<P>,
    /// A list of how to handle each message in the signature.
    /// Length must be equal to the number of signed messages in the signature
    pub msgs_handling: Vec<MessageHandling<C>>,
    /// The Pointcheval-Sanders public key with which the signature was
    /// generated
    pub ps_pub_key: PsSigPublicKey<P>,
    /// A commitment key with which the commitments were generated.
    pub comm_key: CommitmentKey<C>,
}

pub struct ComEqSigSecret<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    pub r_prime: BlindingRandomness<P>,
    pub msgs_secret: Vec<MessageSecret<C>>,
}

pub struct ComEqSigState<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    pub r_prime: P::ScalarField,
    pub ms_rs: Vec<(Value<C>, Randomness<C>)>,
}

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>> SigmaProtocol for ComEqSig<P, C> {
    type CommitMessage = (P::TargetField, Vec<Commitment<C>>);
    type ProtocolChallenge = C::Scalar;
    type ProverState = ComEqSigState<P, C>;
    type Response = Response<P, C>;
    type SecretData = ComEqSigSecret<P, C>;

    #[inline]
    fn public(&self, ro: &mut RandomOracle) {
        ro.append_message(b"blinded_sig", &self.blinded_sig);
        ro.extend_from(b"messages", self.msgs_handling.iter());
        ro.append_message(b"ps_pub_key", &self.ps_pub_key);
        ro.append_message(b"comm_key", &self.comm_key)
    }

    #[inline]
    fn get_challenge(
        &self,
        challenge: &crate::random_oracle::Challenge,
    ) -> Self::ProtocolChallenge {
        C::scalar_from_bytes(challenge)
    }

    #[inline]
    fn compute_commit_message<R: Rng>(
        &self,
        csprng: &mut R,
    ) -> Option<(Self::CommitMessage, Self::ProverState)> {
        let g_tilda = self.ps_pub_key.g_tilda;
        let a_hat = self.blinded_sig.sig.0;
        let _b_hat = self.blinded_sig.sig.1;
        let _x_tilda = self.ps_pub_key.x_tilda;
        let y_tilda = |i| self.ps_pub_key.y_tildas[i];
        let cmm_key = self.comm_key;

        if self.msgs_handling.len() > self.ps_pub_key.len() {
            return None;
        }

        let cmm_count = self
            .msgs_handling
            .iter()
            .filter(|msg| matches!(msg, MessageHandling::EqualToCommitment(_)))
            .count();

        // Random elements corresponding to the messages m_i, used as responses
        // for the aggregate log part of the proof, and the randomness r_i used
        // for the commitment part of the proof.
        let mut ms_rs = Vec::with_capacity(cmm_count);

        // randomness corresponding to the r'
        let r_prime = <P::G2 as Curve>::generate_non_zero_scalar(csprng);

        // The auxiliary point which we are going to pair with a_hat to obtain the final
        // challenge. This is using the bilinearity property of pairings and differs
        // from the specification in the way the computation is carried out, but
        // not in the observable outcomes.
        let mut v_2_curve = g_tilda.mul_by_scalar(&r_prime);

        let mut cmms = Vec::with_capacity(cmm_count);
        for (i, msg_handling) in self.msgs_handling.iter().enumerate() {
            if let MessageHandling::EqualToCommitment(_) = msg_handling {
                // Random value.
                let m_i = Value::generate_non_zero(csprng);

                // And a point in G2 computed from it.
                let y_exp_m_i = y_tilda(i).mul_by_scalar(&m_i);
                // A commitment to the value v_i, and a randomness
                let (c_i, r_i) = cmm_key.commit(&m_i, csprng);

                cmms.push(c_i);

                // Save these for later
                ms_rs.push((m_i, r_i));

                // And the other point to the running total (since we have to hash the result of
                // the pairing)
                v_2_curve = v_2_curve.plus_point(&y_exp_m_i);
            }
        }
        let v_2 = P::pair(&a_hat, &v_2_curve);
        Some(((v_2, cmms), ComEqSigState { r_prime, ms_rs }))
    }

    #[inline]
    fn compute_response(
        &self,
        secret: Self::SecretData,
        state: Self::ProverState,
        challenge: &Self::ProtocolChallenge,
    ) -> Option<Self::Response> {
        let cmm_count = secret
            .msgs_secret
            .iter()
            .filter(|secret| matches!(secret, MessageSecret::EqualToCommitment(_, _)))
            .count();

        if state.ms_rs.len() != cmm_count {
            return None;
        }

        let r_prime = secret.r_prime.1;
        // If challange = 0 the proof is not going to be valid.
        // However this is an exceedingly unlikely case
        let mut res_r_prime = *challenge;
        res_r_prime.mul_assign(&r_prime);
        res_r_prime.negate();
        res_r_prime.add_assign(&state.r_prime);

        let mut res_ms_rs = Vec::with_capacity(cmm_count);
        for ((m, r), (ref m_t, ref r_t)) in izip!(
            secret.msgs_secret.iter().filter_map(|msg| match msg {
                MessageSecret::EqualToCommitment(m, r) => Some((m, r)),
                MessageSecret::Revealed(_) => None,
            }),
            state.ms_rs
        ) {
            let mut res_m = *challenge;
            res_m.mul_assign(m);
            res_m.negate();
            res_m.add_assign(m_t);

            let mut res_r = *challenge;
            res_r.mul_assign(r);
            res_r.negate();
            res_r.add_assign(r_t);

            res_ms_rs.push((res_m, res_r));
        }
        Some(Response {
            r_prime: res_r_prime,
            ms_rs: res_ms_rs,
        })
    }

    #[inline]
    fn extract_commit_message(
        &self,
        challenge: &Self::ProtocolChallenge,
        response: &Self::Response,
    ) -> Option<Self::CommitMessage> {
        let g_tilda = self.ps_pub_key.g_tilda;
        let a_hat = self.blinded_sig.sig.0;
        let b_hat = self.blinded_sig.sig.1;
        let x_tilda = self.ps_pub_key.x_tilda;
        let y_tilda = |i| self.ps_pub_key.y_tildas[i];
        let cmm_key = self.comm_key;

        if self.msgs_handling.len() > self.ps_pub_key.len() {
            return None;
        }

        let cmm_count = self
            .msgs_handling
            .iter()
            .filter(|msg| matches!(msg, MessageHandling::EqualToCommitment(_)))
            .count();

        if response.ms_rs.len() != cmm_count {
            return None;
        }

        // storing values for multiexponentiation. gs is bases, es is powers.
        let mut gs = Vec::with_capacity(self.msgs_handling.len() + 2);
        let mut es = Vec::with_capacity(self.msgs_handling.len() + 2);

        gs.push(g_tilda);
        es.push(response.r_prime);
        let challenge_neg = {
            let mut x = *challenge;
            x.negate();
            x
        };
        let mut cmms = Vec::with_capacity(cmm_count);
        for ((i, c_i), (res_m, res_r)) in izip!(
            self.msgs_handling
                .iter()
                .enumerate()
                .filter_map(|(i, msg)| match msg {
                    MessageHandling::EqualToCommitment(c_i) => Some((i, c_i)),
                    MessageHandling::Revealed(_) => None,
                }),
            response.ms_rs.iter()
        ) {
            // compute c_i^c * g^m_i h^r_i
            let bases = [c_i.0, cmm_key.g, cmm_key.h];
            let powers = [*challenge, *res_m, *res_r];
            let c = multiexp(&bases, &powers);
            cmms.push(Commitment(c));
            gs.push(y_tilda(i));
            es.push(*res_m);
        }

        for (i, m_i) in self
            .msgs_handling
            .iter()
            .enumerate()
            .filter_map(|(i, msg)| match msg {
                MessageHandling::EqualToCommitment(c_i) => None,
                MessageHandling::Revealed(value) => Some((i, value)),
            })
        {
            gs.push(y_tilda(i));
            let mut exp = challenge_neg;
            exp.mul_assign(m_i);
            es.push(exp);
        }

        // finally add X_tilda and -challenge to the power (adjustment since X_tilda is not part of the commitment)
        gs.push(x_tilda);
        es.push(challenge_neg);

        let v_2_curve = multiexp(&gs, &es);

        // We have now computed a point `point` such that
        // ```v_3^{-c} * v_1^R \prod u_i^w_i = e(a_hat, point)```
        // If the proof is correct then the challenge was computed with
        // v_2^c * v^3{-c} * ...
        // where * is the multiplication in the target field (of which the G_T is a multiplicative subgroup).

        // Combine the pairing computations to compute the product.
        let v_2 = P::pairing_product(
            &b_hat,
            &g_tilda.mul_by_scalar(challenge),
            &a_hat,
            &v_2_curve,
        )?;

        Some((v_2, cmms))
    }

    #[cfg(test)]
    fn with_valid_data<R: Rng>(
        data_size: usize,
        csprng: &mut R,
        f: impl FnOnce(Self, Self::SecretData, &mut R),
    ) {
        use crate::ps_sig::{SecretKey as PsSigSecretKey, SigRetrievalRandomness, UnknownMessage};
        let ps_sk: PsSigSecretKey<P> = PsSigSecretKey::generate(data_size, csprng);
        let ps_pk: PsSigPublicKey<P> = PsSigPublicKey::from(&ps_sk);
        let cmm_key = CommitmentKey::generate(csprng);

        let mut secrets = Vec::with_capacity(data_size);
        // commitment to the signer.
        // the randomness used to mask the actual values.
        let mask = SigRetrievalRandomness::generate_non_zero(csprng);
        let mut comm_to_signer: P::G1 = ps_pk.g.mul_by_scalar(&mask);
        let mut messages = Vec::with_capacity(data_size);
        for cY_j in ps_pk.ys.iter().take(csprng.gen_range(0..data_size)) {
            let v_j = Value::generate(csprng);
            comm_to_signer = comm_to_signer.plus_point(&cY_j.mul_by_scalar(&v_j));

            let commitment = csprng.gen_bool(0.5);
            if commitment {
                let (c_j, r_j) = cmm_key.commit(&v_j, csprng);
                secrets.push(MessageSecret::EqualToCommitment(v_j, r_j));
                messages.push(MessageHandling::EqualToCommitment(c_j));
            } else {
                secrets.push(MessageSecret::Revealed(Clone::clone(&v_j)));
                messages.push(MessageHandling::Revealed(v_j));
            }
        }
        let unknown_message = UnknownMessage(comm_to_signer);
        let sig = ps_sk
            .sign_unknown_message(&unknown_message, csprng)
            .retrieve(&mask);
        let (blinded_sig, blind_rand) = sig.blind(csprng);
        let ces = ComEqSig {
            msgs_handling: messages,
            ps_pub_key: ps_pk,
            comm_key: cmm_key,
            blinded_sig,
        };

        let secret = ComEqSigSecret {
            r_prime: blind_rand,
            msgs_secret: secrets,
        };
        f(ces, secret, csprng)
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::G1Projective;

    use super::*;
    use crate::{
        curve_arithmetic::arkworks_instances::ArkGroup,
        ps_sig::{SecretKey as PsSigSecretKey, Signature},
    };

    type G1 = ArkGroup<G1Projective>;
    type Bls12 = ark_ec::models::bls12::Bls12<ark_bls12_381::Config>;

    const TEST_RUNS: usize = 200;

    #[test]
    #[allow(non_snake_case)]
    pub fn test_com_eq_sig_correctness() {
        let mut csprng = thread_rng();
        for i in 1..TEST_RUNS + 1 {
            ComEqSig::<Bls12, G1>::with_valid_data(i, &mut csprng, |ces, secret, csprng| {
                let challenge_prefix = generate_challenge_prefix(csprng);
                let mut ro = RandomOracle::domain(challenge_prefix);

                let proof =
                    prove(&mut ro.split(), &ces, secret, csprng).expect("Proving should succeed.");
                assert!(verify(&mut ro, &ces, &proof));
            })
        }
    }

    // todo ar more soundness tests?

    #[test]
    #[allow(non_snake_case)]
    pub fn test_com_eq_sig_soundness() {
        let mut csprng = thread_rng();
        for i in 1..TEST_RUNS + 1 {
            ComEqSig::<Bls12, G1>::with_valid_data(i, &mut csprng, |ces, secret, csprng| {
                let challenge_prefix = generate_challenge_prefix(csprng);
                let ro = RandomOracle::domain(challenge_prefix);

                let proof =
                    prove(&mut ro.split(), &ces, secret, csprng).expect("Proving should succeed.");
                assert!(verify(&mut ro.split(), &ces, &proof));

                // Construct invalid parameters
                let mut wrong_ro = RandomOracle::domain(generate_challenge_prefix(csprng));
                if verify(&mut wrong_ro, &ces, &proof) {
                    assert_eq!(wrong_ro, ro);
                }

                let mut wrong_ces = ces;
                {
                    let tmp = wrong_ces.blinded_sig;
                    wrong_ces.blinded_sig = BlindedSignature {
                        sig: Signature(G1::generate(csprng), G1::generate(csprng)),
                    };
                    assert!(!verify(&mut ro.split(), &wrong_ces, &proof));
                    wrong_ces.blinded_sig = tmp;
                }

                {
                    if !wrong_ces.msgs_handling.is_empty() {
                        let idx = csprng.gen_range(0..wrong_ces.msgs_handling.len());
                        let tmp = wrong_ces.msgs_handling[idx].clone();
                        wrong_ces.msgs_handling[idx] = MessageHandling::EqualToCommitment(
                            wrong_ces
                                .comm_key
                                .commit(&Value::<G1>::generate(csprng), csprng)
                                .0,
                        );
                        assert!(!verify(&mut ro.split(), &wrong_ces, &proof));
                        wrong_ces.msgs_handling[idx] = tmp;
                    }
                }

                {
                    let tmp = wrong_ces.comm_key;
                    wrong_ces.comm_key = CommitmentKey::generate(csprng);
                    assert!(!verify(&mut ro.split(), &wrong_ces, &proof));
                    wrong_ces.comm_key = tmp;
                }

                {
                    let tmp = wrong_ces.ps_pub_key;
                    wrong_ces.ps_pub_key =
                        PsSigPublicKey::from(&PsSigSecretKey::generate(i, csprng));
                    assert!(!verify(&mut ro.split(), &wrong_ces, &proof));
                    wrong_ces.ps_pub_key = tmp;
                }
            })
        }
    }
}
