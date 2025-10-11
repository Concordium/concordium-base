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
    ps_sig::{BlindedSignature, PublicKey as PsSigPublicKey},
    random_oracle::RandomOracle,
};
use rand::*;

/// How to handle a single part of the signed message
#[derive(Clone)]
pub enum MsgPartHandling<C: Curve> {
    /// The message is proven known and equal to a commitment to the value
    EqualToCommitment(Commitment<C>),
    /// The value is revealed
    Revealed(Value<C>),
    /// The value is proven known
    Known,
}

// Serialization used to hash into the transcript
impl<C: Curve> Serial for MsgPartHandling<C> {
    fn serial<B: Buffer>(&self, out: &mut B) {
        match &self {
            MsgPartHandling::EqualToCommitment(cmm) => {
                out.put(&0u8);
                out.put(cmm);
            }
            MsgPartHandling::Revealed(value) => {
                out.put(&1u8);
                out.put(value);
            }
            MsgPartHandling::Known => {
                out.put(&2u8);
            }
        }
    }
}

pub struct ComEqSig<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// The blinded signature
    pub blinded_sig: BlindedSignature<P>,
    /// A list of how to handle each message in the signature.
    /// Length must be equal to the number of signed messages in the signature
    pub msgs_handling: Vec<MsgPartHandling<C>>,
    /// The Pointcheval-Sanders public key with which the signature was
    /// generated
    pub ps_pub_key: PsSigPublicKey<P>,
    /// A commitment key with which the commitments were generated.
    pub comm_key: CommitmentKey<C>,
}

/// Random state used to calculate sigma protocol commitment and to calculate response later
pub struct ComEqSigState<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    r_prime_rand: P::ScalarField,
    msgs_rand: Vec<MsgPartSecret<C>>,
}

/// How to handle a signed message
#[derive(Debug, Clone)]
pub enum MsgPartSecret<C: Curve> {
    /// The message is proven known and equal to a commitment to the value
    EqualToCommitment(Value<C>, Randomness<C>),
    /// The value is revealed
    Revealed,
    /// The value is proven known
    Known(Value<C>),
}

impl<C: Curve> Serial for MsgPartSecret<C> {
    fn serial<B: Buffer>(&self, out: &mut B) {
        todo!()
    }
}

impl<C: Curve> Deserial for MsgPartSecret<C> {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        todo!()
    }
}

/// Secret values used in proof
pub struct ComEqSigSecret<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    pub r_prime: Secret<P::ScalarField>,
    pub msgs: Vec<MsgPartSecret<C>>,
}

/// Response in sigma protocol
#[derive(Clone, Debug, Serialize)]
pub struct Response<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// The response that the prover knows $r'$ (see specification)
    r_prime_resp: P::ScalarField,
    /// List of responses $(res_m_i, res_R_i)$ that the user knows the messages
    /// m_i and randomness R_i that combine to commitments and the public
    /// randomized signature.
    #[size_length = 4]
    msgs_resp: Vec<MsgPartSecret<C>>,
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
            .filter(|msg| matches!(msg, MsgPartHandling::EqualToCommitment(_)))
            .count();

        // Random elements corresponding to the secrets (used for blinding when the .
        let mut msgs_rand = Vec::with_capacity(self.msgs_handling.len());

        // randomness corresponding to the r'
        let r_prime_rand = <P::G2 as Curve>::generate_non_zero_scalar(csprng);

        // Group element to pair with a_hat to obtain the commitment
        // corresponding to v_2.
        let mut v_2_curve = g_tilda.mul_by_scalar(&r_prime_rand);

        let mut cmms = Vec::with_capacity(cmm_count);
        for (i, msg_handling) in self.msgs_handling.iter().enumerate() {
            match msg_handling {
                MsgPartHandling::EqualToCommitment(_) => {
                    // Random value.
                    let m_i = Value::generate_non_zero(csprng);

                    // A commitment to the value m_i, and a randomness
                    let (c_i, r_i) = cmm_key.commit(&m_i, csprng);
                    cmms.push(c_i);

                    let y_exp_m_i = y_tilda(i).mul_by_scalar(&m_i);
                    v_2_curve = v_2_curve.plus_point(&y_exp_m_i);

                    // Save state for response
                    msgs_rand.push(MsgPartSecret::EqualToCommitment(m_i, r_i));
                }
                MsgPartHandling::Revealed(_) => {
                    msgs_rand.push(MsgPartSecret::Revealed);
                }
                MsgPartHandling::Known => {
                    // Random value.
                    let m_i = Value::generate_non_zero(csprng);

                    let y_exp_m_i = y_tilda(i).mul_by_scalar(&m_i);
                    v_2_curve = v_2_curve.plus_point(&y_exp_m_i);

                    // Save state for response
                    msgs_rand.push(MsgPartSecret::Known(m_i));
                }
            }
        }
        let v_2 = P::pair(&a_hat, &v_2_curve);
        Some((
            (v_2, cmms),
            ComEqSigState {
                r_prime_rand,
                msgs_rand,
            },
        ))
    }

    #[inline]
    fn compute_response(
        &self,
        secret: Self::SecretData,
        state: Self::ProverState,
        challenge: &Self::ProtocolChallenge,
    ) -> Option<Self::Response> {
        // If challange = 0 the proof is not going to be valid.
        // However this is an exceedingly unlikely case
        let mut r_prime_resp = *challenge;
        r_prime_resp.mul_assign(&secret.r_prime);
        r_prime_resp.negate();
        r_prime_resp.add_assign(&state.r_prime_rand);

        let mut msgs_resp = Vec::with_capacity(self.msgs_handling.len());
        for (msg_part_state, msg_part_secret) in state.msgs_rand.iter().zip(secret.msgs.iter()) {
            match (msg_part_state, msg_part_secret) {
                (
                    MsgPartSecret::EqualToCommitment(m_i_rand, r_i_rand),
                    MsgPartSecret::EqualToCommitment(m_i, r_i),
                ) => {
                    let mut m_i_resp = *challenge;
                    m_i_resp.mul_assign(m_i);
                    m_i_resp.negate();
                    m_i_resp.add_assign(m_i_rand);

                    let mut r_i_resp = *challenge;
                    r_i_resp.mul_assign(r_i);
                    r_i_resp.negate();
                    r_i_resp.add_assign(r_i_rand);

                    msgs_resp.push(MsgPartSecret::EqualToCommitment(
                        Value::new(m_i_resp),
                        Randomness::new(r_i_resp),
                    ));
                }
                (MsgPartSecret::Revealed, MsgPartSecret::Revealed) => {
                    msgs_resp.push(MsgPartSecret::Revealed);
                }
                (MsgPartSecret::Known(m_i_rand), MsgPartSecret::Known(m_i)) => {
                    let mut m_i_resp = *challenge;
                    m_i_resp.mul_assign(m_i);
                    m_i_resp.negate();
                    m_i_resp.add_assign(m_i_rand);

                    msgs_resp.push(MsgPartSecret::Known(Value::new(m_i_resp)));
                }
                _ => return None,
            }
        }
        Some(Response {
            r_prime_resp,
            msgs_resp,
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
            .filter(|msg| matches!(msg, MsgPartHandling::EqualToCommitment(_)))
            .count();

        // storing values for multiexponentiation. gs is bases, es is powers.
        let mut gs = Vec::with_capacity(self.msgs_handling.len() + 2);
        let mut es = Vec::with_capacity(self.msgs_handling.len() + 2);

        gs.push(g_tilda);
        es.push(response.r_prime_resp);
        let challenge_neg = {
            let mut x = *challenge;
            x.negate();
            x
        };
        let mut cmms = Vec::with_capacity(cmm_count);
        for (i, (msg_handling, msg_part_resp)) in self
            .msgs_handling
            .iter()
            .zip(&response.msgs_resp)
            .enumerate()
        {
            match (msg_handling, msg_part_resp) {
                (
                    MsgPartHandling::EqualToCommitment(c_i),
                    MsgPartSecret::EqualToCommitment(m_i_resp, r_i_resp),
                ) => {
                    let bases = [c_i.0, cmm_key.g, cmm_key.h];
                    let powers = [*challenge, **m_i_resp.value, **r_i_resp.randomness];
                    let c = multiexp(&bases, &powers);
                    cmms.push(Commitment(c));
                    gs.push(y_tilda(i));
                    es.push(**m_i_resp);
                }
                (MsgPartHandling::Revealed(m_i), MsgPartSecret::Revealed) => {
                    gs.push(y_tilda(i));
                    let mut exp = challenge_neg;
                    exp.mul_assign(m_i);
                    es.push(exp);
                }
                (MsgPartHandling::Known, MsgPartSecret::Known(m_i_resp)) => {
                    gs.push(y_tilda(i));
                    es.push(**m_i_resp);
                }
                _ => return None,
            }
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
        let mut msgs_handling = Vec::with_capacity(data_size);
        for y_j in ps_pk.ys.iter().take(csprng.gen_range(0..data_size)) {
            let v_j = Value::generate(csprng);
            comm_to_signer = comm_to_signer.plus_point(&y_j.mul_by_scalar(&v_j));

            match csprng.gen_range(0..3) {
                0 => {
                    let (c_j, r_j) = cmm_key.commit(&v_j, csprng);
                    secrets.push(MsgPartSecret::EqualToCommitment(v_j, r_j));
                    msgs_handling.push(MsgPartHandling::EqualToCommitment(c_j));
                }
                1 => {
                    secrets.push(MsgPartSecret::Revealed);
                    msgs_handling.push(MsgPartHandling::Revealed(v_j));
                }
                2 => {
                    secrets.push(MsgPartSecret::Known(v_j));
                    msgs_handling.push(MsgPartHandling::Known);
                }
                _ => unreachable!(),
            }
        }
        let unknown_message = UnknownMessage(comm_to_signer);
        let sig = ps_sk
            .sign_unknown_message(&unknown_message, csprng)
            .retrieve(&mask);
        let (blinded_sig, blind_rand) = sig.blind(csprng);
        let ces = ComEqSig {
            msgs_handling,
            ps_pub_key: ps_pk,
            comm_key: cmm_key,
            blinded_sig,
        };

        let secret = ComEqSigSecret {
            r_prime: blind_rand.1,
            msgs: secrets,
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

    #[test]
    #[allow(non_snake_case)]
    pub fn test_com_eq_sig_correctness() {
        let mut csprng = thread_rng();
        for i in 1..20 {
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
        for i in 1..20 {
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
                        wrong_ces.msgs_handling[idx] = MsgPartHandling::EqualToCommitment(
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
