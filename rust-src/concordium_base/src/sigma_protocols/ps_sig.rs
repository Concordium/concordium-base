//! This module implements the proof of knowledge of a PS (Pointcheval-Sanders) signature.
//! The protocol allows a user to prove knowledge of a PS signature without
//! revealing the signature, nor the message signed by the signature (unless chosen to be revealed).
//! As part of the proof, the different parts of the message $\\{m_i\\}$ can either
//! be proven known ($i \in K$), be proven equal to a commitment $c_i$ ($i \in C$), or revealed ($i \in R$).
//!
//! The proof is done as a sigma protocol, see "9.1 Abstract Treatment of Sigma Protocols".
//! Using the notation from "5.3.5 Proof of Knowledge of a Signature with Public Values"
//! and "9.2.3 Proof of Knowledge of Opening of Commitment", the homomorphism used is
//! $$
//!     \varphi: \left(r', \\{ m_i \\}\_{i \in K}, \\{ m_i, r_i \\}\_{i \in C} \right) \mapsto
//!        \left(e\left(\hat{a}, \tilde{g}^{r'} \prod\nolimits\_{i\in K \cup C} \tilde{Y}\_i^{m_i}\right), \\{ g^{m_i} h^{r_i} \\}\_{i \in C} \right)
//! $$
//!
//! and we prove knowledge of a preimage of the "statement" $y$:
//! $$
//!     y = \left(e\left(\hat{b}, \tilde{X}^{-1} \prod\nolimits\_{i\in R} \tilde{Y}\_i^{-m_i} \tilde{g} \right) , \\{ c_i \\}\_{i \in C}\right)
//! $$
//!
//! Notice that the input to $\varphi$ has a signature blinding component $r'$ and a component for each message part.
//! The output has a signature component and a commitment component for each message part that is proven equal to a commitment.

use crate::curve_arithmetic::{Curve, Field, Pairing, Secret};
use crate::sigma_protocols::common::SigmaProtocol;
use crate::{
    common::*,
    curve_arithmetic,
    pedersen_commitment::{Commitment, CommitmentKey, Randomness, Value},
    ps_sig,
    ps_sig::BlindedSignature,
    random_oracle::RandomOracle,
};
use rand::Rng;

/// How to handle a single part of the signed message
#[derive(Debug, Clone)]
pub enum PsSigMsg<C: Curve> {
    /// The message is proven known and equal to the value in commitment $c_i$
    EqualToCommitment(Commitment<C>),
    /// The value/message part $m_i$ is revealed
    Revealed(Value<C>),
    /// The value is proven known
    Known,
}

// Serialization used to hash into the transcript
impl<C: Curve> Serial for PsSigMsg<C> {
    fn serial<B: Buffer>(&self, out: &mut B) {
        match &self {
            PsSigMsg::EqualToCommitment(cmm) => {
                out.put(&0u8);
                out.put(cmm);
            }
            PsSigMsg::Revealed(value) => {
                out.put(&1u8);
                out.put(value);
            }
            PsSigMsg::Known => {
                out.put(&2u8);
            }
        }
    }
}

/// Proof of knowledge of a PS (Pointcheval-Sanders) signature. See
/// module documentation [`self`].
pub struct PsSig<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// The blinded signature $(\hat{a}, \hat{b})$
    pub blinded_sig: BlindedSignature<P>,
    /// A list of how to handle each message in the signature.
    /// Length must be equal to the number of signed messages in the signature
    pub msgs: Vec<PsSigMsg<C>>,
    /// The Pointcheval-Sanders public key with which the signature was
    /// generated
    pub ps_pub_key: ps_sig::PublicKey<P>,
    /// A commitment key with which the commitments were generated.
    pub cmm_key: CommitmentKey<C>,
}

/// Commit secret used to calculate sigma protocol commitment and to calculate response later
pub struct PsSigState<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// Commitment secret for $r'$
    cmm_sec_r_prime: P::ScalarField,
    /// Commitment secret for each part of the message $\\{m_i\\}$
    cmm_sec_msgs: Vec<CommitSecretMsg<C>>,
}

/// Commit secret in the sigma protocol
type CommitSecretMsg<C> = SecretMsg<C>;

/// How to handle a signed message
#[derive(Debug, Clone)]
pub enum SecretMsg<C: Curve> {
    /// The value/message part $m_i$ is proven known and equal to a commitment to the value under the randomness $r_i$
    EqualToCommitment(Value<C>, Randomness<C>),
    /// The value is revealed
    Revealed,
    /// The value/message part $m_i$ is proven known
    Known(Value<C>),
}

// todo ar implement serial/deserial?
impl<C: Curve> Serial for SecretMsg<C> {
    fn serial<B: Buffer>(&self, out: &mut B) {
        todo!()
    }
}

impl<C: Curve> Deserial for SecretMsg<C> {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        todo!()
    }
}

/// Witness used in proof, maps to the "statement" $y$ under $\varphi$
pub struct PsSigSecret<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// Secret $r'$ value
    pub r_prime: Secret<P::ScalarField>,
    /// Secret value for each message part
    pub msgs: Vec<SecretMsg<C>>,
}

/// Response in the protocol
type ResponseMsg<C> = SecretMsg<C>;

/// Response in sigma protocol
#[derive(Clone, Debug, Serialize)]
pub struct Response<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// The response corresponding to $r'$
    resp_r_prime: P::ScalarField,
    /// The response corresponding to each part of the message
    #[size_length = 4]
    resp_msgs: Vec<ResponseMsg<C>>,
}

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>> SigmaProtocol for PsSig<P, C> {
    type CommitMessage = (P::TargetField, Vec<Commitment<C>>);
    type ProtocolChallenge = C::Scalar;
    type ProverState = PsSigState<P, C>;
    type Response = Response<P, C>;
    type SecretData = PsSigSecret<P, C>;

    #[inline]
    fn public(&self, ro: &mut RandomOracle) {
        ro.append_message(b"blinded_sig", &self.blinded_sig);
        ro.extend_from(b"messages", self.msgs.iter());
        ro.append_message(b"ps_pub_key", &self.ps_pub_key);
        ro.append_message(b"comm_key", &self.cmm_key)
    }

    #[inline]
    fn get_challenge(
        &self,
        challenge: &crate::random_oracle::Challenge,
    ) -> Self::ProtocolChallenge {
        C::scalar_from_bytes(challenge)
    }

    /// Compute commit secrets $\alpha$ and their image $a = \varphi(\alpha)$ under $\varphi$ (see module [`self`] for definition of $\varphi$).
    #[inline]
    fn compute_commit_message<R: Rng>(
        &self,
        csprng: &mut R,
    ) -> Option<(Self::CommitMessage, Self::ProverState)> {
        let g_tilde = self.ps_pub_key.g_tilda;
        let a_hat = self.blinded_sig.sig.0;
        let y_tilde = |i| self.ps_pub_key.y_tildas[i];
        let cmm_key = self.cmm_key;

        if self.msgs.len() > self.ps_pub_key.len() {
            return None;
        }

        let cmm_count = self
            .msgs
            .iter()
            .filter(|msg| matches!(msg, PsSigMsg::EqualToCommitment(_)))
            .count();

        // randomness corresponding to the r'
        let cmm_sec_r_prime = <P::G2 as Curve>::generate_non_zero_scalar(csprng);
        // random elements corresponding to the message parts
        let mut cmm_sec_msgs = Vec::with_capacity(self.msgs.len());

        // group element to pair with a_hat to obtain the commit message for the signature
        let mut cmm_msg_signature_elm = g_tilde.mul_by_scalar(&cmm_sec_r_prime);
        // commit messages for the value commitments
        let mut cmm_msg_commitments = Vec::with_capacity(cmm_count);

        for (i, msg) in self.msgs.iter().enumerate() {
            match msg {
                PsSigMsg::EqualToCommitment(_) => {
                    let cmm_sec_m_i = Value::generate_non_zero(csprng);

                    let (cmm_msg_c_i, cmm_sec_r_i) = cmm_key.commit(&cmm_sec_m_i, csprng);
                    cmm_msg_commitments.push(cmm_msg_c_i);

                    let y_exp_m_i = y_tilde(i).mul_by_scalar(&cmm_sec_m_i);
                    cmm_msg_signature_elm = cmm_msg_signature_elm.plus_point(&y_exp_m_i);

                    cmm_sec_msgs.push(SecretMsg::EqualToCommitment(cmm_sec_m_i, cmm_sec_r_i));
                }
                PsSigMsg::Revealed(_) => {
                    cmm_sec_msgs.push(SecretMsg::Revealed);
                }
                PsSigMsg::Known => {
                    let cmm_sec_m_i = Value::generate_non_zero(csprng);

                    let y_exp_m_i = y_tilde(i).mul_by_scalar(&cmm_sec_m_i);
                    cmm_msg_signature_elm = cmm_msg_signature_elm.plus_point(&y_exp_m_i);

                    cmm_sec_msgs.push(SecretMsg::Known(cmm_sec_m_i));
                }
            }
        }
        let cmm_msg_signature = P::pair(&a_hat, &cmm_msg_signature_elm);
        Some((
            (cmm_msg_signature, cmm_msg_commitments),
            PsSigState {
                cmm_sec_r_prime,
                cmm_sec_msgs,
            },
        ))
    }

    /// Compute response as $\alpha - c x$ where $\alpha$: the commit secret, $c$: the challenge, $x$: the witness
    #[inline]
    fn compute_response(
        &self,
        secret: Self::SecretData,
        state: Self::ProverState,
        challenge: &Self::ProtocolChallenge,
    ) -> Option<Self::Response> {
        // If challange = 0 the proof is not going to be valid.
        // However this is an exceedingly unlikely case
        let mut resp_r_prime = *challenge;
        resp_r_prime.mul_assign(&secret.r_prime);
        resp_r_prime.negate();
        resp_r_prime.add_assign(&state.cmm_sec_r_prime);

        let mut resp_msgs = Vec::with_capacity(self.msgs.len());
        for (cmm_sec_msg, witness_msg) in state.cmm_sec_msgs.iter().zip(secret.msgs.iter()) {
            match (cmm_sec_msg, witness_msg) {
                (
                    CommitSecretMsg::EqualToCommitment(cmm_sec_m_i, cmm_sec_r_i),
                    SecretMsg::EqualToCommitment(m_i, r_i),
                ) => {
                    let mut resp_m_i = *challenge;
                    resp_m_i.mul_assign(m_i);
                    resp_m_i.negate();
                    resp_m_i.add_assign(cmm_sec_m_i);

                    let mut resp_r_i = *challenge;
                    resp_r_i.mul_assign(r_i);
                    resp_r_i.negate();
                    resp_r_i.add_assign(cmm_sec_r_i);

                    resp_msgs.push(SecretMsg::EqualToCommitment(
                        Value::new(resp_m_i),
                        Randomness::new(resp_r_i),
                    ));
                }
                (CommitSecretMsg::Revealed, SecretMsg::Revealed) => {
                    resp_msgs.push(SecretMsg::Revealed);
                }
                (CommitSecretMsg::Known(cmm_sec_m_i), SecretMsg::Known(m_i)) => {
                    let mut resp_m_i = *challenge;
                    resp_m_i.mul_assign(m_i);
                    resp_m_i.negate();
                    resp_m_i.add_assign(cmm_sec_m_i);

                    resp_msgs.push(SecretMsg::Known(Value::new(resp_m_i)));
                }
                _ => return None,
            }
        }
        Some(Response {
            resp_r_prime,
            resp_msgs,
        })
    }

    /// Extract commit message as $a = y^c \varphi(z)$ where $c$: the challenge, $z$ the response.
    /// Notice that the signature component of the commit message $a$ can be calculated as following (inserting $y$ and $\varphi$ from module [`self`] ):
    /// $$
    ///     e\left(\hat{b}, \tilde{g}^c\right) e\left(\hat{a}, \tilde{X}^{-c} \tilde{g}^{r\_z'} \prod\nolimits\_{i\in R} \tilde{Y}\_i^{-c m_{z,i}} \prod\nolimits\_{i\in K \cup C} \tilde{Y}\_i^{m_{z,i}}\right)
    /// $$
    /// (using $z$ underscore to mark the response values)
    ///
    /// Variable-time: Notice that we use the inherently variable time multi-exponentiation algorithm `curve_arithmetic::multiexp`.
    /// This is ok since `extract_commit_message` is called from the verifier. It should not be used by the prover.
    #[inline]
    fn extract_commit_message(
        &self,
        challenge: &Self::ProtocolChallenge,
        response: &Self::Response,
    ) -> Option<Self::CommitMessage> {
        let g_tilde = self.ps_pub_key.g_tilda;
        let a_hat = self.blinded_sig.sig.0;
        let b_hat = self.blinded_sig.sig.1;
        let x_tilde = self.ps_pub_key.x_tilda;
        let y_tilde = |i| self.ps_pub_key.y_tildas[i];
        let cmm_key = self.cmm_key;

        if self.msgs.len() > self.ps_pub_key.len() {
            return None;
        }

        let cmm_count = self
            .msgs
            .iter()
            .filter(|msg| matches!(msg, PsSigMsg::EqualToCommitment(_)))
            .count();

        // values for multi exponentiation to calculate signature part of commit message: gs are bases, es are powers.
        let mut cmm_msg_sig_gs = Vec::with_capacity(self.msgs.len() + 2);
        let mut cmm_msg_sig_es = Vec::with_capacity(self.msgs.len() + 2);
        // commit message for message part commitments
        let mut cmm_msg_commitments = Vec::with_capacity(cmm_count);

        let challenge_neg = {
            let mut x = *challenge;
            x.negate();
            x
        };

        cmm_msg_sig_gs.push(g_tilde);
        cmm_msg_sig_es.push(response.resp_r_prime);

        cmm_msg_sig_gs.push(x_tilde);
        cmm_msg_sig_es.push(challenge_neg);

        for (i, (msg, resp_msg)) in self.msgs.iter().zip(&response.resp_msgs).enumerate() {
            match (msg, resp_msg) {
                (
                    PsSigMsg::EqualToCommitment(c_i),
                    ResponseMsg::EqualToCommitment(resp_m_i, resp_r_i),
                ) => {
                    let cmm_msg_c_i = curve_arithmetic::multiexp(
                        &[c_i.0, cmm_key.g, cmm_key.h],
                        &[*challenge, **resp_m_i.value, **resp_r_i.randomness],
                    );
                    cmm_msg_commitments.push(Commitment(cmm_msg_c_i));

                    cmm_msg_sig_gs.push(y_tilde(i));
                    cmm_msg_sig_es.push(**resp_m_i);
                }
                (PsSigMsg::Revealed(m_i), ResponseMsg::Revealed) => {
                    cmm_msg_sig_gs.push(y_tilde(i));
                    let mut exp = challenge_neg;
                    exp.mul_assign(m_i);
                    cmm_msg_sig_es.push(exp);
                }
                (PsSigMsg::Known, ResponseMsg::Known(resp_m_i)) => {
                    cmm_msg_sig_gs.push(y_tilde(i));
                    cmm_msg_sig_es.push(**resp_m_i);
                }
                _ => return None,
            }
        }

        let cmm_msg_sig_elm = curve_arithmetic::multiexp(&cmm_msg_sig_gs, &cmm_msg_sig_es);

        // Combine the pairing computations to compute the product.
        let cmm_msg_sig = P::pairing_product(
            &b_hat,
            &g_tilde.mul_by_scalar(challenge),
            &a_hat,
            &cmm_msg_sig_elm,
        )?;

        Some((cmm_msg_sig, cmm_msg_commitments))
    }

    #[cfg(test)]
    fn with_valid_data<R: Rng>(
        data_size: usize,
        csprng: &mut R,
        f: impl FnOnce(Self, Self::SecretData, &mut R),
    ) {
        let msgs_spec: Vec<_> = (0..data_size)
            .map(|i| match i % 3 {
                0 => tests::InstanceSpecMsg::EqualToCommitment,
                1 => tests::InstanceSpecMsg::Revealed,
                2 => tests::InstanceSpecMsg::Known,
                _ => unreachable!(),
            })
            .collect();

        let (ps_sig, secrets) = tests::instance_with_secrets(&msgs_spec, csprng);

        f(ps_sig, secrets, csprng)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::constants::ArCurve;
    use crate::{
        curve_arithmetic::arkworks_instances::ArkGroup,
        ps_sig,
        ps_sig::{SecretKey as PsSigSecretKey, Signature},
        sigma_protocols,
    };
    use ark_bls12_381::G1Projective;
    use assert_matches::assert_matches;
    use std::iter;

    type G1 = ArkGroup<G1Projective>;
    type Bls12 = ark_ec::models::bls12::Bls12<ark_bls12_381::Config>;
    use crate::ps_sig::{SigRetrievalRandomness, UnknownMessage};

    #[derive(Debug, Clone, Copy)]
    pub enum InstanceSpecMsg {
        EqualToCommitment,
        Revealed,
        Known,
    }

    pub fn instance_with_secrets<P: Pairing, C: Curve<Scalar = P::ScalarField>>(
        msgs_spec: &[InstanceSpecMsg],
        prng: &mut impl Rng,
    ) -> (PsSig<P, C>, PsSigSecret<P, C>) {
        let ps_sk: ps_sig::SecretKey<P> = ps_sig::SecretKey::generate(msgs_spec.len(), prng);
        let ps_pk: ps_sig::PublicKey<P> = ps_sig::PublicKey::from(&ps_sk);
        let y = |i| ps_pk.ys[i];
        let cmm_key = CommitmentKey::generate(prng);

        // commitment to the signer.
        // the randomness used to mask the actual values.
        let signature_mask = SigRetrievalRandomness::generate_non_zero(prng);
        let mut comm_to_signer: P::G1 = ps_pk.g.mul_by_scalar(&signature_mask);

        let mut secret_msgs = Vec::with_capacity(msgs_spec.len());
        let mut msgs = Vec::with_capacity(msgs_spec.len());

        for (i, msg_spec) in msgs_spec.iter().enumerate() {
            let m_i = Value::generate(prng);
            comm_to_signer = comm_to_signer.plus_point(&y(i).mul_by_scalar(&m_i));

            match msg_spec {
                InstanceSpecMsg::EqualToCommitment => {
                    let (c_j, r_j) = cmm_key.commit(&m_i, prng);
                    secret_msgs.push(SecretMsg::EqualToCommitment(m_i, r_j));
                    msgs.push(PsSigMsg::EqualToCommitment(c_j));
                }
                InstanceSpecMsg::Revealed => {
                    secret_msgs.push(SecretMsg::Revealed);
                    msgs.push(PsSigMsg::Revealed(m_i));
                }
                InstanceSpecMsg::Known => {
                    secret_msgs.push(SecretMsg::Known(m_i));
                    msgs.push(PsSigMsg::Known);
                }
            }
        }
        let unknown_message = UnknownMessage(comm_to_signer);
        let signature = ps_sk
            .sign_unknown_message(&unknown_message, prng)
            .retrieve(&signature_mask);
        let (blinded_sig, blind_rand) = signature.blind(prng);
        let ps_sig = PsSig {
            msgs,
            ps_pub_key: ps_pk,
            cmm_key: cmm_key,
            blinded_sig,
        };

        let secret = PsSigSecret {
            r_prime: blind_rand.1,
            msgs: secret_msgs,
        };
        (ps_sig, secret)
    }

    fn value_add_one<C: Curve>(v: &Value<C>) -> Value<C> {
        let mut value = Clone::clone(v.as_ref());
        value.add_assign(&Field::one());
        Value::new(value)
    }

    fn randomness_add_one<C: Curve>(v: &Randomness<C>) -> Randomness<C> {
        let mut randomness = Clone::clone(v.as_ref());
        randomness.add_assign(&Field::one());
        Randomness::new(randomness)
    }

    /// Tests completeness for varying message lengths and varying ways of handling the message parts
    #[test]
    pub fn test_ps_sig_completeness() {
        for length in 1..20 {
            let specs: Vec<_> = (0..length)
                .map(|i| match i % 3 {
                    0 => InstanceSpecMsg::EqualToCommitment,
                    1 => InstanceSpecMsg::Revealed,
                    2 => InstanceSpecMsg::Known,
                    _ => unreachable!(),
                })
                .collect();

            let mut csprng = rand::thread_rng();

            let (ps_sig, secret) = instance_with_secrets::<Bls12, G1>(&specs, &mut csprng);

            let mut ro = RandomOracle::empty();
            let proof =
                sigma_protocols::common::prove(&mut ro.split(), &ps_sig, secret, &mut csprng)
                    .expect("prove");
            assert!(sigma_protocols::common::verify(&mut ro, &ps_sig, &proof));
        }
    }

    /// Test completeness for no messages
    #[test]
    pub fn test_ps_sig_completeness_empty() {
        let mut csprng = rand::thread_rng();

        let (ps_sig, secret) = instance_with_secrets::<Bls12, G1>(&[], &mut csprng);

        let mut ro = RandomOracle::empty();
        let proof = sigma_protocols::common::prove(&mut ro.split(), &ps_sig, secret, &mut csprng)
            .expect("prove");
        assert!(sigma_protocols::common::verify(&mut ro, &ps_sig, &proof));
    }

    /// Test completeness only commitments
    #[test]
    pub fn test_ps_sig_completeness_commitments() {
        let mut csprng = rand::thread_rng();

        for i in 1..=3 {
            let specs: Vec<_> = iter::repeat(())
                .take(i)
                .map(|_| InstanceSpecMsg::EqualToCommitment)
                .collect();
            let (ps_sig, secret) = instance_with_secrets::<Bls12, G1>(&specs, &mut csprng);

            let mut ro = RandomOracle::empty();
            let proof =
                sigma_protocols::common::prove(&mut ro.split(), &ps_sig, secret, &mut csprng)
                    .expect("prove");
            assert!(sigma_protocols::common::verify(&mut ro, &ps_sig, &proof));
        }
    }

    /// Test completeness only known message parts
    #[test]
    pub fn test_ps_sig_completeness_known() {
        let mut csprng = rand::thread_rng();

        for i in 1..=3 {
            let specs: Vec<_> = iter::repeat(())
                .take(i)
                .map(|_| InstanceSpecMsg::Known)
                .collect();
            let (ps_sig, secret) = instance_with_secrets::<Bls12, G1>(&specs, &mut csprng);

            let mut ro = RandomOracle::empty();
            let proof =
                sigma_protocols::common::prove(&mut ro.split(), &ps_sig, secret, &mut csprng)
                    .expect("prove");
            assert!(sigma_protocols::common::verify(&mut ro, &ps_sig, &proof));
        }
    }

    /// Test completeness only revealed message parts
    #[test]
    pub fn test_ps_sig_completeness_revealed() {
        let mut csprng = rand::thread_rng();

        for i in 1..=3 {
            let specs: Vec<_> = iter::repeat(())
                .take(i)
                .map(|_| InstanceSpecMsg::Revealed)
                .collect();
            let (ps_sig, secret) = instance_with_secrets::<Bls12, G1>(&specs, &mut csprng);

            let mut ro = RandomOracle::empty();
            let proof =
                sigma_protocols::common::prove(&mut ro.split(), &ps_sig, secret, &mut csprng)
                    .expect("prove");
            assert!(sigma_protocols::common::verify(&mut ro, &ps_sig, &proof));
        }
    }

    /// Test commitment to something else than in the signature
    #[test]
    pub fn test_ps_sig_soundness_commitment_incorrect() {
        let mut csprng = rand::thread_rng();

        let (mut ps_sig, mut secret) =
            instance_with_secrets::<Bls12, G1>(&[InstanceSpecMsg::EqualToCommitment], &mut csprng);

        let new_m = assert_matches!(&mut secret.msgs[0], SecretMsg::EqualToCommitment(m, _r) => {
           value_add_one(m)
        });
        let (new_c, new_r) = ps_sig.cmm_key.commit(&new_m, &mut csprng);

        assert_matches!(&mut ps_sig.msgs[0], PsSigMsg::EqualToCommitment(c) => {
            *c = new_c
        });
        assert_matches!(&mut secret.msgs[0], SecretMsg::EqualToCommitment(v, r) => {
            *v = new_m;
            *r = new_r;
        });

        let mut ro = RandomOracle::empty();
        let proof = sigma_protocols::common::prove(&mut ro.split(), &ps_sig, secret, &mut csprng)
            .expect("prove");
        assert!(!sigma_protocols::common::verify(&mut ro, &ps_sig, &proof));
    }

    /// Test commitment where message secret is incorrect
    #[test]
    pub fn test_ps_sig_soundness_commitment_message_secret_invalid() {
        let mut csprng = rand::thread_rng();

        let (ps_sig, mut secret) =
            instance_with_secrets::<Bls12, G1>(&[InstanceSpecMsg::EqualToCommitment], &mut csprng);

        assert_matches!(&mut secret.msgs[0], SecretMsg::EqualToCommitment(m, _r) => {
           *m = value_add_one(m);
        });

        let mut ro = RandomOracle::empty();
        let proof = sigma_protocols::common::prove(&mut ro.split(), &ps_sig, secret, &mut csprng)
            .expect("prove");
        assert!(!sigma_protocols::common::verify(&mut ro, &ps_sig, &proof));
    }

    /// Test commitment where randomness secret is incorrect
    #[test]
    pub fn test_ps_sig_soundness_commitment_randomness_secret_invalid() {
        let mut csprng = rand::thread_rng();

        let (ps_sig, mut secret) =
            instance_with_secrets::<Bls12, G1>(&[InstanceSpecMsg::EqualToCommitment], &mut csprng);

        assert_matches!(&mut secret.msgs[0], SecretMsg::EqualToCommitment(_m, r) => {
           *r = randomness_add_one(r);
        });

        let mut ro = RandomOracle::empty();
        let proof = sigma_protocols::common::prove(&mut ro.split(), &ps_sig, secret, &mut csprng)
            .expect("prove");
        assert!(!sigma_protocols::common::verify(&mut ro, &ps_sig, &proof));
    }

    /// Test revealed value that is something else than in the signature
    #[test]
    pub fn test_ps_sig_soundness_revealed_incorrect() {
        let mut csprng = rand::thread_rng();

        let (mut ps_sig, secret) =
            instance_with_secrets::<Bls12, G1>(&[InstanceSpecMsg::Revealed], &mut csprng);

        assert_matches!(&mut ps_sig.msgs[0], PsSigMsg::Revealed(m) => {
            *m = value_add_one(m);
        });

        let mut ro = RandomOracle::empty();
        let proof = sigma_protocols::common::prove(&mut ro.split(), &ps_sig, secret, &mut csprng)
            .expect("prove");
        assert!(!sigma_protocols::common::verify(&mut ro, &ps_sig, &proof));
    }

    /// Test known message where secret message is invalid
    #[test]
    pub fn test_ps_sig_soundness_known_invalid() {
        let mut csprng = rand::thread_rng();

        let (ps_sig, mut secret) =
            instance_with_secrets::<Bls12, G1>(&[InstanceSpecMsg::Known], &mut csprng);

        assert_matches!(&mut secret.msgs[0], SecretMsg::Known(m) => {
           *m = value_add_one(m);
        });

        let mut ro = RandomOracle::empty();
        let proof = sigma_protocols::common::prove(&mut ro.split(), &ps_sig, secret, &mut csprng)
            .expect("prove");
        assert!(!sigma_protocols::common::verify(&mut ro, &ps_sig, &proof));
    }
}
