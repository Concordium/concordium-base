//! This module implements the proof of knowledge of a PS (Pointcheval-Sanders) signature.
//! The protocol allows a user to prove knowledge of a PS signature without
//! revealing the signature, nor the message signed by the signature (unless chosen to be public).
//! As part of the proof, the different parts of the message $\\{m_i\\}$ can either
//! be proven known ($i \in K$), be proven equal to a value in a commitment $C_i$ ($i \in C$), or proven equal to a public value ($i \in P$).
//!
//! The proof is done as a sigma protocol, see "9.1 Abstract Treatment of Sigma Protocols".
//! Using the notation from "5.3.5 Proof of Knowledge of a Signature with Public Values"
//! and "9.2.3 Proof of Knowledge of Opening of Commitment" (blue paper v2.2.0), the homomorphism used is
//! $$
//!     \varphi: \left(r', \\{ m_i \\}\_{i \in K}, \\{ m_i, r_i \\}\_{i \in C} \right) \mapsto
//!        \left(e\left(\hat{a}, \tilde{g}^{r'} \prod\nolimits\_{i\in K \cup C} \tilde{Y}\_i^{m_i}\right), \\{ g^{m_i} h^{r_i} \\}\_{i \in C} \right)
//! $$
//!
//! where $(\hat{a}, \hat{b})$ is the signature blinded by $r'$. And we prove knowledge of a preimage of the "statement" $\boldsymbol{y}$:
//! $$
//!     \boldsymbol{y} = \left(e\left(\hat{b}, \tilde{X}^{-1} \prod\nolimits\_{i\in P} \tilde{Y}\_i^{-m_i} \tilde{g} \right) , \\{ C_i \\}\_{i \in C}\right)
//! $$
//!
//! Notice that the input to $\varphi$ has a signature blinding component $r'$ and a component for each message part.
//! The output has a signature component and a commitment component for each message part that is proven equal to a commitment.

use crate::curve_arithmetic::{Curve, Field, Pairing, Secret};
use crate::random_oracle::TranscriptProtocol;
use crate::sigma_protocols::common::SigmaProtocol;
use crate::{
    curve_arithmetic,
    pedersen_commitment::{Commitment, CommitmentKey, Randomness, Value},
    ps_sig,
    ps_sig::BlindedSignature,
};
use concordium_base_derive::Serialize;
use rand::Rng;

/// How to handle a single part of the signed message
#[derive(Debug, Clone, Serialize)]
pub enum PsSigMsg<C: Curve> {
    /// The message is proven known and equal to the value in commitment $C_i$
    EqualToCommitment(Commitment<C>),
    /// The value/message part $m_i$ is public
    Public(Value<C>),
    /// The value is proven known
    Known,
}

/// Proof of knowledge of a PS (Pointcheval-Sanders) signature. See
/// module documentation [`self`].
pub struct PsSigKnown<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
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
pub struct PsSigCommitSecret<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// Commitment secret for $r'$
    cmm_sec_r_prime: P::ScalarField,
    /// Commitment secret for each part of the message $\\{m_i\\}$
    cmm_sec_msgs: Vec<CommitSecretMsg<C>>,
}

/// Commit secret in the sigma protocol
type CommitSecretMsg<C> = PsSigWitnessMsg<C>;

/// How to handle a signed message
#[derive(Debug, Eq, PartialEq, Clone, Serialize)]
pub enum PsSigWitnessMsg<C: Curve> {
    /// The value/message part $m_i$ is proven known and equal to a commitment to the value under the randomness $r_i$
    EqualToCommitment(Value<C>, Randomness<C>),
    /// The value is public
    Public,
    /// The value/message part $m_i$ is proven known
    Known(Value<C>),
}

/// Witness used in proof, maps to the "statement" $\boldsymbol{y}$ under $\varphi$
pub struct PsSigWitness<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// Secret $r'$ value
    pub r_prime: Secret<P::ScalarField>,
    /// Secret value for each message part
    pub msgs: Vec<PsSigWitnessMsg<C>>,
}

/// Response in the protocol
type ResponseMsg<C> = PsSigWitnessMsg<C>;

/// Response in sigma protocol
#[derive(Clone, Eq, PartialEq, Debug, Serialize)]
pub struct Response<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// The response corresponding to $r'$
    resp_r_prime: P::ScalarField,
    /// The response corresponding to each part of the message
    #[size_length = 4]
    resp_msgs: Vec<ResponseMsg<C>>,
}

impl<P: Pairing, C: Curve<Scalar = P::ScalarField>> SigmaProtocol for PsSigKnown<P, C> {
    type CommitMessage = (P::TargetField, Vec<Commitment<C>>);
    type ProtocolChallenge = C::Scalar;
    type ProverState = PsSigCommitSecret<P, C>;
    type Response = Response<P, C>;
    type SecretData = PsSigWitness<P, C>;

    #[inline]
    fn public(&self, ro: &mut impl TranscriptProtocol) {
        ro.append_label("PsSigKnown");
        // public input to statement:
        ro.append_message("blinded_sig", &self.blinded_sig);
        ro.append_message("messages", &self.msgs);
        // implicit public values
        ro.append_message("ps_pub_key", &self.ps_pub_key);
        ro.append_message("comm_key", &self.cmm_key)
    }

    #[inline]
    fn get_challenge(
        &self,
        challenge: &crate::random_oracle::Challenge,
    ) -> Self::ProtocolChallenge {
        C::scalar_from_bytes(challenge)
    }

    /// Compute commit secrets $\boldsymbol{\alpha}$ and their image $\boldsymbol{a} = \varphi(\boldsymbol{\alpha})$ under $\varphi$ (see module [`self`] for definition of $\varphi$).
    #[inline]
    fn compute_commit_message<R: Rng>(
        &self,
        csprng: &mut R,
    ) -> Option<(Self::CommitMessage, Self::ProverState)> {
        let g_tilde = self.ps_pub_key.g_tilda;
        let a_hat = self.blinded_sig.sig.0;
        let y_tilde = |i| self.ps_pub_key.y_tildas.get(i).copied();
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

                    let y_exp_m_i = y_tilde(i)?.mul_by_scalar(&cmm_sec_m_i);
                    cmm_msg_signature_elm = cmm_msg_signature_elm.plus_point(&y_exp_m_i);

                    cmm_sec_msgs.push(PsSigWitnessMsg::EqualToCommitment(cmm_sec_m_i, cmm_sec_r_i));
                }
                PsSigMsg::Public(_) => {
                    cmm_sec_msgs.push(PsSigWitnessMsg::Public);
                }
                PsSigMsg::Known => {
                    let cmm_sec_m_i = Value::generate_non_zero(csprng);

                    let y_exp_m_i = y_tilde(i)?.mul_by_scalar(&cmm_sec_m_i);
                    cmm_msg_signature_elm = cmm_msg_signature_elm.plus_point(&y_exp_m_i);

                    cmm_sec_msgs.push(PsSigWitnessMsg::Known(cmm_sec_m_i));
                }
            }
        }
        let cmm_msg_signature = P::pair(&a_hat, &cmm_msg_signature_elm);
        Some((
            (cmm_msg_signature, cmm_msg_commitments),
            PsSigCommitSecret {
                cmm_sec_r_prime,
                cmm_sec_msgs,
            },
        ))
    }

    /// Compute response as $\boldsymbol{\alpha} - c \boldsymbol{x}$ where $\boldsymbol{\alpha}$: the commit secret, $c$: the challenge, $\boldsymbol{x}$: the witness
    #[inline]
    fn compute_response(
        &self,
        witness: Self::SecretData,
        state: Self::ProverState,
        challenge: &Self::ProtocolChallenge,
    ) -> Option<Self::Response> {
        // If challenge = 0 the proof is not going to be valid.
        // However this is an exceedingly unlikely case
        let mut resp_r_prime = *challenge;
        resp_r_prime.mul_assign(&witness.r_prime);
        resp_r_prime.negate();
        resp_r_prime.add_assign(&state.cmm_sec_r_prime);

        let mut resp_msgs = Vec::with_capacity(self.msgs.len());
        for (cmm_sec_msg, witness_msg) in state.cmm_sec_msgs.iter().zip(witness.msgs.iter()) {
            match (cmm_sec_msg, witness_msg) {
                (
                    CommitSecretMsg::EqualToCommitment(cmm_sec_m_i, cmm_sec_r_i),
                    PsSigWitnessMsg::EqualToCommitment(m_i, r_i),
                ) => {
                    let mut resp_m_i = *challenge;
                    resp_m_i.mul_assign(m_i);
                    resp_m_i.negate();
                    resp_m_i.add_assign(cmm_sec_m_i);

                    let mut resp_r_i = *challenge;
                    resp_r_i.mul_assign(r_i);
                    resp_r_i.negate();
                    resp_r_i.add_assign(cmm_sec_r_i);

                    resp_msgs.push(PsSigWitnessMsg::EqualToCommitment(
                        Value::new(resp_m_i),
                        Randomness::new(resp_r_i),
                    ));
                }
                (CommitSecretMsg::Public, PsSigWitnessMsg::Public) => {
                    resp_msgs.push(PsSigWitnessMsg::Public);
                }
                (CommitSecretMsg::Known(cmm_sec_m_i), PsSigWitnessMsg::Known(m_i)) => {
                    let mut resp_m_i = *challenge;
                    resp_m_i.mul_assign(m_i);
                    resp_m_i.negate();
                    resp_m_i.add_assign(cmm_sec_m_i);

                    resp_msgs.push(PsSigWitnessMsg::Known(Value::new(resp_m_i)));
                }
                _ => return None,
            }
        }
        Some(Response {
            resp_r_prime,
            resp_msgs,
        })
    }

    /// Extract commit message as $\boldsymbol{a} = \boldsymbol{y}^c \varphi(\boldsymbol{z})$ where $c$: the challenge, $\boldsymbol{z}$ the response.
    /// Notice that the signature component of the commit message $\boldsymbol{a}$ can be calculated as following (inserting $\boldsymbol{y}$ and $\varphi$ from module [`self`] ):
    /// $$
    ///     e\left(\hat{b}, \tilde{g}^c\right) e\left(\hat{a}, \tilde{X}^{-c} \tilde{g}^{r\_z'} \prod\nolimits\_{i\in P} \tilde{Y}\_i^{-c m_{z,i}} \prod\nolimits\_{i\in K \cup C} \tilde{Y}\_i^{m_{z,i}}\right)
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
        let y_tilde = |i| self.ps_pub_key.y_tildas.get(i).copied();
        let cmm_key = self.cmm_key;

        if self.msgs.len() > self.ps_pub_key.len() {
            return None;
        }

        if self.msgs.len() != response.resp_msgs.len() {
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

                    cmm_msg_sig_gs.push(y_tilde(i)?);
                    cmm_msg_sig_es.push(**resp_m_i);
                }
                (PsSigMsg::Public(m_i), ResponseMsg::Public) => {
                    cmm_msg_sig_gs.push(y_tilde(i)?);
                    let mut exp = challenge_neg;
                    exp.mul_assign(m_i);
                    cmm_msg_sig_es.push(exp);
                }
                (PsSigMsg::Known, ResponseMsg::Known(resp_m_i)) => {
                    cmm_msg_sig_gs.push(y_tilde(i)?);
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
                1 => tests::InstanceSpecMsg::Public,
                2 => tests::InstanceSpecMsg::Known,
                _ => unreachable!(),
            })
            .collect();

        let (ps_sig, secrets) = tests::instance_with_witness(&msgs_spec, 0, csprng);

        f(ps_sig, secrets, csprng)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{common, curve_arithmetic::arkworks_instances::ArkGroup, ps_sig, sigma_protocols};
    use ark_bls12_381::G1Projective;
    use assert_matches::assert_matches;
    use itertools::Itertools;
    use rand::SeedableRng;
    use std::iter;

    type G1 = ArkGroup<G1Projective>;
    type Bls12 = ark_ec::models::bls12::Bls12<ark_bls12_381::Config>;
    use crate::ps_sig::{SigRetrievalRandomness, UnknownMessage};
    use crate::random_oracle::RandomOracle;
    use crate::sigma_protocols::common::SigmaProof;

    #[derive(Debug, Clone, Copy)]
    pub enum InstanceSpecMsg {
        EqualToCommitment,
        Public,
        Known,
    }

    pub fn instance_with_witness<P: Pairing, C: Curve<Scalar = P::ScalarField>>(
        msgs_spec: &[InstanceSpecMsg],
        additional_key_length: usize,
        prng: &mut impl Rng,
    ) -> (PsSigKnown<P, C>, PsSigWitness<P, C>) {
        let ps_sk: ps_sig::SecretKey<P> =
            ps_sig::SecretKey::generate(msgs_spec.len() + additional_key_length, prng);
        let ps_pk: ps_sig::PublicKey<P> = ps_sig::PublicKey::from(&ps_sk);
        let y = |i| ps_pk.ys[i];
        let cmm_key = CommitmentKey::generate(prng);

        // commitment to the signer.
        // the randomness used to mask the actual values.
        let signature_mask = SigRetrievalRandomness::generate_non_zero(prng);
        let mut comm_to_signer: P::G1 = ps_pk.g.mul_by_scalar(&signature_mask);

        let mut witness_msgs = Vec::with_capacity(msgs_spec.len());
        let mut msgs = Vec::with_capacity(msgs_spec.len());

        for (i, msg_spec) in msgs_spec.iter().enumerate() {
            let m_i = Value::generate(prng);
            comm_to_signer = comm_to_signer.plus_point(&y(i).mul_by_scalar(&m_i));

            match msg_spec {
                InstanceSpecMsg::EqualToCommitment => {
                    let (c_j, r_j) = cmm_key.commit(&m_i, prng);
                    witness_msgs.push(PsSigWitnessMsg::EqualToCommitment(m_i, r_j));
                    msgs.push(PsSigMsg::EqualToCommitment(c_j));
                }
                InstanceSpecMsg::Public => {
                    witness_msgs.push(PsSigWitnessMsg::Public);
                    msgs.push(PsSigMsg::Public(m_i));
                }
                InstanceSpecMsg::Known => {
                    witness_msgs.push(PsSigWitnessMsg::Known(m_i));
                    msgs.push(PsSigMsg::Known);
                }
            }
        }
        let unknown_message = UnknownMessage(comm_to_signer);
        let signature = ps_sk
            .sign_unknown_message(&unknown_message, prng)
            .retrieve(&signature_mask);
        let (blinded_sig, blind_rand) = signature.blind(prng);
        let ps_sig = PsSigKnown {
            msgs,
            ps_pub_key: ps_pk,
            cmm_key,
            blinded_sig,
        };

        let secret = PsSigWitness {
            r_prime: blind_rand.1,
            msgs: witness_msgs,
        };
        (ps_sig, secret)
    }

    /// Tests completeness for varying message lengths and varying ways of handling the message parts
    #[test]
    pub fn test_ps_sig_completeness() {
        // test message length from 1 to 20 and with exactly the needed key length or key length 5 more than needed
        for (msg_length, additional_key_length) in (1..20).cartesian_product([0, 5]) {
            let specs: Vec<_> = (0..msg_length)
                .map(|i| match i % 3 {
                    0 => InstanceSpecMsg::EqualToCommitment,
                    1 => InstanceSpecMsg::Public,
                    2 => InstanceSpecMsg::Known,
                    _ => unreachable!(),
                })
                .collect();

            let mut csprng = rand::thread_rng();

            let (ps_sig, secret) =
                instance_with_witness::<Bls12, G1>(&specs, additional_key_length, &mut csprng);

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

        let (ps_sig, witness) = instance_with_witness::<Bls12, G1>(&[], 0, &mut csprng);

        let mut ro = RandomOracle::empty();
        let proof = sigma_protocols::common::prove(&mut ro.split(), &ps_sig, witness, &mut csprng)
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
            let (ps_sig, witness) = instance_with_witness::<Bls12, G1>(&specs, 0, &mut csprng);

            let mut ro = RandomOracle::empty();
            let proof =
                sigma_protocols::common::prove(&mut ro.split(), &ps_sig, witness, &mut csprng)
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
            let (ps_sig, witness) = instance_with_witness::<Bls12, G1>(&specs, 0, &mut csprng);

            let mut ro = RandomOracle::empty();
            let proof =
                sigma_protocols::common::prove(&mut ro.split(), &ps_sig, witness, &mut csprng)
                    .expect("prove");
            assert!(sigma_protocols::common::verify(&mut ro, &ps_sig, &proof));
        }
    }

    /// Test completeness only public message parts
    #[test]
    pub fn test_ps_sig_completeness_public() {
        let mut csprng = rand::thread_rng();

        for i in 1..=3 {
            let specs: Vec<_> = iter::repeat(())
                .take(i)
                .map(|_| InstanceSpecMsg::Public)
                .collect();
            let (ps_sig, witness) = instance_with_witness::<Bls12, G1>(&specs, 0, &mut csprng);

            let mut ro = RandomOracle::empty();
            let proof =
                sigma_protocols::common::prove(&mut ro.split(), &ps_sig, witness, &mut csprng)
                    .expect("prove");
            assert!(sigma_protocols::common::verify(&mut ro, &ps_sig, &proof));
        }
    }

    /// Test commitment to something else than in the signature
    #[test]
    pub fn test_ps_sig_soundness_commitment_incorrect() {
        let mut csprng = rand::thread_rng();

        let (mut ps_sig, mut witness) = instance_with_witness::<Bls12, G1>(
            &[InstanceSpecMsg::EqualToCommitment],
            0,
            &mut csprng,
        );

        let new_m = Value::generate(&mut csprng);
        let (new_c, new_r) = ps_sig.cmm_key.commit(&new_m, &mut csprng);

        assert_matches!(&mut ps_sig.msgs[0], PsSigMsg::EqualToCommitment(c) => {
            *c = new_c
        });
        assert_matches!(&mut witness.msgs[0], PsSigWitnessMsg::EqualToCommitment(v, r) => {
            *v = new_m;
            *r = new_r;
        });

        let mut ro = RandomOracle::empty();
        let proof = sigma_protocols::common::prove(&mut ro.split(), &ps_sig, witness, &mut csprng)
            .expect("prove");
        assert!(!sigma_protocols::common::verify(&mut ro, &ps_sig, &proof));
    }

    /// Test commitment where message witness is incorrect
    #[test]
    pub fn test_ps_sig_soundness_commitment_message_secret_invalid() {
        let mut csprng = rand::thread_rng();

        let (ps_sig, mut witness) = instance_with_witness::<Bls12, G1>(
            &[InstanceSpecMsg::EqualToCommitment],
            0,
            &mut csprng,
        );

        assert_matches!(&mut witness.msgs[0], PsSigWitnessMsg::EqualToCommitment(m, _r) => {
           *m = Value::generate(&mut csprng);
        });

        let mut ro = RandomOracle::empty();
        let proof = sigma_protocols::common::prove(&mut ro.split(), &ps_sig, witness, &mut csprng)
            .expect("prove");
        assert!(!sigma_protocols::common::verify(&mut ro, &ps_sig, &proof));
    }

    /// Test commitment where commit randomness is incorrect
    #[test]
    pub fn test_ps_sig_soundness_commitment_randomness_secret_invalid() {
        let mut csprng = rand::thread_rng();

        let (ps_sig, mut witness) = instance_with_witness::<Bls12, G1>(
            &[InstanceSpecMsg::EqualToCommitment],
            0,
            &mut csprng,
        );

        assert_matches!(&mut witness.msgs[0], PsSigWitnessMsg::EqualToCommitment(_m, r) => {
           *r = Randomness::generate(&mut csprng)
        });

        let mut ro = RandomOracle::empty();
        let proof = sigma_protocols::common::prove(&mut ro.split(), &ps_sig, witness, &mut csprng)
            .expect("prove");
        assert!(!sigma_protocols::common::verify(&mut ro, &ps_sig, &proof));
    }

    /// Test public value that is something else than in the signature
    #[test]
    pub fn test_ps_sig_soundness_public_incorrect() {
        let mut csprng = rand::thread_rng();

        let (mut ps_sig, witness) =
            instance_with_witness::<Bls12, G1>(&[InstanceSpecMsg::Public], 0, &mut csprng);

        assert_matches!(&mut ps_sig.msgs[0], PsSigMsg::Public(m) => {
            *m = Value::generate(&mut csprng);
        });

        let mut ro = RandomOracle::empty();
        let proof = sigma_protocols::common::prove(&mut ro.split(), &ps_sig, witness, &mut csprng)
            .expect("prove");
        assert!(!sigma_protocols::common::verify(&mut ro, &ps_sig, &proof));
    }

    /// Test known message where witness is invalid
    #[test]
    pub fn test_ps_sig_soundness_known_invalid() {
        let mut csprng = rand::thread_rng();

        let (ps_sig, mut witness) =
            instance_with_witness::<Bls12, G1>(&[InstanceSpecMsg::Known], 0, &mut csprng);

        assert_matches!(&mut witness.msgs[0], PsSigWitnessMsg::Known(m) => {
           *m = Value::generate(&mut csprng);
        });

        let mut ro = RandomOracle::empty();
        let proof = sigma_protocols::common::prove(&mut ro.split(), &ps_sig, witness, &mut csprng)
            .expect("prove");
        assert!(!sigma_protocols::common::verify(&mut ro, &ps_sig, &proof));
    }

    /// Test changing public value in a statement
    #[test]
    pub fn test_ps_sig_soundness_public_changed() {
        let mut csprng = rand::thread_rng();

        let (mut ps_sig, witness) =
            instance_with_witness::<Bls12, G1>(&[InstanceSpecMsg::Public], 0, &mut csprng);

        let mut ro = RandomOracle::empty();
        let proof = sigma_protocols::common::prove(&mut ro.split(), &ps_sig, witness, &mut csprng)
            .expect("prove");

        assert_matches!(&mut ps_sig.msgs[0], PsSigMsg::Public(m) => {
            *m = Value::generate(&mut csprng);
        });

        assert!(!sigma_protocols::common::verify(&mut ro, &ps_sig, &proof));
    }

    /// Test changing commitment in a statement
    #[test]
    pub fn test_ps_sig_soundness_commitment_changed() {
        let mut csprng = rand::thread_rng();

        let (mut ps_sig, witness) = instance_with_witness::<Bls12, G1>(
            &[InstanceSpecMsg::EqualToCommitment],
            0,
            &mut csprng,
        );

        let mut ro = RandomOracle::empty();
        let proof = sigma_protocols::common::prove(&mut ro.split(), &ps_sig, witness, &mut csprng)
            .expect("prove");

        let new_m: Value<G1> = Value::generate(&mut csprng);
        let (new_c, _new_r) = ps_sig.cmm_key.commit(&new_m, &mut csprng);

        assert_matches!(&mut ps_sig.msgs[0], PsSigMsg::EqualToCommitment(c) => {
            *c = new_c;
        });

        assert!(!sigma_protocols::common::verify(&mut ro, &ps_sig, &proof));
    }

    /// Test removing msg from proven statement
    #[test]
    pub fn test_ps_sig_soundness_msg_removed() {
        let mut csprng = rand::thread_rng();

        let (mut ps_sig, witness) = instance_with_witness::<Bls12, G1>(
            &[InstanceSpecMsg::Known, InstanceSpecMsg::Public],
            0,
            &mut csprng,
        );

        let ro = RandomOracle::empty();
        let mut proof =
            sigma_protocols::common::prove(&mut ro.split(), &ps_sig, witness, &mut csprng)
                .expect("prove");

        ps_sig.msgs.pop();
        proof.response.resp_msgs.pop();

        assert!(!sigma_protocols::common::verify(
            &mut ro.split(),
            &ps_sig,
            &proof
        ));
    }

    /// Test adding msg to proven statement
    #[test]
    pub fn test_ps_sig_soundness_msg_added() {
        let mut csprng = rand::thread_rng();

        let (mut ps_sig, witness) = instance_with_witness::<Bls12, G1>(
            &[InstanceSpecMsg::Known, InstanceSpecMsg::Public],
            5,
            &mut csprng,
        );

        let ro = RandomOracle::empty();
        let proof = sigma_protocols::common::prove(&mut ro.split(), &ps_sig, witness, &mut csprng)
            .expect("prove");

        ps_sig
            .msgs
            .push(PsSigMsg::Public(Value::generate(&mut csprng)));

        assert!(!sigma_protocols::common::verify(
            &mut ro.split(),
            &ps_sig,
            &proof
        ));
    }

    /// Test that we can verify proofs created by previous versions of the protocol.
    /// This test protects from changes that introduces braking changes.
    ///
    /// The test uses a serialization of a previously created proof.
    #[test]
    pub fn test_ps_sig_stable() {
        fn seed0() -> impl Rng {
            rand::rngs::StdRng::seed_from_u64(0)
        }

        let ps_sk: ps_sig::SecretKey<Bls12> = ps_sig::SecretKey::generate(10, &mut seed0());
        let ps_pk: ps_sig::PublicKey<Bls12> = ps_sig::PublicKey::from(&ps_sk);
        let cmm_key: CommitmentKey<G1> = CommitmentKey::generate(&mut seed0());

        let signature_mask = SigRetrievalRandomness::generate_non_zero(&mut seed0());
        let mut comm_to_signer: G1 = ps_pk.g.mul_by_scalar(&signature_mask);

        let mut msgs = Vec::new();

        let m_0: Value<G1> = Value::new(G1::scalar_from_u64(42));
        comm_to_signer = comm_to_signer.plus_point(&ps_pk.ys[0].mul_by_scalar(&m_0));
        let r_0 = Randomness::new(G1::scalar_from_u64(10));
        let c_0 = cmm_key.hide(&m_0, &r_0);
        msgs.push(PsSigMsg::EqualToCommitment(c_0));

        let m_1: Value<G1> = Value::new(G1::scalar_from_u64(42));
        comm_to_signer = comm_to_signer.plus_point(&ps_pk.ys[1].mul_by_scalar(&m_1));
        msgs.push(PsSigMsg::Public(m_1));

        let m_2: Value<G1> = Value::new(G1::scalar_from_u64(42));
        comm_to_signer = comm_to_signer.plus_point(&ps_pk.ys[2].mul_by_scalar(&m_2));
        msgs.push(PsSigMsg::Known);

        let unknown_message = UnknownMessage(comm_to_signer);
        let signature = ps_sk
            .sign_unknown_message(&unknown_message, &mut seed0())
            .retrieve(&signature_mask);
        let (blinded_sig, _blind_rand) = signature.blind(&mut seed0());

        let ps_sig = PsSigKnown {
            msgs,
            ps_pub_key: ps_pk,
            cmm_key,
            blinded_sig,
        };

        let proof_bytes_hex = "25207d6ee28196c6e9323be3984ce3be8c891fa0a33c2d830431055621c5500e29028a7a91da2f8b0b54836484d507f09a0d319944058c759d75513c30d992b700000003006b33753485415971000b4a8d46d46e55f7fb2bcea3561e83a6535bafed712c900be4bb1cc0e3a14821257f030b7cb9edd5919f0c1f2f49f562d2de756e58d02f01023510ef149cff79dbf3cf47a19cb9588157caf1cd5ac07ff62baf80cbe6a3b763";
        let proof_bytes = hex::decode(&proof_bytes_hex).unwrap();
        let proof: SigmaProof<Response<Bls12, G1>> =
            common::from_bytes(&mut proof_bytes.as_slice()).expect("deserialize");
        assert_eq!(proof.response.resp_msgs.len(), 3);

        let mut ro = RandomOracle::empty();
        assert!(sigma_protocols::common::verify(&mut ro, &ps_sig, &proof));
    }

    /// The type `ResponseMsg` is part of the proof, and hence must be able to the serialized
    /// and deserialized.
    #[test]
    pub fn test_serialize_response_msg() {
        let mut csprng = rand::thread_rng();

        let orig_msg = ResponseMsg::<G1>::EqualToCommitment(
            Value::generate(&mut csprng),
            Randomness::generate(&mut csprng),
        );
        let msg = common::serialize_deserialize(&orig_msg).unwrap();
        assert_eq!(msg, orig_msg);

        let orig_msg = ResponseMsg::<G1>::Public;
        let msg = common::serialize_deserialize(&orig_msg).unwrap();
        assert_eq!(msg, orig_msg);

        let orig_msg = ResponseMsg::<G1>::Known(Value::generate(&mut csprng));
        let msg = common::serialize_deserialize(&orig_msg).unwrap();
        assert_eq!(msg, orig_msg);
    }

    /// Test case where we have more message parts than the PS key length.
    /// Assert that we fail gracefully and don't panic
    #[test]
    pub fn test_more_message_parts_than_key_length_prover() {
        let mut csprng = rand::thread_rng();

        let (mut ps_sig, mut witness) =
            instance_with_witness::<Bls12, G1>(&[InstanceSpecMsg::Known], 0, &mut csprng);

        ps_sig.msgs.push(PsSigMsg::Known);
        witness
            .msgs
            .push(PsSigWitnessMsg::Known(Value::generate(&mut csprng)));

        let ro = RandomOracle::empty();
        assert!(
            sigma_protocols::common::prove(&mut ro.split(), &ps_sig, witness, &mut csprng)
                .is_none()
        );
    }

    /// Test case where we have more message parts than the PS key length.
    /// Assert that we fail gracefully and don't panic
    #[test]
    pub fn test_more_message_parts_than_key_length_verifier() {
        let mut csprng = rand::thread_rng();

        let (mut ps_sig, witness) =
            instance_with_witness::<Bls12, G1>(&[InstanceSpecMsg::Known], 0, &mut csprng);

        let ro = RandomOracle::empty();
        let proof = sigma_protocols::common::prove(&mut ro.split(), &ps_sig, witness, &mut csprng)
            .expect("prove");

        ps_sig.msgs.push(PsSigMsg::Known);

        assert!(!sigma_protocols::common::verify(
            &mut ro.split(),
            &ps_sig,
            &proof
        ));
    }
}
