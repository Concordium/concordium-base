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
//!     \varphi: (r', \\{ m_i \\}\_{i \in K}, \\{ m_i, r_i \\}\_{i \in C} ) \mapsto
//!        (\mathrm{e}(\hat{a}, \tilde{g}^{r'} \prod\_{i\in K \cup C} \tilde{Y}\_i^{m_i}), \\{ g^{m_i} h^{r_i} \\}\_{i \in C} )
//! $$
//!
//! and we prove knowledge of a preimage of the "statement" $y$:
//! $$
//!     y = (\mathrm{e}(\hat{b}, \tilde{X}^{-1} \prod\_{i\in R} \tilde{Y}\_i^{-m_i} \tilde{g} ) , \\{ c_i \\}\_{i \in C})
//! $$
//!
//! Notice that the input to $\varphi$ has a signature blinding component $r'$ and a component for each message part.
//! The output has a signature component and a commitment component for each message part that is proven equal to a commitment.

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
    pub ps_pub_key: PsSigPublicKey<P>,
    /// A commitment key with which the commitments were generated.
    pub comm_key: CommitmentKey<C>,
}

/// Commit secret used to calculate sigma protocol commitment and to calculate response later
pub struct PsSigState<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// Commitment secret for $r'$
    cmm_sec_r_prime: P::ScalarField,
    /// Commitment secret for each part of the message $\\{m_i\\}$
    cmm_sec_msgs: Vec<MsgCommitSecret<C>>,
}

/// Commit secret in the sigma protocol
type MsgCommitSecret<C> = MsgSecret<C>;

/// How to handle a signed message
#[derive(Debug, Clone)]
pub enum MsgSecret<C: Curve> {
    /// The value/message part $m_i$ is proven known and equal to a commitment to the value under the randomness $r_i$
    EqualToCommitment(Value<C>, Randomness<C>),
    /// The value is revealed
    Revealed,
    /// The value/message part $m_i$ is proven known
    Known(Value<C>),
}

impl<C: Curve> Serial for MsgSecret<C> {
    fn serial<B: Buffer>(&self, out: &mut B) {
        todo!()
    }
}

impl<C: Curve> Deserial for MsgSecret<C> {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        todo!()
    }
}

/// Witness used in proof, maps to the "statement" $y$ under $\varphi$
pub struct PsSigSecret<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// Secret $r'$ value
    pub r_prime: Secret<P::ScalarField>,
    /// Secret value for each message part
    pub msgs: Vec<MsgSecret<C>>,
}

/// Response in the protocol
type MsgResponse<C> = MsgSecret<C>;

/// Response in sigma protocol
#[derive(Clone, Debug, Serialize)]
pub struct Response<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// The response corresponding to $r'$
    resp_r_prime: P::ScalarField,
    /// The response corresponding to each part of the message
    #[size_length = 4]
    resp_msgs: Vec<MsgResponse<C>>,
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
        ro.append_message(b"comm_key", &self.comm_key)
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
        let y_tilda = |i| self.ps_pub_key.y_tildas[i];
        let cmm_key = self.comm_key;

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

                    let y_exp_m_i = y_tilda(i).mul_by_scalar(&cmm_sec_m_i);
                    cmm_msg_signature_elm = cmm_msg_signature_elm.plus_point(&y_exp_m_i);

                    cmm_sec_msgs.push(MsgSecret::EqualToCommitment(cmm_sec_m_i, cmm_sec_r_i));
                }
                PsSigMsg::Revealed(_) => {
                    cmm_sec_msgs.push(MsgSecret::Revealed);
                }
                PsSigMsg::Known => {
                    let cmm_sec_m_i = Value::generate_non_zero(csprng);

                    let y_exp_m_i = y_tilda(i).mul_by_scalar(&cmm_sec_m_i);
                    cmm_msg_signature_elm = cmm_msg_signature_elm.plus_point(&y_exp_m_i);

                    cmm_sec_msgs.push(MsgSecret::Known(cmm_sec_m_i));
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
                    MsgSecret::EqualToCommitment(cmm_sec_m_i, cmm_sec_r_i),
                    MsgSecret::EqualToCommitment(m_i, r_i),
                ) => {
                    let mut resp_m_i = *challenge;
                    resp_m_i.mul_assign(m_i);
                    resp_m_i.negate();
                    resp_m_i.add_assign(cmm_sec_m_i);

                    let mut resp_r_i = *challenge;
                    resp_r_i.mul_assign(r_i);
                    resp_r_i.negate();
                    resp_r_i.add_assign(cmm_sec_r_i);

                    resp_msgs.push(MsgSecret::EqualToCommitment(
                        Value::new(resp_m_i),
                        Randomness::new(resp_r_i),
                    ));
                }
                (MsgSecret::Revealed, MsgSecret::Revealed) => {
                    resp_msgs.push(MsgSecret::Revealed);
                }
                (MsgSecret::Known(cmm_sec_m_i), MsgSecret::Known(m_i)) => {
                    let mut resp_m_i = *challenge;
                    resp_m_i.mul_assign(m_i);
                    resp_m_i.negate();
                    resp_m_i.add_assign(cmm_sec_m_i);

                    resp_msgs.push(MsgSecret::Known(Value::new(resp_m_i)));
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
    ///     \mathrm{e}(\hat{b}, \tilde{g}^c) \mathrm{e}(\hat{a}, \tilde{X}^{-c} \tilde{g}^{r\_z'} \prod\_{i\in R} \tilde{Y}\_i^{-c m_{z,i}} \prod\_{i\in K \cup C} \tilde{Y}\_i^{m_{z,i}})
    /// $$
    /// (using $z$ underscore to mark the response values)
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

        if self.msgs.len() > self.ps_pub_key.len() {
            return None;
        }

        let cmm_count = self
            .msgs
            .iter()
            .filter(|msg| matches!(msg, PsSigMsg::EqualToCommitment(_)))
            .count();

        // values for multi exponentiation to calculate signature part of commit message. gs is bases, es is powers.
        let mut cmm_msg_sig_gs = Vec::with_capacity(self.msgs.len() + 2);
        let mut cmm_msg_sig_es = Vec::with_capacity(self.msgs.len() + 2);
        // commit message for message part commitments
        let mut cmm_msg_commitments = Vec::with_capacity(cmm_count);

        let challenge_neg = {
            let mut x = *challenge;
            x.negate();
            x
        };

        cmm_msg_sig_gs.push(g_tilda);
        cmm_msg_sig_es.push(response.resp_r_prime);

        cmm_msg_sig_gs.push(x_tilda);
        cmm_msg_sig_es.push(challenge_neg);

        for (i, (msg, resp_msg)) in self.msgs.iter().zip(&response.resp_msgs).enumerate() {
            match (msg, resp_msg) {
                (
                    PsSigMsg::EqualToCommitment(c_i),
                    MsgSecret::EqualToCommitment(resp_m_i, resp_r_i),
                ) => {
                    let cmm_msg_c_i = multiexp(
                        &[c_i.0, cmm_key.g, cmm_key.h],
                        &[*challenge, **resp_m_i.value, **resp_r_i.randomness],
                    );
                    cmm_msg_commitments.push(Commitment(cmm_msg_c_i));

                    cmm_msg_sig_gs.push(y_tilda(i));
                    cmm_msg_sig_es.push(**resp_m_i);
                }
                (PsSigMsg::Revealed(m_i), MsgSecret::Revealed) => {
                    cmm_msg_sig_gs.push(y_tilda(i));
                    let mut exp = challenge_neg;
                    exp.mul_assign(m_i);
                    cmm_msg_sig_es.push(exp);
                }
                (PsSigMsg::Known, MsgSecret::Known(resp_m_i)) => {
                    cmm_msg_sig_gs.push(y_tilda(i));
                    cmm_msg_sig_es.push(**resp_m_i);
                }
                _ => return None,
            }
        }

        let cmm_msg_sig_elm = multiexp(&cmm_msg_sig_gs, &cmm_msg_sig_es);

        // Combine the pairing computations to compute the product.
        let cmm_msg_sig = P::pairing_product(
            &b_hat,
            &g_tilda.mul_by_scalar(challenge),
            &a_hat,
            &cmm_msg_sig_elm,
        )?;

        Some((cmm_msg_sig, cmm_msg_commitments))
    }

    // todo ar valid data simplify/refactor
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
                    secrets.push(MsgSecret::EqualToCommitment(v_j, r_j));
                    msgs_handling.push(PsSigMsg::EqualToCommitment(c_j));
                }
                1 => {
                    secrets.push(MsgSecret::Revealed);
                    msgs_handling.push(PsSigMsg::Revealed(v_j));
                }
                2 => {
                    secrets.push(MsgSecret::Known(v_j));
                    msgs_handling.push(PsSigMsg::Known);
                }
                _ => unreachable!(),
            }
        }
        let unknown_message = UnknownMessage(comm_to_signer);
        let sig = ps_sk
            .sign_unknown_message(&unknown_message, csprng)
            .retrieve(&mask);
        let (blinded_sig, blind_rand) = sig.blind(csprng);
        let ces = PsSig {
            msgs: msgs_handling,
            ps_pub_key: ps_pk,
            comm_key: cmm_key,
            blinded_sig,
        };

        let secret = PsSigSecret {
            r_prime: blind_rand.1,
            msgs: secrets,
        };
        f(ces, secret, csprng)
    }
}

// todo ar check constant time stuff and calculations

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
            PsSig::<Bls12, G1>::with_valid_data(i, &mut csprng, |ces, secret, csprng| {
                let challenge_prefix = generate_challenge_prefix(csprng);
                let mut ro = RandomOracle::domain(challenge_prefix);

                let proof =
                    prove(&mut ro.split(), &ces, secret, csprng).expect("Proving should succeed.");
                assert!(verify(&mut ro, &ces, &proof));
            })
        }
    }

    // todo ar more soundness tests?
    // todo ar tests

    #[test]
    #[allow(non_snake_case)]
    pub fn test_com_eq_sig_soundness() {
        let mut csprng = thread_rng();
        for i in 1..20 {
            PsSig::<Bls12, G1>::with_valid_data(i, &mut csprng, |ces, secret, csprng| {
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
                    if !wrong_ces.msgs.is_empty() {
                        let idx = csprng.gen_range(0..wrong_ces.msgs.len());
                        let tmp = wrong_ces.msgs[idx].clone();
                        wrong_ces.msgs[idx] = PsSigMsg::EqualToCommitment(
                            wrong_ces
                                .comm_key
                                .commit(&Value::<G1>::generate(csprng), csprng)
                                .0,
                        );
                        assert!(!verify(&mut ro.split(), &wrong_ces, &proof));
                        wrong_ces.msgs[idx] = tmp;
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
