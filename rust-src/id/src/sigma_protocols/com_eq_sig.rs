//! This module implements the proof of knowledge of signature sigma protocol.
//! This protocol allows a user to prove knowledge of a signature without
//! revealing the original signature, or the message, but they have to reveal
//! the blinded version of the signature, and commitments to the values that
//! were signed.

use crate::sigma_protocols::common::*;
use crypto_common::*;
use curve_arithmetic::*;
use ff::Field;
use pedersen_scheme::{Commitment, CommitmentKey, Randomness, Value};
use ps_sig::{BlindedSignature, BlindingRandomness, PublicKey as PsSigPublicKey};
use rand::*;
use random_oracle::RandomOracle;

#[derive(Clone, Debug, Serialize)]
pub struct Witness<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// The witness that the prover knows $r'$ (see specification)
    witness_rho:    P::ScalarField,
    /// List of witnesses $(w_i, R_i)$ that the user knows the messages m_i and
    /// randomness R_i that combine to commitments and the public randomized
    /// signature.
    #[size_length = 4]
    witness_commit: Vec<(P::ScalarField, C::Scalar)>,
}

pub struct ComEqSig<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// The blinded signature
    pub blinded_sig: BlindedSignature<P>,
    ///  A list of commitments that were signed.
    pub commitments: Vec<Commitment<C>>,
    /// The Pointcheval-Sanders public key with which the signature was
    /// generated
    pub ps_pub_key:  PsSigPublicKey<P>,
    /// A commitment key with which the commitments were generated.
    pub comm_key:    CommitmentKey<C>,
}

pub type ValuesAndRands<C> = (Value<C>, Randomness<C>);

pub struct ComEqSigSecret<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    pub blind_rand:       BlindingRandomness<P>,
    pub values_and_rands: Vec<ValuesAndRands<C>>,
}

pub struct ComEqSigState<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    pub rho_prime:  P::ScalarField,
    pub mus_and_rs: Vec<(Value<C>, Randomness<C>)>,
}

#[allow(non_snake_case)]
impl<P: Pairing, C: Curve<Scalar = P::ScalarField>> SigmaProtocol for ComEqSig<P, C> {
    type CommitMessage = (P::TargetField, Vec<Commitment<C>>);
    type ProtocolChallenge = C::Scalar;
    // Triple (rho', [mu_i], [R_i])
    type ProverState = ComEqSigState<P, C>;
    type ProverWitness = Witness<P, C>;
    type SecretData = ComEqSigSecret<P, C>;

    #[inline]
    fn public(&self, ro: &mut RandomOracle) {
        ro.append_message(b"blinded_sig", &self.blinded_sig);
        ro.extend_from(b"commitments", self.commitments.iter());
        ro.append_message(b"ps_pub_key", &self.ps_pub_key);
        ro.append_message(b"comm_key", &self.comm_key)
    }

    #[inline]
    fn get_challenge(&self, challenge: &random_oracle::Challenge) -> Self::ProtocolChallenge {
        C::scalar_from_bytes(challenge)
    }

    #[inline]
    fn commit_point<R: Rng>(
        &self,
        csprng: &mut R,
    ) -> Option<(Self::CommitMessage, Self::ProverState)> {
        let g_tilda = self.ps_pub_key.g_tilda;
        let a_hat = self.blinded_sig.sig.0;
        let _b_hat = self.blinded_sig.sig.1;
        let _cX_tilda = self.ps_pub_key.x_tilda;
        let cY_tilda = |i| self.ps_pub_key.y_tildas[i];
        let cmm_key = self.comm_key;

        let n = self.commitments.len();
        if n > self.ps_pub_key.len() {
            return None;
        }

        // Random elements corresponding to the messages m_i, used as witnesses
        // for the aggregate log part of the proof, and the randomness R_i used
        // for the commitment part of the proof.
        let mut mus_cRs = Vec::with_capacity(n);

        // randomness corresponding to the r_prime (r').
        let rho_prime = <P::G2 as Curve>::generate_non_zero_scalar(csprng);

        // The auxiliary point which we are going to pair with a_hat to obtain the final
        // challenge. This is using the bilinearity property of pairings and differs
        // from the specification in the way the computation is carried out, but
        // not in the observable outcomes.
        let mut point = g_tilda.mul_by_scalar(&rho_prime);

        let mut commitments = Vec::with_capacity(n);
        for i in 0..n {
            // Random value.
            let mu_i = Value::generate_non_zero(csprng);

            // And a point in G2 computed from it.
            let cU_i = cY_tilda(i).mul_by_scalar(&mu_i);
            // A commitment to the value v_i, and a randomness
            let (c_i, cR_i) = cmm_key.commit(&mu_i, csprng);

            commitments.push(c_i);

            // Save these for later
            mus_cRs.push((mu_i, cR_i));

            // And the other point to the running total (since we have to hash the result of
            // the pairing)
            point = point.plus_point(&cU_i);
        }
        // // add X_tilda (corresponds to multiplying by v_3)
        // let v_2_pre_pair = cX_tilda.plus_point(&point);
        // let v_2_pair = P::pair(a_hat, v_2_pre_pair);
        let paired = P::pair(&a_hat, &point);
        Some(((paired, commitments), ComEqSigState {
            rho_prime,
            mus_and_rs: mus_cRs,
        }))
    }

    #[inline]
    fn generate_witness(
        &self,
        secret: Self::SecretData,
        state: Self::ProverState,
        challenge: &Self::ProtocolChallenge,
    ) -> Option<Self::ProverWitness> {
        if secret.values_and_rands.len() != state.mus_and_rs.len() {
            return None;
        }
        let n = secret.values_and_rands.len();

        let r_prime = secret.blind_rand.1;
        // If challange = 0 the proof is not going to be valid.
        // However this is an exceedingly unlikely case
        let mut wit_r_prime = *challenge;
        wit_r_prime.mul_assign(&r_prime);
        wit_r_prime.negate();
        wit_r_prime.add_assign(&state.rho_prime);

        let mut wit_messages_randoms = Vec::with_capacity(n);
        for ((ref m, ref r), (ref mu, ref rho)) in izip!(secret.values_and_rands, state.mus_and_rs)
        {
            let mut wit_m = *challenge;
            wit_m.mul_assign(m);
            wit_m.negate();
            wit_m.add_assign(mu);

            let mut wit_r = *challenge;
            wit_r.mul_assign(r);
            wit_r.negate();
            wit_r.add_assign(rho);

            wit_messages_randoms.push((wit_m, wit_r));
        }
        Some(Witness {
            witness_rho:    wit_r_prime,
            witness_commit: wit_messages_randoms,
        })
    }

    #[inline]
    fn extract_point(
        &self,
        challenge: &Self::ProtocolChallenge,
        witness: &Self::ProverWitness,
    ) -> Option<Self::CommitMessage> {
        let g_tilda = self.ps_pub_key.g_tilda;
        let a_hat = self.blinded_sig.sig.0;
        let b_hat = self.blinded_sig.sig.1;
        let cX_tilda = self.ps_pub_key.x_tilda;
        let cY_tildas = &self.ps_pub_key.y_tildas;
        let cmm_key = self.comm_key;

        let commitments = &self.commitments;
        let n = commitments.len();
        if witness.witness_commit.len() != n {
            return None;
        }
        if n > cY_tildas.len() {
            return None;
        }

        // storing values for multiexponentiation. gs is bases, es is powers.
        let mut gs = Vec::with_capacity(n + 2);
        let mut es = Vec::with_capacity(n + 2);

        // let mut point = g_tilda.mul_by_scalar(&witness.witness_rho);
        gs.push(g_tilda);
        es.push(witness.witness_rho);
        let mut cmms = Vec::with_capacity(n);
        for (cC_i, cY_tilda, (wit_m, wit_r)) in
            izip!(commitments.iter(), cY_tildas, witness.witness_commit.iter())
        {
            // compute C_i^c * g^mu_i h^R_i
            let bases = [cC_i.0, cmm_key.g, cmm_key.h];
            let powers = [*challenge, *wit_m, *wit_r];
            let cP = multiexp(&bases, &powers);
            // let cP = cC_i
            //     .mul_by_scalar(challenge)
            //     .plus_point(&cmm_key.hide_worker(wit_m, wit_r));
            cmms.push(Commitment(cP));
            gs.push(*cY_tilda);
            es.push(*wit_m);
            // point = point.plus_point(&cY_tilda.mul_by_scalar(&wit_m));
        }
        // finally add X_tilda and -challenge to the powers.
        gs.push(cX_tilda);
        {
            let mut x = *challenge;
            x.negate();
            es.push(x);
        }

        // let point =
        // point.plus_point(&cX_tilda.inverse_point().mul_by_scalar(challenge));

        let point = multiexp(&gs, &es);

        // We have now computed a point `point` such that
        // ```v_3^{-c} * v_1^R \prod u_i^w_i = e(a_hat, point)```
        // If the proof is correct then the challenge was computed with
        // v_2^c * v^3{-c} * ...
        // where * is the multiplication in the target field (of which the G_T is a multiplicative subgroup).

        // Combine the pairing computations to compute the product.
        let paired = P::pairing_product(&b_hat, &g_tilda.mul_by_scalar(challenge), &a_hat, &point);

        paired.map(|paired| (paired, cmms))
    }

    #[cfg(test)]
    fn with_valid_data<R: Rng>(
        data_size: usize,
        csprng: &mut R,
        f: impl FnOnce(Self, Self::SecretData, &mut R),
    ) {
        use ps_sig::{SecretKey as PsSigSecretKey, SigRetrievalRandomness, UnknownMessage};
        let ps_sk: PsSigSecretKey<P> = PsSigSecretKey::generate(data_size, csprng);
        let ps_pk: PsSigPublicKey<P> = PsSigPublicKey::from(&ps_sk);
        let cmm_key = CommitmentKey::generate(csprng);

        let mut secrets = Vec::with_capacity(data_size);
        // commitment to the signer.
        // the randomness used to mask the actual values.
        let mask = SigRetrievalRandomness::generate_non_zero(csprng);
        let mut comm_to_signer: P::G1 = ps_pk.g.mul_by_scalar(&mask);
        let mut commitments = Vec::with_capacity(data_size);
        for cY_j in ps_pk.ys.iter().take(csprng.gen_range(0, data_size)) {
            let v_j = Value::generate(csprng);
            let (c_j, r_j) = cmm_key.commit(&v_j, csprng);
            comm_to_signer = comm_to_signer.plus_point(&cY_j.mul_by_scalar(&v_j));
            secrets.push((v_j, r_j));
            commitments.push(c_j);
        }
        let unknown_message = UnknownMessage(comm_to_signer);
        let sig = ps_sk
            .sign_unknown_message(&unknown_message, csprng)
            .retrieve(&mask);
        let (blinded_sig, blind_rand) = sig.blind(csprng);
        let ces = ComEqSig {
            commitments,
            ps_pub_key: ps_pk,
            comm_key: cmm_key,
            blinded_sig,
        };

        let secret = ComEqSigSecret {
            blind_rand,
            values_and_rands: secrets,
        };
        f(ces, secret, csprng)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::{Bls12, G1};
    use ps_sig::{SecretKey as PsSigSecretKey, Signature};

    #[test]
    #[allow(non_snake_case)]
    pub fn test_com_eq_sig_correctness() {
        let mut csprng = thread_rng();
        for i in 1..20 {
            ComEqSig::<Bls12, G1>::with_valid_data(i, &mut csprng, |ces, secret, csprng| {
                let challenge_prefix = generate_challenge_prefix(csprng);
                let mut ro = RandomOracle::domain(&challenge_prefix);

                let proof =
                    prove(&mut ro.split(), &ces, secret, csprng).expect("Proving should succeed.");
                assert!(verify(&mut ro, &ces, &proof));
            })
        }
    }

    #[test]
    #[allow(non_snake_case)]
    pub fn test_com_eq_sig_soundness() {
        let mut csprng = thread_rng();
        for i in 1..20 {
            ComEqSig::<Bls12, G1>::with_valid_data(i, &mut csprng, |ces, secret, csprng| {
                let challenge_prefix = generate_challenge_prefix(csprng);
                let ro = RandomOracle::domain(&challenge_prefix);

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
                    if !wrong_ces.commitments.is_empty() {
                        let idx = csprng.gen_range(0, wrong_ces.commitments.len());
                        let tmp = wrong_ces.commitments[idx];
                        wrong_ces.commitments[idx] = wrong_ces
                            .comm_key
                            .commit(&Value::<G1>::generate(csprng), csprng)
                            .0;
                        assert!(!verify(&mut ro.split(), &wrong_ces, &proof));
                        wrong_ces.commitments[idx] = tmp;
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
