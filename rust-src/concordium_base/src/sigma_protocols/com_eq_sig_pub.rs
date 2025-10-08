//! This module implements the proof of knowledge of signature with public values sigma protocol.
//! It allows a user to prove knowledge of a PS signature on a private message vector given a public PS signature verification key.
//! In addition the user can reveal a subset of messages and commit to another subset of messages.
//! The protocol is a essentially `com-dlog-eq` from "Proof of Equality for Aggregated Discrete Logarithms and Commitments" Section 9.2.5,
//! Bluepaper v2.3.0 where the blinded signature (with the revealed values omitted) is the aggregated dlog (cf.
//! "Proof of Knowledge of a Signature" Section 5.3.5, Bluepaper v2.3.0").

use std::collections::BTreeMap;

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

type ValueIndex = u32; //TODO: usize vs u32 vs u64

pub struct ComEqSigPub<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// The blinded PS signature
    pub blinded_sig: BlindedSignature<P>,
    /// The length of the message vector
    pub msg_vec_length: usize,
    /// The commitments where the index indicates the position of the committed value in the signed message vector
    pub commitments: BTreeMap<ValueIndex,Commitment<C>>,
    ///  The revealed values and their indices in the message vector.
    pub revealed_values: BTreeMap<ValueIndex,Value<C>>,
    /// The Pointcheval-Sanders public key with which the signature was generated
    pub ps_pub_key: PsSigPublicKey<P>,
    /// A commitment key with which the commitments were generated.
    pub comm_key: CommitmentKey<C>,
}

pub struct ComEqSigPubWitness<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// The signature blinding randomness r'
    pub blind_rand: BlindingRandomness<P>,
    /// The message vector (for simplicity the full message vector)
    pub values: Vec<Value<C>>,
    /// The commitment randomness
    pub commit_rands: Vec<Randomness<C>>
}

pub struct ComEqSigState<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// The commit state for the randomness r' term in the aggregate dlog
    pub rho_prime: P::ScalarField,
    /// The commit state for the message vector term in the aggregate dlog, this is also used for the commitment part
    pub alphas: Vec<Value<C>>,
    /// The randomness tilde{r}_i for the commitment part
    pub tilda_rs: Vec<Randomness<C>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Response<P: Pairing, C: Curve<Scalar = P::ScalarField>> {
    /// The response for the randomness r' term in the aggregate dlog.
    response_rho: P::ScalarField,
    /// The (rest of the) s_i terms of the response
    response_si: Vec<P::ScalarField>,
    /// The t_i terms of the response
    response_ti: Vec<C::Scalar>,
}

#[allow(non_snake_case)]
impl<P: Pairing, C: Curve<Scalar = P::ScalarField>> SigmaProtocol for ComEqSigPub<P, C> {
    type CommitMessage = (P::TargetField, Vec<Commitment<C>>);
    type ProtocolChallenge = C::Scalar;
    type ProverState = ComEqSigState<P, C>;
    type Response = Response<P, C>;
    type SecretData = ComEqSigPubWitness<P, C>;

    #[inline]
    fn public(&self, ro: &mut RandomOracle) {
        // Append all public values of the proof
        ro.append_message(b"blinded_sig", &self.blinded_sig);
        ro.append_message(b"message_vec_length", &(self.msg_vec_length as u32)); //TODO: Check this hack
        // Here it is important to also add the indices!
        ro.extend_from_kv(b"commitments", self.commitments.iter());
        // Here it is important to also add the indices!
        ro.extend_from_kv(b"revealed_values", self.revealed_values.iter());
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
        // Generator of G2 as used by the signature scheme
        let g_two = self.ps_pub_key.g_tilda;
        // The Y_tilda parts of the public key
        let Y_tilda = |i| self.ps_pub_key.y_tildas[i];
        // The parts of the blinded signature
        let a_hat = self.blinded_sig.sig.0;
        // The commitment key
        let cmm_key = self.comm_key;

        // The length of the message vector
        let n = self.msg_vec_length;
        // must be smaller than the public key length
        if n > self.ps_pub_key.len() {
            return None;
        }
        // The number of revealed messages
        let rev_val_length = self.revealed_values.len();
        // Basic sanity check
        if rev_val_length > n {
            return None;
        }
        // The number of commitments
        let com_length = self.commitments.len();
        // Basic sanity check
        if com_length > n-rev_val_length {
            return  None;
        }

        // For every private value an alpha needs to be generated
        let mut alphas = Vec::with_capacity(n-rev_val_length);
        // For every commitment a r_tilde needs to be generated
        let mut tilda_rs = Vec::with_capacity(com_length);
        let mut commitments = Vec::with_capacity(com_length);


        // The commit message consists of a point `paired` in the target group computed as `v_1^{rho_prime}\prod u_i^{alpha_j}`
        // and the Pedersen commitments to some of the `alpha_j` using randomness `tilde_rs`
        // In contrast to the specification, we only use one pairing operation to compute paired as `paired = e(a_hat,point)` where `point =  g_2^{rho_prime}\prod tilde_Y_j^{alpha_j}`.

        // randomness corresponding to r' entry in the agglog
        let rho_prime = <P::G2 as Curve>::generate_non_zero_scalar(csprng);

        // starting the computation of `point` with `g_2^{rho_prime}`
        let mut point = g_two.mul_by_scalar(&rho_prime);

        // iterate over all messages to compute the commitments and the `\prod tilde_Y_j^{alpha_j}` part of `point`
        for i in 0..n {
            match self.revealed_values.get(&(i as u32)) {
                // Do nothing for revealed values
                None => {
                    // but check that the revealed value is not committed
                    if self.commitments.contains_key(&(i as u32)){
                        return None
                    }
                },
                // Do computation for the index
                Some(_) => {
                    // Random value alpha_i.
                    let alpha_i = Value::generate_non_zero(csprng);
                    // Compute Y_tilda^{alpha_i} and add it to point
                    let Y_tilda_alpha_i = Y_tilda(i).mul_by_scalar(&alpha_i);
                    point.plus_point(&Y_tilda_alpha_i);
                    // Commit to alpha_i if value is committed
                    if self.commitments.contains_key(&(i as u32)){
                        let (c_i, tilda_r_i) = cmm_key.commit(&alpha_i, csprng);
                        tilda_rs.push(tilda_r_i);
                        commitments.push(c_i);
                    }
                    alphas.push(alpha_i);
                },
            }
        }
        let paired = P::pair(&a_hat, &point);
        Some((
            (paired, commitments),
            ComEqSigState {
                rho_prime,
                alphas,
                tilda_rs
            },
        ))
    }

    #[inline]
    fn compute_response(
        &self,
        witness: Self::SecretData,
        state: Self::ProverState,
        challenge: &Self::ProtocolChallenge,
    ) -> Option<Self::Response> {
        // Number of commitments must match 
        if witness.commit_rands.len() != state.tilda_rs.len() {
            return None
        }
        let n = self.msg_vec_length;
        // Public length must match vector length in witness
        if witness.values.len() != n {
            return None
        }
        // Number of alphas must match private message vector length
        if state.alphas.len() != self.msg_vec_length - self.revealed_values.len() {
            return None
        } 

        // Compute response_rho as rho_prime - challenge * r_prime
        let r_prime = witness.blind_rand.1;
        let mut response_rho = *challenge;
        response_rho.mul_assign(&r_prime);
        response_rho.negate();
        response_rho.add_assign(&state.rho_prime);

        // Compute s_i as alpha_i - challenge * ith private value
        let mut response_si = Vec::with_capacity(state.alphas.len());
        let mut i = 0;
        for j in 0..n {
            // Only compute s_i for private values
            if !self.revealed_values.contains_key(&(j as u32)){
                let mut s_i = *challenge;
                s_i.mul_assign(&witness.values[j]);
                s_i.negate();
                s_i.add_assign(&state.alphas[i]); 
                response_si.push(s_i);
                i += 1           
            }
        }

        // Compute t_i as tilda_rs_i - challenge * commit_rands_i
        let mut response_ti = Vec::with_capacity(state.tilda_rs.len());
        for (ref tilda_rs_i, ref commit_rands_i) in izip!(state.tilda_rs,witness.commit_rands) {
            let mut t_i = *challenge;
            t_i.mul_assign(commit_rands_i);
            t_i.negate();
            t_i.add_assign(tilda_rs_i);
            response_ti.push(t_i);
        }

        Some(Response {
            response_rho, response_si, response_ti
        })
    }

    #[inline]
    fn extract_commit_message(
        &self,
        challenge: &Self::ProtocolChallenge,
        response: &Self::Response,
    ) -> Option<Self::CommitMessage> {
        todo!()
        // let g_tilda = self.ps_pub_key.g_tilda;
        // let a_hat = self.blinded_sig.sig.0;
        // let b_hat = self.blinded_sig.sig.1;
        // let cX_tilda = self.ps_pub_key.x_tilda;
        // let cY_tildas = &self.ps_pub_key.y_tildas;
        // let cmm_key = self.comm_key;

        // let commitments = &self.commitments;
        // let n = commitments.len();
        // if response.response_commit.len() != n {
        //     return None;
        // }
        // if n > cY_tildas.len() {
        //     return None;
        // }

        // // storing values for multiexponentiation. gs is bases, es is powers.
        // let mut gs = Vec::with_capacity(n + 2);
        // let mut es = Vec::with_capacity(n + 2);

        // gs.push(g_tilda);
        // es.push(response.response_rho);
        // let mut cmms = Vec::with_capacity(n);
        // for (cC_i, cY_tilda, (res_m, res_r)) in izip!(
        //     commitments.iter(),
        //     cY_tildas,
        //     response.response_commit.iter()
        // ) {
        //     // compute C_i^c * g^mu_i h^R_i
        //     let bases = [cC_i.0, cmm_key.g, cmm_key.h];
        //     let powers = [*challenge, *res_m, *res_r];
        //     let cP = multiexp(&bases, &powers);
        //     cmms.push(Commitment(cP));
        //     gs.push(*cY_tilda);
        //     es.push(*res_m);
        // }
        // // finally add X_tilda and -challenge to the powers.
        // gs.push(cX_tilda);
        // {
        //     let mut x = *challenge;
        //     x.negate();
        //     es.push(x);
        // }

        // // let point =
        // // point.plus_point(&cX_tilda.inverse_point().mul_by_scalar(challenge));

        // let point = multiexp(&gs, &es);

        // // We have now computed a point `point` such that
        // // ```v_3^{-c} * v_1^R \prod u_i^w_i = e(a_hat, point)```
        // // If the proof is correct then the challenge was computed with
        // // v_2^c * v^3{-c} * ...
        // // where * is the multiplication in the target field (of which the G_T is a multiplicative subgroup).

        // // Combine the pairing computations to compute the product.
        // let paired = P::pairing_product(&b_hat, &g_tilda.mul_by_scalar(challenge), &a_hat, &point);

        // paired.map(|paired| (paired, cmms))
    }

    #[cfg(test)]
    fn with_valid_data<R: Rng>(
        data_size: usize,
        csprng: &mut R,
        f: impl FnOnce(Self, Self::SecretData, &mut R),
    ) {
        todo!()
        // use crate::ps_sig::{SecretKey as PsSigSecretKey, SigRetrievalRandomness, UnknownMessage};
        // let ps_sk: PsSigSecretKey<P> = PsSigSecretKey::generate(data_size, csprng);
        // let ps_pk: PsSigPublicKey<P> = PsSigPublicKey::from(&ps_sk);
        // let cmm_key = CommitmentKey::generate(csprng);

        // let mut secrets = Vec::with_capacity(data_size);
        // // commitment to the signer.
        // // the randomness used to mask the actual values.
        // let mask = SigRetrievalRandomness::generate_non_zero(csprng);
        // let mut comm_to_signer: P::G1 = ps_pk.g.mul_by_scalar(&mask);
        // let mut commitments = Vec::with_capacity(data_size);
        // for cY_j in ps_pk.ys.iter().take(csprng.gen_range(0..data_size)) {
        //     let v_j = Value::generate(csprng);
        //     let (c_j, r_j) = cmm_key.commit(&v_j, csprng);
        //     comm_to_signer = comm_to_signer.plus_point(&cY_j.mul_by_scalar(&v_j));
        //     secrets.push((v_j, r_j));
        //     commitments.push(c_j);
        // }
        // let unknown_message = UnknownMessage(comm_to_signer);
        // let sig = ps_sk
        //     .sign_unknown_message(&unknown_message, csprng)
        //     .retrieve(&mask);
        // let (blinded_sig, blind_rand) = sig.blind(csprng);
        // let ces = ComEqSig {
        //     commitments,
        //     ps_pub_key: ps_pk,
        //     comm_key: cmm_key,
        //     blinded_sig,
        // };

        // let secret = ComEqSigPubWitness {
        //     blind_rand,
        //     values_and_rands: secrets,
        // };
        // f(ces, secret, csprng)
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
            ComEqSigPub::<Bls12, G1>::with_valid_data(i, &mut csprng, |ces, secret, csprng| {
                let challenge_prefix = generate_challenge_prefix(csprng);
                let mut ro = RandomOracle::domain(challenge_prefix);

                let proof =
                    prove(&mut ro.split(), &ces, secret, csprng).expect("Proving should succeed.");
                assert!(verify(&mut ro, &ces, &proof));
            })
        }
    }

    #[test]
    #[allow(non_snake_case)]
    pub fn test_com_eq_sig_soundness() {
        todo!()
        // let mut csprng = thread_rng();
        // for i in 1..20 {
        //     ComEqSigPub::<Bls12, G1>::with_valid_data(i, &mut csprng, |ces, secret, csprng| {
        //         let challenge_prefix = generate_challenge_prefix(csprng);
        //         let ro = RandomOracle::domain(challenge_prefix);

        //         let proof =
        //             prove(&mut ro.split(), &ces, secret, csprng).expect("Proving should succeed.");
        //         assert!(verify(&mut ro.split(), &ces, &proof));

        //         // Construct invalid parameters
        //         let mut wrong_ro = RandomOracle::domain(generate_challenge_prefix(csprng));
        //         if verify(&mut wrong_ro, &ces, &proof) {
        //             assert_eq!(wrong_ro, ro);
        //         }

        //         let mut wrong_ces = ces;
        //         {
        //             let tmp = wrong_ces.blinded_sig;
        //             wrong_ces.blinded_sig = BlindedSignature {
        //                 sig: Signature(G1::generate(csprng), G1::generate(csprng)),
        //             };
        //             assert!(!verify(&mut ro.split(), &wrong_ces, &proof));
        //             wrong_ces.blinded_sig = tmp;
        //         }

        //         {
        //             if !wrong_ces.commitments.is_empty() {
        //                 let idx = csprng.gen_range(0..wrong_ces.commitments.len());
        //                 let tmp = wrong_ces.commitments[idx];
        //                 wrong_ces.commitments[idx] = wrong_ces
        //                     .comm_key
        //                     .commit(&Value::<G1>::generate(csprng), csprng)
        //                     .0;
        //                 assert!(!verify(&mut ro.split(), &wrong_ces, &proof));
        //                 wrong_ces.commitments[idx] = tmp;
        //             }
        //         }

        //         {
        //             let tmp = wrong_ces.comm_key;
        //             wrong_ces.comm_key = CommitmentKey::generate(csprng);
        //             assert!(!verify(&mut ro.split(), &wrong_ces, &proof));
        //             wrong_ces.comm_key = tmp;
        //         }

        //         {
        //             let tmp = wrong_ces.ps_pub_key;
        //             wrong_ces.ps_pub_key =
        //                 PsSigPublicKey::from(&PsSigSecretKey::generate(i, csprng));
        //             assert!(!verify(&mut ro.split(), &wrong_ces, &proof));
        //             wrong_ces.ps_pub_key = tmp;
        //         }
        //     })
        // }
    }
}
