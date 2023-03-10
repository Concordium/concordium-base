//! This module provides an implementation of the sigma protocol used for
//! encrypted transfers.
//!
//! It enables one to prove knowledge of a secret key `sk`,
//! exponent `s` and chunks a_1, ..., a_t, s_1', ..., s_(t')', r_1, ..., r_t,
//! r_1', ..., r_(t')' such that pk_sender = g^sk, S_2 = S_1^sk h^s , and
//! c_{i,1} = g^{r_i}, c_{i,2} = h^{a_i} pk_receiver^{r_i} for all i in {1,..,
//! t},
//! d_{i,1} = g^{r_i'}, d_{i,2} = h^{s_i'} pk_sender^{r_i'} for all i in {1,..,
//! t'}, and s = \sum_{j=1}^t 2^{(chunk_size)*(j-1)} (a_j)
//!             +\sum_{j=1}^(t') 2^{(chunk_size)*(j-1)} s_j',
//!
//! This is done using the subprotocols Dlog, Elgdec and EncExp (EncExp is
//! basically just several ComEq's (can be found in
//! sigma_protocols in the id crate)) as described in Id Layer Bluepaper, see
//! genEncTransProofInfo and genEncTrans. The resulting sigma protocol is
//! contructed using the sigma protocols for equality and linear relations
//! described in the Cryptoprim Bluepaper.
//!
//! Proving knowledge of (a_i, r_i) such that c_{i,1} = g^{r_i} and c_{i,2} =
//! h^{a_i} pk_receiver^{r_i} is done using the ComEq sigma protocol in the
//! following way.
//! Recall that pk_receiver = g^x where x is the corresponding secret key and
//! notice that proving knowledge of a_i and r_i such that the above statement
//! is true is the same as proving knowledge of a_i and r_i such that c_{i,2} is
//! a Pedersen commitment to r_i under Pedersen commitment key (pk_receiver, h)
//! and randomness a_i, subject to the extra condition that r_i is the discreet
//! log of c_{i,1} with respect to g. This is exactly the relation proven by
//! ComEq with {commitment: c_{i,2}, cmm_key: (pk_receiver, h), y: g^r_i, g: g}
//!
//! Ensuring that the same secret is known in the dlog proof and the elg-dec
//! proof is done by ensuring that the same randomness alpha and challenge c is
//! used in the dlog proof and in the elg-dec proof (see the Cryptoprim
//! bluepaper).
//!
//! Proving the relation
//!         s = \sum_{j=1}^t 2^{(chunk_size)*(j-1)} (a_j)
//!             +\sum_{j=1}^(t') 2^{(chunk_size)*(j-1)} s_j' s'
//! is done using the protocol 10.1.4 in the Cryptoprim bluepaper for proving
//! linear relations of preimages of homomorphisms. The homomorphism in question
//! is the one that maps the amounts in chunks to the encrypted amounts.
//!
//! The trait SigmaProtocol is
//! implemented directly for the EncTrans struct below, and it is not used that
//! the Sigmaprotocol trait is already implemented for Dlog, as we need to
//! specify the randomness to be used directly

#![allow(non_snake_case)]
use crate::types::CHUNK_SIZE;
use crypto_common::*;
use crypto_common_derive::*;
use curve_arithmetic::{multiexp, Curve};
use elgamal::ChunkSize;
use ff::Field;
use id::sigma_protocols::{
    com_eq::{ComEq, ComEqSecret, CommittedPoints, Witness as ComEqWitness},
    common::*,
    dlog::*,
};
use pedersen_scheme::{Randomness as PedersenRandomness, Value};
use random_oracle::{Challenge, RandomOracle};
use std::rc::Rc;

/// An auxiliary structure that contains data related to the proof of correct
/// decryption. This is stated as an independent protocol in the blue papers,
/// but for efficiency reasons the prover and verifier are inlined together with
/// the main [EncTrans] proof provers and verifiers. Only the data is separate.
pub struct ElgDec<C: Curve> {
    /// S_2 above
    pub public: C,
    /// The points S_1 and h.
    pub coeff:  [C; 2],
}

impl<C: Curve> ElgDec<C> {
    fn public(&self, ro: &mut RandomOracle) {
        ro.append_message(b"public", &self.public);
        ro.extend_from(b"coeff", &self.coeff)
    }
}

/// The [EncTrans] sigma protocol as specified in the blue paper.
pub struct EncTrans<C: Curve> {
    pub dlog:    Dlog<C>,
    /// elg_dec contains the publicly known values S_1, S_2 and h
    pub elg_dec: ElgDec<C>,
    /// encexp1 contains the publicly known values a_{i,j}'s, g, h, pk_receiver
    pub encexp1: Vec<ComEq<C, C>>,
    /// encexp2 contains the publicly known values s'_{i,j}'s, g, h, pk_sender
    pub encexp2: Vec<ComEq<C, C>>,
}

/// Witness for the [EncTrans] protocol.
///
/// The elc_dec protocol actually has two witnesses, one involving sk and one
/// involving s, but since sk is also the secret for the dlog, and since
/// s is a linear combination of the secrets for the EncExp/ComEq's,
/// we calculate the same linear combination, but of the witnesses, in
/// the extract_point function. We do therefore not need to transfer/send
/// those witnesses, since they are determined by the ones below.
#[derive(Debug, Serialize, Clone)]
pub struct EncTransWitness<C: Curve> {
    /// The common witness for both dlog and elc-dec
    witness_common:  C::Scalar,
    /// For EncExp/ComEq's involving a_i
    #[size_length = 4]
    witness_encexp1: Vec<ComEqWitness<C>>,
    /// For EncExp/ComEq's involving s_i'
    #[size_length = 4]
    witness_encexp2: Vec<ComEqWitness<C>>,
}

/// Secret values which the [EncTrans] proof talks about. For constructing
/// proofs these must match the public values that are part of the [EncTrans]
/// structure.
pub struct EncTransSecret<C: Curve> {
    /// dlog_secret contains the secret key `sk`
    pub dlog_secret:     Rc<C::Scalar>,
    /// ComEq secrets for encexp1
    pub encexp1_secrets: Vec<ComEqSecret<C>>,
    /// ComeEq secrets for encexp2
    pub encexp2_secrets: Vec<ComEqSecret<C>>,
}

#[derive(Debug, Serialize)]
/// A structure that represents the intermediate state of the sigma protocol
/// after the prover has committed to all the values they wish to prove
/// statements about. This is then used in the computation of the challenge.
pub struct EncTransCommit<C: Curve> {
    /// Commitmessage for dlog
    dlog:    C,
    /// Commitmessage for elg_dec
    elg_dec: C,
    /// Commitmessages for EncExp/ComEq's involving a_i
    #[size_length = 4]
    encexp1: Vec<CommittedPoints<C, C>>,
    /// Commitmessages for EncExp/ComEq's involving s_i'
    #[size_length = 4]
    encexp2: Vec<CommittedPoints<C, C>>,
}

/// As for the witness, we don't need the state for elg_dec
#[derive(Debug, Serialize)]
pub struct EncTransState<C: Curve> {
    /// Randomness used for dlog
    dlog:    C::Scalar,
    /// Randomness used for EncExp/ComEq's involving a_i
    #[size_length = 4]
    encexp1: Vec<(Value<C>, PedersenRandomness<C>)>,
    /// Randomness used for EncExp/ComEq's involving s_i'
    #[size_length = 4]
    encexp2: Vec<(Value<C>, PedersenRandomness<C>)>,
}

/// This function takes scalars x_1, ..., x_n and returns
/// \sum_{i=1}^n 2^{(chunk_size)*(i-1)} (x_i)
fn linear_combination_with_powers_of_two<C: Curve>(
    scalars: &[C::Scalar],
    chunk_size: ChunkSize,
) -> C::Scalar {
    let u8_chunk_size = u8::from(chunk_size);
    let two_chunksize = C::scalar_from_u64(1 << u8_chunk_size);
    let mut power_of_two = C::Scalar::one();
    let mut sum = C::Scalar::zero();
    for term in scalars.iter() {
        let mut term = *term;
        term.mul_assign(&power_of_two);
        sum.add_assign(&term);
        power_of_two.mul_assign(&two_chunksize);
    }
    sum
}

impl<C: Curve> SigmaProtocol for EncTrans<C> {
    type CommitMessage = EncTransCommit<C>;
    type ProtocolChallenge = C::Scalar;
    type ProverState = EncTransState<C>;
    type ProverWitness = EncTransWitness<C>;
    type SecretData = EncTransSecret<C>;

    fn public(&self, ro: &mut RandomOracle) {
        self.elg_dec.public(ro);
        self.encexp1.iter().for_each(|p| p.public(ro));
        self.encexp2.iter().for_each(|p| p.public(ro));
        self.dlog.public(ro)
    }

    fn get_challenge(&self, challenge: &Challenge) -> Self::ProtocolChallenge {
        C::scalar_from_bytes(challenge)
    }

    fn commit_point<R: rand::Rng>(
        &self,
        csprng: &mut R,
    ) -> Option<(Self::CommitMessage, Self::ProverState)> {
        // For enc_exps:
        let mut commit_encexp_1 = Vec::with_capacity(self.encexp1.len());
        let mut rands_encexp_1 = Vec::with_capacity(self.encexp1.len());
        let mut commit_encexp_2 = Vec::with_capacity(self.encexp2.len());
        let mut rands_encexp_2 = Vec::with_capacity(self.encexp2.len());
        let mut Rs_a = vec![];
        let mut Rs_s_prime = vec![];
        for comeq in &self.encexp1 {
            match comeq.commit_point(csprng) {
                Some((comm_point, (alpha, R_i))) => {
                    rands_encexp_1.push((alpha, R_i.clone()));
                    commit_encexp_1.push(comm_point);
                    Rs_a.push(*R_i);
                }
                None => return None,
            };
        }
        for comeq in &self.encexp2 {
            match comeq.commit_point(csprng) {
                Some((comm_point, (alpha, R_s))) => {
                    rands_encexp_2.push((alpha, R_s.clone()));
                    commit_encexp_2.push(comm_point);
                    Rs_s_prime.push(*R_s);
                }
                None => return None,
            };
        }
        // For dlog and elcdec:
        let rand_scalar_common = C::generate_non_zero_scalar(csprng);
        let commit_dlog = self.dlog.coeff.mul_by_scalar(&rand_scalar_common);
        let rand_lin_a = linear_combination_with_powers_of_two::<C>(&Rs_a, CHUNK_SIZE);
        let rand_lin_s_prime = linear_combination_with_powers_of_two::<C>(&Rs_s_prime, CHUNK_SIZE);
        let mut rand_lin = rand_lin_a;
        rand_lin.add_assign(&rand_lin_s_prime);
        let rands = [rand_scalar_common, rand_lin];
        let point = multiexp(&self.elg_dec.coeff, &rands);

        let commit = EncTransCommit {
            dlog:    commit_dlog,
            elg_dec: point,
            encexp1: commit_encexp_1,
            encexp2: commit_encexp_2,
        };
        let rand = EncTransState {
            dlog:    rand_scalar_common,
            encexp1: rands_encexp_1,
            encexp2: rands_encexp_2,
        };
        Some((commit, rand))
    }

    fn generate_witness(
        &self,
        secret: Self::SecretData,
        state: Self::ProverState,
        challenge: &Self::ProtocolChallenge,
    ) -> Option<Self::ProverWitness> {
        let mut witness_common = *challenge;
        witness_common.mul_assign(&secret.dlog_secret);
        witness_common.negate();
        witness_common.add_assign(&state.dlog);
        // For encexps:
        let mut witness_encexp1 = Vec::with_capacity(secret.encexp1_secrets.len());
        let mut witness_encexp2 = Vec::with_capacity(secret.encexp2_secrets.len());
        if secret.encexp1_secrets.len() != state.encexp1.len() {
            return None;
        }
        for (sec, encexp1, comeq1) in izip!(
            secret.encexp1_secrets,
            state.encexp1.iter(),
            self.encexp1.iter()
        ) {
            match comeq1.generate_witness(sec, (*encexp1).clone(), challenge) {
                Some(w) => witness_encexp1.push(w),
                None => return None,
            }
        }
        if secret.encexp2_secrets.len() != state.encexp2.len() {
            return None;
        }
        for (sec, encexp2, comeq2) in izip!(
            secret.encexp2_secrets,
            state.encexp2.iter(),
            self.encexp2.iter()
        ) {
            match comeq2.generate_witness(sec, (*encexp2).clone(), challenge) {
                Some(w) => witness_encexp2.push(w),
                None => return None,
            }
        }

        Some(EncTransWitness {
            witness_common,
            witness_encexp1,
            witness_encexp2,
        })
    }

    fn extract_point(
        &self,
        challenge: &Self::ProtocolChallenge,
        witness: &Self::ProverWitness,
    ) -> Option<Self::CommitMessage> {
        if self.encexp1.len() != witness.witness_encexp1.len() {
            return None;
        }
        if self.encexp2.len() != witness.witness_encexp2.len() {
            return None;
        }
        // For enc_exps:
        let mut commit_encexp1 = Vec::with_capacity(self.encexp1.len());
        let mut commit_encexp2 = Vec::with_capacity(self.encexp2.len());
        let mut w_a_vec = Vec::with_capacity(self.encexp1.len());
        let mut w_s_prime_vec = Vec::with_capacity(self.encexp2.len());
        for (comeq, witness) in izip!(&self.encexp1, &witness.witness_encexp1) {
            match comeq.extract_point(challenge, witness) {
                Some(m) => {
                    commit_encexp1.push(m);
                    w_a_vec.push(witness.witness.1);
                }
                None => return None,
            }
        }
        for (comeq, witness) in izip!(&self.encexp2, &witness.witness_encexp2) {
            match comeq.extract_point(challenge, witness) {
                Some(m) => {
                    commit_encexp2.push(m);
                    w_s_prime_vec.push(witness.witness.1);
                }
                None => return None,
            }
        }

        // For dlog and elg-dec:
        let w_lin_a = linear_combination_with_powers_of_two::<C>(&w_a_vec, CHUNK_SIZE);
        let w_lin_s_prime = linear_combination_with_powers_of_two::<C>(&w_s_prime_vec, CHUNK_SIZE);
        let mut w_lin = w_lin_a;
        w_lin.add_assign(&w_lin_s_prime);
        let dlog_point = self
            .dlog
            .coeff
            .mul_by_scalar(&witness.witness_common)
            .plus_point(&self.dlog.public.mul_by_scalar(challenge));
        let mut point = self.elg_dec.public.mul_by_scalar(challenge);
        let exps = vec![witness.witness_common, w_lin];
        let product = multiexp(&self.elg_dec.coeff, &exps);
        point = point.plus_point(&product);
        Some(EncTransCommit {
            dlog:    dlog_point,
            elg_dec: point,
            encexp1: commit_encexp1,
            encexp2: commit_encexp2,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elgamal::{PublicKey, Randomness, SecretKey};
    use pairing::bls12_381::G1;
    use pedersen_scheme::{Commitment, CommitmentKey};
    use rand::Rng;

    impl<C: Curve> EncTrans<C> {
        fn with_valid_data<R: Rng>(
            rng: &mut R,
            f: impl FnOnce(Self, <Self as SigmaProtocol>::SecretData, &mut R) -> (),
        ) {
            let sk = SecretKey::generate_all(rng);
            let pk = PublicKey::from(&sk);
            let s = rng.gen::<u64>(); // s.

            let dlog = Dlog {
                public: pk.key,
                coeff:  sk.generator,
            };

            let encr_exp_base = C::generate(rng); // h
            let S = pk.encrypt_exponent_given_generator(&Value::from(s), &encr_exp_base, rng);
            let elgdec = ElgDec {
                public: S.1,
                coeff:  [S.0, encr_exp_base],
            };

            let a = rng.gen_range(0, s); // amount to send
            let s_prime = s - a;
            let a_chunks = CHUNK_SIZE.u64_to_chunks(a);
            let s_prime_chunks = CHUNK_SIZE.u64_to_chunks(s_prime);

            let sk2 = SecretKey::generate(&pk.generator, rng);
            let pk2 = PublicKey::from(&sk2);

            let a_chunks_as_values: Vec<Value<C>> =
                a_chunks.iter().map(|v| Value::from(*v)).collect();
            let A_enc_randomness = pk2.encrypt_exponent_vec_given_generator(
                a_chunks_as_values.iter(),
                &encr_exp_base,
                rng,
            );
            let (A, A_rand): (Vec<_>, Vec<_>) = A_enc_randomness.iter().cloned().unzip();
            let s_prime_chunks_as_values: Vec<Value<C>> =
                s_prime_chunks.iter().map(|v| Value::from(*v)).collect();
            let S_prime_enc_randomness = pk.encrypt_exponent_vec_given_generator(
                s_prime_chunks_as_values.iter(),
                &encr_exp_base,
                rng,
            );
            let (S_prime, S_prime_rand): (Vec<_>, Vec<_>) =
                S_prime_enc_randomness.iter().cloned().unzip();

            let a_secrets: Vec<ComEqSecret<C>> = izip!(a_chunks.iter(), A_rand.iter())
                .map(|(a_i, r_i)| ComEqSecret::<C> {
                    r: PedersenRandomness::from_u64(*a_i),
                    a: Randomness::to_value(r_i),
                })
                .collect();
            let s_prime_secrets: Vec<ComEqSecret<C>> =
                izip!(s_prime_chunks.iter(), S_prime_rand.iter())
                    .map(|(a_i, r_i)| ComEqSecret::<C> {
                        r: PedersenRandomness::from_u64(*a_i),
                        a: Randomness::to_value(r_i),
                    })
                    .collect();

            let mut a_com_eqs = vec![];
            for a_chunk in A.iter() {
                a_com_eqs.push(ComEq {
                    commitment: Commitment(a_chunk.1),
                    y:          a_chunk.0,
                    cmm_key:    CommitmentKey {
                        g: pk2.key,
                        h: encr_exp_base,
                    },
                    g:          pk.generator,
                });
            }

            let mut s_prime_com_eqs = vec![];
            for s_prime_chunk in S_prime.iter() {
                s_prime_com_eqs.push(ComEq {
                    commitment: Commitment(s_prime_chunk.1),
                    y:          s_prime_chunk.0,
                    cmm_key:    CommitmentKey {
                        g: pk.key,
                        h: encr_exp_base,
                    },
                    g:          pk.generator,
                });
            }

            let secret = EncTransSecret {
                dlog_secret:     Rc::new(sk.scalar),
                encexp1_secrets: a_secrets,
                encexp2_secrets: s_prime_secrets,
            };
            let enc_trans = EncTrans {
                dlog,
                elg_dec: elgdec,
                encexp1: a_com_eqs,
                encexp2: s_prime_com_eqs,
            };

            f(enc_trans, secret, rng)
        }
    }

    fn generate_challenge_prefix<R: rand::Rng>(csprng: &mut R) -> Vec<u8> {
        // length of the challenge
        let l = csprng.gen_range(0, 1000);
        let mut challenge_prefix = vec![0; l];
        for v in challenge_prefix.iter_mut() {
            *v = csprng.gen();
        }
        challenge_prefix
    }

    #[test]
    fn enctrans_correctness() {
        let mut rng = rand::thread_rng();
        for _i in 1..20 {
            EncTrans::<G1>::with_valid_data(&mut rng, |enc_trans, secret, rng| {
                let challenge_prefix = generate_challenge_prefix(rng);
                let mut ro = RandomOracle::domain(&challenge_prefix);
                let mut ro_copy = ro.split();
                let proof =
                    prove(&mut ro_copy, &enc_trans, secret, rng).expect("Proving should succeed.");
                let res = verify(&mut ro, &enc_trans, &proof);
                assert!(res, "Verification of produced proof.");
            })
        }
    }

    #[test]
    fn enctrans_soundness() {
        let mut rng = rand::thread_rng();
        for _ in 1..20 {
            EncTrans::<G1>::with_valid_data(&mut rng, |enc_trans, secret, rng| {
                let challenge_prefix = generate_challenge_prefix(rng);
                let ro = RandomOracle::domain(&challenge_prefix);
                let mut ro_split = ro.split();
                let proof =
                    prove(&mut ro_split, &enc_trans, secret, rng).expect("Proving should succeed.");

                let mut wrong_ro = RandomOracle::domain(generate_challenge_prefix(rng));
                if verify(&mut wrong_ro, &enc_trans, &proof) {
                    assert_eq!(wrong_ro, ro);
                }

                // check that changing any information in the protocol makes the proof not
                // verify
                let mut wrong_enc_trans = enc_trans;
                {
                    let tmp = wrong_enc_trans.dlog;
                    wrong_enc_trans.dlog = Dlog {
                        public: G1::generate(rng),
                        coeff:  tmp.coeff,
                    };
                    let mut ro_split = ro.split();
                    assert!(!verify(&mut ro_split, &wrong_enc_trans, &proof));

                    wrong_enc_trans.dlog = Dlog {
                        public: tmp.public,
                        coeff:  G1::generate(rng),
                    };
                    let mut ro_split = ro.split();
                    assert!(!verify(&mut ro_split, &wrong_enc_trans, &proof));
                    wrong_enc_trans.dlog = tmp;
                }
                {
                    let tmp = wrong_enc_trans.elg_dec;
                    wrong_enc_trans.elg_dec = ElgDec {
                        public: G1::generate(rng),
                        coeff:  tmp.coeff,
                    };
                    let mut ro_split = ro.split();
                    assert!(!verify(&mut ro_split, &wrong_enc_trans, &proof));

                    wrong_enc_trans.elg_dec = ElgDec {
                        public: tmp.public,
                        coeff:  [G1::generate(rng), tmp.coeff[1]],
                    };
                    let mut ro_split = ro.split();
                    assert!(!verify(&mut ro_split, &wrong_enc_trans, &proof));

                    wrong_enc_trans.elg_dec = ElgDec {
                        public: tmp.public,
                        coeff:  [tmp.coeff[1], G1::generate(rng)],
                    };
                    let mut ro_split = ro.split();
                    assert!(!verify(&mut ro_split, &wrong_enc_trans, &proof));
                    wrong_enc_trans.elg_dec = tmp;
                }
                for i in 0..wrong_enc_trans.encexp1.len() {
                    let com_eq = &wrong_enc_trans.encexp1[i];
                    let tmp = ComEq {
                        commitment: com_eq.commitment,
                        y:          com_eq.y,
                        cmm_key:    com_eq.cmm_key,
                        g:          com_eq.g,
                    };

                    let v = Value::<G1>::generate(rng);
                    let wrong_commit = com_eq.cmm_key.commit(&v, rng).0;
                    wrong_enc_trans.encexp1[i] = ComEq {
                        commitment: wrong_commit,
                        y:          tmp.y,
                        cmm_key:    tmp.cmm_key,
                        g:          tmp.g,
                    };
                    let mut ro_split = ro.split();
                    assert!(!verify(&mut ro_split, &wrong_enc_trans, &proof));

                    wrong_enc_trans.encexp1[i] = ComEq {
                        commitment: tmp.commitment,
                        y:          G1::generate(rng),
                        cmm_key:    tmp.cmm_key,
                        g:          tmp.g,
                    };
                    let mut ro_split = ro.split();
                    assert!(!verify(&mut ro_split, &wrong_enc_trans, &proof));

                    wrong_enc_trans.encexp1[i] = ComEq {
                        commitment: tmp.commitment,
                        y:          tmp.y,
                        cmm_key:    CommitmentKey::generate(rng),
                        g:          tmp.g,
                    };
                    let mut ro_split = ro.split();
                    assert!(!verify(&mut ro_split, &wrong_enc_trans, &proof));

                    wrong_enc_trans.encexp1[i] = ComEq {
                        commitment: tmp.commitment,
                        y:          tmp.y,
                        cmm_key:    tmp.cmm_key,
                        g:          G1::generate(rng),
                    };
                    let mut ro_split = ro.split();
                    assert!(!verify(&mut ro_split, &wrong_enc_trans, &proof));

                    wrong_enc_trans.encexp1[i] = tmp;
                }
                for i in 0..wrong_enc_trans.encexp2.len() {
                    let com_eq = &wrong_enc_trans.encexp2[i];
                    let tmp = ComEq {
                        commitment: com_eq.commitment,
                        y:          com_eq.y,
                        cmm_key:    com_eq.cmm_key,
                        g:          com_eq.g,
                    };

                    let v = Value::<G1>::generate(rng);
                    let wrong_commit = com_eq.cmm_key.commit(&v, rng).0;
                    wrong_enc_trans.encexp2[i] = ComEq {
                        commitment: wrong_commit,
                        y:          tmp.y,
                        cmm_key:    tmp.cmm_key,
                        g:          tmp.g,
                    };
                    let mut ro_split = ro.split();
                    assert!(!verify(&mut ro_split, &wrong_enc_trans, &proof));

                    wrong_enc_trans.encexp2[i] = ComEq {
                        commitment: tmp.commitment,
                        y:          G1::generate(rng),
                        cmm_key:    tmp.cmm_key,
                        g:          tmp.g,
                    };
                    let mut ro_split = ro.split();
                    assert!(!verify(&mut ro_split, &wrong_enc_trans, &proof));

                    wrong_enc_trans.encexp2[i] = ComEq {
                        commitment: tmp.commitment,
                        y:          tmp.y,
                        cmm_key:    CommitmentKey::generate(rng),
                        g:          tmp.g,
                    };
                    let mut ro_split = ro.split();
                    assert!(!verify(&mut ro_split, &wrong_enc_trans, &proof));

                    wrong_enc_trans.encexp2[i] = ComEq {
                        commitment: tmp.commitment,
                        y:          tmp.y,
                        cmm_key:    tmp.cmm_key,
                        g:          G1::generate(rng),
                    };
                    let mut ro_split = ro.split();
                    assert!(!verify(&mut ro_split, &wrong_enc_trans, &proof));

                    wrong_enc_trans.encexp2[i] = tmp;
                }
            })
        }
    }
}
