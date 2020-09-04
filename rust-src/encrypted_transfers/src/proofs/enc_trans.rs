#![allow(non_snake_case)]
use crate::types::CHUNK_SIZE;
use crypto_common::*;
use crypto_common_derive::*;
use curve_arithmetic::{multiexp, Curve};
use elgamal::ChunkSize;
use ff::Field;
use id::sigma_protocols::{com_eq::*, common::*, dlog::*};
use pedersen_scheme::{Commitment, Randomness, Value};
use random_oracle::{Challenge, RandomOracle};
use std::rc::Rc;

/// This module provides an implementation of the sigma protocol used for
/// encrypted transfers. It enables one to prove knowledge of a secret key `sk`,
/// exponent `s` and chunks a_1, ..., a_t, s_1', ..., s_(t')', r_1, ..., r_t,
/// r_1', ..., r_(t')' such that pk_sender = g^sk, S_2 = S_1^sk h^s , and
/// c_{i,1} = g^{r_i}, c_{i,2} = h^{a_i} pk_receiver^{r_i} for all i in {1,..,
/// t},
/// d_{i,1} = g^{r_i'}, d_{i,2} = h^{s_i'} pk_sender^{r_i'} for all i in {1,..,
/// t'}, and s = \sum_{j=1}^t 2^{(chunk_size)*(j-1)} (a_j)
///             +\sum_{j=1}^(t') 2^{(chunk_size)*(j-1)} s_j',
///
/// This is done using the subprotocols Dlog, Elgdec and EncExp (EncExp is
/// basically just several ComEq's (can be found in
/// sigma_protocols in the id crate)) as described in Id Layer Bluepaper, see
/// genEncTransProofInfo and genEncTrans. The resulting sigma protocol is
/// contructed using the sigma protocols for equality and linear relations
/// described in the Cryptoprim Bluepaper. The trait Sigmaprotocol is
/// implemented directly for the EncTrans struct below, and it is not used that
/// the Sigmaprotocol trait is already implemented for both Dlog and ComEq.

pub struct ElgDec<C: Curve> {
    /// S_2 above
    pub public: C,
    /// The points S_1 and h.
    pub coeff: [C; 2],
}

impl<C: Curve> ElgDec<C> {
    fn public(&self, ro: RandomOracle) -> RandomOracle {
        ro.append(&self.public).extend_from(&self.coeff)
    }
}

pub struct EncTrans<C: Curve> {
    pub dlog: Dlog<C>,
    /// elg_dec contains the publicly known values S_1, S_2 and h
    pub elg_dec: ElgDec<C>,
    /// encexp1 contains the publicly known values c_{i,j}'s, g, h, pk_receiver
    pub encexp1: Vec<ComEq<C, C>>,
    /// encexp2 contains the publicly known values d_{i,j}'s, g, h, pk_sender
    pub encexp2: Vec<ComEq<C, C>>,
}

/// The elc_dec protocol actually has two witnesses, one involving sk and one
/// involving s, but since sk is also the secret for the dlog, and since
/// s is a linear combination of the secrets for the EncExp/ComEq's,
/// we calculate the same linear combination, but of the witnesses, in
/// the extract_point function. We do therefore not need to transfer/send
/// those witnesses, since they are determined by the ones below.
#[derive(Debug, Serialize)]
pub struct Witness<C: Curve> {
    /// The common witness for both dlog and elc-dec
    witness_common: C::Scalar,
    /// For EncExp/ComEq's involving a_i
    #[size_length = 4]
    witness_encexp1: Vec<(C::Scalar, C::Scalar)>,
    /// For EncExp/ComEq's involving s_i'
    #[size_length = 4]
    witness_encexp2: Vec<(C::Scalar, C::Scalar)>,
}

pub struct EncTransSecret<C: Curve> {
    /// dlog_secret contains the secret key `sk`
    pub dlog_secret: Rc<C::Scalar>,
    /// The chunks a_i:
    pub r_a: Vec<Randomness<C>>,
    /// The r_i:
    pub a: Vec<Value<C>>,
    /// The chunks s_i':
    pub r_s: Vec<Randomness<C>>,
    /// The r_i':
    pub s: Vec<Value<C>>,
}

#[derive(Debug, Serialize)]
pub struct EncTransCommit<C: Curve> {
    /// Commitmessage for dlog
    dlog: C,
    /// Commitmessage for elg_dec
    elg_dec: C,
    /// Commitmessages for EncExp/ComEq's involving a_i
    #[size_length = 4]
    encexp1: Vec<CommittedPoints<C, C>>,
    /// Commitmessages for EncExp/ComEq's involving s_i'
    #[size_length = 4]
    encexp2: Vec<CommittedPoints<C, C>>,
}

/// As for the witness, we don't need the state for elc_dec
#[derive(Debug, Serialize)]
pub struct EncTransState<C: Curve> {
    /// Randomness used for dlog
    dlog: C::Scalar,
    /// Randomness used for EncExp/ComEq's involving a_i
    #[size_length = 4]
    encexp1: Vec<(Value<C>, Randomness<C>)>,
    /// Randomness used for EncExp/ComEq's involving s_i'
    #[size_length = 4]
    encexp2: Vec<(Value<C>, Randomness<C>)>,
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
    type ProverWitness = Witness<C>;
    type SecretData = EncTransSecret<C>;

    fn public(&self, ro: RandomOracle) -> RandomOracle {
        let ro = self.elg_dec.public(ro);
        let ro1 = self
            .encexp1
            .iter()
            .fold(ro, |running_ro, p| p.public(running_ro));
        let ro2 = self
            .encexp2
            .iter()
            .fold(ro1, |running_ro, p| p.public(running_ro));
        self.dlog.public(ro2)
    }

    fn get_challenge(&self, challenge: &Challenge) -> Self::ProtocolChallenge {
        C::scalar_from_bytes(challenge)
    }

    fn commit_point<R: rand::Rng>(
        &self,
        csprng: &mut R,
    ) -> Option<(Self::CommitMessage, Self::ProverState)> {
        // For enc_exps:
        let mut commit_encexp_1 = vec![];
        let mut rands_encexp_1 = vec![];
        let mut commit_encexp_2 = vec![];
        let mut rands_encexp_2 = vec![];
        let mut Rs_a = vec![];
        let mut Rs_s_prime = vec![];
        for comeq in &self.encexp1 {
            let mut u = C::zero_point();

            let alpha = Value::<C>::generate_non_zero(csprng);
            let (v, R_i) = comeq.cmm_key.commit(&alpha, csprng);
            u = u.plus_point(&comeq.g.mul_by_scalar(&alpha));
            commit_encexp_1.push(CommittedPoints { u, v });
            rands_encexp_1.push((alpha, R_i.clone()));
            Rs_a.push(*R_i);
        }
        for comeq in &self.encexp2 {
            let mut u = C::zero_point();

            let alpha = Value::<C>::generate_non_zero(csprng);
            let (v, R_i) = comeq.cmm_key.commit(&alpha, csprng);
            u = u.plus_point(&comeq.g.mul_by_scalar(&alpha));
            commit_encexp_2.push(CommittedPoints { u, v });
            rands_encexp_2.push((alpha, R_i.clone()));
            Rs_s_prime.push(*R_i);
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
        let mut witness_encexp1 = vec![];
        let mut witness_encexp2 = vec![];
        for i in 0..secret.r_a.len() {
            // The R is the randomness
            // that is used together with the secret a_j's
            let (ref alpha, ref R) = state.encexp1[i];
            // compute alpha_i - a_i * c
            let mut s = *challenge;
            s.mul_assign(&secret.a[i]);
            s.negate();
            s.add_assign(alpha);
            // compute R_i - r_i * c
            let mut t: C::Scalar = *challenge;
            t.mul_assign(&secret.r_a[i]); // secret a_j's used here
            t.negate();
            t.add_assign(R); // R used here
            witness_encexp1.push((s, t));
            // It means that the randomness used for s should be the
            // corresponding linear combination of the R's
        }
        for i in 0..secret.r_s.len() {
            let (ref alpha, ref R) = state.encexp2[i];
            // compute alpha_i - a_i * c
            let mut s = *challenge;
            s.mul_assign(&secret.s[i]);
            s.negate();
            s.add_assign(alpha);
            // compute R_i - r_i * c
            let mut t: C::Scalar = *challenge;
            t.mul_assign(&secret.r_s[i]); // secret s'_j's used here
            t.negate();
            t.add_assign(R);
            witness_encexp2.push((s, t));
        }

        Some(Witness {
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
        // For enc_exps:
        let mut commit_encexp1 = vec![];
        let mut commit_encexp2 = vec![];
        let mut w_a_vec = vec![];
        let mut w_s_prime_vec = vec![];
        for (comeq, witness) in izip!(&self.encexp1, &witness.witness_encexp1) {
            let u = multiexp(&[comeq.y, comeq.g], &[*challenge, witness.0]);

            let v = comeq
                .commitment
                .mul_by_scalar(challenge)
                .plus_point(&comeq.cmm_key.hide_worker(&witness.0, &witness.1));
            commit_encexp1.push(CommittedPoints {
                u,
                v: Commitment(v),
            });
            w_a_vec.push(witness.1);
        }
        for (comeq, witness) in izip!(&self.encexp2, &witness.witness_encexp2) {
            let u = multiexp(&[comeq.y, comeq.g], &[*challenge, witness.0]);

            let v = comeq
                .commitment
                .mul_by_scalar(challenge)
                .plus_point(&comeq.cmm_key.hide_worker(&witness.0, &witness.1));
            commit_encexp2.push(CommittedPoints {
                u,
                v: Commitment(v),
            });
            w_s_prime_vec.push(witness.1);
        }

        // For dlog and elcdec:
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
        let mut exps = vec![witness.witness_common];
        exps.push(w_lin);
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
