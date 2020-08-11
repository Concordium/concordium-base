use crypto_common::*;
use crypto_common_derive::*;
use curve_arithmetic::{multiexp, Curve};
use ff::Field;
use id::sigma_protocols::{
    aggregate_dlog::*,
    com_eq::{Witness as ComEqWitness, *},
    common::*,
    dlog::{Witness as DlogWitness, *},
};
use random_oracle::{Challenge, RandomOracle};
use pedersen_scheme::{Commitment, CommitmentKey, Randomness, Value};
use std::rc::Rc;

pub struct EncTrans<C: Curve> {
    pub dlog:            Dlog<C>,
    pub aggregate_dlogs: Vec<AggregateDlog<C>>,
    pub encexp1: Vec<ComEq<C,C>>,
    pub encexp2: Vec<ComEq<C,C>>,
}

#[derive(Debug, Serialize)]
pub struct Witness<C: Curve> {
    #[size_length = 4]
    witnesses: Vec<Vec<C::Scalar>>,
    witness_common: C::Scalar, // For equality
    //For enc_exps:
    #[size_length = 4]
    witness_encexp1: Vec<(C::Scalar, C::Scalar)>,
    #[size_length = 4]
    witness_encexp2: Vec<(C::Scalar, C::Scalar)>
}

pub struct EncTransSecret<C: Curve> {
    pub dlog_secret: Rc<C::Scalar>,
    pub agg_dlog_secret: Vec<Vec<Rc<C::Scalar>>>,
    // For enc_exps:
    pub r_a: Vec<Randomness<C>>,
    pub a: Vec<Value<C>>,
    pub r_s: Vec<Randomness<C>>,
    pub s: Vec<Value<C>>,
}

#[derive(Debug, Serialize)]
pub struct EncTransCommit<C: Curve> {
    dlog: C, 
    #[size_length = 4]
    agg_dlogs: Vec<C>,
    #[size_length = 4]
    encexp1: Vec<CommittedPoints<C, C>>,
    #[size_length = 4]
    encexp2: Vec<CommittedPoints<C, C>>,
}


#[derive(Debug, Serialize)]
pub struct EncTransState<C: Curve> {
    dlog: C::Scalar, 
    #[size_length = 4]
    agg_dlogs: Vec<Vec<C::Scalar>>,
    #[size_length = 4]
    encexp1: Vec<(Value<C>, Randomness<C>)>,
    #[size_length = 4]
    encexp2: Vec<(Value<C>, Randomness<C>)>,
}

impl<C: Curve> SigmaProtocol for EncTrans<C> {
    type CommitMessage = EncTransCommit<C>;
    type ProtocolChallenge = C::Scalar;
    type ProverState = EncTransState<C>;
    type ProverWitness = Witness<C>;
    type SecretData = EncTransSecret<C>;

    fn public(&self, ro: RandomOracle) -> RandomOracle {
        let ro1 = self.aggregate_dlogs
            .iter()
            .fold(ro, |running_ro, p| p.public(running_ro));
        self.dlog.public(ro1)
    }

    fn get_challenge(&self, challenge: &Challenge) -> Self::ProtocolChallenge {
        C::scalar_from_bytes(challenge)
    }

    fn commit_point<R: rand::Rng>(
        &self,
        csprng: &mut R,
    ) -> Option<(Self::CommitMessage, Self::ProverState)> {
        let rand_scalar_common = C::generate_non_zero_scalar(csprng);
        let commit_dlog = self.dlog.coeff.mul_by_scalar(&rand_scalar_common);
        let mut rands_vec = Vec::with_capacity(self.aggregate_dlogs.len());
        let mut point_vec = Vec::with_capacity(self.aggregate_dlogs.len());
        for aggregate_dlog in &self.aggregate_dlogs {
            let n = aggregate_dlog.coeff.len();
    
            let mut rands = Vec::with_capacity(n);
            let mut point = C::zero_point();
            let mut first = true;
            for g in aggregate_dlog.coeff.iter() {
                let rand;
                if first {
                    rand = rand_scalar_common;
                } else {
                    rand = C::generate_non_zero_scalar(csprng);
                }
                // FIXME: Multiexponentiation would be useful in this case.
                point = point.plus_point(&g.mul_by_scalar(&rand));
                
                if !first {
                    rands.push(rand); // Maybe not do this one for the first
                } 
                first = false;
            }
            rands_vec.push(rands);
            point_vec.push(point);
        }
        // For enc_exps:
        let mut commit_encexp_1 = vec![];
        let mut rands_encexp_1 = vec![];
        let mut commit_encexp_2 = vec![];
        let mut rands_encexp_2 = vec![];
        for comeq in &self.encexp1 {
            let mut u = C::zero_point();

            let alpha = Value::<C>::generate_non_zero(csprng);
            let (v, R_i) = comeq.cmm_key.commit(&alpha, csprng);
            u = u.plus_point(&comeq.g.mul_by_scalar(&alpha));
            commit_encexp_1.push(CommittedPoints { u, v });
            rands_encexp_1.push((alpha, R_i));
        }
        for comeq in &self.encexp2 {
            let mut u = C::zero_point();

            let alpha = Value::<C>::generate_non_zero(csprng);
            let (v, R_i) = comeq.cmm_key.commit(&alpha, csprng);
            u = u.plus_point(&comeq.g.mul_by_scalar(&alpha));
            commit_encexp_2.push(CommittedPoints { u, v });
            rands_encexp_2.push((alpha, R_i));
        }

        // let commit = (commit_dlog, point_vec, commit_encexp_1, commit_encexp_2);
        let commit = EncTransCommit{
            dlog: commit_dlog,
            agg_dlogs: point_vec,
            encexp1: commit_encexp_1,
            encexp2: commit_encexp_2,
        };
        // let rand = (rand_scalar_common, rands_vec, rands_encexp_1, rands_encexp_2);
        let rand = EncTransState{
            dlog: rand_scalar_common,
            agg_dlogs: rands_vec,
            encexp1: rands_encexp_1,
            encexp2: rands_encexp_2,
        };
        Some((commit, rand))
        // None
    }

    fn generate_witness(
        &self,
        secret: Self::SecretData,
        state: Self::ProverState,
        challenge: &Self::ProtocolChallenge,
    ) -> Option<Self::ProverWitness> {
        let mut witness_common = *challenge;
        witness_common.mul_assign(&secret.dlog_secret);
        witness_common.negate(); // According to Bluepaper, we negate here. Shouldn't matter.
        witness_common.add_assign(&state.dlog);
        let mut witnesses = vec![];
        for (secret_vec, state_vec) in izip!(secret.agg_dlog_secret, state.agg_dlogs) {
            let mut witness = vec![];
            for (ref s, ref r) in izip!(secret_vec, state_vec) {
                let mut wit = *challenge;
                wit.mul_assign(s);
                wit.negate();
                wit.add_assign(r);
                witness.push(wit);
            }
            witnesses.push(witness);
        }
        // For encexps:
        let mut witness_encexp1 = vec![];
        let mut witness_encexp2 = vec![];
        for i in 0..secret.r_a.len(){
            let (ref alpha, ref R) = state.encexp1[i];
            // compute alpha_i - a_i * c
            let mut s = *challenge;
            s.mul_assign(&secret.a[i]);
            s.negate();
            s.add_assign(alpha);
            // compute R_i - r_i * c
            let mut t: C::Scalar = *challenge;
            t.mul_assign(&secret.r_a[i]);
            t.negate();
            t.add_assign(R);
            witness_encexp1.push((s, t));
        }
        for i in 0..secret.r_a.len(){
            let (ref alpha, ref R) = state.encexp2[i];
            // compute alpha_i - a_i * c
            let mut s = *challenge;
            s.mul_assign(&secret.s[i]);
            s.negate();
            s.add_assign(alpha);
            // compute R_i - r_i * c
            let mut t: C::Scalar = *challenge;
            t.mul_assign(&secret.r_s[i]);
            t.negate();
            t.add_assign(R);
            witness_encexp2.push((s, t));
        }

        Some(Witness{witnesses, witness_common, witness_encexp1, witness_encexp2})
        // None
    }

    fn extract_point(
        &self,
        challenge: &Self::ProtocolChallenge,
        witness: &Self::ProverWitness,
    ) -> Option<Self::CommitMessage> {
        // let p1 = self.dlog1.extract_point(&challenge, &witness)?;
        // let p2 = self.dlog2.extract_point(&challenge, &witness)?;
        // Some((p1, p2))
        let dlog_point = self.dlog
        .coeff
        .mul_by_scalar(&witness.witness_common)
        .plus_point(&self.dlog.public.mul_by_scalar(challenge));
        let mut agg_points = vec![];
        for (aggregate_dlog, w) in izip!(&self.aggregate_dlogs, &witness.witnesses) {
            if w.len()+1 != aggregate_dlog.coeff.len() {
                return None;
            }
            let mut point = aggregate_dlog.public.mul_by_scalar(challenge);
            let mut exps = vec![witness.witness_common];
            exps.extend_from_slice(&w);
            let product = multiexp(&aggregate_dlog.coeff, &exps);
            point = point.plus_point(&product);
            agg_points.push(point);
            // for (ref w, ref g) in izip!(witness.witness.iter(), self.coeff.iter()) {
            //     point = point.plus_point(&g.mul_by_scalar(w));
            // }
        }
        // For enc_exps:
        let mut commit_encexp1 = vec![];
        let mut commit_encexp2 = vec![];
        for (comeq, witness) in izip!(&self.encexp1, &witness.witness_encexp1) {
            let u = multiexp(&[comeq.y, comeq.g], &[*challenge, witness.0]);

            let v = comeq.commitment.mul_by_scalar(challenge).plus_point(
                &comeq
                    .cmm_key
                    .hide_worker(&witness.0, &witness.1),
            );
            commit_encexp1.push(CommittedPoints {
                u,
                v: Commitment(v),
            });
        }
        for (comeq, witness) in izip!(&self.encexp2, &witness.witness_encexp2) {
            let u = multiexp(&[comeq.y, comeq.g], &[*challenge, witness.0]);

            let v = comeq.commitment.mul_by_scalar(challenge).plus_point(
                &comeq
                    .cmm_key
                    .hide_worker(&witness.0, &witness.1),
            );
            commit_encexp2.push(CommittedPoints {
                u,
                v: Commitment(v),
            });
        }
        
        // let res = Some((dlog_point, agg_points));
        Some(EncTransCommit{
            dlog: dlog_point,
            agg_dlogs: agg_points,
            encexp1: commit_encexp1,
            encexp2: commit_encexp2,
        })
        // None
    }
}
