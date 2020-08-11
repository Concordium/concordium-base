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
use std::rc::Rc;

pub struct DlogAndAggregateDlogsEqual<C: Curve> {
    pub dlog:            Dlog<C>,
    pub aggregate_dlogs: Vec<AggregateDlog<C>>,
}

#[derive(Debug, Serialize)]
pub struct Witness<C: Curve> {
    #[size_length = 4]
    witnesses: Vec<Vec<C::Scalar>>,
    witness_common: C::Scalar, // For equality
}

impl<C: Curve> SigmaProtocol for DlogAndAggregateDlogsEqual<C> {
    type CommitMessage = (C, Vec<C>);
    type ProtocolChallenge = C::Scalar;
    type ProverState = (C::Scalar, Vec<Vec<C::Scalar>>);
    type ProverWitness = Witness<C>;
    type SecretData = (Rc<C::Scalar>, Vec<Vec<Rc<C::Scalar>>>);

    fn public(&self, ro: RandomOracle) -> RandomOracle {
        let ro1 = self
            .aggregate_dlogs
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

        let commit = (commit_dlog, point_vec);
        let rand = (rand_scalar_common, rands_vec);
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
        witness_common.mul_assign(&secret.0);
        witness_common.negate(); // According to Bluepaper, we negate here. Shouldn't matter.
        witness_common.add_assign(&state.0);
        let mut witnesses = vec![];
        for (secret_vec, state_vec) in izip!(secret.1, state.1) {
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
        Some(Witness {
            witnesses,
            witness_common,
        })
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
        let dlog_point = self
            .dlog
            .coeff
            .mul_by_scalar(&witness.witness_common)
            .plus_point(&self.dlog.public.mul_by_scalar(challenge));
        let mut agg_points = vec![];
        for (aggregate_dlog, w) in izip!(&self.aggregate_dlogs, &witness.witnesses) {
            if w.len() + 1 != aggregate_dlog.coeff.len() {
                return None;
            }
            let mut point = aggregate_dlog.public.mul_by_scalar(challenge);
            let mut exps = vec![witness.witness_common];
            exps.extend_from_slice(&w);
            let product = multiexp(&aggregate_dlog.coeff, &exps);
            point = point.plus_point(&product);
            agg_points.push(point);
            // for (ref w, ref g) in izip!(witness.witness.iter(),
            // self.coeff.iter()) {     point =
            // point.plus_point(&g.mul_by_scalar(w)); }
        }
        let res = Some((dlog_point, agg_points));
        res
    }
}
