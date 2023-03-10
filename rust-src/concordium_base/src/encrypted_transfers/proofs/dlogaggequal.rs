//! This sigma protocol can be used to prove knowledge of x and x_{ij}'s such
//! that y = g^x and y_i = \prod_{j=1}^{n_i} g_{ij}^{x_ij} for all i
//! and x_{1,j} = x for all j. The public values are y, y_i's, g and g_{ij}'s

//! NB:
//! This module is currently not used, and is only here as a reference.
//! When using the code needs to be thouroughly reviewed.

use crypto_common::*;
use crypto_common_derive::*;
use curve_arithmetic::{multiexp, Curve};
use ff::Field;
use id::sigma_protocols::{aggregate_dlog::*, common::*, dlog::*};
use random_oracle::{Challenge, RandomOracle};
use std::rc::Rc;

pub struct DlogAndAggregateDlogsEqual<C: Curve> {
    pub dlog:            Dlog<C>,
    pub aggregate_dlogs: Vec<AggregateDlog<C>>,
}

#[derive(Debug, Serialize)]
pub struct Witness<C: Curve> {
    #[size_length = 4]
    witnesses:      Vec<Vec<C::Scalar>>,
    witness_common: C::Scalar, // For equality
}

#[allow(clippy::type_complexity)]
impl<C: Curve> SigmaProtocol for DlogAndAggregateDlogsEqual<C> {
    type CommitMessage = (C, Vec<C>);
    type ProtocolChallenge = C::Scalar;
    type ProverState = (C::Scalar, Vec<Vec<C::Scalar>>);
    type ProverWitness = Witness<C>;
    type SecretData = (Rc<C::Scalar>, Vec<Vec<Rc<C::Scalar>>>);

    fn public(&self, ro: &mut RandomOracle) {
        self.aggregate_dlogs.iter().for_each(|p| p.public(ro));
        self.dlog.public(ro)
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
                let rand = if first {
                    rand_scalar_common
                } else {
                    C::generate_non_zero_scalar(csprng)
                };
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
    }

    fn extract_point(
        &self,
        challenge: &Self::ProtocolChallenge,
        witness: &Self::ProverWitness,
    ) -> Option<Self::CommitMessage> {
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
            exps.extend_from_slice(w);
            let product = multiexp(&aggregate_dlog.coeff, &exps);
            point = point.plus_point(&product);
            agg_points.push(point);
        }
        Some((dlog_point, agg_points))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use curve_arithmetic::multiexp;
    use ff::PrimeField;
    use pairing::bls12_381::{Fr, G1};
    use rand::*;

    pub fn generate_challenge_prefix<R: rand::Rng>(csprng: &mut R) -> Vec<u8> {
        // length of the challenge
        let l = csprng.gen_range(0, 1000);
        let mut challenge_prefix = vec![0; l];
        for v in challenge_prefix.iter_mut() {
            *v = csprng.gen();
        }
        challenge_prefix
    }

    #[test]
    fn test_dlog_agg_eq() {
        let mut csprng = thread_rng();
        let x = Fr::from_str("3").unwrap();
        let x1 = Fr::from_str("5").unwrap();
        let x2 = Fr::from_str("7").unwrap();
        let y1 = Fr::from_str("70").unwrap();
        let y2 = Fr::from_str("75").unwrap();
        let g = G1::generate(&mut csprng);
        let g1 = G1::generate(&mut csprng);
        let h1 = G1::generate(&mut csprng);
        let f1 = G1::generate(&mut csprng);
        let g2 = G1::generate(&mut csprng);
        let h2 = G1::generate(&mut csprng);
        let f2 = G1::generate(&mut csprng);
        let gx = g.mul_by_scalar(&x);
        let dlog = Dlog {
            public: gx,
            coeff:  g,
        };
        let g1xh1x1f1y1 = multiexp(&[g1, h1, f1], &[x, x1, y1]);
        let g2xh2x2f2y2 = multiexp(&[g2, h2, f2], &[x, x2, y2]);
        let agg1 = AggregateDlog {
            public: g1xh1x1f1y1,
            coeff:  vec![g1, h1, f1],
        };
        let agg2 = AggregateDlog {
            public: g2xh2x2f2y2,
            coeff:  vec![g2, h2, f2],
        };
        let protocol = DlogAndAggregateDlogsEqual {
            dlog,
            aggregate_dlogs: vec![agg1, agg2],
        };
        let secret = (Rc::new(x), vec![vec![Rc::new(x1), Rc::new(y1)], vec![
            Rc::new(x2),
            Rc::new(y2),
        ]]);
        let challenge_prefix = generate_challenge_prefix(&mut csprng);
        let mut ro = RandomOracle::domain(&challenge_prefix);
        let proof = prove(&mut ro.split(), &protocol, secret, &mut csprng).unwrap();
        assert!(verify(&mut ro, &protocol, &proof));
    }
}
