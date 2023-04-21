//! The module provides the implementation of the `vcom_eq` sigma
//! protocol. This protocol enables one to prove knowledge of
//! $x_1, ..., x_n, r, (r_i)_{i\in I}$ such that $ C = h^r \prod_{i=1}^n
//! g_i^{x_i}$ and $C_i = \bar{g}^{x_i} \bar{h}^{r_i}$ for $i\in I$.
use super::common::*;
use crate::{
    common::*,
    curve_arithmetic::{multiexp, Curve},
    random_oracle::{Challenge, RandomOracle},
};
use ff::Field;
use itertools::izip;
use std::{collections::BTreeMap, rc::Rc};

type IndexType = u8;

/// The public information known to both the prover and the verfier.
pub struct VecComEq<C: Curve> {
    /// The commitment C
    pub comm:  C,
    /// The commitments C_i for i in I
    pub comms: BTreeMap<IndexType, C>,
    /// The points g_i references in the module description, in the given order.
    pub gis:   Vec<C>,
    /// The generator h
    pub h:     C,
    /// The generator \bar{g}
    pub g_bar: C,
    /// The generator \bar{h}
    pub h_bar: C,
}

/// VComEq witness. We deliberately make it opaque.
#[derive(Debug, Serialize)]
pub struct Witness<C: Curve> {
    #[size_length = 4]
    sis: Vec<C::Scalar>,
    t:   C::Scalar,
    tis: BTreeMap<IndexType, C::Scalar>,
}

/// Convenient alias
pub type Proof<C> = SigmaProof<Witness<C>>;

impl<C: Curve> SigmaProtocol for VecComEq<C> {
    type CommitMessage = (C, Vec<C>);
    type ProtocolChallenge = C::Scalar;
    type ProverState = (Vec<C::Scalar>, C::Scalar, BTreeMap<IndexType, C::Scalar>);
    type ProverWitness = Witness<C>;
    type SecretData = (
        Vec<Rc<C::Scalar>>,
        Rc<C::Scalar>,
        BTreeMap<IndexType, Rc<C::Scalar>>,
    );

    fn public(&self, ro: &mut RandomOracle) {
        ro.append_message(b"C", &self.comm);
        ro.append_message(b"Cis", &self.comms);
        ro.extend_from(b"gis", &self.gis);
        ro.append_message(b"h", &self.h);
        ro.append_message("h_bar", &self.h_bar);
        ro.append_message("g_bar", &self.g_bar)
    }

    fn get_challenge(&self, challenge: &Challenge) -> Self::ProtocolChallenge {
        C::scalar_from_bytes(challenge)
    }

    fn commit_point<R: rand::Rng>(
        &self,
        csprng: &mut R,
    ) -> Option<(Self::CommitMessage, Self::ProverState)> {
        let n = self.gis.len();
        let rtilde = C::generate_non_zero_scalar(csprng);
        let mut alphas = Vec::with_capacity(n);
        let mut rtildes = BTreeMap::new();
        let mut ais = Vec::with_capacity(self.comms.len());
        // let mut i = 0;
        for i_usize in 0..n {
            let i = i_usize.try_into().ok()?;
            let alpha_i = C::generate_non_zero_scalar(csprng);
            alphas.push(alpha_i);
            if self.comms.contains_key(&i) {
                let rtilde_i = C::generate_non_zero_scalar(csprng);
                rtildes.insert(i, rtilde_i);
                let ai = multiexp(&[self.g_bar, self.h_bar], &[alpha_i, rtilde_i]);
                ais.push(ai);
            }
            // i += 1;
        }
        // for the factor h^{r_tilde}
        alphas.push(rtilde);
        let mut gis = self.gis.clone();
        gis.push(self.h);
        let a = multiexp(&gis, &alphas); // h^rtilde \prod g_i^(alpha_i)
        alphas.pop(); // remove rtilde from alphas again.
        Some(((a, ais), (alphas, rtilde, rtildes)))
    }

    fn generate_witness(
        &self,
        secret: Self::SecretData,
        state: Self::ProverState,
        challenge: &Self::ProtocolChallenge,
    ) -> Option<Self::ProverWitness> {
        let (alphas, rtilde, rtildes) = state;
        let (xis, r, ris) = secret;
        let n = xis.len();
        if alphas.len() != n || rtildes.len() != ris.len() || ris.len() != self.comms.len() {
            return None;
        }
        let mut sis = Vec::with_capacity(n);
        let mut tis = BTreeMap::new();
        for (i_usize, (ref alpha_i, ref xi)) in izip!(alphas, xis).enumerate() {
            let mut si = *challenge;
            si.mul_assign(xi);
            si.negate();
            si.add_assign(alpha_i);
            sis.push(si);
            let i = i_usize.try_into().ok()?;
            if let (Some(rtilde_i), Some(ri)) = (rtildes.get(&i), ris.get(&i)) {
                let mut ti = *challenge;
                ti.mul_assign(ri);
                ti.negate();
                ti.add_assign(rtilde_i);
                tis.insert(i, ti);
            }
        }
        let mut t = *challenge;
        t.mul_assign(&r);
        t.negate();
        t.add_assign(&rtilde);
        Some(Witness { sis, t, tis })
    }

    fn extract_point(
        &self,
        challenge: &Self::ProtocolChallenge,
        witness: &Self::ProverWitness,
    ) -> Option<Self::CommitMessage> {
        let Witness { sis, t, tis } = witness;
        let maybe_fit: Result<IndexType, _> = (sis.len() - 1).try_into();
        if sis.len() != self.gis.len()
            || tis.len() != self.comms.len()
            || tis.len() > sis.len()
            || maybe_fit.is_err()
        {
            return None;
        }
        let mut points = Vec::with_capacity(self.comms.len());

        let mut scalars = sis.clone();
        scalars.push(*t);
        scalars.push(*challenge);
        let mut bases = self.gis.clone();
        bases.push(self.h);
        bases.push(self.comm);

        let point = multiexp(&bases, &scalars); //  h^t C^challenge \prod g_i^(s_i)

        for (i_usize, si) in sis.iter().enumerate() {
            let i = i_usize.try_into().ok()?;
            if let (Some(comm_i), Some(ti)) = (self.comms.get(&i), tis.get(&i)) {
                let ai_scalars = vec![*si, *ti, *challenge];
                let ai_bases = vec![self.g_bar, self.h_bar, *comm_i];
                let ai = multiexp(&ai_bases, &ai_scalars); // g_bar^{s_i}h_bar^{s_i} C_i^challenge
                points.push(ai);
            }
        }
        Some((point, points))
    }

    #[cfg(test)]
    fn with_valid_data<R: rand::Rng>(
        data_size: usize,
        csprng: &mut R,
        f: impl FnOnce(Self, Self::SecretData, &mut R),
    ) {
        let mut xis = Vec::with_capacity(data_size);
        let mut ris = BTreeMap::new();
        let mut gis = Vec::with_capacity(data_size);
        let mut comms = BTreeMap::new();
        let h = C::generate(csprng);
        let g_bar = C::generate(csprng);
        let h_bar = C::generate(csprng);
        let r = Rc::new(C::generate_scalar(csprng));
        let mut comm = h.mul_by_scalar(&r);
        let mut i = 0;
        for _ in 0..data_size {
            let xi = C::generate_scalar(csprng);
            let ri = C::generate_scalar(csprng);
            let gi = C::generate(csprng);
            comm = comm.plus_point(&gi.mul_by_scalar(&xi));
            xis.push(Rc::new(xi));
            ris.insert(i, Rc::new(ri));
            gis.push(gi);
            let comm_i = g_bar
                .mul_by_scalar(&xi)
                .plus_point(&h_bar.mul_by_scalar(&ri));
            comms.insert(i, comm_i);
            i += 1;
        }
        let agg = VecComEq {
            comm,
            comms,
            h,
            g_bar,
            h_bar,
            gis,
        };
        let secret = (xis, r, ris);
        f(agg, secret, csprng)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::G1;
    use rand::{thread_rng, Rng};

    #[test]
    pub fn test_vcom_eq_correctness() {
        let mut csprng = thread_rng();
        for i in 1..20 {
            VecComEq::with_valid_data(i, &mut csprng, |agg: VecComEq<G1>, secret, csprng| {
                let challenge_prefix = generate_challenge_prefix(csprng);
                let mut ro = RandomOracle::domain(challenge_prefix);
                let proof =
                    prove(&mut ro.split(), &agg, secret, csprng).expect("Input data is valid.");
                assert!(verify(&mut ro, &agg, &proof));
            })
        }
    }

    #[test]
    pub fn test_vcom_correctness_with_setup() {
        let csprng = &mut thread_rng();
        let data_size = 256;
        let mut xis = Vec::with_capacity(data_size);
        let mut ris = BTreeMap::new();
        let mut gis = Vec::with_capacity(data_size);
        let mut comms = BTreeMap::new();
        let h = G1::generate(csprng);
        let g_bar = G1::generate(csprng);
        let h_bar = G1::generate(csprng);
        let r = Rc::new(G1::generate_scalar(csprng));
        let mut comm = h.mul_by_scalar(&r);
        let mut i = 0;
        for _ in 0..data_size {
            let xi = G1::generate_scalar(csprng);
            let gi = G1::generate(csprng);
            comm = comm.plus_point(&gi.mul_by_scalar(&xi));
            xis.push(Rc::new(xi));
            gis.push(gi);
            if i >= 5 && i <= 10 {
                let ri = G1::generate_scalar(csprng);
                ris.insert(i, Rc::new(ri));
                let comm_i = g_bar
                    .mul_by_scalar(&xi)
                    .plus_point(&h_bar.mul_by_scalar(&ri));
                comms.insert(i, comm_i);
            }
            i += 1;
        }
        let agg = VecComEq {
            comm,
            comms,
            h,
            g_bar,
            h_bar,
            gis,
        };
        let secret = (xis, r, ris);
        let challenge_prefix = generate_challenge_prefix(csprng);
        let mut ro = RandomOracle::domain(challenge_prefix);
        let proof = prove(&mut ro.split(), &agg, secret, csprng).expect("Input data is valid.");
        assert!(verify(&mut ro, &agg, &proof));
    }

    #[test]
    pub fn test_vcom_soundness_with_setup() {
        let csprng = &mut thread_rng();
        let data_size = 10;
        let mut xis = Vec::with_capacity(data_size);
        let mut ris = BTreeMap::new();
        let mut gis = Vec::with_capacity(data_size);
        let mut comms = BTreeMap::new();
        let h = G1::generate(csprng);
        let g_bar = G1::generate(csprng);
        let h_bar = G1::generate(csprng);
        let r = Rc::new(G1::generate_scalar(csprng));
        let mut comm = h.mul_by_scalar(&r);
        let mut i = 0;
        for _ in 0..data_size {
            let xi = G1::generate_scalar(csprng);
            let gi = G1::generate(csprng);
            comm = comm.plus_point(&gi.mul_by_scalar(&xi));
            xis.push(Rc::new(xi));
            gis.push(gi);
            if i <= 5 {
                let ri = G1::generate_scalar(csprng);
                ris.insert(i, Rc::new(ri));
                let comm_i = g_bar
                    .mul_by_scalar(&xi)
                    .plus_point(&h_bar.mul_by_scalar(&ri));
                comms.insert(i, comm_i);
            }
            i += 1;
        }
        let wrong_comm = G1::generate(csprng);
        let index_wrong_comm: IndexType = csprng.gen_range(0, 6);
        let index_wrong_gi: usize = csprng.gen_range(0, 10);
        let mut wrong_comms = comms.clone();
        wrong_comms.insert(index_wrong_comm, wrong_comm);
        let mut wrong_gis = gis.clone();
        wrong_gis[index_wrong_gi] = wrong_comm;

        let vcom_wrong_comm = VecComEq {
            comm: wrong_comm,
            comms: comms.clone(),
            h,
            g_bar,
            h_bar,
            gis: gis.clone(),
        };
        let vcom_wrong_comms = VecComEq {
            comms: wrong_comms,
            comm,
            h,
            g_bar,
            h_bar,
            gis: gis.clone(),
        };
        let vcom_wrong_gis = VecComEq {
            comms: comms.clone(),
            comm,
            h,
            g_bar,
            h_bar,
            gis: wrong_gis,
        };
        let vcom = VecComEq {
            comm,
            comms,
            h,
            g_bar,
            h_bar,
            gis,
        };
        let secret = (xis, r, ris);
        let challenge_prefix = generate_challenge_prefix(csprng);
        let mut ro = RandomOracle::domain(challenge_prefix);
        let proof = prove(&mut ro.split(), &vcom, secret, csprng).expect("Input data is valid.");
        let mut wrong_ro = RandomOracle::domain(generate_challenge_prefix(csprng));
        assert!(!verify(&mut wrong_ro, &vcom, &proof));
        assert!(!verify(&mut ro, &vcom_wrong_comm, &proof));
        assert!(!verify(&mut ro, &vcom_wrong_comms, &proof));
        assert!(!verify(&mut ro, &vcom_wrong_gis, &proof));
    }

    #[test]
    pub fn test_vcom_simple_setup() {
        let csprng = &mut thread_rng();

        let g0 = G1::generate(csprng);
        let g1 = G1::generate(csprng);
        let g2 = G1::generate(csprng);
        let g3 = G1::generate(csprng);
        let gis = vec![g0, g1, g2, g3];

        let x0 = G1::generate_scalar(csprng);
        let x1 = G1::generate_scalar(csprng);
        let x2 = G1::generate_scalar(csprng);
        let x3 = G1::generate_scalar(csprng);
        let xis = vec![Rc::new(x0), Rc::new(x1), Rc::new(x2), Rc::new(x3)];

        let r1 = Rc::new(G1::generate_scalar(csprng));
        let r2 = Rc::new(G1::generate_scalar(csprng));
        let mut ris = BTreeMap::new();

        let mut comms = BTreeMap::new();
        let h = G1::generate(csprng);
        let g_bar = G1::generate(csprng);
        let h_bar = G1::generate(csprng);
        let r = Rc::new(G1::generate_scalar(csprng));
        let comm = multiexp(&[g0, g1, g2, g3, h], &[x0, x1, x2, x3, *r]);

        let comm1 = g_bar
            .mul_by_scalar(&x1)
            .plus_point(&h_bar.mul_by_scalar(&r1));
        let comm2 = g_bar
            .mul_by_scalar(&x2)
            .plus_point(&h_bar.mul_by_scalar(&r2));
        comms.insert(1, comm1);
        comms.insert(2, comm2);
        ris.insert(1, r1);
        ris.insert(2, r2);
        let agg = VecComEq {
            comm,
            comms,
            h,
            g_bar,
            h_bar,
            gis,
        };
        let secret = (xis, r, ris);
        let challenge_prefix = generate_challenge_prefix(csprng);
        let mut ro = RandomOracle::domain(challenge_prefix);
        let proof = prove(&mut ro.split(), &agg, secret, csprng).expect("Input data is valid.");
        assert!(verify(&mut ro, &agg, &proof));
    }
}
