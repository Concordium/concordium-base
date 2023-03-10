//! This module implements the com-lin sigma protocol, which allows
//! the prover to prove knowledge of pairs (s_i, r_i) and (s, r) such that
//! \sum_{i} u_i * s_i = u * s for some public constants u_i and u.
//! The r's are randomness in commitments to s_i's and s'.

use crate::sigma_protocols::common::*;
use crypto_common::*;
use crypto_common_derive::*;
use curve_arithmetic::{multiexp, Curve};
use ff::Field;
use pedersen_scheme::{Commitment, CommitmentKey, Randomness, Value};
use random_oracle::{Challenge, RandomOracle};

pub struct ComLinSecret<C: Curve> {
    /// The secret values, s's above.
    xs: Vec<Value<C>>,
    /// The randomness used in commitments to s_i's.
    rs: Vec<Randomness<C>>,
    /// The randomness used in commitment to the linear combination
    /// of s_i's.
    r:  Randomness<C>,
}

pub struct ComLin<C: Curve> {
    /// The coefficients u_i.
    pub us:      Vec<C::Scalar>,
    /// The commitments to s_i's.
    pub cmms:    Vec<Commitment<C>>,
    /// The commitment to the linear combination.
    pub cmm:     Commitment<C>,
    /// The commitment key used to generate all the commitments.
    pub cmm_key: CommitmentKey<C>,
}

// TODO: What if u = 0?

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct Witness<C: Curve> {
    /// Randomized s_i's
    #[size_length = 4]
    /// Randomized r_i's.
    zs: Vec<C::Scalar>,
    #[size_length = 4]
    ss: Vec<C::Scalar>,
    /// Randomized commitment randomness r.
    s:  C::Scalar,
}

impl<C: Curve> SigmaProtocol for ComLin<C> {
    type CommitMessage = (Vec<Commitment<C>>, Commitment<C>);
    type ProtocolChallenge = C::Scalar;
    type ProverState = (Vec<Value<C>>, Vec<Randomness<C>>, Randomness<C>);
    type ProverWitness = Witness<C>;
    type SecretData = ComLinSecret<C>;

    fn public(&self, ro: &mut RandomOracle) {
        ro.extend_from(b"us", self.us.iter());
        ro.extend_from(b"cmms", self.cmms.iter());
        ro.append_message(b"cmm", &self.cmm);
        ro.append_message(b"cmm_key", &self.cmm_key)
    }

    fn get_challenge(&self, challenge: &Challenge) -> Self::ProtocolChallenge {
        C::scalar_from_bytes(challenge)
    }

    fn commit_point<R: rand::Rng>(
        &self,
        csprng: &mut R,
    ) -> Option<(Self::CommitMessage, Self::ProverState)> {
        let n = self.cmms.len();
        // We have to have the same number of linear coefficients as the number of
        // commitments.
        if self.us.len() != n {
            return None;
        }
        let mut ais = Vec::with_capacity(n);
        let mut alphas: Vec<Value<C>> = Vec::with_capacity(n);
        let mut r_i_tildes = Vec::with_capacity(n);

        for _ in 0..n {
            let alpha = Value::generate_non_zero(csprng);
            let (a_i, r_i_tilde) = self.cmm_key.commit(&alpha, csprng);
            ais.push(a_i);
            alphas.push(alpha);
            r_i_tildes.push(r_i_tilde);
        }

        let mut sum_ui_alphai = C::Scalar::zero();
        for (ualpha, alpha) in izip!(&self.us, &alphas) {
            let mut ualpha = *ualpha;
            ualpha.mul_assign(alpha);
            sum_ui_alphai.add_assign(&ualpha);
        }
        let sum_ui_alphai: Value<C> = Value::new(sum_ui_alphai);
        let (a, r_tilde) = self.cmm_key.commit(&sum_ui_alphai, csprng);

        let cm = (ais, a);
        let ps = (alphas, r_i_tildes, r_tilde);

        Some((cm, ps))
    }

    fn generate_witness(
        &self,
        secret: Self::SecretData,
        state: Self::ProverState,
        challenge: &Self::ProtocolChallenge,
    ) -> Option<Self::ProverWitness> {
        let (alphas, r_i_tildes, r_tilde) = state;
        let n = alphas.len();
        if self.cmms.len() != n
            || self.us.len() != n
            || secret.xs.len() != n
            || secret.rs.len() != n
        {
            return None;
        }
        let mut zs = Vec::with_capacity(n);
        let mut ss = Vec::with_capacity(n);
        let c = *challenge;
        for (s, alpha, r, r_i_tilda) in izip!(&secret.xs, &alphas, &secret.rs, &r_i_tildes) {
            let mut zi = c;
            zi.mul_assign(s);
            zi.negate();
            zi.add_assign(alpha);
            zs.push(zi);

            let mut si = c;
            si.mul_assign(r);
            si.negate();
            si.add_assign(r_i_tilda);
            ss.push(si);
        }
        let mut s = c;
        s.mul_assign(&secret.r);
        s.negate();
        s.add_assign(&r_tilde);
        let witness = Witness { zs, ss, s };
        Some(witness)
    }

    #[allow(non_snake_case)]
    #[allow(clippy::many_single_char_names)]
    fn extract_point(
        &self,
        challenge: &Self::ProtocolChallenge,
        witness: &Self::ProverWitness,
    ) -> Option<Self::CommitMessage> {
        let zs = &witness.zs;
        let ss = &witness.ss;
        let c = *challenge;
        let n = zs.len();
        if ss.len() != n || self.us.len() != n || self.cmms.len() != n {
            return None;
        }

        let mut ais = Vec::with_capacity(n);
        let mut sum = C::Scalar::zero();
        let g = self.cmm_key.g;
        let h = self.cmm_key.h;
        for (Ci, z_i, s_i, u_i) in izip!(&self.cmms, zs, ss, &self.us) {
            let ai = Commitment(multiexp(&[g, h, Ci.0], &[*z_i, *s_i, c]));
            ais.push(ai);
            let mut uizi = *u_i;
            uizi.mul_assign(z_i);
            sum.add_assign(&uizi);
        }
        // TODO: The g, h are the same in this, and the loop above.
        // We could partially precompute the table to speed-up the multiexp
        let a = Commitment(multiexp(&[g, h, self.cmm.0], &[sum, witness.s, c]));
        let cm = (ais, a);
        Some(cm)
    }

    #[cfg(test)]
    fn with_valid_data<R: rand::Rng>(
        _data_size: usize,
        csprng: &mut R,
        f: impl FnOnce(Self, Self::SecretData, &mut R),
    ) {
        let n = _data_size;
        let cmm_key = CommitmentKey::generate(csprng);
        let mut xs = Vec::with_capacity(n);
        let mut rs = Vec::with_capacity(n);
        let mut us = Vec::with_capacity(n);
        let mut cmms = Vec::with_capacity(n);
        let r = Randomness::<C>::generate(csprng);
        let mut sum = C::Scalar::zero();
        for _ in 0..n {
            let xi = Value::<C>::generate(csprng);
            let ri = Randomness::<C>::generate(csprng);
            let ui = C::generate_scalar(csprng);
            let mut uixi = ui;
            uixi.mul_assign(&xi);
            sum.add_assign(&uixi);
            cmms.push(cmm_key.hide(&xi, &ri));
            xs.push(xi);
            rs.push(ri);
            us.push(ui);
        }
        let cmm = cmm_key.hide_worker(&sum, &r);
        let com_lin = ComLin {
            us,
            cmms,
            cmm,
            cmm_key,
        };
        let secret = ComLinSecret { xs, rs, r };

        f(com_lin, secret, csprng)
    }
}

#[allow(non_snake_case)]
#[cfg(test)]
mod tests {
    use super::*;
    use ff::PrimeField;
    use pairing::bls12_381::{Fr, G1};
    // use pairing::bls12_381::G1;
    use rand::thread_rng;
    // use std::convert::TryInto;

    #[test]
    pub fn test_com_lin_correctness() {
        let mut csprng = thread_rng();
        for _ in 0..10 {
            ComLin::<G1>::with_valid_data(10, &mut csprng, |com_lin, secret, csprng| {
                let challenge_prefix = generate_challenge_prefix(csprng);
                let mut ro = RandomOracle::domain(&challenge_prefix);
                let proof = prove(&mut ro.split(), &com_lin, secret, csprng)
                    .expect("Proving should succeed.");
                assert!(
                    verify(&mut ro, &com_lin, &proof),
                    "Produced proof did not verify."
                );
            })
        }
    }

    #[test]
    pub fn test_com_lin_soundness() {
        let mut csprng = thread_rng();
        for _ in 0..2 {
            let n = 6;
            ComLin::<G1>::with_valid_data(n, &mut csprng, |com_lin, secret, csprng| {
                let challenge_prefix = generate_challenge_prefix(csprng);
                let mut ro = RandomOracle::domain(&challenge_prefix);
                let proof = prove(&mut ro.split(), &com_lin, secret, csprng)
                    .expect("Proving should succeed.");
                assert!(verify(&mut ro.split(), &com_lin, &proof));

                // Construct invalid parameters
                let mut wrong_ro = RandomOracle::domain(generate_challenge_prefix(csprng));

                // Verify failure for invalid parameters
                if verify(&mut wrong_ro, &com_lin, &proof) {
                    assert_eq!(wrong_ro, ro);
                }
                let mut wrong_cmm = com_lin;
                for i in 0..n {
                    let tmp = wrong_cmm.cmms[i];
                    let v = pedersen_scheme::Value::<G1>::generate(csprng);
                    wrong_cmm.cmms[i] = wrong_cmm.cmm_key.commit(&v, csprng).0;
                    assert!(!verify(&mut ro.split(), &wrong_cmm, &proof));
                    wrong_cmm.cmms[i] = tmp;
                }

                {
                    let tmp = wrong_cmm.cmm;
                    let v = pedersen_scheme::Value::<G1>::generate(csprng);
                    wrong_cmm.cmm = wrong_cmm.cmm_key.commit(&v, csprng).0;
                    assert!(!verify(&mut ro.split(), &wrong_cmm, &proof));
                    wrong_cmm.cmm = tmp;
                }

                wrong_cmm.cmm_key = pedersen_scheme::CommitmentKey::generate(csprng);

                assert!(!verify(&mut ro, &wrong_cmm, &proof))
            })
        }
    }

    #[test]
    pub fn test_linear_relation_of_chunks() {
        let rng = &mut thread_rng();
        let g = G1::generate(rng);
        let h = G1::generate(rng);
        let cmm_key = CommitmentKey { g, h };

        trait ToChunks {
            type Integer: Sized + Clone;
            fn to_chunks(bytes: [u8; 8]) -> Vec<Self::Integer>;
        }

        impl ToChunks for u64 {
            type Integer = u64;

            fn to_chunks(bytes: [u8; 8]) -> Vec<Self::Integer> { vec![u64::from_le_bytes(bytes)] }
        }

        impl ToChunks for u32 {
            type Integer = u32;

            fn to_chunks(bytes: [u8; 8]) -> Vec<Self::Integer> {
                let byte_chunk_1 = [bytes[0], bytes[1], bytes[2], bytes[3]];
                let byte_chunk_2 = [bytes[4], bytes[5], bytes[6], bytes[7]];

                vec![
                    u32::from_le_bytes(byte_chunk_1),
                    u32::from_le_bytes(byte_chunk_2),
                ]
            }
        }

        impl ToChunks for u16 {
            type Integer = u16;

            fn to_chunks(bytes: [u8; 8]) -> Vec<Self::Integer> {
                let byte_chunk_1 = [bytes[0], bytes[1]];
                let byte_chunk_2 = [bytes[2], bytes[3]];
                let byte_chunk_3 = [bytes[4], bytes[5]];
                let byte_chunk_4 = [bytes[6], bytes[7]];

                vec![
                    u16::from_le_bytes(byte_chunk_1),
                    u16::from_le_bytes(byte_chunk_2),
                    u16::from_le_bytes(byte_chunk_3),
                    u16::from_le_bytes(byte_chunk_4),
                ]
            }
        }

        fn u64_to_chunks<T: ToChunks>(n: u64) -> Vec<T::Integer> {
            let bytes = n.to_le_bytes();
            T::to_chunks(bytes)
        }

        fn u64_chunks_to_chunks<T: ToChunks>(u64_chunks: &[u64]) -> Vec<T::Integer> {
            let mut vec = vec![];
            for &v in u64_chunks {
                let chunk = u64_to_chunks::<T>(v);
                vec.extend_from_slice(&chunk);
            }
            vec
        }

        // let j : u64 = 2*4294967296+65536 + 65535;
        // println!("{:?}", u64_to_chunks::<u64>(j));
        // println!("{:?}", u64_to_chunks::<u32>(j));
        // println!("{:?}", u64_to_chunks::<u16>(j));

        // println!("Integration test");

        let n = 32;
        let m: u8 = 8;
        let nm = 256;
        let huge_number = Fr::from_str("18446744073709551618").unwrap();
        let huge_number_repr = huge_number.into_repr();
        let huge_number_ref = huge_number_repr.as_ref();
        let sum = Value::<G1>::new(huge_number);
        let chunks = u64_chunks_to_chunks::<u32>(huge_number_ref);
        // println!("{:?}", chunks);
        let xs_scalars: Vec<Fr> = chunks
            .iter()
            .map(|&x| G1::scalar_from_u64(u64::from(x)))
            .collect();
        let xs_values: Vec<Value<G1>> = xs_scalars.iter().map(|&x| Value::<G1>::new(x)).collect();
        let two_32 = Fr::from_str("4294967296").unwrap();
        let u1 = Fr::from_str("1").unwrap();
        let mut us = Vec::with_capacity(usize::from(m));
        let mut ui = u1;
        let r = Randomness::<G1>::generate(rng);
        let mut rs = Vec::with_capacity(usize::from(m));
        let mut cmms = Vec::with_capacity(usize::from(m));
        let cmm = cmm_key.hide(&sum, &r);
        for x_value in xs_values.iter().take(m.into()) {
            us.push(ui);
            ui.mul_assign(&two_32);
            let ri = Randomness::<G1>::generate(rng);
            cmms.push(cmm_key.hide(x_value, &ri));
            rs.push(ri);
        }
        let rs_copy = rs.clone();
        let xs = xs_values;
        let cmms_copy = cmms.clone();
        let com_lin = ComLin {
            us,
            cmms,
            cmm,
            cmm_key,
        };
        let secret = ComLinSecret { xs, rs, r };
        let challenge_prefix = generate_challenge_prefix(rng);
        let mut ro = RandomOracle::domain(&challenge_prefix);
        let proof = prove(&mut ro.split(), &com_lin, secret, rng).expect("Proving should succeed.");
        assert!(verify(&mut ro, &com_lin, &proof));

        let mut ro = RandomOracle::empty();
        let mut G_H = Vec::with_capacity(nm);
        for _i in 0..(nm) {
            let g = G1::generate(rng);
            let h = G1::generate(rng);
            G_H.push((g, h));
        }
        let gens = bulletproofs::utils::Generators { G_H };
        let proof = bulletproofs::range_proof::prove_given_scalars(
            &mut ro.split(),
            rng,
            n,
            m,
            &xs_scalars,
            &gens,
            &cmm_key,
            &rs_copy,
        );
        assert!(bulletproofs::range_proof::verify_efficient(
            &mut ro,
            n,
            &cmms_copy,
            &proof.unwrap(),
            &gens,
            &cmm_key
        )
        .is_ok());
    }
}
