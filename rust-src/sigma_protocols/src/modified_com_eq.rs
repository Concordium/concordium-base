use curve_arithmetic::curve_arithmetic::Curve;
use ff::Field;
use rand::*;
use sha2::{Digest, Sha256};

use failure::Error;
use std::io::Cursor;

use curve_arithmetic::serialization::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModifiedComEqProof<T: Curve> {
    challenge:        T::Scalar,
    randomised_point: (Vec<T>, T),
    witness:          (T::Scalar, Vec<T::Scalar>, Vec<T::Scalar>),
}

impl<T: Curve> ModifiedComEqProof<T> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let rp_len = self.randomised_point.0.len();
        let witness1_len = self.witness.1.len();
        let witness2_len = self.witness.2.len();
        let bytes_len = T::SCALAR_LENGTH
            + (rp_len + 1) * T::GROUP_ELEMENT_LENGTH
            + (1 + witness1_len + witness2_len) * T::SCALAR_LENGTH;
        let mut bytes = Vec::with_capacity(bytes_len);
        write_curve_scalar::<T>(&self.challenge, &mut bytes);
        write_curve_elements(&self.randomised_point.0, &mut bytes);
        write_curve_element(&self.randomised_point.1, &mut bytes);
        write_curve_scalar::<T>(&self.witness.0, &mut bytes);
        write_curve_scalars::<T>(&self.witness.1, &mut bytes);
        write_curve_scalars::<T>(&self.witness.2, &mut bytes);
        bytes
    }

    pub fn from_bytes(bytes: &mut Cursor<&[u8]>) -> Result<Self, Error> {
        let challenge = read_curve_scalar::<T>(bytes)?;
        let rp1 = read_curve_elements::<T>(bytes)?;
        let rp2 = read_curve::<T>(bytes)?;
        let w0 = read_curve_scalar::<T>(bytes)?;
        let w1 = read_curve_scalars::<T>(bytes)?;
        let w2 = read_curve_scalars::<T>(bytes)?;
        Ok(ModifiedComEqProof {
            challenge,
            randomised_point: (rp1, rp2),
            witness: (w0, w1, w2),
        })
    }
}

#[allow(clippy::many_single_char_names)]
pub fn prove_com_eq<T: Curve, R: Rng>(
    challenge_prefix: &[u8],
    evaluation: &(Vec<T>, T),
    coeff: &(T, T, T, T, Vec<T>),
    secret: &(T::Scalar, Vec<T::Scalar>, Vec<T::Scalar>),
    csprng: &mut R,
) -> ModifiedComEqProof<T> {
    let (p, q, g, h, gxs) = coeff;
    let (sec, bxs, axs) = secret;
    let (cxs, y) = evaluation;
    let n = cxs.len();
    assert_eq!(axs.len(), n);
    assert_eq!(bxs.len(), n);
    assert_eq!(gxs.len(), n);
    let mut suc = false;
    let mut u = T::zero_point();
    let mut vxs = vec![T::zero_point(); n];
    let mut hasher = Sha256::new();
    let mut hash = [0u8; 32];
    let mut challenge = T::Scalar::zero();
    let mut zxs = axs.clone();
    let mut wxs = bxs.clone();
    let mut wit = *sec;
    let mut rands = vec![(T::Scalar::zero(), T::Scalar::zero()); n];
    hasher.input(challenge_prefix);
    for ev in cxs.iter() {
        hasher.input(&*ev.curve_to_bytes());
    }
    hasher.input(&*y.curve_to_bytes());
    while !suc {
        let mut hasher2 = hasher.clone();
        let mut tmp_u = T::zero_point();
        for i in 0..n {
            let r_i = T::generate_scalar(csprng);
            let s_i = T::generate_scalar(csprng);
            rands[i] = (r_i, s_i);
            tmp_u = tmp_u.plus_point(&gxs[i].mul_by_scalar(&r_i));
            vxs[i] = g.mul_by_scalar(&r_i).plus_point(&h.mul_by_scalar(&s_i));
            hasher2.input(&*vxs[i].curve_to_bytes());
        }
        let a_rand = T::generate_scalar(csprng);
        tmp_u = tmp_u.plus_point(&q.mul_by_scalar(&a_rand));
        tmp_u = tmp_u.plus_point(&p);
        hasher2.input(&*tmp_u.curve_to_bytes());
        hash.copy_from_slice(hasher2.result().as_slice());
        match T::bytes_to_scalar(&mut Cursor::new(&hash)) {
            Err(_) => {}
            Ok(x) => {
                if !(x == T::Scalar::zero()) {
                    challenge = x;
                    u = tmp_u;
                    for i in 0..n {
                        let (r_i, s_i) = rands[i];
                        zxs[i].mul_assign(&challenge);
                        zxs[i].negate();
                        zxs[i].add_assign(&r_i);
                        wxs[i].mul_assign(&challenge);
                        wxs[i].negate();
                        wxs[i].add_assign(&s_i);
                    }
                    wit.mul_assign(&challenge);
                    wit.negate();
                    wit.add_assign(&a_rand);
                    suc = true;
                }
            }
        }
    }

    ModifiedComEqProof {
        challenge,
        randomised_point: (vxs, u),
        witness: (wit, wxs, zxs),
    }
}

#[allow(clippy::many_single_char_names)]
pub fn verify_com_eq<T: Curve>(
    challenge_prefix: &[u8],
    evaluation: &(Vec<T>, T),
    coeff: &(T, T, T, T, Vec<T>),
    proof: &ModifiedComEqProof<T>,
) -> bool {
    let challenge = &proof.challenge;
    let (vxs, u) = &proof.randomised_point;
    let (wit, wxs, zxs) = &proof.witness;
    let (p, q, g, h, gxs) = coeff;
    let (cxs, y) = evaluation;
    let n = cxs.len();
    assert_eq!(wxs.len(), n);
    assert_eq!(vxs.len(), n);
    let mut u_c = y.mul_by_scalar(challenge);
    for i in 0..n {
        u_c = u_c.plus_point(&gxs[i].mul_by_scalar(&zxs[i]));
        let v_i = cxs[i]
            .mul_by_scalar(challenge)
            .plus_point(&g.mul_by_scalar(&zxs[i]))
            .plus_point(&h.mul_by_scalar(&wxs[i]));
        if v_i != vxs[i] {
            return false;
        }
    }
    let mut p_exp = *challenge;
    p_exp.negate();
    p_exp.add_assign(&T::Scalar::one());
    u_c = u_c.plus_point(&q.mul_by_scalar(&wit));
    u_c = u_c.plus_point(&p.mul_by_scalar(&p_exp));
    if *u == u_c {
        let mut hasher = Sha256::new();
        hasher.input(challenge_prefix);
        let mut hash = [0u8; 32];
        for ev in cxs.iter() {
            hasher.input(&*ev.curve_to_bytes());
        }
        hasher.input(&*y.curve_to_bytes());
        for p in vxs.iter() {
            hasher.input(&*p.curve_to_bytes());
        }
        hasher.input(&*u.curve_to_bytes());
        hash.copy_from_slice(hasher.result().as_slice());
        match T::bytes_to_scalar(&mut Cursor::new(&hash)) {
            Ok(x) => x == *challenge,
            Err(_) => false,
        }
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::*;
    use pairing::bls12_381::G1;
    #[test]
    pub fn prove_verify_modified_com_eq() {
        let mut csprng = thread_rng();
        for i in 1..20 {
            let mut axs = vec![<G1 as Curve>::Scalar::zero(); i];
            let mut bxs = vec![<G1 as Curve>::Scalar::zero(); i];
            let mut gxs = vec![<G1 as Curve>::zero_point(); i];
            let g = G1::generate(&mut csprng);
            let h = G1::generate(&mut csprng);
            let q = G1::generate(&mut csprng);
            let p = G1::generate(&mut csprng);
            let mut cxs = vec![G1::zero_point(); i];
            let mut y = G1::zero_point();
            let sec = G1::generate_scalar(&mut csprng);
            for j in 0..i {
                axs[j] = G1::generate_scalar(&mut csprng);
                bxs[j] = G1::generate_scalar(&mut csprng);
                gxs[j] = G1::generate(&mut csprng);
                y = y.plus_point(&gxs[j].mul_by_scalar(&axs[j]));
                cxs[j] = cxs[j]
                    .plus_point(&g.mul_by_scalar(&axs[j]))
                    .plus_point(&h.mul_by_scalar(&bxs[j]));
            }
            y = y.plus_point(&q.mul_by_scalar(&sec));
            y = y.plus_point(&p);
            let coeff = (p, q, g, h, gxs);
            let evaluation = (cxs, y);
            let challenge_prefix = generate_challenge_prefix(&mut csprng);
            let proof = prove_com_eq(
                &challenge_prefix,
                &evaluation,
                &coeff,
                &(sec, bxs, axs),
                &mut csprng,
            );
            assert!(verify_com_eq(
                &challenge_prefix,
                &evaluation,
                &coeff,
                &proof
            ));
            let challenge_prefix_1 = generate_challenge_prefix(&mut csprng);
            if verify_com_eq(&challenge_prefix_1, &evaluation, &coeff, &proof) {
                assert_eq!(challenge_prefix, challenge_prefix_1);
            }
        }
    }

    #[test]
    pub fn test_modified_com_eq_proof_serialization() {
        let mut csprng = thread_rng();
        for _ in 1..100 {
            let challenge = G1::generate_scalar(&mut csprng);
            let lrp1 = csprng.gen_range(1, 30);
            let mut rp1 = Vec::with_capacity(lrp1);
            for _ in 0..lrp1 {
                rp1.push(G1::generate(&mut csprng));
            }
            let rp2 = G1::generate(&mut csprng);
            let lw1 = csprng.gen_range(1, 87);
            let mut w1 = Vec::with_capacity(lw1);
            for _ in 0..lw1 {
                w1.push(G1::generate_scalar(&mut csprng));
            }
            let lw2 = csprng.gen_range(1, 100);
            let mut w2 = Vec::with_capacity(lw1);
            for _ in 0..lw2 {
                w2.push(G1::generate_scalar(&mut csprng));
            }
            let cep = ModifiedComEqProof {
                challenge,
                randomised_point: (rp1, rp2),
                witness: (G1::generate_scalar(&mut csprng), w1, w2),
            };
            let bytes = cep.to_bytes();
            let cepp = ModifiedComEqProof::from_bytes(&mut Cursor::new(&bytes));
            assert!(cepp.is_ok());
            assert_eq!(cep, cepp.unwrap());
        }
    }
}
