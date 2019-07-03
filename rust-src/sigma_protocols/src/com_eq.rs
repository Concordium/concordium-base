use curve_arithmetic::{curve_arithmetic::Curve};
use pairing::{Field};
use rand::*;
use sha2::{Digest, Sha256};

use failure::Error;
use std::io::Cursor;

use crate::common::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComEqProof<T: Curve> {
    challenge:        T::Scalar,
    randomised_point: (Vec<T>, T),
    witness:          (Vec<T::Scalar>, Vec<T::Scalar>),
}

impl<T: Curve> ComEqProof<T> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let rp_len = self.randomised_point.0.len();
        let witness0_len = self.witness.0.len();
        let witness1_len = self.witness.1.len();
        let bytes_len = T::SCALAR_LENGTH
            + (rp_len + 1) * T::GROUP_ELEMENT_LENGTH
            + (witness0_len + witness1_len) * T::SCALAR_LENGTH;
        let mut bytes = Vec::with_capacity(bytes_len);
        write_curve_scalar::<T>(&self.challenge, &mut bytes);
        write_curve_elements(&self.randomised_point.0, &mut bytes);
        write_curve_element(&self.randomised_point.1, &mut bytes);
        write_curve_scalars::<T>(&self.witness.0, &mut bytes);
        write_curve_scalars::<T>(&self.witness.1, &mut bytes);
        bytes
    }

    pub fn from_bytes(bytes: &mut Cursor<&[u8]>) -> Result<Self, Error> {
        let mut scalar_buffer = vec![0; T::SCALAR_LENGTH];
        let mut group_buffer = vec![0; T::GROUP_ELEMENT_LENGTH];
        let challenge = read_curve_scalar::<T>(bytes, &mut scalar_buffer)?;
        let rp1 = read_curve_elements::<T>(bytes, &mut group_buffer)?;
        let rp2 = read_curve::<T>(bytes, &mut group_buffer)?;
        let w1 = read_curve_scalars::<T>(bytes, &mut scalar_buffer)?;
        let w2 = read_curve_scalars::<T>(bytes, &mut scalar_buffer)?;
        let randomised_point = (rp1, rp2);
        let witness = (w1, w2);
        Ok(ComEqProof {
            challenge,
            randomised_point,
            witness,
        })
    }
}

pub fn prove_com_eq<T: Curve, R: Rng>(
    evaluation: &(Vec<T>, T),                  // ([c_i], y)
    coeff: &(T, T, Vec<T>),                    // g, h, [g_i]
    secret: &(Vec<T::Scalar>, Vec<T::Scalar>), //([b_i], [a_i])
    csprng: &mut R,
) -> ComEqProof<T> {
    let (g, h, gxs) = coeff;
    let (bxs, axs) = secret;
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
    let mut rands = vec![(T::Scalar::zero(), T::Scalar::zero()); n];
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
        hasher2.input(&*tmp_u.curve_to_bytes());
        hash.copy_from_slice(hasher2.result().as_slice());
        match T::bytes_to_scalar(&hash) {
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
                    suc = true;
                }
            }
        }
    }

    ComEqProof {
        challenge,
        randomised_point: (vxs, u),
        witness: (wxs, zxs),
    }
}
pub fn verify_com_eq<T: Curve>(
    evaluation: &(Vec<T>, T),
    coeff: &(T, T, Vec<T>),
    proof: &ComEqProof<T>,
) -> bool {
    let challenge = &proof.challenge;
    let (vxs, u) = &proof.randomised_point;
    let (wxs, zxs) = &proof.witness;
    // let ComEqProof(challenge, (vxs,u), (wxs,zxs)) = proof;
    let (g, h, gxs) = coeff;
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
            println!("v_{} wrong", i);
            return false;
        }
    }
    if *u == u_c {
        let mut hasher = Sha256::new();
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
        match T::bytes_to_scalar(&hash) {
            Ok(x) => {
                if x == *challenge {
                    return true;
                } else {
                    println!("x!= challenge");
                    return false;
                }
            }
            Err(_) => {
                println!("wrong hash");
                false
            }
        }
    } else {
        false
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use curve_arithmetic::bls12_381_instance::*;
    use pairing::bls12_381::G1Affine;

    #[test]
    pub fn prove_verify_com_eq() {
        let mut csprng = thread_rng();
        for i in 1..20 {
            let mut axs = vec![<G1Affine as Curve>::Scalar::zero(); i];
            let mut bxs = vec![<G1Affine as Curve>::Scalar::zero(); i];
            let mut gxs = vec![<G1Affine as Curve>::zero_point(); i];
            let g = G1Affine::generate(&mut csprng);
            let h = G1Affine::generate(&mut csprng);
            let mut cxs = vec![G1Affine::zero_point(); i];
            let mut y = G1Affine::zero_point();

            for j in 0..i {
                axs[j] = G1Affine::generate_scalar(&mut csprng);
                bxs[j] = G1Affine::generate_scalar(&mut csprng);
                gxs[j] = G1Affine::generate(&mut csprng);
                y = y.plus_point(&gxs[j].mul_by_scalar(&axs[j]));
                cxs[j] = cxs[j]
                    .plus_point(&g.mul_by_scalar(&axs[j]))
                    .plus_point(&h.mul_by_scalar(&bxs[j]));
            }
            let coeff = (g, h, gxs);
            let evaluation = (cxs, y);
            let proof = prove_com_eq(&evaluation, &coeff, &(bxs, axs), &mut csprng);
            assert!(verify_com_eq(&evaluation, &coeff, &proof));
        }
    }
    
    #[test]
    pub fn test_com_eq_proof_serialization() {
        let mut csprng = thread_rng();
        for _ in 1..100 {
            let challenge = G1Affine::generate_scalar(&mut csprng);
            let lrp1 = csprng.gen_range(1, 30);
            let mut rp1 = Vec::with_capacity(lrp1);
            for _ in 0..lrp1 {
                rp1.push(G1Affine::generate(&mut csprng));
            }
            let rp2 = G1Affine::generate(&mut csprng);
            let lw1 = csprng.gen_range(1, 87);
            let mut w1 = Vec::with_capacity(lw1);
            for _ in 0..lw1 {
                w1.push(G1Affine::generate_scalar(&mut csprng));
            }
            let lw2 = csprng.gen_range(1, 100);
            let mut w2 = Vec::with_capacity(lw1);
            for _ in 0..lw2 {
                w2.push(G1Affine::generate_scalar(&mut csprng));
            }
            let cep = ComEqProof {
                challenge,
                randomised_point: (rp1, rp2),
                witness: (w1, w2),
            };
            let bytes = cep.to_bytes();
            let cepp = ComEqProof::from_bytes(&mut Cursor::new(&bytes));
            assert!(cepp.is_ok());
            assert_eq!(cep, cepp.unwrap());
        }
    }
}

//   let coeff = G1Affine::generate(&mut csprng);
// let secret   = G1Affine::generate_scalar(&mut csprng);
// let evaluation = coeff.mul_by_scalar(&secret);
// let mut proof = prove_dlog(&evaluation, &coeff, &secret,  &mut csprng);
// assert!(verify_dlog(&evaluation, &coeff, &proof));
// let wrong_a = G1Affine::generate(&mut csprng);
// let DlogProof(c,(a,z)) = proof;
// assert!(!verify_dlog(&evaluation, &coeff, &DlogProof(c,(wrong_a, z))));
// let wrong_c = G1Affine::generate_scalar(&mut csprng);
// assert!(!verify_dlog(&evaluation, &coeff, &DlogProof(wrong_c,(a, z))));
// let wrong_z = G1Affine::generate_scalar(&mut csprng);
// assert!(!verify_dlog(&evaluation, &coeff, &DlogProof(c, (a, wrong_z))));
//
// }
