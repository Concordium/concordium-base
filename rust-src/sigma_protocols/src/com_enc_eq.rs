use curve_arithmetic::curve_arithmetic::Curve;
use failure::Error;
use pairing::Field;
use rand::*;
use sha2::{Digest, Sha256};

use std::io::Cursor;

use crate::common::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComEncEqProof<T: Curve> {
    challenge:         T::Scalar,
    randomised_points: (T, T, T),
    witness:           (T::Scalar, T::Scalar, T::Scalar),
}

impl<T: Curve> ComEncEqProof<T> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let bytes_len = T::SCALAR_LENGTH + 3 * T::GROUP_ELEMENT_LENGTH + 3 * T::SCALAR_LENGTH;
        let mut bytes = Vec::with_capacity(bytes_len);
        write_curve_scalar::<T>(&self.challenge, &mut bytes);
        write_curve_element::<T>(&self.randomised_points.0, &mut bytes);
        write_curve_element::<T>(&self.randomised_points.1, &mut bytes);
        write_curve_element::<T>(&self.randomised_points.2, &mut bytes);
        write_curve_scalar::<T>(&self.witness.0, &mut bytes);
        write_curve_scalar::<T>(&self.witness.1, &mut bytes);
        write_curve_scalar::<T>(&self.witness.2, &mut bytes);
        bytes
    }

    pub fn from_bytes(bytes: &mut Cursor<&[u8]>) -> Result<Self, Error> {
        let mut scalar_buffer = vec![0; T::SCALAR_LENGTH];
        let mut group_buffer = vec![0; T::GROUP_ELEMENT_LENGTH];
        let challenge = read_curve_scalar::<T>(bytes, &mut scalar_buffer)?;
        let r1 = read_curve::<T>(bytes, &mut group_buffer)?;
        let r2 = read_curve::<T>(bytes, &mut group_buffer)?;
        let r3 = read_curve::<T>(bytes, &mut group_buffer)?;
        let w1 = read_curve_scalar::<T>(bytes, &mut scalar_buffer)?;
        let w2 = read_curve_scalar::<T>(bytes, &mut scalar_buffer)?;
        let w3 = read_curve_scalar::<T>(bytes, &mut scalar_buffer)?;
        let randomised_points = (r1, r2, r3);
        let witness = (w1, w2, w3);
        Ok(ComEncEqProof {
            challenge,
            randomised_points,
            witness,
        })
    }
}

pub fn prove_com_enc_eq<T: Curve, R: Rng>(
    csprng: &mut R,
    public: &(T, T, T),
    secret: &(T::Scalar, T::Scalar, T::Scalar),
    base: &(T, T, T, T),
) -> ComEncEqProof<T> {
    let mut hasher = Sha256::new();
    hasher.input(&*public.0.curve_to_bytes());
    hasher.input(&*public.1.curve_to_bytes());
    hasher.input(&*public.2.curve_to_bytes());
    let (g_1, h_1, g, h) = base;
    let (s_1, s_2, s_3) = secret;
    let mut a_1 = T::zero_point();
    let mut a_2 = T::zero_point();
    let mut a_3 = T::zero_point();
    let mut w_1 = T::Scalar::zero();
    let mut w_2 = T::Scalar::zero();
    let mut w_3 = T::Scalar::zero();
    let mut hash = [0u8; 32];
    let mut suc = false;
    let mut challenge = T::Scalar::zero();
    while !suc {
        let mut hasher2 = hasher.clone();
        let r_1 = T::generate_scalar(csprng);
        let r_2 = T::generate_scalar(csprng);
        let r_3 = T::generate_scalar(csprng);
        a_1 = g_1.mul_by_scalar(&r_1);
        a_2 = g_1.mul_by_scalar(&r_2).plus_point(&h_1.mul_by_scalar(&r_1));
        a_3 = g.mul_by_scalar(&r_2).plus_point(&h.mul_by_scalar(&r_3));
        hasher2.input(&*a_1.curve_to_bytes());
        hasher2.input(&*a_2.curve_to_bytes());
        hasher2.input(&*a_3.curve_to_bytes());
        hash.copy_from_slice(hasher2.result().as_slice());
        match T::bytes_to_scalar(&hash) {
            Err(_) => {}
            Ok(x) => {
                if x == T::Scalar::zero() {
                } else {
                    challenge = x;
                    w_1 = *s_1;
                    w_1.mul_assign(&challenge);
                    w_1.negate();
                    w_1.add_assign(&r_1);
                    w_2 = *s_2;
                    w_2.mul_assign(&challenge);
                    w_2.negate();
                    w_2.add_assign(&r_2);
                    w_3 = *s_3;
                    w_3.mul_assign(&challenge);
                    w_3.negate();
                    w_3.add_assign(&r_3);
                    suc = true;
                }
            }
        }
    }
    let randomised_points = (a_1, a_2, a_3);
    let witness = (w_1, w_2, w_3);
    ComEncEqProof {
        challenge,
        randomised_points,
        witness,
    }
}

pub fn verify_com_enc_eq<T: Curve>(
    base: &(T, T, T, T),
    public: &(T, T, T),
    proof: &ComEncEqProof<T>,
) -> bool {
    let mut hasher = Sha256::new();
    let (g_1, h_1, g, h) = base;
    let (e_1, e_2, e_3) = public;
    let (w_1, w_2, w_3) = proof.witness;
    hasher.input(&*e_1.curve_to_bytes());
    hasher.input(&*e_2.curve_to_bytes());
    hasher.input(&*e_3.curve_to_bytes());
    let (a_1, a_2, a_3) = proof.randomised_points;
    hasher.input(&*a_1.curve_to_bytes());
    hasher.input(&*a_2.curve_to_bytes());
    hasher.input(&*a_3.curve_to_bytes());
    let mut hash = [0u8; 32];
    hash.copy_from_slice(hasher.result().as_slice());
    match T::bytes_to_scalar(&hash) {
        Err(_) => false,
        Ok(c) => {
            if c != proof.challenge {
                return false;
            };
            let b_1 = a_1 == g_1.mul_by_scalar(&w_1).plus_point(&e_1.mul_by_scalar(&c));
            let b_2 = a_2
                == g_1
                    .mul_by_scalar(&w_2)
                    .plus_point(&h_1.mul_by_scalar(&w_1))
                    .plus_point(&e_2.mul_by_scalar(&c));
            let b_3 = a_3
                == g.mul_by_scalar(&w_2)
                    .plus_point(&h.mul_by_scalar(&w_3))
                    .plus_point(&e_3.mul_by_scalar(&c));
            b_1 && b_2 && b_3
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::G1Affine;

    #[test]
    pub fn test_com_enc_eq() {
        let mut csprng = thread_rng();
        for i in 0..100 {
            let (s_1, s_2, s_3) = (
                G1Affine::generate_scalar(&mut csprng),
                G1Affine::generate_scalar(&mut csprng),
                G1Affine::generate_scalar(&mut csprng),
            );
            let (g_1, h_1, g, h) = (
                G1Affine::generate(&mut csprng),
                G1Affine::generate(&mut csprng),
                G1Affine::generate(&mut csprng),
                G1Affine::generate(&mut csprng),
            );
            let e_1 = g_1.mul_by_scalar(&s_1);
            let e_2 = g_1.mul_by_scalar(&s_2).plus_point(&h_1.mul_by_scalar(&s_1));
            let e_3 = g.mul_by_scalar(&s_2).plus_point(&h.mul_by_scalar(&s_3));
            let public = (e_1, e_2, e_3);
            let proof = prove_com_enc_eq::<G1Affine, ThreadRng>(
                &mut csprng,
                &public,
                &(s_1, s_2, s_3),
                &(g_1, h_1, g, h),
            );
            assert!(verify_com_enc_eq(&(g_1, h_1, g, h), &public, &proof));
        }
    }

    #[test]
    pub fn test_proof_serialization() {
        let mut csprng = thread_rng();
        for i in 0..100 {
            let challenge = G1Affine::generate_scalar(&mut csprng);
            let randomised_points = (
                G1Affine::generate(&mut csprng),
                G1Affine::generate(&mut csprng),
                G1Affine::generate(&mut csprng),
            );
            let witness = (
                G1Affine::generate_scalar(&mut csprng),
                G1Affine::generate_scalar(&mut csprng),
                G1Affine::generate_scalar(&mut csprng),
            );
            let ap = ComEncEqProof {
                challenge,
                randomised_points,
                witness,
            };
            let bytes = ap.to_bytes();
            let app = ComEncEqProof::from_bytes(&mut Cursor::new(&bytes));
            assert!(app.is_ok());
            assert_eq!(ap, app.unwrap());
        }
    }
}
