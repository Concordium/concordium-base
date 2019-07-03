use curve_arithmetic::curve_arithmetic::Curve;
use failure::Error;
use pairing::Field;
use rand::*;
use sha2::{Digest, Sha256};
use std::io::Cursor;

use crate::common::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DlogProof<T: Curve> {
    challenge:        T::Scalar,
    randomised_point: T,
    witness:          T::Scalar,
}

impl<T: Curve> DlogProof<T> {
    pub fn to_bytes(&self) -> Box<[u8]> {
        let mut bytes = Vec::with_capacity(2 * T::SCALAR_LENGTH + T::GROUP_ELEMENT_LENGTH);
        write_curve_scalar::<T>(&self.challenge, &mut bytes);
        write_curve_element::<T>(&self.randomised_point, &mut bytes);
        write_curve_scalar::<T>(&self.witness, &mut bytes);
        bytes.into_boxed_slice()
    }

    pub fn from_bytes(bytes: &mut Cursor<&[u8]>) -> Result<Self, Error> {
        let mut scalar_buffer = vec![0; T::SCALAR_LENGTH];
        let mut group_buffer = vec![0; T::GROUP_ELEMENT_LENGTH];
        let challenge = read_curve_scalar::<T>(bytes, &mut scalar_buffer)?;
        let randomised_point = read_curve::<T>(bytes, &mut group_buffer)?;
        let witness = read_curve_scalar::<T>(bytes, &mut scalar_buffer)?;
        Ok(DlogProof {
            challenge,
            randomised_point,
            witness,
        })
    }
}

pub fn prove_dlog<T: Curve, R: Rng>(
    csprng: &mut R,
    public: &T,
    secret: &T::Scalar,
    base: &T,
) -> DlogProof<T> {
    let mut hasher = Sha256::new();
    hasher.input(&*public.curve_to_bytes());
    let mut hash = [0u8; 32];
    let mut suc = false;
    let mut witness = T::Scalar::zero();
    let mut challenge = T::Scalar::zero();
    let mut randomised_point = T::zero_point();
    while !suc {
        let mut hasher2 = hasher.clone();
        let rand_scalar = T::generate_scalar(csprng);
        randomised_point = base.mul_by_scalar(&rand_scalar);
        hasher2.input(&*randomised_point.curve_to_bytes());
        hash.copy_from_slice(hasher2.result().as_slice());
        match T::bytes_to_scalar(&hash) {
            Err(_) => {}
            Ok(x) => {
                if x == T::Scalar::zero() {
                    println!("x = 0");
                } else {
                    challenge = x;
                    witness = secret.clone();
                    witness.mul_assign(&challenge);
                    witness.negate();
                    witness.add_assign(&rand_scalar);
                    suc = true;
                }
            }
        }
    }

    DlogProof {
        challenge,
        randomised_point,
        witness,
    }
}

pub fn verify_dlog<T: Curve>(base: &T, public: &T, proof: &DlogProof<T>) -> bool {
    let mut hasher = Sha256::new();
    hasher.input(&*public.curve_to_bytes());
    hasher.input(&*proof.randomised_point.curve_to_bytes());
    let mut hash = [0u8; 32];
    hash.copy_from_slice(hasher.result().as_slice());
    match T::bytes_to_scalar(&hash) {
        Err(_) => false,
        Ok(c) => {
            proof.randomised_point
                == public
                    .mul_by_scalar(&proof.challenge)
                    .plus_point(&base.mul_by_scalar(&proof.witness))
                && c == proof.challenge
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::G1Affine;
    #[test]
    pub fn test_dlog() {
        let mut csprng = thread_rng();
        for _ in 0..1000 {
            let secret = G1Affine::generate_scalar(&mut csprng);
            let base = G1Affine::generate(&mut csprng);
            let public = &base.mul_by_scalar(&secret);
            let proof = prove_dlog::<G1Affine, ThreadRng>(&mut csprng, &public, &secret, &base);
            assert!(verify_dlog(&base, &public, &proof));
        }
    }

    #[test]
    pub fn test_dlog_proof_serialization() {
        let mut csprng = thread_rng();
        for _ in 0..1000 {
            let challenge = G1Affine::generate_scalar(&mut csprng);
            let randomised_point = G1Affine::generate(&mut csprng);
            let witness = G1Affine::generate_scalar(&mut csprng);

            let dp = DlogProof {
                challenge,
                randomised_point,
                witness,
            };
            let bytes = dp.to_bytes();
            let dpp = DlogProof::from_bytes(&mut Cursor::new(&bytes));
            assert!(dpp.is_ok());
            assert_eq!(dp, dpp.unwrap());
        }
    }
}
