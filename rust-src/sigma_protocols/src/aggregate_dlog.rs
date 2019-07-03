use curve_arithmetic::curve_arithmetic::Curve;
use failure::Error;
use pairing::Field;
use rand::*;
use sha2::{Digest, Sha256};

use std::io::Cursor;

use crate::common::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AggregateDlogProof<T: Curve> {
    challenge:        T::Scalar,
    randomised_point: T,
    witness:          Vec<T::Scalar>,
}

impl<T: Curve> AggregateDlogProof<T> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let bytes_len =
            T::SCALAR_LENGTH + T::GROUP_ELEMENT_LENGTH + 4 + self.witness.len() * T::SCALAR_LENGTH;
        let mut bytes = Vec::with_capacity(bytes_len);
        write_curve_scalar::<T>(&self.challenge, &mut bytes);
        write_curve_element::<T>(&self.randomised_point, &mut bytes);
        write_curve_scalars::<T>(&self.witness, &mut bytes);
        bytes
    }

    pub fn from_bytes(bytes: &mut Cursor<&[u8]>) -> Result<Self, Error> {
        let mut scalar_buffer = vec![0; T::SCALAR_LENGTH];
        let mut group_buffer = vec![0; T::GROUP_ELEMENT_LENGTH];
        let challenge = read_curve_scalar::<T>(bytes, &mut scalar_buffer)?;
        let randomised_point = read_curve::<T>(bytes, &mut group_buffer)?;
        let witness = read_curve_scalars::<T>(bytes, &mut scalar_buffer)?;
        Ok(AggregateDlogProof {
            challenge,
            randomised_point,
            witness,
        })
    }
}

pub fn prove_aggregate_dlog<T: Curve, R: Rng>(
    csprng: &mut R,
    public: &T,
    secret: &[T::Scalar],
    coeff: &[T],
) -> AggregateDlogProof<T> {
    let n = secret.len();
    assert_eq!(coeff.len(), n);
    let mut hasher = Sha256::new();
    hasher.input(&*public.curve_to_bytes());
    let mut hash = [0u8; 32];
    let mut suc = false;
    let mut witness = secret.to_vec();
    let mut rands = vec![T::Scalar::zero(); n];
    let mut challenge = T::Scalar::zero();
    let mut randomised_point = T::zero_point();
    while !suc {
        let mut tmp_rp = T::zero_point();
        let mut hasher2 = hasher.clone();
        for i in 0..n {
            rands[i] = T::generate_scalar(csprng);
            tmp_rp = tmp_rp.plus_point(&coeff[i].mul_by_scalar(&rands[i]));
        }
        hasher2.input(&*tmp_rp.curve_to_bytes());
        hash.copy_from_slice(hasher2.result().as_slice());
        match T::bytes_to_scalar(&hash) {
            Err(_) => {}
            Ok(x) => {
                if x != T::Scalar::zero() {
                    challenge = x;
                    randomised_point = tmp_rp;
                    for i in 0..n {
                        witness[i].mul_assign(&challenge);
                        witness[i].negate();
                        witness[i].add_assign(&rands[i]);
                    }
                    suc = true;
                }
            }
        }
    }

    AggregateDlogProof {
        challenge,
        randomised_point,
        witness,
    }
}

pub fn verify_aggregate_dlog<T: Curve>(
    coeff: &Vec<T>,
    public: &T,
    proof: &AggregateDlogProof<T>,
) -> bool {
    let mut hasher = Sha256::new();
    let randomised_point = proof.randomised_point;
    let witness = &proof.witness;
    let n = witness.len();
    if n != coeff.len() {
        return false;
    };
    hasher.input(&*public.curve_to_bytes());
    hasher.input(&*proof.randomised_point.curve_to_bytes());
    let mut hash = [0u8; 32];
    hash.copy_from_slice(hasher.result().as_slice());
    match T::bytes_to_scalar(&hash) {
        Err(_) => false,
        Ok(c) => {
            if c != proof.challenge {
                false
            } else {
                let mut check = public.mul_by_scalar(&proof.challenge);
                for i in 0..n {
                    check = check.plus_point(&coeff[i].mul_by_scalar(&witness[i]));
                }
                if randomised_point != check {
                    println!("fff");
                }
                randomised_point == check
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::G1Affine;
    #[test]
    pub fn test_aggregate_dlog() {
        let mut csprng = thread_rng();
        for i in 1..20 {
            let mut secret = vec![<G1Affine as Curve>::Scalar::zero(); i];
            let mut coeff = vec![<G1Affine as Curve>::zero_point(); i];
            let mut public = <G1Affine as Curve>::zero_point();
            for j in 0..i {
                secret[j] = G1Affine::generate_scalar(&mut csprng);
                coeff[j] = G1Affine::generate(&mut csprng);
                public = public.plus_point(&coeff[j].mul_by_scalar(&secret[j]));
            }
            let proof =
                prove_aggregate_dlog::<G1Affine, ThreadRng>(&mut csprng, &public, &secret, &coeff);
            assert!(verify_aggregate_dlog(&coeff, &public, &proof));
        }
    }

    #[test]
    pub fn test_serialization() {
        let mut csprng = thread_rng();
        for i in 1..20 {
            let mut witness = vec![<G1Affine as Curve>::Scalar::zero(); i];
            let challenge: <G1Affine as Curve>::Scalar = G1Affine::generate_scalar(&mut csprng);
            let randomised_point: G1Affine = Curve::generate(&mut csprng);
            for j in 0..i {
                witness[j] = G1Affine::generate_scalar(&mut csprng);
            }
            let ap = AggregateDlogProof {
                challenge,
                randomised_point,
                witness,
            };
            let bytes = ap.to_bytes();
            let app = AggregateDlogProof::from_bytes(&mut Cursor::new(&bytes));
            assert!(app.is_ok());
            assert_eq!(ap, app.unwrap());
        }
    }
}
