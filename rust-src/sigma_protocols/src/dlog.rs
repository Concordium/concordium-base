use curve_arithmetic::curve_arithmetic::Curve;
use failure::Error;
use ff::Field;
use rand::*;
use sha2::{Digest, Sha256};
use std::io::Cursor;

use curve_arithmetic::serialization::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DlogProof<T: Curve> {
    challenge: T::Scalar,
    witness:   T::Scalar,
    _phantom:  std::marker::PhantomData<T>,
}

impl<T: Curve> DlogProof<T> {
    pub fn to_bytes(&self) -> Box<[u8]> {
        let mut bytes = Vec::with_capacity(2 * T::SCALAR_LENGTH);
        write_curve_scalar::<T>(&self.challenge, &mut bytes);
        write_curve_scalar::<T>(&self.witness, &mut bytes);
        bytes.into_boxed_slice()
    }

    pub fn from_bytes(bytes: &mut Cursor<&[u8]>) -> Result<Self, Error> {
        let challenge = read_curve_scalar::<T>(bytes)?;
        let witness = read_curve_scalar::<T>(bytes)?;
        Ok(DlogProof {
            challenge,
            witness,
            _phantom: Default::default(),
        })
    }
}

pub fn prove_dlog<T: Curve, R: Rng>(
    csprng: &mut R,
    challenge_prefix: &[u8],
    public: &T,
    secret: &T::Scalar,
    base: &T,
) -> DlogProof<T> {
    let mut hasher = Sha256::new();
    hasher.input(challenge_prefix);
    hasher.input(&public.curve_to_bytes());
    let mut suc = false;
    let mut witness = T::Scalar::zero();
    let mut challenge = T::Scalar::zero();
    while !suc {
        let mut hasher2 = hasher.clone();
        let rand_scalar = T::generate_scalar(csprng);
        let randomised_point = base.mul_by_scalar(&rand_scalar);
        hasher2.input(&randomised_point.curve_to_bytes());
        let maybe_challenge_bytes = hasher2.result();
        match T::bytes_to_scalar(&mut Cursor::new(&maybe_challenge_bytes)) {
            Err(_) => {} // loop again
            Ok(x) => {
                // FIXME: Why is this check useful?
                // We reveal the random scalar if it is, but why is that an issue?
                if x != T::Scalar::zero() {
                    challenge = x;
                    witness = *secret;
                    witness.mul_assign(&challenge);
                    witness.add_assign(&rand_scalar);
                    suc = true;
                } // else loop again

            }
        }
    }

    DlogProof {
        challenge,
        witness,
        _phantom: Default::default(),
    }
}

pub fn verify_dlog<T: Curve>(
    challenge_prefix: &[u8],
    base: &T,
    public: &T,
    proof: &DlogProof<T>,
) -> bool {
    let mut hasher = Sha256::new();
    hasher.input(challenge_prefix);
    hasher.input(&public.curve_to_bytes());
    let mut c = proof.challenge;
    c.negate();
    let randomised_point = public
        .mul_by_scalar(&c)
        .plus_point(&base.mul_by_scalar(&proof.witness));

    hasher.input(&randomised_point.curve_to_bytes());
    let challenge_bytes = hasher.result();
    match T::bytes_to_scalar(&mut Cursor::new(&challenge_bytes)) {
        Err(_) => false,
        Ok(c) => c == proof.challenge,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::*;
    use pairing::bls12_381::G1Affine;
    #[test]
    pub fn test_dlog() {
        let mut csprng = thread_rng();
        for _ in 0..1000 {
            let secret = G1Affine::generate_scalar(&mut csprng);
            let base = G1Affine::generate(&mut csprng);
            let public = &base.mul_by_scalar(&secret);
            let challenge_prefix = generate_challenge_prefix(&mut csprng);
            let proof = prove_dlog::<G1Affine, ThreadRng>(
                &mut csprng,
                &challenge_prefix,
                &public,
                &secret,
                &base,
            );
            assert!(verify_dlog(&challenge_prefix, &base, &public, &proof));
            let challenge_prefix_1 = generate_challenge_prefix(&mut csprng);
            if verify_dlog(&challenge_prefix_1, &base, &public, &proof) {
                assert_eq!(challenge_prefix, challenge_prefix_1);
            }
        }
    }

    #[test]
    pub fn test_dlog_proof_serialization() {
        let mut csprng = thread_rng();
        for _ in 0..1000 {
            let challenge = G1Affine::generate_scalar(&mut csprng);
            let witness = G1Affine::generate_scalar(&mut csprng);

            let dp = DlogProof::<G1Affine> {
                challenge,
                witness,
                _phantom: Default::default(),
            };
            let bytes = dp.to_bytes();
            let dpp = DlogProof::from_bytes(&mut Cursor::new(&bytes));
            assert!(dpp.is_ok());
            assert_eq!(dp, dpp.unwrap());
        }
    }
}
