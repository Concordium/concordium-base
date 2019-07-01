use curve_arithmetic::{bls12_381_instance::*, curve_arithmetic::Curve};
use pairing::{bls12_381::G1Affine, Field};
use rand::*;
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct DlogProof<T: Curve> {
    challenge:        T::Scalar,
    randomised_point: T,
    witness:          T::Scalar,
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

#[test]
pub fn test_dlog() {
    let mut csprng = thread_rng();
    for i in 0..1000 {
        let secret = G1Affine::generate_scalar(&mut csprng);
        let base = G1Affine::generate(&mut csprng);
        let public = &base.mul_by_scalar(&secret);
        let proof = prove_dlog::<G1Affine, ThreadRng>(&mut csprng, &public, &secret, &base);
        assert!(verify_dlog(&base, &public, &proof));
    }
}
