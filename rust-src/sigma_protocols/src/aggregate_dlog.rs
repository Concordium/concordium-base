use curve_arithmetic::{bls12_381_instance::*, curve_arithmetic::Curve};
use pairing::{bls12_381::G1Affine, Field};
use rand::*;
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct AggregateDlogProof<T: Curve> {
    challenge:        T::Scalar,
    randomised_point: T,
    witness:          Vec<T::Scalar>,
}

pub fn prove_aggregate_dlog<T: Curve, R: Rng>(
    csprng: &mut R,
    public: &T,
    secret: &Vec<T::Scalar>,
    coeff: &Vec<T>,
) -> AggregateDlogProof<T> {
    let n = secret.len();
    assert_eq!(coeff.len(), n);
    let mut hasher = Sha256::new();
    hasher.input(&*public.curve_to_bytes());
    let mut hash = [0u8; 32];
    let mut suc = false;
    let mut witness = secret.clone();
    let mut rands = vec![T::Scalar::zero(); n];
    let mut challenge = T::Scalar::zero();
    let mut randomised_point = T::zero_point();
    while !suc {
        let mut tmp_rp = T::zero_point();
        let mut hasher2 = hasher.clone();
        for i in 0..n{
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
                    for i in 0..n{
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
        challenge: challenge,
        randomised_point: randomised_point,
        witness: witness
    }
}

pub fn verify_aggregate_dlog<T: Curve>(coeff: &Vec<T>, public: &T, proof: &AggregateDlogProof<T>) -> bool {
    let mut hasher = Sha256::new();
    let randomised_point = proof.randomised_point;
    let witness = &proof.witness;
    let n = witness.len();
    if n != coeff.len(){ return false};
    hasher.input(&*public.curve_to_bytes());
    hasher.input(&*proof.randomised_point.curve_to_bytes());
    let mut hash = [0u8; 32];
    hash.copy_from_slice(hasher.result().as_slice());
    match T::bytes_to_scalar(&hash) {
        Err(_) => false,
        Ok(c) => {
            if c!= proof.challenge { 
                false
            } else {
                let mut check = public.mul_by_scalar(&proof.challenge);
                for i in 0..n {
                    check = check.plus_point(&coeff[i].mul_by_scalar(&witness[i]));
                }
                if randomised_point != check { println!("fff");}
                randomised_point == check
            }
        }
    }
}

#[test]
pub fn test_aggregate_dlog() {
    let mut csprng = thread_rng();
    for i in 1..20 {
        let mut secret = vec![<G1Affine as Curve>::Scalar::zero();i];
        let mut coeff = vec![<G1Affine as Curve>::zero_point(); i];
        let mut public = <G1Affine as Curve>::zero_point();
        for j in 0..i{
            secret[j] = G1Affine::generate_scalar(&mut csprng);
            coeff[j] = G1Affine::generate(&mut csprng);
            public = public.plus_point(&coeff[j].mul_by_scalar(&secret[j]));
        }
        let proof = prove_aggregate_dlog::<G1Affine, ThreadRng>(&mut csprng, &public, &secret, &coeff);
        assert!(verify_aggregate_dlog(&coeff, &public, &proof));
    }
}
