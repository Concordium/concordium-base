use rand::*;
use sha2::{Digest, Sha512};
use std::io::Cursor;
use ed25519_dalek::*;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::*;
use curve25519_dalek::constants;
use curve25519_dalek::traits::Identity;
use curve25519_dalek::traits::IsIdentity;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ed25519DlogProof {
    challenge:        Scalar,
    randomised_point: EdwardsPoint,
    witness:          Scalar,
}
/*
impl<T: Curve> DlogProof<T> {
    pub fn to_bytes(&self) -> Box<[u8]> {
        let mut bytes = Vec::with_capacity(2 * T::SCALAR_LENGTH + T::GROUP_ELEMENT_LENGTH);
        write_curve_scalar::<T>(&self.challenge, &mut bytes);
        write_curve_element::<T>(&self.randomised_point, &mut bytes);
        write_curve_scalar::<T>(&self.witness, &mut bytes);
        bytes.into_boxed_slice()
    }

    pub fn from_bytes(bytes: &mut Cursor<&[u8]>) -> Result<Self, Error> {
        let challenge = read_curve_scalar::<T>(bytes)?;
        let randomised_point = read_curve::<T>(bytes)?;
        let witness = read_curve_scalar::<T>(bytes)?;
        Ok(DlogProof {
            challenge,
            randomised_point,
            witness,
        })
    }
}
*/

fn generate_rand_scalar<R: Rng>(csprng: &mut R)->Scalar{
    let mut bytes = [0u8;32];
    csprng.fill_bytes(&mut bytes);
    let mut hasher = Sha512::new();
    hasher.input(&bytes);
    let mut hash:   [u8; 64] = [0u8; 64];
    hash.copy_from_slice(hasher.result().as_slice());
    let mut bits = [0u8; 32];
    bits.copy_from_slice(&hash[..32]);
    bits[0]  &= 248;
    bits[31] &= 127;
    bits[31] |= 64;
    Scalar::from_bits(bits)
}

fn scalar_from_secret_key(secret_key: &SecretKey) -> Scalar{
    let mut h = Sha512::new();
    let mut hash:   [u8; 64] = [0u8; 64];
    let mut bits: [u8; 32] = [0u8; 32];
    h.input(secret_key.as_bytes());
    hash.copy_from_slice(h.result().as_slice());
    bits.copy_from_slice(&hash[..32]);
    bits[0]  &= 248;
    bits[31] &= 127;
    bits[31] |= 64;
    Scalar::from_bits(bits)
}

fn point_from_public_key(public_key: &PublicKey) -> Option<EdwardsPoint>{
    let bytes = public_key.to_bytes();
    CompressedEdwardsY::from_slice(&bytes).decompress()

}

pub fn prove_dlog_ed25519<R: Rng>(
    csprng: &mut R,
    challenge_prefix: &[u8],
    public: &PublicKey,
    secret_key: &SecretKey,
) -> Ed25519DlogProof {
    let secret = scalar_from_secret_key(&secret_key);
    let mut hasher = Sha512::new();
    hasher.input(challenge_prefix);
    hasher.input(&public.to_bytes());
    let mut hash = [0u8; 32];
    let mut suc = false;
    let mut witness = Scalar::zero();
    let mut challenge = Scalar::zero();
    let mut randomised_point = EdwardsPoint::identity();
    while !suc {
        let mut hasher2 = hasher.clone();
        let rand_scalar = generate_rand_scalar(csprng);
        randomised_point = &rand_scalar * &constants::ED25519_BASEPOINT_TABLE;
        hasher2.input(&randomised_point.compress().to_bytes());
        hash.copy_from_slice(&hasher2.result().as_slice()[..32]);
        let x = Scalar::from_bytes_mod_order(hash); 
        if x == Scalar::zero() {
            println!("x = 0");
        } else {
             challenge = x;
             witness = rand_scalar - challenge * secret;
             suc = true;
        }
    }


    Ed25519DlogProof {
        challenge,
        randomised_point,
        witness,
    }
}

pub fn verify_dlog_ed25519(
    challenge_prefix: &[u8],
    public_key: &PublicKey,
    proof: &Ed25519DlogProof,
) -> bool {
    let mut hasher = Sha512::new();
    hasher.input(challenge_prefix);
    hasher.input(&public_key.to_bytes());
    hasher.input(&proof.randomised_point.compress().to_bytes());
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hasher.result().as_slice()[..32]);
    let c = Scalar::from_bytes_mod_order(hash);
    if c != proof.challenge {println!("wrong challenge"); return false;}
    match point_from_public_key(&public_key){
        None => false,
        Some(public) => {
    proof.randomised_point
                == public * &proof.challenge + &proof.witness *  &constants::ED25519_BASEPOINT_TABLE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::*;
    #[test]
    pub fn test_ed25519_dlog() {
        let mut csprng = thread_rng();
        for _ in 0..1000 {
            let secret = SecretKey::generate(&mut csprng);
            let public = PublicKey::from(&secret);
            let challenge_prefix = generate_challenge_prefix(&mut csprng);
            let proof = prove_dlog_ed25519(
                &mut csprng,
                &challenge_prefix,
                &public,
                &secret,
            );
            assert!(verify_dlog_ed25519(&challenge_prefix, &public, &proof));
            let challenge_prefix_1 = generate_challenge_prefix(&mut csprng);
            if verify_dlog(&challenge_prefix_1, &public, &proof) {
                assert_eq!(challenge_prefix, challenge_prefix_1);
            }
        }
    }
    /*

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
    */
}

