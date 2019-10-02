use curve25519_dalek::{
    constants,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::*,
    traits::Identity,
};
use ed25519_dalek::*;
use rand::*;
use sha2::{Digest, Sha512};
use std::io::{Cursor, Read};

use failure::{Error, Fail};
use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ed25519DlogProof {
    challenge:        Scalar,
    randomised_point: EdwardsPoint,
    witness:          Scalar,
}

pub static PROOF_LENGTH: usize = 3 * 32;

#[derive(Debug)]
pub enum PointDecodingError {
    NotOnCurve,
    NotAScalar,
}

impl Display for PointDecodingError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            PointDecodingError::NotOnCurve => write!(f, "Not a valid edwards point."),
            PointDecodingError::NotAScalar => write!(f, "Not a scalar."),
        }
    }
}

impl Fail for PointDecodingError {}

impl Ed25519DlogProof {
    pub fn to_bytes(&self) -> Box<[u8]> {
        let mut bytes = Vec::with_capacity(3 * 32);
        bytes.extend_from_slice(self.challenge.as_bytes());
        bytes.extend_from_slice(self.randomised_point.compress().as_bytes());
        bytes.extend_from_slice(self.witness.as_bytes());
        bytes.into_boxed_slice()
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Result<Self, Error> {
        let mut buf = [0; 32];
        cur.read_exact(&mut buf)?;
        let challenge = Scalar::from_canonical_bytes(buf).ok_or(PointDecodingError::NotAScalar)?;
        cur.read_exact(&mut buf)?;
        let randomised_point_y = CompressedEdwardsY(buf);
        let randomised_point = randomised_point_y
            .decompress()
            .ok_or(PointDecodingError::NotOnCurve)?;
        cur.read_exact(&mut buf)?;
        let witness = Scalar::from_canonical_bytes(buf).ok_or(PointDecodingError::NotAScalar)?;
        Ok(Ed25519DlogProof {
            challenge,
            randomised_point,
            witness,
        })
    }
}

/// FIXME: This is a temporary hack due to library incompatibilites (dependencis
/// on rand require two different versions.

fn generate_rand_scalar() -> Scalar {
    let mut csprng = thread_rng();
    let mut bytes = [0u8; 32];
    csprng.fill_bytes(&mut bytes);
    let mut hasher = Sha512::new();
    hasher.input(&bytes);
    Scalar::from_hash(hasher)
}

fn scalar_from_secret_key(secret_key: &SecretKey) -> Scalar {
    let mut h = Sha512::new();
    let mut hash: [u8; 64] = [0u8; 64];
    let mut bits: [u8; 32] = [0u8; 32];
    h.input(secret_key.as_bytes());
    hash.copy_from_slice(h.result().as_slice());
    bits.copy_from_slice(&hash[..32]);
    bits[0] &= 248;
    bits[31] &= 127;
    bits[31] |= 64;
    Scalar::from_bits(bits)
}

fn point_from_public_key(public_key: &PublicKey) -> Option<EdwardsPoint> {
    let bytes = public_key.to_bytes();
    CompressedEdwardsY::from_slice(&bytes).decompress()
}

pub fn prove_dlog_ed25519(
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
        let rand_scalar = generate_rand_scalar();
        randomised_point = &rand_scalar * &constants::ED25519_BASEPOINT_TABLE;
        hasher2.input(&randomised_point.compress().to_bytes());
        hash.copy_from_slice(&hasher2.result().as_slice()[..32]);
        let x = Scalar::from_bytes_mod_order(hash);
        if x != Scalar::zero() {
            challenge = x;
            witness = rand_scalar - challenge * secret;
            suc = true;
        } // else try another time.
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
    if c != proof.challenge {
        return false;
    }
    match point_from_public_key(&public_key) {
        None => false,
        Some(public) => {
            proof.randomised_point
                == public * proof.challenge + &proof.witness * &constants::ED25519_BASEPOINT_TABLE
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
        for _ in 0..10000 {
            let secret = SecretKey::generate(&mut csprng);
            let public = PublicKey::from(&secret);
            let challenge_prefix = generate_challenge_prefix(&mut csprng);
            let proof = prove_dlog_ed25519(&challenge_prefix, &public, &secret);
            assert!(verify_dlog_ed25519(&challenge_prefix, &public, &proof));
            let challenge_prefix_1 = generate_challenge_prefix(&mut csprng);
            if verify_dlog_ed25519(&challenge_prefix_1, &public, &proof) {
                assert_eq!(challenge_prefix, challenge_prefix_1);
            }
        }
    }

    #[test]
    pub fn test_ed25519_dlog_proof_serialization() {
        let mut csprng = thread_rng();
        for _ in 0..10000 {
            let secret = SecretKey::generate(&mut csprng);
            let public = PublicKey::from(&secret);
            let challenge_prefix = generate_challenge_prefix(&mut csprng);
            let proof = prove_dlog_ed25519(&challenge_prefix, &public, &secret);
            let bytes = proof.to_bytes();
            let proof_des = Ed25519DlogProof::from_bytes(&mut Cursor::new(&bytes));
            assert_eq!(proof, proof_des.expect("Proof did not deserialize."));
        }
    }
}
