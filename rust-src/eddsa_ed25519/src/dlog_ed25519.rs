use curve25519_dalek::{
    constants,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::*,
};
use random_oracle::RandomOracle;

use ed25519_dalek::*;
use rand::*;
use sha2::{Digest, Sha512};
use std::io::{Cursor, Read};

use failure::{Error, Fail};
use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ed25519DlogProof {
    challenge: Scalar,
    witness:   Scalar,
}

pub static PROOF_LENGTH: usize = 2 * 32;

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
        bytes.extend_from_slice(self.witness.as_bytes());
        bytes.into_boxed_slice()
    }

    pub fn from_bytes(cur: &mut Cursor<&[u8]>) -> Result<Self, Error> {
        let mut buf = [0; 32];
        cur.read_exact(&mut buf)?;
        let challenge = Scalar::from_canonical_bytes(buf).ok_or(PointDecodingError::NotAScalar)?;
        cur.read_exact(&mut buf)?;
        let witness = Scalar::from_canonical_bytes(buf).ok_or(PointDecodingError::NotAScalar)?;
        Ok(Ed25519DlogProof { challenge, witness })
    }
}

/// FIXME: This is a temporary hack due to library incompatibilites
/// (dependencies on rand require two different versions.

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
    ro: RandomOracle,
    public: &PublicKey,
    secret_key: &SecretKey,
) -> Ed25519DlogProof {
    let secret = scalar_from_secret_key(&secret_key);
    // FIXME: Add base to the proof.
    let hasher = ro.append("dlog_ed25519").append(&public.to_bytes());
    loop {
        // FIXME non_zero scalar should be generated
        let rand_scalar = generate_rand_scalar();
        let randomised_point = &rand_scalar * &constants::ED25519_BASEPOINT_TABLE;
        let challenge_bytes = hasher
            .append_fresh(&randomised_point.compress().to_bytes())
            .result();
        let mut array = [0u8; 32];
        array.copy_from_slice(&challenge_bytes.as_ref()[..32]);
        let maybe_challenge = Scalar::from_canonical_bytes(array);
        match maybe_challenge {
            None => {} // loop again
            Some(challenge) => {
                if challenge != Scalar::zero() {
                    let proof = Ed25519DlogProof {
                        challenge,
                        witness: rand_scalar - challenge * secret,
                    };
                    return proof;
                } // else try another time.
            }
        }
    }
}

pub fn verify_dlog_ed25519(
    ro: RandomOracle,
    public_key: &PublicKey,
    proof: &Ed25519DlogProof,
) -> bool {
    match point_from_public_key(public_key) {
        None => false,
        Some(public) => {
            let randomised_point =
                public * proof.challenge + &proof.witness * &constants::ED25519_BASEPOINT_TABLE;
            let hasher = ro
                .append("dlog_ed25519")
                .append(&public_key.to_bytes())
                .append(&randomised_point.compress().to_bytes());
            // FIXME: Should do the same as for normal dlog.
            let challenge_bytes = hasher.result();
            let mut array = [0u8; 32];
            array.copy_from_slice(&challenge_bytes.as_ref()[..32]);
            let maybe_challenge = Scalar::from_canonical_bytes(array);
            match maybe_challenge {
                None => false,
                Some(challenge) => challenge == proof.challenge,
            }
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
            let ro = RandomOracle::domain(&challenge_prefix);
            let proof = prove_dlog_ed25519(ro.split(), &public, &secret);
            assert!(verify_dlog_ed25519(ro, &public, &proof));
            let challenge_prefix_1 = generate_challenge_prefix(&mut csprng);
            if verify_dlog_ed25519(RandomOracle::domain(&challenge_prefix_1), &public, &proof) {
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
            let ro = RandomOracle::domain(&challenge_prefix);
            let proof = prove_dlog_ed25519(ro, &public, &secret);
            let bytes = proof.to_bytes();
            let proof_des = Ed25519DlogProof::from_bytes(&mut Cursor::new(&bytes));
            assert_eq!(proof, proof_des.expect("Proof did not deserialize."));
        }
    }
}
