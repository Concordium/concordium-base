use crypto_common::*;
use crypto_common_derive::*;
use curve25519_dalek::{
    constants,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::*,
};
use random_oracle::RandomOracle;

use ed25519_dalek::*;
use failure::Fallible;
use rand::*;
use sha2::{Digest, Sha512};

use failure::Fail;
use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, Debug, Eq, PartialEq, SerdeBase16Serialize)]
pub struct Ed25519DlogProof {
    challenge: Scalar,
    witness:   Scalar,
}

impl Serial for Ed25519DlogProof {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.write_all(self.challenge.as_bytes())
            .expect("Writing to buffer should succeed.");
        out.write_all(self.witness.as_bytes())
            .expect("Writing to buffer should succeed.");
    }
}

impl Deserial for Ed25519DlogProof {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> Fallible<Self> {
        let mut buf = [0; 32];
        source.read_exact(&mut buf)?;
        if let Some(challenge) = Scalar::from_canonical_bytes(buf) {
            source.read_exact(&mut buf)?;
            if let Some(witness) = Scalar::from_canonical_bytes(buf) {
                Ok(Ed25519DlogProof { challenge, witness })
            } else {
                bail!("Not a valid witness.")
            }
        } else {
            bail!("Not a valid scalar.")
        }
    }
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

/// FIXME: This is a temporary hack due to library incompatibilites
/// (dependencies on rand require two different versions.

fn generate_rand_scalar() -> Scalar {
    let mut csprng = thread_rng();
    let mut bytes = [0u8; 32];
    csprng.fill_bytes(&mut bytes);
    let mut hasher = Sha512::new();
    hasher.update(&bytes);
    Scalar::from_hash(hasher)
}

fn scalar_from_secret_key(secret_key: &SecretKey) -> Scalar {
    let mut h = Sha512::new();
    let mut hash: [u8; 64] = [0u8; 64];
    let mut bits: [u8; 32] = [0u8; 32];
    h.update(secret_key.as_bytes());
    hash.copy_from_slice(h.finalize().as_slice());
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
    let hasher = ro.append_bytes("dlog_ed25519").append(public);

    // FIXME non_zero scalar should be generated
    let rand_scalar = generate_rand_scalar();
    let randomised_point = &rand_scalar * &constants::ED25519_BASEPOINT_TABLE;
    let challenge_bytes = hasher
        .split()
        .append_bytes(&randomised_point.compress().to_bytes())
        .result();
    // FIXME: Do the same as in other proofs in sigma_protocols in id.
    let mut array = [0u8; 32];
    array.copy_from_slice(&challenge_bytes.as_ref());
    let challenge = Scalar::from_bytes_mod_order(array);
    Ed25519DlogProof {
        challenge,
        witness: rand_scalar - challenge * secret,
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
                .append_bytes("dlog_ed25519")
                .append(public_key)
                .append_bytes(&randomised_point.compress().to_bytes());
            // FIXME: Should do the same as for normal dlog.
            let challenge_bytes = hasher.result();
            // FIXME: Do the same as in other proofs in sigma_protocols in id.
            let mut array = [0u8; 32];
            array.copy_from_slice(&challenge_bytes.as_ref());
            let challenge = Scalar::from_bytes_mod_order(array);
            challenge == proof.challenge
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
            let proof_des = serialize_deserialize(&proof);
            assert_eq!(proof, proof_des.expect("Proof did not deserialize."));
        }
    }
}
