use anyhow::bail;
use crypto_common::*;
use crypto_common_derive::*;
use curve25519_dalek::{
    constants,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::*,
};
use ed25519_dalek::*;
use rand::*;
use random_oracle::RandomOracle;
use sha2::{Digest, Sha512};
use thiserror::Error;

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
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
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

#[derive(Error, Debug)]
pub enum PointDecodingError {
    #[error("Not a valid edwards point.")]
    NotOnCurve,
    #[error("Not a scalar.")]
    NotAScalar,
}

fn scalar_from_secret_key(secret_key: &impl AsRef<[u8]>) -> Scalar {
    let mut h = Sha512::new();
    let mut hash: [u8; 64] = [0u8; 64];
    let mut bits: [u8; 32] = [0u8; 32];
    h.update(secret_key);
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

/// Construct a proof of knowledge of secret key.
///
/// The `public_key` and `secret_key` must be the ed25519 public and secret key
/// pair. The reason this function is not stated with those types is that it is
/// at present used both for proving ownership of normal signature keys, as well
/// as for proving ownership of the VRF keys.
/// The keys for the VRF protocol are physically the same, but they are defined
/// in a different crate and thus have different types. This situation should be
/// remedied to regain type safety when we have time to do it properly. This
/// will probably mean some reorganization of the crates.
pub fn prove_dlog_ed25519<R: Rng + CryptoRng>(
    csprng: &mut R,
    ro: &mut RandomOracle,
    public_key: &impl Serial,
    secret_key: &impl AsRef<[u8]>,
) -> Ed25519DlogProof {
    let secret = scalar_from_secret_key(secret_key);
    // FIXME: Add base to the proof.
    ro.append_message(b"dlog_ed25519", public_key);

    let rand_scalar = Scalar::random(csprng);

    let randomised_point = &rand_scalar * &constants::ED25519_BASEPOINT_TABLE;

    ro.append_message(b"randomised_point", &randomised_point.compress().to_bytes());
    let challenge_bytes = ro.split().result();
    // FIXME: Do the same as in other proofs in sigma_protocols in id.
    let mut array = [0u8; 32];
    array.copy_from_slice(challenge_bytes.as_ref());
    let challenge = Scalar::from_bytes_mod_order(array);
    Ed25519DlogProof {
        challenge,
        witness: rand_scalar - challenge * secret,
    }
}

pub fn verify_dlog_ed25519(
    ro: &mut RandomOracle,
    public_key: &PublicKey,
    proof: &Ed25519DlogProof,
) -> bool {
    match point_from_public_key(public_key) {
        None => false,
        Some(public) => {
            let randomised_point =
                public * proof.challenge + &proof.witness * &constants::ED25519_BASEPOINT_TABLE;
            ro.append_message(b"dlog_ed25519", public_key);
            ro.append_message(b"randomised_point", &randomised_point.compress().to_bytes());

            // FIXME: Should do the same as for normal dlog.
            let challenge_bytes = ro.split().result();
            // FIXME: Do the same as in other proofs in sigma_protocols in id.
            let mut array = [0u8; 32];
            array.copy_from_slice(challenge_bytes.as_ref());
            let challenge = Scalar::from_bytes_mod_order(array);
            challenge == proof.challenge
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_challenge_prefix<R: rand::Rng>(csprng: &mut R) -> Vec<u8> {
        // length of the challenge
        let l = csprng.gen_range(0, 1000);
        let mut challenge_prefix = vec![0; l];
        for v in challenge_prefix.iter_mut() {
            *v = csprng.gen();
        }
        challenge_prefix
    }

    #[test]
    pub fn test_ed25519_dlog() {
        let mut csprng = thread_rng();
        for _ in 0..10000 {
            let secret = SecretKey::generate(&mut csprng);
            let public = PublicKey::from(&secret);
            let challenge_prefix = generate_challenge_prefix(&mut csprng);
            let mut ro = RandomOracle::domain(&challenge_prefix);
            let proof = prove_dlog_ed25519(&mut csprng, &mut ro.split(), &public, &secret);
            assert!(verify_dlog_ed25519(&mut ro, &public, &proof));
            let challenge_prefix_1 = generate_challenge_prefix(&mut csprng);
            if verify_dlog_ed25519(
                &mut RandomOracle::domain(&challenge_prefix_1),
                &public,
                &proof,
            ) {
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
            let proof = prove_dlog_ed25519(
                &mut csprng,
                &mut RandomOracle::domain(&challenge_prefix),
                &public,
                &secret,
            );
            let proof_des = serialize_deserialize(&proof);
            assert_eq!(proof, proof_des.expect("Proof did not deserialize."));
        }
    }
}
