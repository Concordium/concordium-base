//! Implementation of the `com_enc_eq` sigma protocol.
//! This protocol is used to prove that the encrypted value (encrypted via
//! ElGamal) is the same as the value commited to via the Pedersen commitment.

use curve_arithmetic::curve_arithmetic::Curve;
use failure::Error;
use ff::Field;
use rand::*;

use std::io::Cursor;

use curve_arithmetic::serialization::*;
use elgamal::{
    Cipher as ElGamalCipher, PublicKey as ElGamalPublicKey, Randomness as ElgamalRandomness,
};
use pedersen_scheme::{Commitment, CommitmentKey, Randomness, Value};
use random_oracle::RandomOracle;

#[derive(Debug)]
pub struct ComEncEqSecret<'a, T: Curve> {
    pub value:         &'a Value<T>,
    pub elgamal_rand:  &'a ElgamalRandomness<T>,
    pub pedersen_rand: &'a Randomness<T>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComEncEqProof<T: Curve> {
    /// The computed challenge.
    challenge: T::Scalar,
    /// The values
    /// * $\alpha - c R$
    /// * $\beta - c x$
    /// * $\gamma - c r$
    /// where
    /// * c is the challenge
    /// * R is the ElGamal randomness
    /// * r is the Pedersen randomness
    /// * x is the encrypted/commited value
    witness: (T::Scalar, T::Scalar, T::Scalar),
}

impl<T: Curve> ComEncEqProof<T> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let bytes_len = T::SCALAR_LENGTH + 3 * T::GROUP_ELEMENT_LENGTH + 3 * T::SCALAR_LENGTH;
        let mut bytes = Vec::with_capacity(bytes_len);
        write_curve_scalar::<T>(&self.challenge, &mut bytes);
        write_curve_scalar::<T>(&self.witness.0, &mut bytes);
        write_curve_scalar::<T>(&self.witness.1, &mut bytes);
        write_curve_scalar::<T>(&self.witness.2, &mut bytes);
        bytes
    }

    pub fn from_bytes(bytes: &mut Cursor<&[u8]>) -> Result<Self, Error> {
        let challenge = read_curve_scalar::<T>(bytes)?;
        let w1 = read_curve_scalar::<T>(bytes)?;
        let w2 = read_curve_scalar::<T>(bytes)?;
        let w3 = read_curve_scalar::<T>(bytes)?;
        let witness = (w1, w2, w3);
        Ok(ComEncEqProof { challenge, witness })
    }
}

/// Construct a proof of knowledge.
/// The arguments are as follows
/// * `ro` - Random oracle used in the challenge computation. This can be used
///   to make sure that the proof is only valid in a certain context.
/// * `cipher` - The encryption $e$ of the secret value.
/// * `commitment` - The commitment to the same value.
/// * `pub_key` - The elgamal public key.
/// * `cmm_key` - Commitment key with which the commitment was made.
/// * `secret` - The triple $(x, R, r)$ of the encrypted/commited value $x$,
///   elgamal randomness $R$, and pedersen randomness $r$. These are **secret**
///   values.
/// * `csprng` - A cryptographically secure random number generator.
#[allow(non_snake_case)]
pub fn prove_com_enc_eq<T: Curve, R: Rng>(
    ro: RandomOracle,
    cipher: &ElGamalCipher<T>,
    commitment: &Commitment<T>,
    pub_key: &ElGamalPublicKey<T>,
    cmm_key: &CommitmentKey<T>,
    secret: &ComEncEqSecret<T>,
    csprng: &mut R,
) -> ComEncEqProof<T> {
    // NOTE: This relies on the details of serialization of public and commitment
    // keys. This is fine, but we should be mindful of when specifying.
    let hasher = ro
        .append("com_enc_eq")
        .append(cipher.to_bytes())
        .append(commitment.to_bytes())
        .append(pub_key.to_bytes())
        .append(cmm_key.to_bytes());

    loop {
        let beta = Value::generate_non_zero(csprng);
        let (rand_cipher, alpha) = pub_key.encrypt_exponent_rand(csprng, &beta.value);
        let (rand_cmm, gamma) = cmm_key.commit(&beta, csprng);

        let maybe_challenge = hasher
            .append_fresh(&rand_cipher.to_bytes())
            .append(&rand_cmm.to_bytes())
            .result_to_scalar::<T>();
        match maybe_challenge {
            None => {} // loop again
            Some(challenge) => {
                // In an extremely unlikely case the challenge is 0 the proof is
                // not going to be valid (unless alpha, beta, gamma are specific values) so we
                // loop again.
                if challenge != T::Scalar::zero() {
                    let x = secret.value;
                    let cR = secret.elgamal_rand;
                    let r = &secret.pedersen_rand;
                    let mut z_1 = challenge;
                    z_1.negate();
                    z_1.mul_assign(cR);
                    z_1.add_assign(&alpha);

                    let mut z_2 = challenge;
                    z_2.negate();
                    z_2.mul_assign(x);
                    z_2.add_assign(&beta);

                    let mut z_3 = challenge;
                    z_3.negate();
                    z_3.mul_assign(r);
                    z_3.add_assign(&gamma);
                    let witness = (z_1, z_2, z_3);
                    return ComEncEqProof { challenge, witness };
                }
            }
        }
    }
}

/// Verify a proof of knowledge.
/// The arguments are as follows
/// * `ro` - Random oracle used in the challenge computation. This can be used
///   to make sure that the proof is only valid in a certain context.
/// * `cipher` - The encryption $e$ of the secret value.
/// * `commitment` - The commitment to the same value.
/// * `pub_key` - The elgamal public key.
/// * `cmm_key` - Commitment key with which the commitment was made.
#[allow(non_snake_case)]
pub fn verify_com_enc_eq<T: Curve>(
    ro: RandomOracle,
    cipher: &ElGamalCipher<T>,
    commitment: &Commitment<T>,
    pub_key: &ElGamalPublicKey<T>,
    cmm_key: &CommitmentKey<T>,
    proof: &ComEncEqProof<T>,
) -> bool {
    let g_1 = pub_key.generator;
    let h_1 = pub_key.key;
    let g = cmm_key.0;
    let h = cmm_key.1;

    let z_1 = proof.witness.0;
    let z_2 = proof.witness.1;
    let z_3 = proof.witness.2;

    let e_1 = cipher.0;
    let e_2 = cipher.1;
    let cC = commitment.0;

    let a_1 = g_1
        .mul_by_scalar(&z_1)
        .plus_point(&e_1.mul_by_scalar(&proof.challenge));
    let a_2 = g_1
        .mul_by_scalar(&z_2)
        .plus_point(&h_1.mul_by_scalar(&z_1))
        .plus_point(&e_2.mul_by_scalar(&proof.challenge));
    let a_3 = g
        .mul_by_scalar(&z_2)
        .plus_point(&h.mul_by_scalar(&z_3))
        .plus_point(&cC.mul_by_scalar(&proof.challenge));

    let hasher = ro
        .append("com_enc_eq")
        .append(&cipher.to_bytes())
        .append(&commitment.to_bytes())
        .append(pub_key.to_bytes())
        .append(cmm_key.to_bytes())
        .append(&a_1.curve_to_bytes())
        .append(&a_2.curve_to_bytes())
        .append(&a_3.curve_to_bytes());

    let computed_challenge = hasher.result_to_scalar::<T>();
    match computed_challenge {
        None => false,
        Some(computed_challenge) => computed_challenge == proof.challenge,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigma_protocols::common::*;
    use elgamal::SecretKey as ElGamalSecretKey;
    use pairing::bls12_381::G1Affine;

    #[test]
    pub fn test_com_enc_eq_correctness() {
        let mut csprng = thread_rng();
        for _i in 0..100 {
            let sk = ElGamalSecretKey::generate(&mut csprng);
            let public_key = ElGamalPublicKey::from(&sk);
            let comm_key = CommitmentKey::generate(&mut csprng);

            let x: Value<G1Affine> = Value::generate_non_zero(&mut csprng);
            let (cipher, elgamal_randomness) =
                public_key.encrypt_exponent_rand(&mut csprng, &x.value);
            let (commitment, randomness) = comm_key.commit(&x, &mut csprng);
            let secret = ComEncEqSecret {
                value:         &x,
                elgamal_rand:  &elgamal_randomness,
                pedersen_rand: &randomness,
            };

            let challenge_prefix = generate_challenge_prefix(&mut csprng);
            let ro = RandomOracle::domain(&challenge_prefix);
            let proof = prove_com_enc_eq::<G1Affine, ThreadRng>(
                ro.split(),
                &cipher,
                &commitment,
                &public_key,
                &comm_key,
                &secret,
                &mut csprng,
            );
            assert!(verify_com_enc_eq(
                ro,
                &cipher,
                &commitment,
                &public_key,
                &comm_key,
                &proof
            ));
        }
    }

    #[test]
    pub fn test_com_enc_eq_soundness() {
        let mut csprng = thread_rng();
        for _i in 0..100 {
            // Generate proof
            let sk = ElGamalSecretKey::generate(&mut csprng);
            let public_key = ElGamalPublicKey::from(&sk);
            let comm_key = CommitmentKey::generate(&mut csprng);

            let x: Value<G1Affine> = Value::generate_non_zero(&mut csprng);
            let (cipher, elgamal_randomness) =
                public_key.encrypt_exponent_rand(&mut csprng, &x.value);
            let (commitment, randomness) = comm_key.commit(&x, &mut csprng);
            let secret = ComEncEqSecret {
                value:         &x,
                elgamal_rand:  &elgamal_randomness,
                pedersen_rand: &randomness,
            };

            let challenge_prefix = generate_challenge_prefix(&mut csprng);
            let ro = RandomOracle::domain(&challenge_prefix);
            let proof = prove_com_enc_eq::<G1Affine, ThreadRng>(
                ro.split(),
                &cipher,
                &commitment,
                &public_key,
                &comm_key,
                &secret,
                &mut csprng,
            );

            // Construct invalid parameters
            let wrong_ro = RandomOracle::domain(generate_challenge_prefix(&mut csprng));
            let mut wrong_cipher_0 = cipher;
            wrong_cipher_0.0 = wrong_cipher_0.0.double_point();
            let mut wrong_cipher_1 = cipher;
            wrong_cipher_1.1 = wrong_cipher_1.1.double_point();
            let wrong_commitment =
                pedersen_scheme::commitment::Commitment(commitment.double_point());
            let mut wrong_public_key_g = public_key;
            wrong_public_key_g.generator = wrong_public_key_g.generator.double_point();
            let mut wrong_public_key_k = public_key;
            wrong_public_key_k.key = wrong_public_key_k.key.double_point();
            let mut wrong_comm_key_g = comm_key;
            wrong_comm_key_g.0 = wrong_comm_key_g.0.double_point();
            let mut wrong_comm_key_h = comm_key;
            wrong_comm_key_h.1 = wrong_comm_key_h.1.double_point();

            // Verify failure for invalid parameters
            assert!(!verify_com_enc_eq(
                wrong_ro,
                &cipher,
                &commitment,
                &public_key,
                &comm_key,
                &proof
            ));
            assert!(!verify_com_enc_eq(
                ro.split(),
                &wrong_cipher_0,
                &commitment,
                &public_key,
                &comm_key,
                &proof
            ));
            assert!(!verify_com_enc_eq(
                ro.split(),
                &wrong_cipher_1,
                &commitment,
                &public_key,
                &comm_key,
                &proof
            ));
            assert!(!verify_com_enc_eq(
                ro.split(),
                &cipher,
                &wrong_commitment,
                &public_key,
                &comm_key,
                &proof
            ));
            assert!(!verify_com_enc_eq(
                ro.split(),
                &cipher,
                &commitment,
                &wrong_public_key_g,
                &comm_key,
                &proof
            ));
            assert!(!verify_com_enc_eq(
                ro.split(),
                &cipher,
                &commitment,
                &wrong_public_key_k,
                &comm_key,
                &proof
            ));
            assert!(!verify_com_enc_eq(
                ro.split(),
                &cipher,
                &commitment,
                &public_key,
                &wrong_comm_key_g,
                &proof
            ));
            assert!(!verify_com_enc_eq(
                ro.split(),
                &cipher,
                &commitment,
                &public_key,
                &wrong_comm_key_h,
                &proof
            ));
        }
    }

    #[test]
    pub fn test_proof_serialization() {
        let mut csprng = thread_rng();
        for _i in 0..100 {
            let challenge = G1Affine::generate_scalar(&mut csprng);
            let witness = (
                G1Affine::generate_scalar(&mut csprng),
                G1Affine::generate_scalar(&mut csprng),
                G1Affine::generate_scalar(&mut csprng),
            );
            let ap = ComEncEqProof::<G1Affine> { challenge, witness };
            let bytes = ap.to_bytes();
            let app = ComEncEqProof::from_bytes(&mut Cursor::new(&bytes));
            assert!(app.is_ok());
            assert_eq!(ap, app.unwrap());
        }
    }
}
