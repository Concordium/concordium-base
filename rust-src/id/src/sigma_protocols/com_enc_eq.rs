//! Implementation of the `com_enc_eq` sigma protocol.
//! This protocol is used to prove that the encrypted value (encrypted via
//! ElGamal) is the same as the value commited to via the Pedersen commitment.

use curve_arithmetic::Curve;
use ff::Field;
use rand::*;

use crate::sigma_protocols::common::*;
use crypto_common::*;
use crypto_common_derive::*;
use elgamal::{
    Cipher as ElGamalCipher, PublicKey as ElGamalPublicKey, Randomness as ElgamalRandomness,
};
use pedersen_scheme::{Commitment, CommitmentKey, Randomness as PedersenRandomness, Value};
use random_oracle::RandomOracle;

#[derive(Debug)]
pub struct ComEncEqSecret<T: Curve> {
    pub value:         Value<T>,
    pub elgamal_rand:  ElgamalRandomness<T>,
    pub pedersen_rand: PedersenRandomness<T>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, SerdeBase16Serialize)]
pub struct Witness<T: Curve> {
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

pub struct ComEncEq<C: Curve> {
    /// The encryption $e$ of the secret value.
    pub cipher: ElGamalCipher<C>,
    /// The commitment to the same value.
    pub commitment: Commitment<C>,
    /// The elgamal public key.
    pub pub_key: ElGamalPublicKey<C>,
    /// Commitment key with which the commitment was made.
    pub cmm_key: CommitmentKey<C>,
}

#[allow(non_snake_case)]
impl<C: Curve> SigmaProtocol for ComEncEq<C> {
    type CommitMessage = (ElGamalCipher<C>, Commitment<C>);
    type ProtocolChallenge = C::Scalar;
    // (beta, alpha, gamma)
    type ProverState = (Value<C>, ElgamalRandomness<C>, PedersenRandomness<C>);
    type ProverWitness = Witness<C>;
    type SecretData = ComEncEqSecret<C>;

    #[inline]
    fn public(&self, ro: RandomOracle) -> RandomOracle {
        ro.append(&self.cipher)
            .append(&self.commitment)
            .append(&self.pub_key)
            .append(&self.cmm_key)
    }

    #[inline]
    fn get_challenge(&self, challenge: &random_oracle::Challenge) -> Self::ProtocolChallenge {
        C::scalar_from_bytes_mod(challenge)
    }

    #[inline]
    fn commit_point<R: Rng>(
        &self,
        csprng: &mut R,
    ) -> Option<(Self::CommitMessage, Self::ProverState)> {
        let beta = Value::generate_non_zero(csprng);
        let (rand_cipher, alpha) = self.pub_key.encrypt_exponent_rand(csprng, &beta);
        let (rand_cmm, gamma) = self.cmm_key.commit(&beta, csprng);
        Some(((rand_cipher, rand_cmm), (beta, alpha, gamma)))
    }

    #[inline]
    fn generate_witness(
        &self,
        secret: Self::SecretData,
        state: Self::ProverState,
        challenge: &Self::ProtocolChallenge,
    ) -> Option<Self::ProverWitness> {
        let x = &secret.value;
        let cR = &secret.elgamal_rand;
        let r = &secret.pedersen_rand;
        let mut z_1 = *challenge;
        let (beta, alpha, gamma) = state;
        z_1.negate();
        z_1.mul_assign(cR);
        z_1.add_assign(&alpha);

        let mut z_2 = *challenge;
        z_2.negate();
        z_2.mul_assign(x);
        z_2.add_assign(&beta);

        let mut z_3 = *challenge;
        z_3.negate();
        z_3.mul_assign(r);
        z_3.add_assign(&gamma);
        Some(Witness {
            witness: (z_1, z_2, z_3),
        })
    }

    #[inline]
    fn extract_point(
        &self,
        challenge: &Self::ProtocolChallenge,
        witness: &Self::ProverWitness,
    ) -> Option<Self::CommitMessage> {
        let g_1 = self.pub_key.generator;
        let h_1 = self.pub_key.key;
        let g = self.cmm_key.0;
        let h = self.cmm_key.1;

        let z_1 = witness.witness.0;
        let z_2 = witness.witness.1;
        let z_3 = witness.witness.2;

        let e_1 = self.cipher.0;
        let e_2 = self.cipher.1;
        let cC = self.commitment.0;

        let a_1 = g_1
            .mul_by_scalar(&z_1)
            .plus_point(&e_1.mul_by_scalar(&challenge));
        let a_2 = g_1
            .mul_by_scalar(&z_2)
            .plus_point(&h_1.mul_by_scalar(&z_1))
            .plus_point(&e_2.mul_by_scalar(&challenge));
        let a_3 = g
            .mul_by_scalar(&z_2)
            .plus_point(&h.mul_by_scalar(&z_3))
            .plus_point(&cC.mul_by_scalar(&challenge));
        Some((ElGamalCipher(a_1, a_2), Commitment(a_3)))
    }

    #[cfg(test)]
    fn with_valid_data<R: Rng>(
        _data_size: usize,
        csprng: &mut R,
        f: impl FnOnce(Self, Self::SecretData, &mut R) -> (),
    ) {
        use elgamal::SecretKey;
        let sk = SecretKey::generate_all(csprng);
        let public_key = ElGamalPublicKey::from(&sk);
        let comm_key = CommitmentKey::generate(csprng);

        let x = Value::generate_non_zero(csprng);
        let (cipher, elgamal_randomness) = public_key.encrypt_exponent_rand(csprng, &x);
        let (commitment, randomness) = comm_key.commit(&x, csprng);
        let secret = ComEncEqSecret {
            value:         x,
            elgamal_rand:  elgamal_randomness,
            pedersen_rand: randomness,
        };
        let com_enc_eq = ComEncEq {
            cipher,
            commitment,
            pub_key: public_key,
            cmm_key: comm_key,
        };
        f(com_enc_eq, secret, csprng)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elgamal::{Message, SecretKey as ElgamalSecretKey};
    use pairing::bls12_381::G1;

    #[test]
    pub fn test_com_enc_eq_correctness() {
        let mut csprng = thread_rng();
        for _i in 0..100 {
            ComEncEq::<G1>::with_valid_data(0, &mut csprng, |com_enc_eq, secret, csprng| {
                let challenge_prefix = generate_challenge_prefix(csprng);
                let ro = RandomOracle::domain(&challenge_prefix);
                let proof = prove(ro.split(), &com_enc_eq, secret, csprng)
                    .expect("Proving should succeed.");
                assert!(verify(ro, &com_enc_eq, &proof));
            })
        }
    }

    #[test]
    pub fn test_com_enc_eq_soundness() {
        let mut csprng = thread_rng();
        for _i in 0..100 {
            ComEncEq::<G1>::with_valid_data(0, &mut csprng, |com_enc_eq, secret, csprng| {
                let challenge_prefix = generate_challenge_prefix(csprng);
                let ro = RandomOracle::domain(&challenge_prefix);
                let proof = prove(ro.split(), &com_enc_eq, secret, csprng)
                    .expect("Proving should succeed.");
                assert!(verify(ro.split(), &com_enc_eq, &proof));

                // Construct invalid parameters
                let wrong_ro = RandomOracle::domain(generate_challenge_prefix(csprng));
                // Verify failure for invalid parameters
                assert!(!verify(wrong_ro, &com_enc_eq, &proof));
                let mut wrong_com_enc_eq = com_enc_eq;
                {
                    let tmp = wrong_com_enc_eq.cipher;
                    let m = Message::generate(csprng);
                    wrong_com_enc_eq.cipher = wrong_com_enc_eq.pub_key.encrypt(csprng, &m);
                    assert!(!verify(ro.split(), &wrong_com_enc_eq, &proof));
                    wrong_com_enc_eq.cipher = tmp;
                }

                {
                    let tmp = wrong_com_enc_eq.commitment;
                    let v = Value::<G1>::generate(csprng);
                    wrong_com_enc_eq.commitment = wrong_com_enc_eq.cmm_key.commit(&v, csprng).0;
                    assert!(!verify(ro.split(), &wrong_com_enc_eq, &proof));
                    wrong_com_enc_eq.commitment = tmp;
                }

                {
                    let tmp = wrong_com_enc_eq.pub_key;
                    wrong_com_enc_eq.pub_key =
                        ElGamalPublicKey::from(&ElgamalSecretKey::generate_all(csprng));
                    assert!(!verify(ro.split(), &wrong_com_enc_eq, &proof));
                    wrong_com_enc_eq.pub_key = tmp;
                }

                {
                    let tmp = wrong_com_enc_eq.cmm_key;
                    wrong_com_enc_eq.cmm_key = CommitmentKey::generate(csprng);
                    assert!(!verify(ro.split(), &wrong_com_enc_eq, &proof));
                    wrong_com_enc_eq.cmm_key = tmp;
                }
            })
        }
    }
}
