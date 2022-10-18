//! ed25519 secret key types.

use crate::{constants::*, errors::*, public::*};
use core::fmt::Debug;
use crypto_common::*;
use curve25519_dalek::{constants, scalar::Scalar};
use rand::{CryptoRng, Rng};
use sha2::{digest::Digest, Sha512};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

/// An EdDSA secret key.
pub struct SecretKey(pub(crate) [u8; SECRET_KEY_LENGTH]);

impl ConstantTimeEq for SecretKey {
    fn ct_eq(&self, other: &Self) -> Choice { self.0.ct_eq(&other.0) }
}

impl Serial for SecretKey {
    #[inline]
    fn serial<B: Buffer>(&self, x: &mut B) {
        x.write_all(&self.0)
            .expect("Writing to buffer should succeed.")
    }
}

/// Construct a `SecretKey` from a slice of bytes.
impl Deserial for SecretKey {
    #[inline]
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let mut buf = [0u8; SECRET_KEY_LENGTH];
        source.read_exact(&mut buf)?;
        Ok(SecretKey(buf))
    }
}

impl Debug for SecretKey {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "SecretKey: {:?}", &self.0[..])
    }
}

/// Overwrite secret key material with null bytes when it goes out of scope.
impl Drop for SecretKey {
    fn drop(&mut self) { self.0.zeroize(); }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] { self.as_bytes() }
}

impl SecretKey {
    /// Convert this secret key to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> Box<[u8]> { Box::new(self.0) }

    /// View this secret key as a byte array.
    #[inline]
    pub fn as_bytes(&self) -> &'_ [u8; SECRET_KEY_LENGTH] { &self.0 }

    /// Construct a `SecretKey` from a slice of bytes.
    ///
    /// A `Result` whose okay value is an EdDSA `SecretKey` or whose error value
    /// is an `ProofError` wrapping the internal error that occurred.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<SecretKey, ProofError> {
        if bytes.len() != SECRET_KEY_LENGTH {
            return Err(ProofError(InternalError::BytesLength {
                name:   "SecretKey",
                length: SECRET_KEY_LENGTH,
            }));
        }
        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&bytes[..32]);

        Ok(SecretKey(bits))
    }

    /// Construct a VRF proof seeded by the given message.
    pub fn prove(&self, public_key: &PublicKey, message: &[u8]) -> Proof {
        ExpandedSecretKey::from(self).prove(public_key, message)
    }

    /// Generate a `SecretKey` from a `csprng`.
    pub fn generate<T>(csprng: &mut T) -> SecretKey
    where
        T: CryptoRng + Rng, {
        let mut sk: SecretKey = SecretKey([0u8; 32]);

        csprng.fill_bytes(&mut sk.0);

        sk
    }
}

/// An "expanded" secret key used internally as a step from a secret key to
/// signing.
pub(crate) struct ExpandedSecretKey {
    pub(crate) key:   Scalar,
    pub(crate) nonce: [u8; 32],
}

/// Overwrite secret key material with null bytes when it goes out of scope.
impl Drop for ExpandedSecretKey {
    fn drop(&mut self) {
        self.key.zeroize();
        self.nonce.zeroize();
    }
}

impl From<&SecretKey> for ExpandedSecretKey {
    /// Construct an `ExpandedSecretKey` from a `SecretKey`.
    /// Implements <https://tools.ietf.org/html/rfc8032#section-5.1.5>
    fn from(secret_key: &SecretKey) -> ExpandedSecretKey {
        let mut h: Sha512 = Sha512::new();
        let mut hash: [u8; 64] = [0u8; 64];
        let mut lower: [u8; 32] = [0u8; 32];
        let mut upper: [u8; 32] = [0u8; 32];

        h.update(secret_key.as_bytes());
        hash.copy_from_slice(h.finalize().as_slice());

        lower.copy_from_slice(&hash[00..32]);
        upper.copy_from_slice(&hash[32..64]);

        lower[0] &= 0b_1111_1000;
        lower[31] &= 0b_0111_1111;
        lower[31] |= 0b_0100_0000;

        ExpandedSecretKey {
            key:   Scalar::from_bits(lower),
            nonce: upper,
        }
    }
}
use crate::proof::*;

impl ExpandedSecretKey {
    /// VRF proof with expanded secret key
    /// Implements <https://tools.ietf.org/id/draft-irtf-cfrg-vrf-07.html#rfc.section.5.1>
    pub fn prove(&self, public_key: &PublicKey, alpha: &[u8]) -> Proof {
        let x = self.key;
        let h = public_key
            .hash_to_curve(alpha)
            .expect("Failure should not happen for non-maliciously crafted input.");
        let h_string = h.compress().to_bytes();
        let k = self.nonce_generation(&h_string);

        let gamma = x * h;

        let c = hash_points(&[
            h.compress(),
            gamma.compress(),
            (k * constants::ED25519_BASEPOINT_POINT).compress(), // b^k
            (k * h).compress(),                                  // h^k
        ]);

        let k_plus_cx = k + c * x;

        Proof(gamma, c, k_plus_cx)
    }

    /// Implements <https://tools.ietf.org/id/draft-irtf-cfrg-vrf-07.html#rfc.section.5.4.2.2>
    fn nonce_generation(&self, h_string: &[u8]) -> Scalar {
        let digest = Sha512::new()
            .chain_update(self.nonce)
            .chain_update(h_string)
            .finalize();
        Scalar::from_bytes_mod_order_wide(&digest.into())
    }
}
