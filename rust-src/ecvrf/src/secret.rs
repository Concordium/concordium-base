//! ed25519 secret key types.

use crate::{constants::*, errors::*, public::*};
use core::fmt::Debug;
use crypto_common::*;
use curve25519_dalek::{constants, digest::Digest, scalar::Scalar};
use rand::{CryptoRng, Rng};
use sha2::Sha512;
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

    #[allow(non_snake_case)]
    pub fn prove(&self, public_key: &PublicKey, message: &[u8]) -> Proof {
        ExpandedSecretKey::from(self).prove(&public_key, &message)
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

#[cfg(feature = "serde")]
impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer, {
        serializer.serialize_bytes(self.as_bytes())
    }
}

#[cfg(feature = "serde")]
impl<'d> Deserialize<'d> for SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>, {
        struct SecretKeyVisitor;

        impl<'d> Visitor<'d> for SecretKeyVisitor {
            type Value = SecretKey;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                formatter.write_str("An ed25519 secret key as 32 bytes, as specified in RFC8032.")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<SecretKey, E>
            where
                E: SerdeError, {
                SecretKey::from_bytes(bytes).or(Err(SerdeError::invalid_length(bytes.len(), &self)))
            }
        }
        deserializer.deserialize_bytes(SecretKeyVisitor)
    }
}

/// An "expanded" secret key.
///
/// This is produced by using an hash function with 512-bits output to digest a
/// `SecretKey`.  The output digest is then split in half, the lower half being
/// the actual `key` used to sign messages, after twiddling with some bits.¹ The
/// upper half is used a sort of half-baked, ill-designed²
/// pseudo-domain-separation "nonce"-like thing, which is used during signature
/// production by concatenating it with the message to be signed before the
/// message is hashed.
// ¹ This results in a slight bias towards non-uniformity at one spectrum of
// the range of valid keys.  Oh well: not my idea; not my problem.
//
// ² It is the author's view (specifically, isis agora lovecruft, in the event
// you'd like to complain about me, again) that this is "ill-designed" because
// this doesn't actually provide true hash domain separation, in that in many
// real-world applications a user wishes to have one key which is used in
// several contexts (such as within tor, which does does domain separation
// manually by pre-concatenating static strings to messages to achieve more
// robust domain separation).  In other real-world applications, such as
// bitcoind, a user might wish to have one master keypair from which others are
// derived (à la BIP32) and different domain separators between keys derived at
// different levels (and similarly for tree-based key derivation constructions,
// such as hash-based signatures).  Leaving the domain separation to
// application designers, who thus far have produced incompatible,
// slightly-differing, ad hoc domain separation (at least those application
// designers who knew enough cryptographic theory to do so!), is therefore a
// bad design choice on the part of the cryptographer designing primitives
// which should be simple and as foolproof as possible to use for
// non-cryptographers.  Further, later in the ed25519 signature scheme, as
// specified in RFC8032, the public key is added into *another* hash digest
// (along with the message, again); it is unclear to this author why there's
// not only one but two poorly-thought-out attempts at domain separation in the
// same signature scheme, and which both fail in exactly the same way.  For a
// better-designed, Schnorr-based signature scheme, see Trevor Perrin's work on
// "generalised EdDSA" and "VXEdDSA".
pub struct ExpandedSecretKey {
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

impl<'a> From<&'a SecretKey> for ExpandedSecretKey {
    /// Construct an `ExpandedSecretKey` from a `SecretKey`.
    /// Implements <https://tools.ietf.org/html/rfc8032#section-5.1.5>
    fn from(secret_key: &'a SecretKey) -> ExpandedSecretKey {
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
    /// Convert this `ExpandedSecretKey` into an array of 64 bytes.
    ///
    /// # Returns
    ///
    /// An array of 64 bytes.  The first 32 bytes represent the "expanded"
    /// secret key, and the last 32 bytes represent the "domain-separation"
    /// "nonce".
    #[inline]
    pub fn to_bytes(&self) -> [u8; EXPANDED_SECRET_KEY_LENGTH] {
        let mut bytes: [u8; 64] = [0u8; 64];

        bytes[..32].copy_from_slice(self.key.as_bytes());
        bytes[32..].copy_from_slice(&self.nonce[..]);
        bytes
    }

    /// Construct an `ExpandedSecretKey` from a slice of bytes.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<ExpandedSecretKey, ProofError> {
        if bytes.len() != EXPANDED_SECRET_KEY_LENGTH {
            return Err(ProofError(InternalError::BytesLength {
                name:   "ExpandedSecretKey",
                length: EXPANDED_SECRET_KEY_LENGTH,
            }));
        }
        let mut lower: [u8; 32] = [0u8; 32];
        let mut upper: [u8; 32] = [0u8; 32];

        lower.copy_from_slice(&bytes[00..32]);
        upper.copy_from_slice(&bytes[32..64]);

        Ok(ExpandedSecretKey {
            key:   Scalar::from_bits(lower),
            nonce: upper,
        })
    }

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
        let h: Sha512 = Sha512::new().chain(self.nonce).chain(h_string);
        Scalar::from_hash(h)
    }
}
