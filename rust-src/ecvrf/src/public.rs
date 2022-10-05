//! ed25519 public keys.

use core::fmt::Debug;
use crypto_common::*;
use curve25519_dalek::{
    constants,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use sha2::{Digest, Sha512};

use crate::{constants::*, errors::*, proof::*, secret::*};
/// An ed25519-like public key. This has a bit stricter requirements than the
/// signature scheme public keys, in particular points of small order are not
/// allowed, and this is checked during serialization.
#[derive(Copy, Clone, Default, Eq, PartialEq)]
pub struct PublicKey(pub(crate) CompressedEdwardsY, pub(crate) EdwardsPoint);

impl Debug for PublicKey {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "PublicKey({:?}), {:?})", self.0, self.1)
    }
}

impl Serial for PublicKey {
    #[inline]
    fn serial<B: Buffer>(&self, x: &mut B) {
        x.write_all(&self.0.to_bytes())
            .expect("Writing to buffer should succeed.")
    }
}

/// Construct a `PublicKey` from a slice of bytes. This function always
/// results in a valid public key, in particular the curve point is not of
/// small order (and hence also not a point at infinity).
impl Deserial for PublicKey {
    #[inline]
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let mut buf = [0u8; PUBLIC_KEY_LENGTH];
        source.read_exact(&mut buf)?;

        let compressed = CompressedEdwardsY(buf);
        let point = compressed
            .decompress()
            .ok_or(ProofError(InternalError::PointDecompression))?;
        // Verify the public key is valid, c.f. verify_key below.
        // In particular check that the point is not the point at infinity.
        if !point.is_small_order() {
            Ok(PublicKey(compressed, point))
        } else {
            Err(ProofError(InternalError::Verify).into())
        }
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] { self.as_bytes() }
}

impl From<&SecretKey> for PublicKey {
    /// Derive this public key from its corresponding `SecretKey`.
    /// Implements <https://tools.ietf.org/html/rfc8032#section-5.1.5>
    fn from(secret_key: &SecretKey) -> PublicKey {
        let mut h: Sha512 = Sha512::new();
        let mut hash: [u8; 64] = [0u8; 64];
        let mut digest: [u8; 32] = [0u8; 32];

        h.update(secret_key.as_bytes());
        hash.copy_from_slice(h.finalize().as_slice());

        digest.copy_from_slice(&hash[..32]);

        PublicKey::mangle_scalar_bits_and_multiply_by_basepoint_to_produce_public_key(&mut digest)
    }
}

impl From<&ExpandedSecretKey> for PublicKey {
    /// Derive this public key from its corresponding `ExpandedSecretKey`.
    fn from(expanded_secret_key: &ExpandedSecretKey) -> PublicKey {
        let mut bits: [u8; 32] = expanded_secret_key.key.to_bytes();

        PublicKey::mangle_scalar_bits_and_multiply_by_basepoint_to_produce_public_key(&mut bits)
    }
}

impl PublicKey {
    /// View this public key as a byte array.
    #[inline]
    pub fn as_bytes(&self) -> &'_ [u8; PUBLIC_KEY_LENGTH] { &(self.0).0 }

    /// Internal utility function for mangling the bits of a (formerly
    /// mathematically well-defined) "scalar" and multiplying it to produce a
    /// public key.
    fn mangle_scalar_bits_and_multiply_by_basepoint_to_produce_public_key(
        bits: &mut [u8; 32],
    ) -> PublicKey {
        bits[0] &= 0b_1111_1000;
        bits[31] &= 0b_0111_1111;
        bits[31] |= 0b_0100_0000;

        let point = &Scalar::from_bits(*bits) * &constants::ED25519_BASEPOINT_TABLE;
        let compressed = point.compress();

        PublicKey(compressed, point)
    }

    /// Implements <https://tools.ietf.org/id/draft-irtf-cfrg-vrf-07.html#rfc.section.5.4.1.1>
    /// The failure should not happen in practice, expected number of iterations
    /// is 2.
    pub fn hash_to_curve(&self, message: &[u8]) -> Option<EdwardsPoint> {
        let mut p_candidate_bytes = [0u8; 32];
        let mut h: Sha512 = Sha512::new();
        h.update(SUITE_STRING);
        h.update(ONE_STRING);
        h.update(&self.as_bytes()); // PK_string
        h.update(&message); // alpha_string
        for ctr in 0..=u8::max_value() {
            // Each iteration fails, indpendent of other iterations, with probability about
            // a half. This happens if the digest does not represent a point on
            // the curve when decoded as in https://tools.ietf.org/html/rfc8032#section-5.1.3
            let mut attempt_h = h.clone();
            attempt_h.update(ctr.to_le_bytes()); // ctr_string
            attempt_h.update(ZERO_STRING);
            let hash = attempt_h.finalize();
            p_candidate_bytes.copy_from_slice(&hash[..32]);
            let p_candidate = CompressedEdwardsY(p_candidate_bytes);
            if let Some(ed_point) = p_candidate.decompress() {
                // Make sure the point is not of small order, i.e., it will
                // not be 0 after multiplying by cofactor.
                if !ed_point.is_small_order() {
                    return Some(ed_point.mul_by_cofactor());
                }
            }
        }
        None
    }

    pub fn verify_key(&self) -> bool { !self.1.is_small_order() }

    /// Implements <https://tools.ietf.org/id/draft-irtf-cfrg-vrf-07.html#rfc.section.5.3>
    #[allow(clippy::many_single_char_names)]
    pub fn verify(&self, pi: &Proof, message: &[u8]) -> bool {
        if let Some(h) = self.hash_to_curve(message) {
            let Proof(gamma, c, s) = pi; // s should be equal k + cx, where k is a deterministically
                                         // generated nonce and x is the secret key
                                         // self should be equal y=b^x

            let b_to_s = s * &constants::ED25519_BASEPOINT_TABLE; // should be equal to b^(k+cx)
            let y_to_c = c * self.1; // y_to_c should be equal to b^(cx)
            let u = b_to_s - y_to_c; // should equal b^k

            let h_to_s = s * h; // should equal h^(k + cx)
            let gamma_to_c = c * gamma; // should equal h^cx
            let v = h_to_s - gamma_to_c; // should equal h^k

            let derivable_c =
                hash_points(&[h.compress(), gamma.compress(), u.compress(), v.compress()]);
            *c == derivable_c
        } else {
            false
        }
    }
}
