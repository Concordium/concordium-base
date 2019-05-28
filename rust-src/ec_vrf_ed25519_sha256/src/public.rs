// -*- mode: rust; -*-
//
// This file is part of concordium_crypto
// Copyright (c) 2019 -
// See LICENSE for licensing information.
//
// Authors:
// - bm@concordium.com

//! ed25519 public keys.

use core::fmt::Debug;

use curve25519_dalek::constants;
use curve25519_dalek::digest::Digest;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

pub use sha2::Sha512;
pub use sha2::Sha256;

#[cfg(feature = "serde")]
use serde::de::Error as SerdeError;
#[cfg(feature = "serde")]
use serde::de::Visitor;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde::{Deserializer, Serializer};

use crate::constants::*;
use crate::errors::*;
use crate::secret::*;
use crate::proof::*;
/// An ed25519 public key.
#[derive(Copy, Clone, Default, Eq, PartialEq)]
pub struct PublicKey(pub(crate) CompressedEdwardsY, pub(crate) EdwardsPoint);

impl Debug for PublicKey {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "PublicKey({:?}), {:?})", self.0, self.1)
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}


impl<'a> From<&'a SecretKey> for PublicKey {
    /// Derive this public key from its corresponding `SecretKey`.
    fn from(secret_key: &SecretKey) -> PublicKey {
        let mut h: Sha512 = Sha512::new();
        let mut hash: [u8; 64] = [0u8; 64];
        let mut digest: [u8; 32] = [0u8; 32];

        h.input(secret_key.as_bytes());
        hash.copy_from_slice(h.result().as_slice());

        digest.copy_from_slice(&hash[..32]);

        PublicKey::mangle_scalar_bits_and_multiply_by_basepoint_to_produce_public_key(&mut digest)
    }
}

impl<'a> From<&'a ExpandedSecretKey> for PublicKey {
    /// Derive this public key from its corresponding `ExpandedSecretKey`.
    fn from(expanded_secret_key: &ExpandedSecretKey) -> PublicKey {
        let mut bits: [u8; 32] = expanded_secret_key.key.to_bytes();

        PublicKey::mangle_scalar_bits_and_multiply_by_basepoint_to_produce_public_key(&mut bits)
    }
}

impl PublicKey {
    /// Convert this public key to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.0.to_bytes()
    }

    /// View this public key as a byte array.
    #[inline]
    pub fn as_bytes(&self) -> &'_ [u8; PUBLIC_KEY_LENGTH] {
        &(self.0).0
    }

    /// Construct a `PublicKey` from a slice of bytes.
    ///
    /// # Warning
    ///
    /// The caller is responsible for ensuring that the bytes passed into this
    /// method actually represent a `curve25519_dalek::curve::CompressedEdwardsY`
    /// and that said compressed point is actually a point on the curve.
    ///
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, ProofError> {
        if bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(ProofError(InternalError::BytesLength {
                name: "PublicKey",
                length: PUBLIC_KEY_LENGTH,
            }));
        }
        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&bytes[..32]);

        let compressed = CompressedEdwardsY(bits);
        let point = compressed
            .decompress()
            .ok_or(ProofError(InternalError::PointDecompression))?;

        Ok(PublicKey(compressed, point))
    }
    

    /// Internal utility function for mangling the bits of a (formerly
    /// mathematically well-defined) "scalar" and multiplying it to produce a
    /// public key.
    fn mangle_scalar_bits_and_multiply_by_basepoint_to_produce_public_key(
        bits: &mut [u8; 32],
    ) -> PublicKey {
        bits[0] &= 248;
        bits[31] &= 127;
        bits[31] |= 64;

        let point = &Scalar::from_bits(*bits) * &constants::ED25519_BASEPOINT_TABLE;
        let compressed = point.compress();

        PublicKey(compressed, point)
    }

    pub fn hash_to_curve(&self, message: &[u8]) -> Result<EdwardsPoint, ProofError>{
        let mut ctr = 0u32;
        let mut done = false;
        let mut p_candidate_bytes = [0u8;32];
        let mut h: Sha256 = Sha256::new();        
        h.input(&self.as_bytes());
        h.input(&message);
        while !done {
            let mut attempt_h = h.clone();
            attempt_h.input(ctr.to_be_bytes());
            let hash = attempt_h.result();
            p_candidate_bytes.copy_from_slice(hash.as_slice());
            let p_candidate = CompressedEdwardsY(p_candidate_bytes);
            if let Some(ed_point)= p_candidate.decompress(){
                return Ok(ed_point.mul_by_cofactor());
            }
            if ctr== u32::max_value() {done=true;} else {ctr += 1;}
        }
        Err(ProofError(InternalError::PointDecompression))
    }
    pub fn verify_key(public_key_bytes: &[u8;32])->bool{
        match PublicKey::from_bytes(public_key_bytes){
            Ok(pk) => ! pk.1.is_small_order(),
            _      => false
        }
    }

    // TODO : Rename variable names more appropriately
    #[allow(clippy::many_single_char_names)]
    pub fn verify(&self, pi: Proof, message: &[u8])-> bool{
        let Proof(point, c, s) = pi; //s should be equal k- c x, where k is random and x is secret key
                                     //self should be equal g^x
        let g_to_s = &s * &constants::ED25519_BASEPOINT_TABLE;//should be equal to g^(k-c x)
        let self_to_c = c * self.1; //self_to_c should be equal to g^(cx)
        let u = self_to_c + g_to_s; //should equal g^k
        match self.hash_to_curve(message) {
            Err(_) => false,
            Ok (h) => {
                let v = (c * point) + (s * h); //should equal h^cs * h^(k-cx) = h^k
                let derivable_c = hash_points(&[
                                              constants::ED25519_BASEPOINT_COMPRESSED,
                                              h.compress(),
                                              self.0,
                                              point.compress(),
                                              u.compress(),
                                              v.compress()
                ]);
                c==derivable_c
            } 
        }
    }

}

#[cfg(feature = "serde")]
impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_bytes())
    }
}

#[cfg(feature = "serde")]
impl<'d> Deserialize<'d> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        struct PublicKeyVisitor;

        impl<'d> Visitor<'d> for PublicKeyVisitor {
            type Value = PublicKey;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                formatter.write_str(
                    "An ed25519 public key as a 32-byte compressed point, as specified in RFC8032",
                )
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<PublicKey, E>
            where
                E: SerdeError,
            {
                PublicKey::from_bytes(bytes).or(Err(SerdeError::invalid_length(bytes.len(), &self)))
            }
        }
        deserializer.deserialize_bytes(PublicKeyVisitor)
    }
}
