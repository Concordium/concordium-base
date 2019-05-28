// -*- mode: rust; -*-
//
// Authors:
// - bm@concordium.com

//! An VRF Proof.

use core::fmt::Debug;

use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};

#[cfg(feature = "serde")]
use serde::de::Error as SerdeError;
#[cfg(feature = "serde")]
use serde::de::Unexpected::Bytes;
#[cfg(feature = "serde")]
use serde::de::Visitor;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde::{Deserializer, Serializer};

use crate::{constants::*, errors::*};

use sha2::*;

pub fn hash_points(pts: &[CompressedEdwardsY]) -> Scalar {
    let mut hash: Sha256 = Sha256::new();
    for p in pts {
        hash.input(p.to_bytes());
    }
    let mut c_bytes: [u8; 32] = [0; 32];
    // taking firt 16 bytes of the hash
    c_bytes[0..16].copy_from_slice(&hash.result().as_slice()[0..16]);
    Scalar::from_bytes_mod_order(c_bytes)
}

#[derive(Copy, Clone)]

pub struct Proof(pub EdwardsPoint, pub Scalar, pub Scalar);

// impl Clone for Proof {
//    fn clone(&self) -> Self {
//        *self
//    }
//}

impl Debug for Proof {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "Proof( {:?}, {:?}, {:?} )", &self.0, &self.1, &self.2)
    }
}

impl Proof {
    /// Convert this `Proof` to a byte array.
    #[inline]
    pub fn to_bytes(&self) -> [u8; PROOF_LENGTH] {
        let c = &self.1.reduce().to_bytes();
        // assert c is within range
        assert_eq!(c[16..32], [0u8; 16]);
        let mut proof_bytes: [u8; PROOF_LENGTH] = [0u8; PROOF_LENGTH];
        proof_bytes[..32].copy_from_slice(&self.0.compress().to_bytes()[..]);
        proof_bytes[32..48].copy_from_slice(&c[..16]);
        proof_bytes[48..].copy_from_slice(&self.2.reduce().to_bytes()[..]);
        proof_bytes
    }

    pub fn from_bytes(proof_bytes: &[u8; PROOF_LENGTH]) -> Result<Self, ProofError> {
        let mut point_bytes: [u8; 32] = [0u8; 32];
        point_bytes.copy_from_slice(&proof_bytes[..32]);
        let mut scalar_bytes1: [u8; 32] = [0u8; 32];
        scalar_bytes1[0..16].copy_from_slice(&proof_bytes[32..48]);
        let mut scalar_bytes2: [u8; 32] = [0u8; 32];
        scalar_bytes2.copy_from_slice(&proof_bytes[48..PROOF_LENGTH]);
        let compressed_point = CompressedEdwardsY(point_bytes);
        match compressed_point.decompress() {
            None => Err(ProofError(InternalError::PointDecompression)),
            Some(p) => match Scalar::from_canonical_bytes(scalar_bytes1) {
                None => Err(ProofError(InternalError::ScalarFormat)),
                Some(s1) => match Scalar::from_canonical_bytes(scalar_bytes2) {
                    None => Err(ProofError(InternalError::ScalarFormat)),
                    Some(s2) => Ok(Proof(p, s1, s2)),
                },
            },
        }
    }

    pub fn to_hash(&self) -> [u8; 32] {
        let p = self.0.mul_by_cofactor();
        let mut hash: Sha256 = Sha256::new();
        hash.input(p.compress().to_bytes());
        let mut c_bytes: [u8; 32] = [0; 32];
        c_bytes.copy_from_slice(&hash.result().as_slice());
        c_bytes
    }
}

#[cfg(feature = "serde")]
impl Serialize for Proof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer, {
        serializer.serialize_bytes(&self.to_bytes()[..])
    }
}

#[cfg(feature = "serde")]
impl<'d> Deserialize<'d> for Proof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>, {
        struct ProofVisitor;

        impl<'d> Visitor<'d> for ProofVisitor {
            type Value = Proof;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                formatter
                    .write_str("An vrf-ed25519-sha256 proof as 80 bytes, as specified in RFCXXX.")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Proof, E>
            where
                E: SerdeError, {
                if bytes.len() != PROOF_LENGTH {
                    Err(SerdeError::invalid_length(bytes.len(), &self))
                } else {
                    let mut bytes_copy = [0u8; PROOF_LENGTH];
                    bytes_copy.copy_from_slice(bytes);
                    Proof::from_bytes(&bytes_copy)
                        .or(Err(SerdeError::invalid_value(Bytes(bytes), &self)))
                }
            }
        }
        deserializer.deserialize_bytes(ProofVisitor)
    }
}
