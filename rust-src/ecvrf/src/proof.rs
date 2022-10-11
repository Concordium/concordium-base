//! An VRF Proof.

use crate::{constants::*, errors::*};
use core::fmt::Debug;
use crypto_common::*;
use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use sha2::*;

/// Implements <https://tools.ietf.org/id/draft-irtf-cfrg-vrf-07.html#rfc.section.5.4.3>
pub fn hash_points(pts: &[CompressedEdwardsY]) -> Scalar {
    let mut hash: Sha512 = Sha512::new();
    hash.update(SUITE_STRING);
    hash.update(TWO_STRING);
    for p in pts {
        hash.update(p.to_bytes());
    }
    hash.update(ZERO_STRING);
    let mut c_bytes: [u8; 32] = [0; 32];
    // taking first n=16 bytes of the hash
    c_bytes[0..16].copy_from_slice(&hash.finalize().as_slice()[0..16]);
    Scalar::from_bytes_mod_order(c_bytes)
}

#[derive(Clone, PartialEq, Eq)]
/// Proof that the value produced by the VRF function is correct with respect to
/// a given public key.
pub struct Proof(pub EdwardsPoint, pub Scalar, pub Scalar);

/// Implements step 8 of <https://tools.ietf.org/id/draft-irtf-cfrg-vrf-07.html#rfc.section.5.1>
/// i.e. transforms a proof to a byte string
impl Serial for Proof {
    #[inline]
    fn serial<B: Buffer>(&self, x: &mut B) {
        let c = &self.1.reduce().to_bytes();
        // assert c is within range
        assert_eq!(c[16..32], [0u8; 16]);
        x.write_all(&self.0.compress().to_bytes()[..])
            .expect("Writing to buffer should succeed.");
        x.write_all(&c[..16])
            .expect("Writing to buffer should succeed.");
        x.write_all(&self.2.reduce().to_bytes()[..])
            .expect("Writing to buffer should succeed.");
    }
}

/// Implements <https://tools.ietf.org/id/draft-irtf-cfrg-vrf-07.html#rfc.section.5.4.4>
/// Construct a `Proof` from a slice of bytes. This function always
/// results in a valid proof object.
impl Deserial for Proof {
    #[inline]
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let mut point_bytes: [u8; 32] = [0u8; 32];
        source.read_exact(&mut point_bytes)?;
        let mut scalar_bytes1: [u8; 32] = [0u8; 32];
        source.read_exact(&mut scalar_bytes1[0..16])?;
        let mut scalar_bytes2: [u8; 32] = [0u8; 32];
        source.read_exact(&mut scalar_bytes2)?;
        let compressed_point = CompressedEdwardsY(point_bytes);
        match compressed_point.decompress() {
            None => Err(ProofError(InternalError::PointDecompression).into()),
            Some(p) => match Scalar::from_canonical_bytes(scalar_bytes1) {
                None => Err(ProofError(InternalError::ScalarFormat).into()),
                Some(s1) => match Scalar::from_canonical_bytes(scalar_bytes2) {
                    None => Err(ProofError(InternalError::ScalarFormat).into()),
                    Some(s2) => Ok(Proof(p, s1, s2)),
                },
            },
        }
    }
}

impl Debug for Proof {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        write!(f, "Proof( {:?}, {:?}, {:?} )", &self.0, &self.1, &self.2)
    }
}

/// Implements <https://tools.ietf.org/id/draft-irtf-cfrg-vrf-07.html#rfc.section.5.2>
impl Proof {
    pub fn to_hash(&self) -> [u8; 64] {
        let p = self.0.mul_by_cofactor();
        let hash: Sha512 = Sha512::new()
            .chain_update(SUITE_STRING)
            .chain_update(THREE_STRING)
            .chain_update(p.compress().to_bytes())
            .chain_update(ZERO_STRING);
        let mut c_bytes: [u8; 64] = [0; 64];
        c_bytes.copy_from_slice(hash.finalize().as_slice());
        c_bytes
    }
}
