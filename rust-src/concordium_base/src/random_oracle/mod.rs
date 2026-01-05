//! This module provides the random oracle replacement function needed in the
//! sigma protocols, bulletproofs, and any other constructions. It is based on
//! SHA3.
//!
//! # Using the random oracle replacement
//! [`RandomOracle`] instances should be initialized with at domain-separation
//! string and passed to protocols by mutable borrow. Protocols should update
//! the state of the [`RandomOracle`], allowing them to be sequentially
//! composed.
//!
//! The [`RandomOracle`] instance used to verify a proof needs to be initialised
//! with the context used to produce the proof. Any verification of sub-proofs
//! needs to be performed in the same order as when producing the proof.

use crate::{common::*, curve_arithmetic::Curve};
use sha3::{Digest, Sha3_256};
use std::io::Write;

/// State of the random oracle, used to incrementally build up the output.
#[repr(transparent)]
#[derive(Debug)]
pub struct RandomOracle(Sha3_256);

/// Type of challenges computed from the random oracle.
/// We use 32 byte output of SHA3-256
#[derive(Debug, Serialize, PartialEq, Eq, Clone, Copy)]
pub struct Challenge {
    challenge: [u8; 32],
}

impl AsRef<[u8]> for Challenge {
    fn as_ref(&self) -> &[u8] {
        &self.challenge
    }
}

/// This implementation allows the use of a random oracle without intermediate
/// allocations of byte buffers.
impl Write for RandomOracle {
    #[inline(always)]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    #[inline(always)]
    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.0.update(buf);
        Ok(())
    }

    #[inline(always)]
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// This implementation allows the use of a random oracle without intermediate
/// allocations of byte buffers.
impl Buffer for RandomOracle {
    type Result = sha3::digest::Output<Sha3_256>;

    #[inline(always)]
    fn start() -> Self {
        RandomOracle::empty()
    }

    // Compute the result in the given state, consuming the state.
    fn result(self) -> Self::Result {
        self.0.finalize()
    }
}

impl Eq for RandomOracle {}

impl PartialEq for RandomOracle {
    fn eq(&self, other: &Self) -> bool {
        self.0.clone().finalize() == other.0.clone().finalize()
    }
}

impl RandomOracle {
    /// Start with the initial empty state of the oracle.
    pub fn empty() -> Self {
        RandomOracle(Sha3_256::new())
    }

    /// Start with the initial domain string.
    pub fn domain<B: AsRef<[u8]>>(data: B) -> Self {
        RandomOracle(Sha3_256::new().chain_update(data))
    }

    /// Duplicate the random oracle, creating a fresh copy of it.
    /// Further updates are independent.
    pub fn split(&self) -> Self {
        RandomOracle(self.0.clone())
    }

    /// Append the input to the state of the oracle.
    pub fn add<B: Serial>(&mut self, data: &B) {
        self.put(data)
    }

    pub fn add_bytes<B: AsRef<[u8]>>(&mut self, data: B) {
        self.0.update(data)
    }

    /// Append the input to the state of the oracle, using `label` as domain
    /// separation.
    pub fn append_message<S: Serial, B: AsRef<[u8]>>(&mut self, label: B, message: &S) {
        self.add_bytes(label);
        self.add(message)
    }

    /// Append all items from an iterator to the random oracle. Equivalent to
    /// repeatedly calling append in sequence.
    /// Returns the new state of the random oracle, consuming the initial state.
    pub fn extend_from<'a, I, S, B: AsRef<[u8]>>(&mut self, label: B, iter: I)
    where
        S: Serial + 'a,
        I: IntoIterator<Item = &'a S>,
    {
        self.add_bytes(label);
        for i in iter.into_iter() {
            self.add(i)
        }
    }

    /// Try to convert the computed result into a field element. This interprets
    /// the output of the random oracle as a big-endian integer and reduces is
    /// mod field order.
    pub fn result_to_scalar<C: Curve>(self) -> C::Scalar {
        C::scalar_from_bytes(self.result())
    }

    /// Get a challenge from the current state, consuming the state.
    pub fn get_challenge(self) -> Challenge {
        Challenge {
            challenge: self.result().into(),
        }
    }

    /// Get a challenge in the form of a Scalar, using `label` as domain
    /// separation.
    pub fn challenge_scalar<C: Curve, B: AsRef<[u8]>>(&mut self, label: B) -> C::Scalar {
        self.add_bytes(label);
        self.split().result_to_scalar::<C>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common;
    use crate::id::constants::ArCurve;
    use rand::*;

    // Tests that extend_from acts in the intended way.
    #[test]
    pub fn test_extend_from() {
        let mut v1 = vec![0u8; 50];
        let mut csprng = thread_rng();
        for _ in 0..1000 {
            for v in v1.iter_mut() {
                *v = csprng.gen::<u8>();
            }
            let mut s1 = RandomOracle::empty();
            for x in v1.iter() {
                s1.add(x);
            }
            let mut s2 = RandomOracle::empty();
            s2.extend_from(b"", v1.iter());
            let res1 = s1.result();
            let ref_res1: &[u8] = res1.as_ref();
            let res2 = s2.result();
            let ref_res2: &[u8] = res2.as_ref();
            assert_eq!(ref_res1, ref_res2);
        }
    }

    #[test]
    pub fn test_split() {
        let mut v1 = vec![0u8; 50];
        let mut csprng = thread_rng();
        for _ in 0..1000 {
            let mut s1 = RandomOracle::empty();
            s1.add(&v1);
            let mut s2 = s1.split();
            for v in v1.iter_mut() {
                *v = csprng.gen::<u8>();
                s1.add(v);
            }
            let res1 = s1.result();
            let ref_res1: &[u8] = res1.as_ref();
            s2.add_bytes(&v1);
            let res2 = s2.result();
            let ref_res2: &[u8] = res2.as_ref();
            assert_eq!(ref_res1, ref_res2);
        }
    }

    /// Test that we don't accidentally change the digest produced
    /// by [`RandomOracle::domain`]
    #[test]
    pub fn test_domain_stable() {
        let ro = RandomOracle::domain("Domain1");

        let challenge_hex = hex::encode(ro.get_challenge());
        assert_eq!(
            challenge_hex,
            "b6dbfe8bfbc515d92bcc322b1e98291a45536f81f6eca2411d8dae54766666f1"
        );
    }

    /// Test that we don't accidentally change the digest produced
    /// by [`RandomOracle::add_bytes`]
    #[test]
    pub fn test_add_bytes_stable() {
        let mut ro = RandomOracle::empty();
        ro.add_bytes([1u8, 2, 3]);

        let challenge_hex = hex::encode(ro.get_challenge());
        assert_eq!(
            challenge_hex,
            "fd1780a6fc9ee0dab26ceb4b3941ab03e66ccd970d1db91612c66df4515b0a0a"
        );
    }

    /// Test that we don't accidentally change the digest produced
    /// by [`StructuredDigest::append_message`]
    #[test]
    pub fn test_append_message_stable() {
        let mut ro = RandomOracle::empty();
        ro.append_message("Label1", &vec![1u8, 2, 3]);

        let challenge_hex = hex::encode(ro.get_challenge());
        assert_eq!(
            challenge_hex,
            "3756eec6f9241f9a1cd8b401f54679cf9be2e057365728336221b1871ff666fb"
        );
    }

    /// Test that we don't accidentally change the scalar produced
    /// by [`RandomOracle::challenge_scalar`]
    #[test]
    pub fn test_challenge_scalar_stable() {
        let mut ro = RandomOracle::empty();

        let scalar_hex = hex::encode(common::to_bytes(
            &ro.challenge_scalar::<ArCurve, _>("Scalar1"),
        ));
        assert_eq!(
            scalar_hex,
            "08646777f9c47efc863115861aa18d95653212c3bdf36899c7db46fbdae095cd"
        );
    }

    /// Test that we don't accidentally change the digest produced
    /// by [`RandomOracle::extend_from`]
    #[test]
    pub fn test_extend_from_stable() {
        let mut ro = RandomOracle::empty();
        ro.extend_from("Label1", &vec![1u8, 2, 3]);

        let challenge_hex = hex::encode(ro.get_challenge());
        assert_eq!(
            challenge_hex,
            "6b1addb1c08e887242f5e78127c31c17851f29349c45aa415adce255f95fd292"
        );
    }
}
