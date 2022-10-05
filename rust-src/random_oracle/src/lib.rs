//! This module provides the random oracle replacement function needed in the
//! sigma protocols, bulletproofs, and any other constructions. It is based on
//! SHA3.
use crypto_common::*;
use crypto_common_derive::Serialize;
use curve_arithmetic::Curve;
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
    fn as_ref(&self) -> &[u8] { &self.challenge }
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
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

/// This implementation allows the use of a random oracle without intermediate
/// allocations of byte buffers.
impl Buffer for RandomOracle {
    type Result = sha3::digest::Output<Sha3_256>;

    #[inline(always)]
    fn start() -> Self { RandomOracle::empty() }

    // Compute the result in the given state, consuming the state.
    fn result(self) -> Self::Result { self.0.finalize() }
}

impl Eq for RandomOracle {}

impl PartialEq for RandomOracle {
    fn eq(&self, other: &Self) -> bool { self.0.clone().finalize() == other.0.clone().finalize() }
}

impl RandomOracle {
    /// Start with the initial empty state of the oracle.
    pub fn empty() -> Self { RandomOracle(Sha3_256::new()) }

    /// Start with the initial domain string.
    pub fn domain<B: AsRef<[u8]>>(data: B) -> Self {
        RandomOracle(Sha3_256::new().chain_update(data))
    }

    /// Duplicate the random oracle, creating a fresh copy of it.
    /// Further updates are independent.
    pub fn split(&self) -> Self { RandomOracle(self.0.clone()) }

    /// Append the input to the state of the oracle.
    pub fn add<B: Serial>(&mut self, data: &B) { self.put(data) }

    pub fn add_bytes<B: AsRef<[u8]>>(&mut self, data: B) { self.0.update(data) }

    /// Append the input to the state of the oracle, using `label` as domain
    /// separation.
    pub fn append_message<S: Serial, B: AsRef<[u8]>>(&mut self, label: B, message: &S) {
        self.add_bytes(label);
        self.add(message)
    }

    /// Append all items from an iterator to the random oracle. Equivalent to
    /// repeatedly calling append in sequence.
    /// Returns the new state of the random oracle, consuming the initial state.
    pub fn extend_from<'a, I, S: 'a, B: AsRef<[u8]>>(&mut self, label: B, iter: I)
    where
        S: Serial,
        I: IntoIterator<Item = &'a S>, {
        self.add_bytes(label);
        for i in iter.into_iter() {
            self.add(i)
        }
    }

    /// Try to convert the computed result into a field element. This interprets
    /// the output of the random oracle as a big-endian integer and reduces is
    /// mod field order.
    pub fn result_to_scalar<C: Curve>(self) -> C::Scalar { C::scalar_from_bytes(self.result()) }

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
}
