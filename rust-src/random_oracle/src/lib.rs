//! This module provides the random oracle replacement function needed in the
//! sigma protocols, and any other constructions needing it.
use crypto_common::*;
use crypto_common_derive::Serialize;
use curve_arithmetic::Curve;

use sha3::{Digest, Sha3_256};
use std::io::Write;

/// State of the random oracle, used to incrementally build up the output.
#[repr(transparent)]
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

impl Buffer for RandomOracle {
    type Result = sha3::digest::generic_array::GenericArray<
        u8,
        <Sha3_256 as sha3::digest::Digest>::OutputSize,
    >;

    #[inline(always)]
    fn start() -> Self { RandomOracle::empty() }

    // Compute the result in the given state, consuming the state.
    fn result(self) -> Self::Result { self.0.finalize() }
}

impl RandomOracle {
    /// Start with the initial empty state of the oracle.
    pub fn empty() -> Self { RandomOracle(Sha3_256::new()) }

    /// Start with the initial string.
    /// Equivalent to ```ro.empty().append()```, but meant to be
    /// used with a domain string.
    pub fn domain<B: AsRef<[u8]>>(data: B) -> Self { RandomOracle(Sha3_256::new().chain(data)) }

    /// Duplicate the random oracle, creating a fresh copy of it.
    /// Further calls to 'append' or 'add' are independent.
    pub fn split(&self) -> Self { RandomOracle(self.0.clone()) }

    /// Append the input to the state of the oracle, obtaining a new state.
    /// This function satisfies
    ///
    ///    ```s.append(x_1).append(x_2) == s.append(x_1 <> x_2)```
    ///
    /// where equality means equality of outcomes, i.e., calling result on each
    /// of the states will produce the same bytearray.
    pub fn append<B: Serial>(self, data: &B) -> Self {
        let mut buf = self;
        data.serial(&mut buf);
        buf
    }

    /// Same as append, but modifies the oracle state instead of consuming it
    pub fn add<B: Serial>(&mut self, data: &B) { self.put(data) }

    pub fn add_bytes<B: AsRef<[u8]>>(&mut self, data: B) { self.0.update(data) }

    pub fn append_bytes<B: AsRef<[u8]>>(self, data: B) -> RandomOracle {
        RandomOracle(self.0.chain(data))
    }

    /// Similar to append, but instead of consuming the state it creates a fresh
    /// random oracle state and then acts as `append`.
    /// Equivalent to ```ro.split().append()```
    pub fn append_fresh<B: Serial>(&self, data: &B) -> Self { self.split().append(data) }

    /// Append all items from an iterator to the random oracle. Equivalent to
    /// repeatedly calling append in sequence.
    /// Returns the new state of the random oracle, consuming the initial state.
    pub fn extend_from<'a, I, B: 'a>(self, iter: I) -> Self
    where
        B: Serial,
        I: IntoIterator<Item = &'a B>, {
        let mut ro = self;
        for i in iter.into_iter() {
            ro.add(i)
        }
        ro
    }

    /// Append all items from an iterator to the random oracle. Equivalent to
    /// repeatedly calling append_fresh in sequence, but more efficient since it
    /// does not created fresh intermediate states. Returns the a fresh state of
    /// the random oracle and leaves the original state untouched.
    pub fn extend_from_fresh<'a, I, B: 'a>(&self, iter: I) -> Self
    where
        B: Serial,
        I: Iterator<Item = &'a B>, {
        let mut ro = self.split();
        for i in iter {
            ro.add(i)
        }
        ro
    }

    /// Try to convert the computed result into a field element. This interprets
    /// the output of the random oracle as a big-endian integer and reduces is
    /// mod field order.
    pub fn result_to_scalar<C: Curve>(self) -> C::Scalar { C::scalar_from_bytes(self.result()) }

    /// Finish and try to convert to scalar. Equivalent to
    /// ```ro.append(input).result_to_scalar()```.
    pub fn finish_to_scalar<C: Curve, B: Serial>(self, data: &B) -> C::Scalar {
        self.append(data).result_to_scalar::<C>()
    }

    /// Get a challenge from the current state, consuming the state.
    pub fn get_challenge(self) -> Challenge {
        Challenge {
            challenge: self.result().into(),
        }
    }

    pub fn append_point<C: Curve>(&mut self, label: &'static [u8], point: &C) {
        for elem in label.iter() {
            self.add(elem)
        }
        self.add(point)
    }

    pub fn append_scalar<C: Curve>(&mut self, label: &'static [u8], scalar: &C::Scalar) {
        for elem in label.iter() {
            self.add(elem)
        }
        self.add(scalar)
    }

    pub fn append_message(&mut self, label: &'static [u8], message: &[u8]) {
        for elem in label.iter() {
            self.add(elem)
        }
        for elem in message.iter() {
            self.add(elem)
        }
    }

    pub fn challenge_scalar<C: Curve>(&mut self, label: &'static [u8]) -> C::Scalar {
        for elem in label.iter() {
            self.add(elem)
        }
        self.split().result_to_scalar::<C>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::*;
    #[test]
    // Tests that append is homomorphic in the sense explained in the documentation.
    pub fn test_append() {
        let mut v1 = vec![0u8; 50];
        let mut v2 = vec![0u8; 188];
        let mut v3 = vec![0u8; 238];
        let mut csprng = thread_rng();
        for _ in 0..1000 {
            for i in 0..50 {
                v1[i] = csprng.gen::<u8>();
                v3[i] = v1[i];
            }
            for i in 0..188 {
                v2[i] = csprng.gen::<u8>();
                v3[i + 50] = v2[i];
            }
            let s1 = RandomOracle::empty();
            let s2 = RandomOracle::empty();
            let res1 = s1.append_bytes(&v1).append_bytes(&v2).result();
            let ref_res1: &[u8] = res1.as_ref();
            let res2 = s2.append_bytes(&v3).result();
            let ref_res2: &[u8] = res2.as_ref();
            assert_eq!(ref_res1, ref_res2);
        }
    }

    // Tests that extend_from acts in the intended way.
    #[test]
    pub fn test_extend_from() {
        let mut v1 = vec![0u8; 50];
        let mut csprng = thread_rng();
        for _ in 0..1000 {
            for i in 0..50 {
                v1[i] = csprng.gen::<u8>();
            }
            let mut s1 = RandomOracle::empty();
            for x in v1.iter() {
                s1.add(x);
            }
            let s2 = RandomOracle::empty().extend_from(v1.iter());
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
            let mut s1 = RandomOracle::empty().append(&v1);
            let s2 = s1.split();
            for i in 0..50 {
                v1[i] = csprng.gen::<u8>();
                s1.add(&v1[i]);
            }
            let res1 = s1.result();
            let ref_res1: &[u8] = res1.as_ref();
            let res2 = s2.append_bytes(&v1).result();
            let ref_res2: &[u8] = res2.as_ref();
            assert_eq!(ref_res1, ref_res2);
        }
    }

    #[test]
    // append acts as if we serialized first and then used append_bytes.
    pub fn test_append_bytes() {
        let mut v1 = vec![0u8; 50];
        let mut csprng = thread_rng();
        for _ in 0..1000 {
            for i in 0..50 {
                v1[i] = csprng.gen::<u8>();
            }
            let bytes = to_bytes(&v1);
            assert_eq!(
                RandomOracle::empty().append(&v1).result(),
                RandomOracle::empty().append_bytes(&bytes).result()
            )
        }
    }
}
