//! This module provides the random oracle replacement function needed in the
//! sigma protocols, and any other constructions needing it.
//! FIXME: We should be using SHA3 as the random oracle replacement function.
use curve_arithmetic::curve_arithmetic::Curve;
use sha3::{Digest, Sha3_256};
use std::io::Cursor;

/// State of the random oracle, used to incrementally build up the output.
#[repr(transparent)]
pub struct RandomOracle(Sha3_256);

impl RandomOracle {
    /// Start with the initial empty state of the oracle.
    pub fn empty() -> Self { RandomOracle(Sha3_256::new()) }

    /// Start with the initial string.
    /// Equivalent to ```ro.empty().append()```, but meant to be
    /// used with a domain string.
    pub fn domain<B: AsRef<[u8]>>(data: B) -> Self { Self::empty().append(data) }

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
    pub fn append<B: AsRef<[u8]>>(self, data: B) -> Self { RandomOracle(self.0.chain(data)) }

    /// Same as append, but modifies the oracle state instead of consuming it
    pub fn add<B: AsRef<[u8]>>(&mut self, data: B) { self.0.input(data) }

    /// Similar to append, but instead of consuming the state it creates a fresh
    /// random oracle state and then acts as `append`.
    /// Equivalent to ```ro.split().append()```
    pub fn append_fresh<B: AsRef<[u8]>>(&self, data: B) -> Self { self.split().append(data) }

    /// Append all items from an iterator to the random oracle. Equivalent to
    /// repeatedly calling append in sequence.
    /// Returns the new state of the random oracle, consuming the initial state.
    pub fn extend_from<I, B>(self, iter: I) -> Self
    where
        B: AsRef<[u8]>,
        I: Iterator<Item = B>, {
        let mut ro = self;
        for i in iter {
            ro.add(i)
        }
        ro
    }

    /// Append all items from an iterator to the random oracle. Equivalent to
    /// repeatedly calling append_fresh in sequence, but more efficient since it
    /// does not created fresh intermediate states. Returns the a fresh state of
    /// the random oracle and leaves the original state untouched.
    pub fn extend_from_fresh<I, B>(&self, iter: I) -> Self
    where
        B: AsRef<[u8]>,
        I: Iterator<Item = B>, {
        let mut ro = self.split();
        for i in iter {
            ro.add(i)
        }
        ro
    }

    /// Compute the result in the given state, consuming the state.
    pub fn result(self) -> impl AsRef<[u8]> { self.0.result() }

    /// Try to convert the computed result into a field element. This takes the
    /// first SCALAR_LENGTH elements of result and tries to convert them to a
    /// scalar.
    /// This will fail (return None) if either
    /// * the output of the oracle does not have enought bytes (should not
    ///   happen)
    /// * the output of the oracle is not < q (the size of the scalar field).
    ///   Here the bytes are taken to represent a number in big-endian encoding.
    pub fn result_to_scalar<C: Curve>(self) -> Option<C::Scalar> {
        let res = self.result();
        let res_ref = res.as_ref();
        if res_ref.len() >= C::SCALAR_LENGTH {
            C::bytes_to_scalar(&mut Cursor::new(&res_ref[..C::SCALAR_LENGTH])).ok()
        } else {
            None
        }
    }

    /// Finish and try to convert to scalar. Equivalent to
    /// ```ro.append(input).result_to_scalar()```.
    pub fn finish_to_scalar<C: Curve, B: AsRef<[u8]>>(self, data: B) -> Option<C::Scalar> {
        self.append(data).result_to_scalar::<C>()
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
            let res1 = s1.append(&v1).append(&v2).result();
            let res2 = s2.append(&v3).result();
            assert_eq!(res1.as_ref(), res2.as_ref());
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
            for &x in v1.iter() {
                s1.add(&vec![x]);
            }
            let s2 = RandomOracle::empty().extend_from(v1.iter().map(|&x| vec![x]));
            let res1 = s1.result();
            let res2 = s2.result();
            assert_eq!(res1.as_ref(), res2.as_ref());
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
                s1.add(vec![v1[i]]);
            }
            let res1 = s1.result();
            let res2 = s2.append(&v1).result();
            assert_eq!(res1.as_ref(), res2.as_ref());
        }
    }
}
