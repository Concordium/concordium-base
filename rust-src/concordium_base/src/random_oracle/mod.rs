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
//!
//! The [`RandomOracle`] instance should be used to append bytes to its internal state.
//! After adding data, call [`crate::random_oracle::RandomOracle::get_challenge`] to consume/hash the bytes
//! and produce a random challenge.
//!
//! # Caution: Type/Field ambiguity without domain separation
//! Special care is required when adding bytes to domain separate them with labels.
//! Naively appending just bytes (without separation) can produce collisions of different types.
//! For example:
//!
//! ```
//! struct Type1 {
//!     field_1: u8,
//!     field_2: u8,
//! }
//!
//! struct Type2 {
//!     field_1: u8,
//!     field_2: u8,
//! }
//!
//! let example1 = Type1 {
//!     field_1: 1u8,
//!     field_2: 2u8,
//! };
//!
//! let example2 = Type2 {
//!     field_1: 1u8,
//!     field_2: 2u8,
//! };
//! ```
//!
//! Appending the [`RandomOracle`] with either of above types by just adding each type's field values naively
//! (meaning `hash([1u8, 2u8]`) would produce the same hashing result for both examples. To avoid this, the
//! recommendation is to add the type name and its field names as labels for domain separation.
//!
//! # Example: Adding struct data
//!
//! If you add a struct to the transcript use its type name as separator and use `append_message`
//! with a **label** for each field as domain separation.
//!
//! ```
//! # use concordium_base::random_oracle::RandomOracle;
//! struct Type {
//!     field_1: u8,
//!     field_2: u8,
//! }
//!
//! let example = Type {
//!     field_1: 1u8,
//!     field_2: 2u8,
//! };
//!
//! let mut transcript = RandomOracle::empty();
//! transcript.add_bytes(b"Type");
//! transcript.append_message(b"field_1", &example.field_1);
//! transcript.append_message(b"field_2", &example.field_2);
//!```
//!
//! # Caution: Ambigious variable-length data
//! Special care is required when handling variable-length types such as
//! `String`, `Vec`, `BTreeSet`, `BTreeMap`, or other collections.
//! Naively appending the bytes (without including the length of the collection) can produce collisions.
//! For example:
//!
//! ```
//! struct Type {
//!     field_1: String,
//!     field_2: String,
//! }
//!
//! let example1 = Type {
//!     field_1: "field_2".to_string(),
//!     field_2: "".to_string(),
//! };
//!
//! let example2 = Type {
//!     field_1: "".to_string(),
//!     field_2: "field_2".to_string(),
//! };
//! ```
//!
//! Appending the [`RandomOracle`] with each field label and value naively
//! (meaning `hash("field_1" + "field_2" + "field_2")`) would produce
//! the same hashing result for both examples. To avoid this,
//! prepend the length of the variable-length data.
//!
//! Note: The serialization implementation of a variable-length type already
//! prepends the length of the data which is why it is used to add data to the transcript.
//!
//! References for serialization implementations:
//! - [`concordium_base_derive::Serial`]
//! - [serialize.rs](https://github.com/Concordium/concordium-base/blob/main/rust-src/concordium_base/src/common/serialize.rs)
//!
//! # Example: Adding struct data with variable-length data
//!
//! ```
//! # use concordium_base::random_oracle::RandomOracle;
//! struct Type {
//!     field_1: String,
//!     field_2: String,
//! }
//!
//! let example = Type {
//!     field_1: "abc".to_string(),
//!     field_2: "def".to_string(),
//! };
//!
//! let mut transcript = RandomOracle::empty();
//! transcript.add_bytes(b"Type");
//! // The serialization implementation of the `String` type prepends the lenght of the field values.
//! transcript.append_message(b"field_1", &example.field_1);
//! transcript.append_message(b"field_2", &example.field_2);
//! ```
//!
//! # Example: Adding data in loops
//!
//! If you manually iterate through any collection, add the length of the collection to the transcript.
//!
//! ```
//! # use concordium_base::random_oracle::RandomOracle;
//! let mut transcript = RandomOracle::empty();
//! let collection = vec![2,3,4];
//! transcript.add(&(collection.len() as u64));
//! for item in collection {
//!     transcript.add(&item);
//! }
//! ```
//!
//! # Example: Adding data with different variants
//!
//! If you add an enum manually to the transcript add the tag/version
//! to the transcript.
//!
//! ```
//! # use concordium_base::random_oracle::RandomOracle;
//! enum Enum {
//!     Variant_0
//! }
//!
//! let mut transcript = RandomOracle::empty();
//!
//! // --- Option 1: Numeric tag ---
//! transcript.add_bytes(b"Enum");
//! transcript.add_bytes(&[0u8]); // Variant0
//!
//! // --- Option 2: String tag / version ---
//! transcript.add_bytes(b"Enum");
//! transcript.add_bytes(b"V0"); // Variant0
//! ```
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
