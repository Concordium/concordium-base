//! This module provides the random oracle replacement function needed in the
//! sigma protocols, bulletproofs, and any other constructions. It is based on
//! SHA3. It is used in non-interactive proofs and plays the same role as a random
//! oracle would play in the corresponding interactive protocol (via
//! Fiat–Shamir transformation).
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
//! After adding data, call [`RandomOracle::get_challenge`] to consume/hash the bytes
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
//! # use concordium_base::random_oracle::{StructuredDigest, RandomOracle};
//!
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
//! # Caution: Ambiguous variable-length data
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
//! The serialization implementation of a variable-length type already
//! prepends the length of the data and can be used to add data to the transcript.
//! See [`Serial`](trait@crate::common::Serial) trait and [`Serial`](macro@crate::common::Serial) macro.
//!
//! # Example: Adding data of variable-length
//!
//! ```
//! # use concordium_base::random_oracle::{StructuredDigest, RandomOracle};
//!
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
//! let string = "abc".to_string();
//! // The serialization implementation of the `String` type prepends the length of the field values.
//! transcript.append_message(b"String", &string);
//! ```
//!
//! # Example: Adding lists of data
//!
//! ```
//! # use concordium_base::random_oracle::{StructuredDigest, RandomOracle};
//!
//! let mut transcript = RandomOracle::empty();
//! let collection = vec![2,3,4];
//! transcript.append_message(b"Collection", &collection);
//! ```
//!
//! # Example: Adding data with different variants
//!
//! If you add an enum manually to the transcript add the tag/version
//! to the transcript.
//!
//! ```
//! # use concordium_base::random_oracle::{StructuredDigest, RandomOracle};
//!
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

/// State of the random oracle, used to incrementally build up the output. See [`random_oracle`](self).
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

/// Trait for digesting messages that encourages encoding the structure of the data into
/// the message bytes. This is done e.g. by applying length prefixes for variable-length data and
/// prefixing variants with a discriminator.
/// And by labelling types and fields for domain separation. Both are done to prevent malleability
/// in the proofs where the oracle is used.
///
/// Using [`Serial`] is one of the approaches to correctly produce the message
/// bytes for variable-length types (including enums), since the corresponding [`Deserial`]
/// implementation guarantees the message bytes are unique for the data. Notice that using [`Serial`]
/// does not label types or fields in the nested data.
pub trait StructuredDigest: Buffer {
    /// Add raw message bytes to the state of the oracle.
    fn add_bytes<B: AsRef<[u8]>>(&mut self, data: B);

    /// Append the given data as the message bytes produced by its [`Serial`] implementation to the state of the oracle.
    /// The given label as appended first as domain separation.
    fn append_message<S: Serial, B: AsRef<[u8]>>(&mut self, label: B, data: &S) {
        self.add_bytes(label);
        self.put(data)
    }
}

impl StructuredDigest for RandomOracle {
    fn add_bytes<B: AsRef<[u8]>>(&mut self, data: B) {
        self.0.update(data)
    }
}

impl StructuredDigest for sha2::Sha256 {
    fn add_bytes<B: AsRef<[u8]>>(&mut self, data: B) {
        self.update(data)
    }
}

impl StructuredDigest for sha2::Sha512 {
    fn add_bytes<B: AsRef<[u8]>>(&mut self, data: B) {
        self.update(data)
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

    /// Append all items from an iterator to the random oracle. Equivalent to
    /// repeatedly calling append in sequence.
    /// Returns the new state of the random oracle, consuming the initial state.
    #[deprecated(
        note = "Use the labelled version RandomOracle::append_messages instead. Do not change existing provers/verifiers since it will break compatability with existing proofs."
    )]
    pub fn extend_from<'a, I, S, B: AsRef<[u8]>>(&mut self, label: B, iter: I)
    where
        S: Serial + 'a,
        I: IntoIterator<Item = &'a S>,
    {
        self.add_bytes(label);
        for i in iter.into_iter() {
            self.put(i)
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
                s1.put(x);
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
            s1.put(&v1);
            let mut s2 = s1.split();
            for v in v1.iter_mut() {
                *v = csprng.gen::<u8>();
                s1.put(v);
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
    /// by [`StructuredDigest::add_bytes`]
    #[test]
    pub fn test_add_bytes_stable() {
        let mut ro = RandomOracle::empty();
        ro.add_bytes([0x1, 0x2, 0x3]);

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
        ro.append_message(b"Label1", &vec![1, 2, 3]);

        let challenge_hex = hex::encode(ro.get_challenge());
        assert_eq!(
            challenge_hex,
            "544c5dc5dbde3b40f86935b5dc8556dc42d2fef240c902f0b627ce2541c4b0a6"
        );
    }
}
