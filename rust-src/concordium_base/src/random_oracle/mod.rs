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
//! For background, the Merlin transcript can also be studied here: <https://merlin.cool/index.html> (implemented at <https://github.com/dalek-cryptography/merlin>).
//!
//! # Example: Ensuring proper domain separation
//!
//! The oracle should be initialized with a domain separating string. Further branches in the code
//! or nested proofs should also be labelled for domain separation.
//!
//! ```
//! # use concordium_base::random_oracle::{StructuredDigest, RandomOracle};
//! let mut transcript = RandomOracle::with_domain("Proof of something");
//! // ...
//! transcript.append_label("Subproof1");
//! // ...
//! transcript.append_label("Branch1");
//! // ...
//!```
//!
//! # Caution: Type ambiguity without domain separation
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
//! recommendation is to add the type name as labels for domain separation.
//!
//! # Example: Adding struct data
//!
//! If you add a struct to the transcript use its type name as separator and its [`Serial`]
//! to define the data message bytes.
//!
//! ```rust,ignore
//! # use concordium_base::random_oracle::{StructuredDigest, RandomOracle};
//! # use concordium_base::common::Serialize;
//! #[derive(Serialize)]
//! struct Type1 {
//!     field_1: u8,
//!     field_2: u8,
//! }
//!
//! let example = Type1 {
//!     field_1: 1u8,
//!     field_2: 2u8,
//! };
//!
//! let mut transcript = RandomOracle::with_domain("Proof of something");
//! transcript.append_message(b"Type1", &example);
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
//! # Example: Adding data of variable-length using `Serial`
//!
//! Serialization of variable-length primitives like `String` will prepend the length.
//!
//! ```
//! # use concordium_base::random_oracle::{StructuredDigest, RandomOracle};
//! let mut transcript = RandomOracle::with_domain("Proof of something");
//! let string = "abc".to_string();
//! // The serialization implementation of the `String` type prepends the length of the field values.
//! transcript.append_message("String1", &string);
//! ```
//!
//! # Example: Adding collections of data using `Serial`
//!
//! Serialization of collections like `Vec` will prepend the size of the collection.
//!
//! ```
//! # use concordium_base::random_oracle::{StructuredDigest, RandomOracle};
//! let mut transcript = RandomOracle::with_domain("Proof of something");
//! let collection = vec![2,3,4];
//! transcript.append_message("Collection1", &collection);
//! ```
//!
//! # Example: Adding variable number of items
//!
//! Digesting a variable number of items without relying on `Serial` implementation on the items:
//!
//! ```
//! # use concordium_base::random_oracle::{StructuredDigest, RandomOracle};
//!
//! struct Type1;
//!
//! fn append_type1(transcript: &mut impl StructuredDigest, val: &Type1) {
//!     // digest Type1
//! }
//!
//! let vec = vec![Type1, Type1];
//!
//! let mut transcript = RandomOracle::with_domain("Proof of something");
//! transcript.append_each("Collection", &vec, |transcript, item| {
//!     append_type1(transcript, item);
//! });
//! ```
//!
//! # Example: Adding data with different variants
//!
//! If you add an enum manually to the transcript add the variant name
//! to the transcript followed by the variant data.
//!
//! ```
//! # use concordium_base::random_oracle::{StructuredDigest, RandomOracle};
//! enum Enum1 {
//!     Variant_0,
//!     Variant_1
//! }
//!
//! let mut transcript = RandomOracle::with_domain("Proof of something");
//!
//! transcript.append_label("Enum1");
//! transcript.append_label("Variant_0");
//! // add data from Variant_0
//! ```
//!
//! Notice that if you serialize an enum that implements [`Serial`],
//! the variant discriminator will be serialized (check the [`Serial`] of the enum)
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
        #[allow(deprecated)]
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
/// the message bytes and doing proper domain separation. This is done e.g. by applying length
/// prefixes for variable-length data and prefixing data variants with a discriminator.
/// And by labelling data for domain separation. Both are done to prevent malleability
/// in the proofs or signatures where the digest is used.
///
/// Using [`Serial`] is one of the approaches to correctly produce the message
/// bytes for variable-length types and data types with different variants (enums), since the corresponding [`Deserial`]
/// implementation guarantees the message bytes are unique for the data. Notice that using [`Serial`]
/// does not label types or fields in the nested data. This can be ok, as labelling top level data types
/// is the most important.
pub trait StructuredDigest: Buffer {
    /// Add raw message bytes to the state of the digest, without any length prepended.
    /// Should generally not be used directly, prefer using one of the other methods on the trait.
    fn add_raw_bytes(&mut self, data: impl AsRef<[u8]>);

    /// Add domain separating label to the digest. The label bytes will be prepended with the bytes length.
    fn append_label(&mut self, label: impl AsRef<[u8]>) {
        let label = label.as_ref();
        self.put(&(label.len() as u64));
        self.add_raw_bytes(label);
    }

    /// Append the given data as the message bytes produced by its [`Serial`] implementation to the state of the digest.
    /// The given label is appended first as domain separation. Notice that slices, `Vec`s, and several other collections of
    /// items implementing [`Serial`], itself implements [`Serial`]. When serializing variable-length
    /// types or collection types, the length or size will be prepended in the serialization.
    fn append_message(&mut self, label: impl AsRef<[u8]>, data: &impl Serial) {
        self.append_label(label);
        self.put(data)
    }

    /// Append the items in the given iterator using the `append_item` closure to the state of the oracle.
    /// The given label is appended first as domain separation followed by the length of the iterator.
    fn append_each<T, B: IntoIterator<Item = T>>(
        &mut self,
        label: &str,
        items: B,
        mut append_item: impl FnMut(&mut Self, T),
    ) where
        B::IntoIter: ExactSizeIterator,
    {
        let items = items.into_iter();
        self.append_label(label);
        self.put(&(items.len() as u64));
        for item in items {
            append_item(self, item);
        }
    }
}

impl StructuredDigest for RandomOracle {
    fn add_raw_bytes(&mut self, data: impl AsRef<[u8]>) {
        self.0.update(data)
    }
}

impl StructuredDigest for sha2::Sha256 {
    fn add_raw_bytes(&mut self, data: impl AsRef<[u8]>) {
        self.update(data)
    }
}

impl StructuredDigest for sha2::Sha512 {
    fn add_raw_bytes(&mut self, data: impl AsRef<[u8]>) {
        self.update(data)
    }
}

impl RandomOracle {
    /// Start with the initial empty state of the oracle.
    #[cfg_attr(
        not(test),
        deprecated(
            note = "Use RandomOracle::with_domain initializes with a domain. Do not change existing provers/verifiers since it will break compatability with existing proofs."
        )
    )]
    pub fn empty() -> Self {
        RandomOracle(Sha3_256::new())
    }

    /// Start with the initial domain string. Prepend with length of the domain string bytes.
    pub fn with_domain(label: impl AsRef<[u8]>) -> Self {
        let mut ro = RandomOracle(Sha3_256::new());
        ro.append_label(label);
        ro
    }

    /// Start with the initial domain string.
    #[cfg_attr(
        not(test),
        deprecated(
            note = "Use RandomOracle::with_domain which prepends the label length. Do not change existing provers/verifiers since it will break compatability with existing proofs."
        )
    )]
    pub fn domain<B: AsRef<[u8]>>(data: B) -> Self {
        RandomOracle(Sha3_256::new().chain_update(data))
    }

    /// Duplicate the random oracle, creating a fresh copy of it.
    /// Further updates are independent.
    pub fn split(&self) -> Self {
        RandomOracle(self.0.clone())
    }

    #[deprecated(
        note = "Use either StructuredDigest::append_label or StructuredDigest::add_raw_bytes instead. Do not change existing provers/verifiers since it will break compatability with existing proofs."
    )]
    pub fn add_bytes<B: AsRef<[u8]>>(&mut self, data: B) {
        self.0.update(data)
    }

    /// Append all items from an iterator to the random oracle. Equivalent to
    /// repeatedly calling append in sequence.
    /// Returns the new state of the random oracle, consuming the initial state.
    #[deprecated(
        note = "Use RandomOracle::append_message (with a collection type) instead such that the number of elements is prepended. Do not change existing provers/verifiers since it will break compatability with existing proofs."
    )]
    pub fn extend_from<'a, I, S, B: AsRef<[u8]>>(&mut self, label: B, iter: I)
    where
        S: Serial + 'a,
        I: IntoIterator<Item = &'a S>,
    {
        #[allow(deprecated)]
        self.add_bytes(label);
        for i in iter.into_iter() {
            self.put(i)
        }
    }

    /// Try to convert the computed result into a field element. This interprets
    /// the output of the random oracle as a big-endian integer and reduces is
    /// mod field order.
    ///
    /// Use the public method [`Self::challenge_scalar`] which labels as part of getting the challenge.
    fn result_to_scalar<C: Curve>(self) -> C::Scalar {
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
        self.add_raw_bytes(label);
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
                s1.put(x);
            }
            let mut s2 = RandomOracle::empty();
            #[allow(deprecated)]
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
            s2.add_raw_bytes(&v1);
            let res2 = s2.result();
            let ref_res2: &[u8] = res2.as_ref();
            assert_eq!(ref_res1, ref_res2);
        }
    }

    /// Test that we don't accidentally change the digest produced
    /// by [`RandomOracle::domain`]
    #[test]
    pub fn test_domain_stable() {
        #[allow(deprecated)]
        let ro = RandomOracle::domain("Domain1");

        let challenge_hex = hex::encode(ro.get_challenge());
        assert_eq!(
            challenge_hex,
            "b6dbfe8bfbc515d92bcc322b1e98291a45536f81f6eca2411d8dae54766666f1"
        );
    }

    /// Test that we don't accidentally change the digest produced
    /// by [`RandomOracle::with_domain`]
    #[test]
    pub fn test_with_domain_stable() {
        let ro = RandomOracle::with_domain("Domain1");

        let challenge_hex = hex::encode(ro.get_challenge());
        assert_eq!(
            challenge_hex,
            "5691f0658460c461ffe14baa70071545df78725892d0decfe6f6642233a0d8e2"
        );
    }

    /// Test that we don't accidentally change the digest produced
    /// by [`RandomOracle::add_bytes`]
    #[test]
    pub fn test_add_bytes_stable() {
        let mut ro = RandomOracle::empty();
        #[allow(deprecated)]
        ro.add_bytes([1u8, 2, 3]);

        let challenge_hex = hex::encode(ro.get_challenge());
        assert_eq!(
            challenge_hex,
            "fd1780a6fc9ee0dab26ceb4b3941ab03e66ccd970d1db91612c66df4515b0a0a"
        );
    }

    /// Test that we don't accidentally change the digest produced
    /// by [`StructuredDigest::add_raw_bytes`]
    #[test]
    pub fn test_add_raw_bytes_stable() {
        let mut ro = RandomOracle::empty();
        ro.add_raw_bytes([1u8, 2, 3]);

        let challenge_hex = hex::encode(ro.get_challenge());
        assert_eq!(
            challenge_hex,
            "fd1780a6fc9ee0dab26ceb4b3941ab03e66ccd970d1db91612c66df4515b0a0a"
        );
    }

    /// Test that we don't accidentally change the digest produced
    /// by [`StructuredDigest::append_label`]
    #[test]
    pub fn test_append_label_stable() {
        let mut ro = RandomOracle::empty();
        ro.append_label("Label1");

        let challenge_hex = hex::encode(ro.get_challenge());
        assert_eq!(
            challenge_hex,
            "fa7389e2cab48f620de96d0a0f8e82f84336f77e45fc545af21c7cef1dd999a4"
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
    /// by [`StructuredDigest::append_message`]
    #[test]
    pub fn test_append_each_stable() {
        let mut ro = RandomOracle::empty();
        ro.append_each("Label1", &vec![1u8, 2, 3], |ro, item| {
            ro.append_message("Item", item)
        });

        let challenge_hex = hex::encode(ro.get_challenge());
        assert_eq!(
            challenge_hex,
            "652c10e0ce89b6932b47161b7f29f9eee578917b906519f4a3e85a4aae93cc50"
        );
    }
}
