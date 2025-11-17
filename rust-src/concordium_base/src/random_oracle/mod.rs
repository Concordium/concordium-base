//! This module implements the transcript used in sigma protocols, bulletproofs, and other
//! public-coin multi-round proof systems, that has undergone the Fiat-Shamir transformation.
//! It plays the same role as a random oracle would play in the corresponding interactive protocol,
//! hence the name of the present module and some of the types in the module.
//!
//! For background, see "9.3 Non-interactive Proofs using the Fiat-Shamir Transformation" in tbe blue paper.
//! For understanding the general concepts and the considerations put into a transcript implementation,
//! the Merlin transcript can be studied here: <https://merlin.cool/index.html> (implemented at <https://github.com/dalek-cryptography/merlin>).
//!
//! # Using the transcript
//! Transcript instances should be initialized with at domain-separation
//! string that defines the particular protocol. See <https://merlin.cool/use/passing.html#domain-separation>.
//!
//! For each proof, protocols should update the state of the transcript with public input
//! and implicit public values, and each message send by prover, including the final message
//! send by the prover. Proofs can be be sequentially composed, see <https://merlin.cool/use/passing.html#sequential-composition>.
//! It is specifically because of sequential composition, that it is important that also the final message send by the prover is added to the transcript.
//!
//! Verifier messages (the challenges) in the proof should be extracted from the transcript instance.
//! It is in this extraction, that the transcript plays the role of a random oracle.
//!
//! The transcript instance used to verify a proof needs to be initialised and updated
//! with the same input used to produce the proof. Any verification of sub-proofs
//! needs to be performed in the same order as when producing the proof.
//! See <https://merlin.cool/use/duality.html>
//!
//! Part of a transcript protocol (see <https://merlin.cool/use/protocol.html>) is defining
//! how messages of types defined by the protocol (often mathematical objects) are encoded to message bytes and how
//! challenge bytes are decoded to challenges of types defined in the protocol (again mathematical objects). The latter must
//! preserve uniform distribution in the challenge space.
//! This is handled via [`TranscriptProtocol`] and largely uses the [`Serial`]
//! and [`Deserial`] implementations on the message and challenge types.
//!
//! # Example: Ensuring proper domain separation
//!
//! The transcript should be initialized with a domain separating string. Further branches in the code
//! or nested proofs should also be labelled for domain separation.
//!
//! ```
//! # use concordium_base::random_oracle::{TranscriptProtocol, TranscriptV1};
//! let mut transcript = TranscriptV1::with_domain("Proof of something");
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
//! Appending the transcript with either of above types by just adding each type's field values naively
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
//! # use concordium_base::common::{Serialize};
//!
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
//! let mut transcript = RandomOracle::empty();
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
//! Appending the transcript with each field label and value naively
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
//!```
//! # use concordium_base::random_oracle::{TranscriptProtocol, TranscriptV1};
//! let mut transcript = TranscriptV1::with_domain("Proof of something");
//! let string = "abc".to_string();
//! // The serialization implementation of the `String` type prepends the length of the field values.
//! transcript.append_message("String1", &string);
//! ```
//!
//! # Example: Adding collections of data using `Serial`
//!
//! Serialization of collections like `Vec` will prepend the size of the collection.
//!
//!```
//! # use concordium_base::random_oracle::{TranscriptProtocol, TranscriptV1};
//! let mut transcript = TranscriptV1::with_domain("Proof of something");
//! let collection = vec![2,3,4];
//! transcript.append_message("Collection1", &collection);
//! ```
//!
//! # Example: Adding variable number of items
//!
//! Digesting a variable number of items without relying on `Serial` implementation on the items:
//!
//!```
//! # use concordium_base::random_oracle::{TranscriptProtocol, TranscriptV1};
//!
//! struct Type1;
//!
//! fn append_type1(transcript: &mut impl TranscriptProtocol, val: &Type1) {
//!     // digest Type1
//! }
//!
//! let vec = vec![Type1, Type1];
//!
//! let mut transcript = TranscriptV1::with_domain("Proof of something");
//! transcript.append_each_message("Collection", &vec, |transcript, item| {
//!     append_type1(transcript, item);
//! });
//! ```
//!
//! # Example: Adding data with different variants
//!
//! If you add an enum manually to the transcript add the variant name
//! to the transcript followed by the variant data.
//!
//!```
//! # use concordium_base::random_oracle::{TranscriptProtocol, TranscriptV1};
//!
//! enum Enum1 {
//!     Variant_0,
//!     Variant_1
//! }
//!
//! let mut transcript = TranscriptV1::with_domain("Proof of something");
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
use std::convert::Infallible;
use std::fmt::Arguments;
use std::io::{IoSlice, Write};

/// Transcript implementation V0. Implements [`TranscriptProtocol`]. See [`random_oracle`](self)
/// and [`TranscriptProtocol`] for how to use it.
#[repr(transparent)]
#[derive(Debug)]
// todo ar deprecate?
// #[cfg_attr(
//     not(test),
//     deprecated(
//         note = "Use TranscriptV1 which does proper length prefixing of labels and includes last prover message in transcript for proper sequential composition. Do not change existing protocols without changing their proof version since it will break compatability with existing proofs."
//     )
// )]
pub struct RandomOracle(Sha3_256);

/// Transcript implementation V1. Implements [`TranscriptProtocol`]. See [`random_oracle`](self)
/// and [`TranscriptProtocol`] for how to use it.
#[repr(transparent)]
#[derive(Debug)]
pub struct TranscriptV1(Sha3_256);

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

// todo ar finish doc
/// Transcript protocol that defines how messages and challenges are encoded to and
/// decoded from bytes.
/// The transcript protocol also encourages doing domain separation and labelling data,
/// and helps handling structured data in the right way
///
/// This is largely done using the [`Serial`]
/// and [`Deserial`] implementations on the message and challenge types.
///
/// See <https://merlin.cool/use/protocol.html> for a description of the concept of a transcript protocol.
///
/// This is done e.g. by applying length prefixes for variable-length data and
/// prefixing variants with a discriminator.
/// And by labelling types and fields for domain separation. Both are done to prevent malleability
/// in the proofs where the oracle is used.
///
/// Using [`Serial`] is one of the approaches to correctly produce the message
/// bytes for variable-length types (including enums), since the corresponding [`Deserial`]
/// implementation guarantees the message bytes are unique for the data. Notice that using [`Serial`]
/// does not label types or fields in the nested data.
pub trait TranscriptProtocol {
    /// Add domain separating label to the digest. The label bytes will be prepended with the bytes length.
    fn append_label(&mut self, label: impl AsRef<[u8]>);

    /// Append the given data as the message bytes produced by its [`Serial`] implementation to the transcript.
    /// The given label is appended first as domain separation. Notice that a slice, `Vec` and several other collections of
    /// items implementing [`Serial`] itself implements [`Serial`]. When serializing variable-length
    /// types or collection types, the length or size will be prepended in the serialization.
    fn append_message(&mut self, label: impl AsRef<[u8]>, message: &impl Serial);

    // todo ar finish doc
    fn append_messages<'a, T: Serial + 'a, B: IntoIterator<Item = &'a T>>(
        &mut self,
        label: impl AsRef<[u8]>,
        messages: B,
    ) where
        B::IntoIter: ExactSizeIterator;

    // todo ar finish doc
    fn append_final_prover_message(&mut self, label: impl AsRef<[u8]>, message: &impl Serial);

    /// Append the items in the given iterator using the `append_item` closure to the state of the oracle.
    /// The given label is appended first as domain separation followed by the length of the iterator.
    fn append_each_message<T, B: IntoIterator<Item = T>>(
        &mut self,
        label: impl AsRef<[u8]>,
        messages: B,
        append_item: impl FnMut(&mut Self, T),
    ) where
        B::IntoIter: ExactSizeIterator;

    // todo ar finish doc
    fn extract_challenge_scalar<C: Curve>(&mut self, label: impl AsRef<[u8]>) -> C::Scalar;

    // todo ar finish doc
    fn extract_raw_challenge(&self) -> Challenge;
}

impl TranscriptProtocol for RandomOracle {
    fn append_label(&mut self, label: impl AsRef<[u8]>) {
        self.0.update(label)
    }

    fn append_message(&mut self, label: impl AsRef<[u8]>, message: &impl Serial) {
        self.append_label(label);
        self.put(message)
    }

    fn append_messages<'a, T: Serial + 'a, B: IntoIterator<Item = &'a T>>(
        &mut self,
        label: impl AsRef<[u8]>,
        messages: B,
    ) where
        B::IntoIter: ExactSizeIterator,
    {
        self.append_label(label);
        for message in messages {
            self.put(message);
        }
    }

    fn append_final_prover_message(&mut self, _label: impl AsRef<[u8]>, _message: &impl Serial) {
        // not added in V0
    }

    fn append_each_message<T, B: IntoIterator<Item = T>>(
        &mut self,
        label: impl AsRef<[u8]>,
        messages: B,
        mut append_item: impl FnMut(&mut Self, T),
    ) where
        B::IntoIter: ExactSizeIterator,
    {
        self.append_label(label);
        for message in messages {
            append_item(self, message);
        }
    }

    fn extract_challenge_scalar<C: Curve>(&mut self, label: impl AsRef<[u8]>) -> C::Scalar {
        self.challenge_scalar::<C, _>(label)
    }

    fn extract_raw_challenge(&self) -> Challenge {
        self.split().get_challenge()
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

    pub fn add_bytes<B: AsRef<[u8]>>(&mut self, data: B) {
        self.0.update(data)
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

struct BufferAdapter<T>(T);

impl<T: Write> Write for BufferAdapter<T> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> std::io::Result<usize> {
        self.0.write_vectored(bufs)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.0.write_all(buf)
    }

    fn write_fmt(&mut self, args: Arguments<'_>) -> std::io::Result<()> {
        self.0.write_fmt(args)
    }
}

impl<T: Write> Buffer for BufferAdapter<T> {
    type Result = Infallible;

    fn start() -> Self {
        unimplemented!()
    }

    fn result(self) -> Self::Result {
        unimplemented!()
    }
}

impl TranscriptProtocol for TranscriptV1 {
    fn append_label(&mut self, label: impl AsRef<[u8]>) {
        let label = label.as_ref();
        BufferAdapter(&mut self.0).put(&(label.len() as u64));
        self.0.update(label)
    }

    fn append_message(&mut self, label: impl AsRef<[u8]>, message: &impl Serial) {
        self.append_label(label);
        BufferAdapter(&mut self.0).put(message)
    }

    fn append_messages<'a, T: Serial + 'a, B: IntoIterator<Item = &'a T>>(
        &mut self,
        label: impl AsRef<[u8]>,
        messages: B,
    ) where
        B::IntoIter: ExactSizeIterator,
    {
        let messages = messages.into_iter();
        self.append_label(label);
        BufferAdapter(&mut self.0).put(&(messages.len() as u64));
        for message in messages {
            BufferAdapter(&mut self.0).put(message);
        }
    }

    fn append_final_prover_message(&mut self, label: impl AsRef<[u8]>, message: &impl Serial) {
        self.append_message(label, message);
    }

    fn append_each_message<T, B: IntoIterator<Item = T>>(
        &mut self,
        label: impl AsRef<[u8]>,
        messages: B,
        mut append_item: impl FnMut(&mut Self, T),
    ) where
        B::IntoIter: ExactSizeIterator,
    {
        let messages = messages.into_iter();
        self.append_label(label);
        BufferAdapter(&mut self.0).put(&(messages.len() as u64));
        for message in messages {
            append_item(self, message);
        }
    }

    fn extract_challenge_scalar<C: Curve>(&mut self, label: impl AsRef<[u8]>) -> C::Scalar {
        self.append_label(label);
        C::scalar_from_bytes(self.extract_raw_challenge().challenge)
    }

    fn extract_raw_challenge(&self) -> Challenge {
        Challenge {
            challenge: self.0.clone().finalize().into(),
        }
    }
}

impl TranscriptV1 {
    /// Start with the initial domain string.
    pub fn with_domain(domain: impl AsRef<[u8]>) -> Self {
        let mut transcript = TranscriptV1(Sha3_256::new());
        transcript.append_label(domain);
        transcript
    }

    /// Duplicate the transcript, creating a fresh copy of it.
    /// Further updates are independent.
    pub fn split(&self) -> Self {
        TranscriptV1(self.0.clone())
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
            s2.add_bytes(&v1);
            let res2 = s2.result();
            let ref_res2: &[u8] = res2.as_ref();
            assert_eq!(ref_res1, ref_res2);
        }
    }

    /// Test that we don't accidentally change the digest produced
    /// by [`RandomOracle::domain`]
    #[test]
    pub fn test_v0_domain_stable() {
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
    pub fn test_v0_add_bytes_stable() {
        let mut ro = RandomOracle::empty();
        ro.add_bytes([1u8, 2, 3]);

        let challenge_hex = hex::encode(ro.get_challenge());
        assert_eq!(
            challenge_hex,
            "fd1780a6fc9ee0dab26ceb4b3941ab03e66ccd970d1db91612c66df4515b0a0a"
        );
    }

    /// Test that we don't accidentally change the digest produced
    /// by [`TranscriptProtocol::append_label`]
    #[test]
    pub fn test_v0_append_label_stable() {
        let mut ro = RandomOracle::empty();
        ro.append_label([1u8, 2, 3]);

        let challenge_hex = hex::encode(ro.get_challenge());
        assert_eq!(
            challenge_hex,
            "fd1780a6fc9ee0dab26ceb4b3941ab03e66ccd970d1db91612c66df4515b0a0a"
        );
    }

    /// Test that we don't accidentally change the digest produced
    /// by [`TranscriptProtocol::append_message`]
    #[test]
    pub fn test_v0_append_message_stable() {
        let mut ro = RandomOracle::empty();
        ro.append_message("Label1", &vec![1u8, 2, 3]);

        let challenge_hex = hex::encode(ro.get_challenge());
        assert_eq!(
            challenge_hex,
            "3756eec6f9241f9a1cd8b401f54679cf9be2e057365728336221b1871ff666fb"
        );
    }

    /// Test that we don't accidentally change the digest produced
    /// by [`TranscriptProtocol::append_messages`] and [`RandomOracle::extend_from`]
    #[test]
    pub fn test_v0_append_messages_stable() {
        // todo ar copy to main
        let mut ro = RandomOracle::empty();
        ro.append_messages("Label1", &vec![1u8, 2, 3]);

        let challenge_hex = hex::encode(ro.get_challenge());
        assert_eq!(
            challenge_hex,
            "6b1addb1c08e887242f5e78127c31c17851f29349c45aa415adce255f95fd292"
        );

        let mut ro = RandomOracle::empty();
        ro.extend_from("Label1", &vec![1u8, 2, 3]);

        let challenge_hex = hex::encode(ro.get_challenge());
        assert_eq!(
            challenge_hex,
            "6b1addb1c08e887242f5e78127c31c17851f29349c45aa415adce255f95fd292"
        );
    }

    /// Test that we don't accidentally change the digest produced
    /// by [`TranscriptProtocol::append_final_prover_message`]
    #[test]
    pub fn test_v0_append_final_prover_message_stable() {
        let mut ro = RandomOracle::empty();
        ro.append_final_prover_message("Label1", &vec![1u8, 2, 3]);

        let challenge_hex = hex::encode(ro.get_challenge());
        assert_eq!(
            challenge_hex,
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
    }

    /// Test that we don't accidentally change the scalar produced
    /// by [`TranscriptProtocol::extract_challenge_scalar`]
    #[test]
    pub fn test_v0_extract_challenge_scalar_stable() {
        let ro = RandomOracle::empty();

        let scalar_hex = hex::encode(common::to_bytes(
            &ro.split().extract_challenge_scalar::<ArCurve>("Scalar1"),
        ));
        assert_eq!(
            scalar_hex,
            "08646777f9c47efc863115861aa18d95653212c3bdf36899c7db46fbdae095cd"
        );

        let scalar_hex = hex::encode(common::to_bytes(
            &ro.split().challenge_scalar::<ArCurve, _>("Scalar1"),
        ));
        assert_eq!(
            scalar_hex,
            "08646777f9c47efc863115861aa18d95653212c3bdf36899c7db46fbdae095cd"
        );
    }

    /// Test that we don't accidentally change the digest produced
    /// by [`TranscriptProtocol::append_message`]
    #[test]
    pub fn test_v0_append_each_message_stable() {
        let mut ro = RandomOracle::empty();
        ro.append_each_message("Label1", &vec![1u8, 2, 3], |ro, item| {
            ro.append_message("Item", item)
        });

        let challenge_hex = hex::encode(ro.get_challenge());
        assert_eq!(
            challenge_hex,
            "90da7b2dc7bc9091be9201598ef0d8b43f8b00c53454822a2f8ce41c6a3f3d85"
        );
    }

    /// Test that we don't accidentally change the digest produced
    /// by [`TranscriptV1::with_domain`]
    #[test]
    pub fn test_v1_with_domain_stable() {
        let ro = TranscriptV1::with_domain("Domain1");

        let challenge_hex = hex::encode(ro.extract_raw_challenge());
        assert_eq!(
            challenge_hex,
            "5691f0658460c461ffe14baa70071545df78725892d0decfe6f6642233a0d8e2"
        );
    }

    /// Test that we don't accidentally change the digest produced
    /// by [`TranscriptProtocol::append_label`]
    #[test]
    pub fn test_v1_append_label_stable() {
        let mut ro = TranscriptV1::with_domain("Domain1");
        ro.append_label([1u8, 2, 3]);

        let challenge_hex = hex::encode(ro.extract_raw_challenge());
        assert_eq!(
            challenge_hex,
            "683a300a44b3f9165f78dd9fd90efc9a632c11131ef5e805ff3505b5bf0cc7d2"
        );
    }

    /// Test that we don't accidentally change the digest produced
    /// by [`TranscriptProtocol::append_message`]
    #[test]
    pub fn test_v1_append_message_stable() {
        let mut ro = TranscriptV1::with_domain("Domain1");
        ro.append_message("Label1", &vec![1u8, 2, 3]);

        let challenge_hex = hex::encode(ro.extract_raw_challenge());
        assert_eq!(
            challenge_hex,
            "5fb23e3d1cfb33d1b2e2da1c070c7a79056b00d13d642ee47fba542d4863a911"
        );
    }

    /// Test that we don't accidentally change the digest produced
    /// by [`TranscriptProtocol::append_messages`]
    #[test]
    pub fn test_v1_append_messages_stable() {
        let mut ro = TranscriptV1::with_domain("Domain1");
        ro.append_messages("Label1", &vec![1u8, 2, 3]);

        let challenge_hex = hex::encode(ro.extract_raw_challenge());
        assert_eq!(
            challenge_hex,
            "5fb23e3d1cfb33d1b2e2da1c070c7a79056b00d13d642ee47fba542d4863a911"
        );
    }

    /// Test that we don't accidentally change the digest produced
    /// by [`TranscriptProtocol::append_final_prover_message`]
    #[test]
    pub fn test_v1_append_final_prover_message_stable() {
        let mut ro = TranscriptV1::with_domain("Domain1");
        ro.append_final_prover_message("Label1", &vec![1u8, 2, 3]);

        let challenge_hex = hex::encode(ro.extract_raw_challenge());
        assert_eq!(
            challenge_hex,
            "5fb23e3d1cfb33d1b2e2da1c070c7a79056b00d13d642ee47fba542d4863a911"
        );
    }

    /// Test that we don't accidentally change the scalar produced
    /// by [`TranscriptProtocol::extract_challenge_scalar`]
    #[test]
    pub fn test_v1_extract_challenge_scalar_stable() {
        let ro = TranscriptV1::with_domain("Domain1");

        let scalar_hex = hex::encode(common::to_bytes(
            &ro.split().extract_challenge_scalar::<ArCurve>("Scalar1"),
        ));
        assert_eq!(
            scalar_hex,
            "3efcc0fdddcc90a71a022212338ae1c6c7b102fdb9af6befd460d68561856ad9"
        );
    }

    /// Test that we don't accidentally change the digest produced
    /// by [`TranscriptProtocol::append_message`]
    #[test]
    pub fn test_v1_append_each_message_stable() {
        let mut ro = TranscriptV1::with_domain("Domain1");
        ro.append_each_message("Label1", &vec![1u8, 2, 3], |ro, item| {
            ro.append_message("Item", item)
        });

        let challenge_hex = hex::encode(ro.extract_raw_challenge());
        assert_eq!(
            challenge_hex,
            "ffd0694d68003afd3751f33bbadd38ae26db78aa4e62ce4d53814b9676d6c7dd"
        );
    }
}
