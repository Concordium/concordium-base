// -*- mode: rust; -*-
//
// Authors:
// - bm@concordium.com
//

//! ed25519 VRF

use rand::{thread_rng, CryptoRng, Rng, RngCore};

use std::slice;

#[cfg(feature = "serde")]
use serde::de::Error as SerdeError;
#[cfg(feature = "serde")]
use serde::de::Visitor;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde::{Deserializer, Serializer};

use ffi_helpers::*;
use libc::size_t;
use std::cmp::Ordering;
use subtle::ConstantTimeEq;

pub use sha2::Sha512;

pub use curve25519_dalek::digest::Digest;

pub use crate::{constants::*, errors::*, proof::*, public::*, secret::*};

/// An ed25519 keypair.
#[derive(Debug, Default)] // we derive Default in order to use the clear() method in Drop
pub struct Keypair {
    /// The secret half of this keypair.
    pub secret: SecretKey,
    /// The public half of this keypair.
    pub public: PublicKey,
}

/// Hack to get around different versions of the rand dependency.
pub fn generate_keypair() -> Keypair { Keypair::generate(&mut thread_rng()) }

impl Keypair {
    /// Convert this keypair to bytes.
    ///
    /// # Returns
    ///
    /// An array of bytes, `[u8; KEYPAIR_LENGTH]`.  The first
    /// `SECRET_KEY_LENGTH` of bytes is the `SecretKey`, and the next
    /// `PUBLIC_KEY_LENGTH` bytes is the `PublicKey` (the same as other
    /// libraries, such as [Adam Langley's ed25519 Golang
    /// implementation](https://github.com/agl/ed25519/)).
    pub fn to_bytes(&self) -> [u8; KEYPAIR_LENGTH] {
        let mut bytes: [u8; KEYPAIR_LENGTH] = [0u8; KEYPAIR_LENGTH];

        bytes[..SECRET_KEY_LENGTH].copy_from_slice(self.secret.as_bytes());
        bytes[SECRET_KEY_LENGTH..].copy_from_slice(self.public.as_bytes());
        bytes
    }

    /// Construct a `Keypair` from the bytes of a `PublicKey` and `SecretKey`.
    ///
    /// # Inputs
    ///
    /// * `bytes`: an `&[u8]` representing the scalar for the secret key, and a
    ///   compressed Edwards-Y coordinate of a point on curve25519, both as
    ///   bytes. (As obtained from `Keypair::to_bytes()`.)
    ///
    /// # Warning
    ///
    /// Absolutely no validation is done on the key.  If you give this function
    /// bytes which do not represent a valid point, or which do not represent
    /// corresponding parts of the key, then your `Keypair` will be broken and
    /// it will be your fault.
    ///
    /// # Returns
    ///
    /// A `Result` whose okay value is an EdDSA `Keypair` or whose error value
    /// is an `ProofError` describing the error that occurred.
    pub fn from_bytes(bytes: &[u8]) -> Result<Keypair, ProofError> {
        if bytes.len() != KEYPAIR_LENGTH {
            return Err(ProofError(InternalError::BytesLength {
                name:   "Keypair",
                length: KEYPAIR_LENGTH,
            }));
        }
        let secret = SecretKey::from_bytes(&bytes[..SECRET_KEY_LENGTH])?;
        let public = PublicKey::from_bytes(&bytes[SECRET_KEY_LENGTH..])?;

        Ok(Keypair { secret, public })
    }

    /// Generate an ed25519 keypair.
    pub fn generate<R>(csprng: &mut R) -> Keypair
    where
        R: CryptoRng + Rng, {
        let sk: SecretKey = SecretKey::generate(csprng);
        let pk: PublicKey = (&sk).into();

        Keypair {
            public: pk,
            secret: sk,
        }
    }

    /// prove a message with this keypair's secret key.
    pub fn prove<R: RngCore + CryptoRng>(&self, message: &[u8], rng: &mut R) -> Proof {
        let expanded: ExpandedSecretKey = (&self.secret).into();

        expanded.prove(&self.public, &message, rng)
    }
}

#[cfg(feature = "serde")]
impl Serialize for Keypair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer, {
        serializer.serialize_bytes(&self.to_bytes()[..])
    }
}

#[cfg(feature = "serde")]
impl<'d> Deserialize<'d> for Keypair {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>, {
        struct KeypairVisitor;

        impl<'d> Visitor<'d> for KeypairVisitor {
            type Value = Keypair;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                formatter.write_str(
                    "An ed25519 keypair, 64 bytes in total where the secret key is the first 32 \
                     bytes and is in unexpanded form, and the second 32 bytes is a compressed \
                     point for a public key.",
                )
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Keypair, E>
            where
                E: SerdeError, {
                let secret_key = SecretKey::from_bytes(&bytes[..SECRET_KEY_LENGTH]);
                let public_key = PublicKey::from_bytes(&bytes[SECRET_KEY_LENGTH..]);

                if secret_key.is_ok() && public_key.is_ok() {
                    Ok(Keypair {
                        secret: secret_key.unwrap(),
                        public: public_key.unwrap(),
                    })
                } else {
                    Err(SerdeError::invalid_length(bytes.len(), &self))
                }
            }
        }
        deserializer.deserialize_bytes(KeypairVisitor)
    }
}

// foreign interface

// Boilerplate serialization functions.
macro_derive_from_bytes_no_cursor!(ec_vrf_proof_from_bytes, Proof, Proof::from_bytes);
macro_derive_from_bytes_no_cursor!(
    ec_vrf_public_key_from_bytes,
    PublicKey,
    PublicKey::from_bytes
);
macro_derive_from_bytes_no_cursor!(
    ec_vrf_secret_key_from_bytes,
    SecretKey,
    SecretKey::from_bytes
);
macro_derive_to_bytes!(ec_vrf_proof_to_bytes, Proof);
macro_derive_to_bytes!(ec_vrf_public_key_to_bytes, PublicKey);
macro_derive_to_bytes!(ec_vrf_secret_key_to_bytes, SecretKey);
// Cleanup of allocated structs.
macro_free_ffi!(ec_vrf_proof_free, Proof);
macro_free_ffi!(ec_vrf_public_key_free, PublicKey);
macro_free_ffi!(ec_vrf_secret_key_free, SecretKey);

// equality testing
macro_derive_binary!(ec_vrf_proof_eq, Proof, Proof::eq);
macro_derive_binary!(ec_vrf_public_key_eq, PublicKey, PublicKey::eq);
// NB: Using constant time comparison.
macro_derive_binary!(ec_vrf_secret_key_eq, SecretKey, |x, y| bool::from(
    SecretKey::ct_eq(x, y)
));

// ord instance for proof

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
/// Generate a VRF proof. This function assumes the arguments are not
/// null-pointers and it always returns a non-null pointer.
/// NB: This function is non-deterministic (i.e., uses randomness).
pub extern "C" fn ec_vrf_prove(
    public: *const PublicKey,
    secret: *const SecretKey,
    message: *const u8,
    len: size_t,
) -> *const Proof {
    let sk = from_ptr!(secret);
    let pk = from_ptr!(public);

    let data: &[u8] = slice_from_c_bytes!(message, len);
    let mut csprng = thread_rng();
    let proof = sk.prove(&pk, data, &mut csprng);
    Box::into_raw(Box::new(proof))
}

#[no_mangle]
/// Generate a new secret key using the system random number generator.
/// The result is always a non-null pointer.
pub extern "C" fn ec_vrf_priv_key() -> *const SecretKey {
    let mut csprng = thread_rng();
    let sk = SecretKey::generate(&mut csprng);
    Box::into_raw(Box::new(sk))
}

#[no_mangle]
/// Derive a public key from a secret key.
/// We assume the secret key pointer is non-null.
/// The result is always a non-null pointer.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn ec_vrf_pub_key(secret_key: *const SecretKey) -> *const PublicKey {
    let sk = from_ptr!(secret_key);
    let pk = PublicKey::from(sk);
    Box::into_raw(Box::new(pk))
}

#[no_mangle]
/// Compute hash of a proof.
/// We assume the proof pointer is non-null.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn ec_vrf_proof_to_hash(hash_ptr: *mut u8, proof_ptr: *const Proof) {
    let hash = mut_slice_from_c_bytes!(hash_ptr, 32);
    let proof = from_ptr!(proof_ptr);
    hash.copy_from_slice(&proof.to_hash())
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn ec_vrf_verify_key(key_ptr: *const PublicKey) -> i32 {
    let key = from_ptr!(key_ptr);
    if key.verify_key() {
        1
    } else {
        0
    }
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
/// Verify. Returns 1 if verification successful and 0 otherwise.
/// We assume all pointers are non-null.
pub extern "C" fn ec_vrf_verify(
    public_key_ptr: *const PublicKey,
    proof_ptr: *const Proof,
    message_ptr: *const u8,
    len: size_t,
) -> i32 {
    let pk = from_ptr!(public_key_ptr);
    let proof = from_ptr!(proof_ptr);
    let message: &[u8] = slice_from_c_bytes!(message_ptr, len);

    if pk.verify(proof, message) {
        1
    } else {
        0
    }
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
// support ord instance needed in Haskell
pub extern "C" fn ec_vrf_proof_cmp(proof_ptr_1: *const Proof, proof_ptr_2: *const Proof) -> i32 {
    // optimistic check first.
    if proof_ptr_1 == proof_ptr_2 {
        return 0;
    }

    let p1 = from_ptr!(proof_ptr_1);
    let p2 = from_ptr!(proof_ptr_2);
    match p1.2.as_bytes().cmp(p2.2.as_bytes()) {
        Ordering::Less => return -1,
        Ordering::Greater => return 1,
        Ordering::Equal => (),
    }

    // we now have that the last component is equal
    // check the middle scalar
    match p1.1.as_bytes().cmp(p2.1.as_bytes()) {
        Ordering::Less => return -1,
        Ordering::Greater => return 1,
        Ordering::Equal => (),
    }

    // the scalars are equal, need to check the edwards point
    match p1.0.compress().as_bytes().cmp(p2.0.compress().as_bytes()) {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
// ord instance for public keys
pub extern "C" fn ec_vrf_public_key_cmp(
    public_key_ptr_1: *const PublicKey,
    public_key_ptr_2: *const PublicKey,
) -> i32 {
    // optimistic check first.
    if public_key_ptr_1 == public_key_ptr_2 {
        return 0;
    }

    let p1 = from_ptr!(public_key_ptr_1);
    let p2 = from_ptr!(public_key_ptr_2);

    // only compare the compressed point since the
    // decompressed one is derived.
    match p1.0.as_bytes().cmp(p2.0.as_bytes()) {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}
