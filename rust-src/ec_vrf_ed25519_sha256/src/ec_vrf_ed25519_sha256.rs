// -*- mode: rust; -*-
//
// Authors:
// - bm@concordium.com
//

//! ed25519 VRF 

use core::default::Default;

use rand::CryptoRng;
use rand::RngCore;
use rand::Rng;
use rand::thread_rng;

use std::slice;

#[cfg(feature = "serde")]
use serde::de::Error as SerdeError;
#[cfg(feature = "serde")]
use serde::de::Visitor;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde::{Deserializer, Serializer};

pub use sha2::Sha512;

use curve25519_dalek::digest::generic_array::typenum::U64;
pub use curve25519_dalek::digest::Digest;

use curve25519_dalek::constants;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

pub use crate::constants::*;
pub use crate::errors::*;
pub use crate::public::*;
pub use crate::secret::*;
pub use crate::proof::*;

/// An ed25519 keypair.
#[derive(Debug, Default)] // we derive Default in order to use the clear() method in Drop
pub struct Keypair {
    /// The secret half of this keypair.
    pub secret: SecretKey,
    /// The public half of this keypair.
    pub public: PublicKey,
}

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
    ///   compressed Edwards-Y coordinate of a point on curve25519, both as bytes.
    ///   (As obtained from `Keypair::to_bytes()`.)
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
    pub fn from_bytes<'a>(bytes: &'a [u8]) -> Result<Keypair, ProofError> {
        if bytes.len() != KEYPAIR_LENGTH {
            return Err(ProofError(InternalError::BytesLengthError {
                name: "Keypair",
                length: KEYPAIR_LENGTH,
            }));
        }
        let secret = SecretKey::from_bytes(&bytes[..SECRET_KEY_LENGTH])?;
        let public = PublicKey::from_bytes(&bytes[SECRET_KEY_LENGTH..])?;

        Ok(Keypair{ secret: secret, public: public })
    }

    /// Generate an ed25519 keypair.
    ///
    /// # Example
    ///
    /// ```
    /// extern crate rand;
    /// extern crate ed25519_dalek;
    ///
    /// # #[cfg(feature = "std")]
    /// # fn main() {
    ///
    /// use rand::Rng;
    /// use rand::rngs::OsRng;
    /// use ed25519_dalek::Keypair;
    /// use ed25519_dalek::Signature;
    ///
    /// let mut csprng: OsRng = OsRng::new().unwrap();
    /// let keypair: Keypair = Keypair::generate(&mut csprng);
    ///
    /// # }
    /// #
    /// # #[cfg(not(feature = "std"))]
    /// # fn main() { }
    /// ```
    ///
    /// # Input
    ///
    /// A CSPRNG with a `fill_bytes()` method, e.g. `rand_chacha::ChaChaRng`.
    ///
    /// The caller must also supply a hash function which implements the
    /// `Digest` and `Default` traits, and which returns 512 bits of output.
    /// The standard hash function used for most ed25519 libraries is SHA-512,
    /// which is available with `use sha2::Sha512` as in the example above.
    /// Other suitable hash functions include Keccak-512 and Blake2b-512.
    pub fn generate<R>(csprng: &mut R) -> Keypair
    where
        R: CryptoRng + Rng,
    {
        let sk: SecretKey = SecretKey::generate(csprng);
        let pk: PublicKey = (&sk).into();

        Keypair{ public: pk, secret: sk }
    }

    /// prove a message with this keypair's secret key.
    pub fn prove<R: RngCore + CryptoRng>(&self, message: &[u8], rng:&mut R) -> Result<Proof, ProofError> {
        let expanded: ExpandedSecretKey = (&self.secret).into();

        expanded.prove(&self.public, &message,  rng)
    }
}

#[cfg(feature = "serde")]
impl Serialize for Keypair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes()[..])
    }
}

#[cfg(feature = "serde")]
impl<'d> Deserialize<'d> for Keypair {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        struct KeypairVisitor;

        impl<'d> Visitor<'d> for KeypairVisitor {
            type Value = Keypair;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                formatter.write_str("An ed25519 keypair, 64 bytes in total where the secret key is \
                                     the first 32 bytes and is in unexpanded form, and the second \
                                     32 bytes is a compressed point for a public key.")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<Keypair, E>
            where
                E: SerdeError,
            {
                let secret_key = SecretKey::from_bytes(&bytes[..SECRET_KEY_LENGTH]);
                let public_key = PublicKey::from_bytes(&bytes[SECRET_KEY_LENGTH..]);

                if secret_key.is_ok() && public_key.is_ok() {
                    Ok(Keypair{ secret: secret_key.unwrap(), public: public_key.unwrap() })
                } else {
                    Err(SerdeError::invalid_length(bytes.len(), &self))
                }
            }
        }
        deserializer.deserialize_bytes(KeypairVisitor)
    }
}


//foreign interface
#[no_mangle]

//Error encoding
//-1 secret key extraction failed
//-2 public key extraction failed
//0 proving failed
//1 success
pub extern fn ec_vrf_prove(proof: &mut [u8;PROOF_LENGTH], public_key_bytes: &[u8;PUBLIC_KEY_LENGTH], secret_key_bytes: &[u8;SECRET_KEY_LENGTH], message: *const u8, len: usize)->i32{
   let res_sk = SecretKey::from_bytes(secret_key_bytes);
   let res_pk = PublicKey::from_bytes(public_key_bytes);
   if res_sk.is_err() { return -1 };
   if res_pk.is_err() { return -2 };
   let sk = res_sk.unwrap();
   let pk = res_pk.unwrap();
                
   assert!(!message.is_null(), "Null pointer in ec_vrf_prove");
   let data: &[u8]= unsafe { slice::from_raw_parts(message, len)};
   let mut csprng = thread_rng();
   match sk.prove(&pk, data, &mut csprng){
       Err(_) => 0,
       p    => {proof.copy_from_slice(&p.unwrap().to_bytes()); 
                 1
       }
    }
}

#[no_mangle]
pub extern fn ec_vrf_priv_key(secret_key_bytes: &mut[u8;SECRET_KEY_LENGTH])-> i32{
   let mut csprng = thread_rng();
   let sk = SecretKey::generate(&mut csprng); 
   secret_key_bytes.copy_from_slice(&sk.to_bytes());
   1
}

//error encodeing
//bad input
#[no_mangle]
pub extern fn ec_vrf_pub_key(public_key_bytes: &mut[u8;32], secret_key_bytes: &[u8;32])->i32{
    let res_sk = SecretKey::from_bytes(secret_key_bytes);
    if res_sk.is_err() { return -1 };
    let sk = res_sk.unwrap();
    let pk = PublicKey::from(&sk); 
    public_key_bytes.copy_from_slice(&pk.to_bytes());
    1
}

#[no_mangle]
pub extern fn ec_vrf_proof_to_hash(hash: &mut[u8;32], pi: &[u8;80]) {
    let proof = Proof::from_bytes(&pi).expect("Proof Parsing failed");
    hash.copy_from_slice(&proof.to_hash());
}

#[no_mangle]
pub extern fn ec_vrf_verify_key(key: &[u8;32]) -> i32{
   if PublicKey::verify_key(key) { 1 } else { 0 } 
}

#[no_mangle]
pub extern fn ec_vrf_verify(public_key_bytes: &[u8;32], proof_bytes: &[u8;80], message: *const u8, len:usize)-> i32{
    let res_pk = PublicKey::from_bytes(public_key_bytes);
    if res_pk.is_err() { return -2 };
    let pk = res_pk.unwrap();

    let res_proof = Proof::from_bytes(&proof_bytes);
    if res_proof.is_err() { return -1 };
    let proof = res_proof.unwrap();

    assert!(!message.is_null(), "Null pointer in ec_vrf_prove");
    let data: &[u8]= unsafe { slice::from_raw_parts(message, len)};

    if pk.verify(proof, data) { 1 } else { 0 }
}

#[cfg(test)]
mod test {
    use super::*;

    use clear_on_drop::clear::Clear;

    #[test]
    fn keypair_clear_on_drop() {
        let mut keypair: Keypair = Keypair::from_bytes(&[1u8; KEYPAIR_LENGTH][..]).unwrap();

        keypair.clear();

        fn as_bytes<T>(x: &T) -> &[u8] {
            use std::mem;
            use std::slice;

            unsafe { slice::from_raw_parts(x as *const T as *const u8, mem::size_of_val(x)) }
        }

        assert!(!as_bytes(&keypair).contains(&0x15));
    }
}
