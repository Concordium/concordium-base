//! This library provides the API needed by the chain, the wallet, and the
//! supporting tools to deal with encrypted amounts.
#[macro_use]
extern crate itertools;
#[macro_use]
extern crate crypto_common_derive;
#[macro_use]
extern crate failure;

mod ffi;

use crypto_common::*;
use curve_arithmetic::*;
use elgamal::*;
use id::types::*;
use rand::*;

#[derive(Serialize, Clone)]
pub struct EncryptedAmount<C: Curve> {
    /// Encryption of the high-chunk (highest 32 bits).
    pub encryption_hi: Cipher<C>,
    /// Encryption of the high-chunk (lowest 32 bits).
    pub encryption_low: Cipher<C>,
}

pub struct EncryptedAmountRandomness<C: Curve> {
    /// Randomness used to encrypt the high-chunk.
    pub randomness_hi: Randomness<C>,
    /// Randomness used to encrypt the low-chunk.
    pub randomness_low: Randomness<C>,
}

/// The type of amounts on the chain.
pub type Amount = u64;

pub const CHUNK_SIZE: ChunkSize = ChunkSize::ThirtyTwo;

/// Encrypt a single amount using the given public key.
pub fn encrypt_amount<C: Curve, R: Rng>(
    context: &GlobalContext<C>,
    pk: &PublicKey<C>,
    amount: Amount,
    csprng: &mut R,
) -> (EncryptedAmount<C>, EncryptedAmountRandomness<C>) {
    // The generator for encryption in the exponent is the second component of the
    // commitment key, the 'h'.
    let h = context.encryption_in_exponent_generator();
    let mut ciphers = encrypt_u64_in_chunks_given_generator(pk, amount, CHUNK_SIZE, h, csprng);
    // these two are guaranteed to exist because we used `ChunkSize::ThirtyTwo`. The
    // encryptions are in little-endian limbs, so the last one is the encryption
    // of the high bits.
    let (encryption_hi, randomness_hi) = ciphers.pop().unwrap();
    let (encryption_low, randomness_low) = ciphers.pop().unwrap();

    let enc = EncryptedAmount {
        encryption_low,
        encryption_hi,
    };
    let rand = EncryptedAmountRandomness {
        randomness_hi,
        randomness_low,
    };
    (enc, rand)
}

/// Combine two encrypted amounts into one.
pub fn aggregate<C: Curve>(
    left: &EncryptedAmount<C>,
    right: &EncryptedAmount<C>,
) -> EncryptedAmount<C> {
    let encryption_hi = left.encryption_hi.combine(&right.encryption_hi);
    let encryption_low = left.encryption_low.combine(&right.encryption_low);
    EncryptedAmount {
        encryption_hi,
        encryption_low,
    }
}

/// Aggregate many encrypted amounts together, starting from an existing one.
pub fn aggregate_many<'a, C: Curve>(start: &EncryptedAmount<C>, others: impl IntoIterator<Item=&'a EncryptedAmount<C>>) -> EncryptedAmount<C> {
    others.into_iter().fold(start.clone(), |left, right| aggregate(&left, right))
}

/// Decrypt a single amount given the helper table.
///
/// This function assumes that the encryption of the amount was done correctly,
/// and that the chunks are therefore small enough.
///
/// It also assumes that the generator used to encrypt the amount is the same
/// one that is used to contruct the table.
///
/// If not, this function will appear not to terminate.
pub fn decrypt_amount<C: Curve>(
    table: &BabyStepGiantStep<C>,
    sk: &SecretKey<C>,
    amount: &EncryptedAmount<C>,
) -> Amount {
    let hi_chunk = sk.decrypt_exponent(&amount.encryption_hi, table);
    let low_chunk = sk.decrypt_exponent(&amount.encryption_low, table);
    CHUNK_SIZE.chunks_to_u64([low_chunk, hi_chunk].iter().copied())
}
