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

/// Size of the chunk for encrypted amounts.
pub const CHUNK_SIZE: ChunkSize = ChunkSize::ThirtyTwo;

/// Encrypt a single amount using the given public key, returning the encrypted
/// amount as well as the randomness used in the encryption of chunks.
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
pub fn aggregate_many<'a, C: Curve>(
    start: &EncryptedAmount<C>,
    others: impl IntoIterator<Item = &'a EncryptedAmount<C>>,
) -> EncryptedAmount<C> {
    others
        .into_iter()
        .fold(start.clone(), |left, right| aggregate(&left, right))
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

/// Data that will go onto an encrypted amount transfer.
pub struct EncryptedAmountTransferData<C: Curve> {
    /// Encryption of the remaining amount.
    pub remaining_amount: EncryptedAmount<C>,
    /// Amount that will be sent.
    pub transfer_amount: EncryptedAmount<C>,
    // TODO: Proofs.
}

/// Data that will go into a "transfer to encrypted balance" transaction.
pub struct EncryptAmountData<C: Curve> {
    /// Encryption of the amount to be transfered.
    pub transfer_amount: EncryptedAmount<C>,
    /// The actual amount to move from public to secret balance.
    pub to_encrypt: Amount,
    // TODO: Proofs.
}

/// Data that will go into a "transfer to public balance" transaction.
pub struct DecryptAmountData<C: Curve> {
    /// Encryption
    pub remaining_amount: EncryptedAmount<C>,
    pub reveal_amount: Amount,
    // TODO: Proofs.
}

/// Encrypted amount with a decrypted value.
///
/// Since decryption is an expensive process, we only do it once, and then store
/// the data.
pub struct EncryptedAmountWithDecryption<C: Curve> {
    pub encrypted_amount: EncryptedAmount<C>,
    pub amount:           Amount,
}

/// Produce the payload of an encrypted amount transaction.
/// The arguments are
///
/// - global context with parameters for generating proofs, and generators for
///   encrypting amounts.
/// - public key of the receiver of the transfer
/// - secret key of the sender of the transfer
/// - input amount from which to send
/// - amount to send
///
/// The return value is going to be `None` if a transfer could not be produced.
/// This could be because the `to_transfer` is too large, or because of some
/// other data inconsistency that means a proof could not be produced.
pub fn make_transfer_data<C: Curve, R: Rng>(
    ctx: &GlobalContext<C>,
    receiver_pk: &PublicKey<C>,
    sender_sk: &SecretKey<C>,
    input_amount: &EncryptedAmountWithDecryption<C>,
    to_transfer: Amount,
    csprng: &mut R,
) -> Option<EncryptedAmountTransferData<C>> {
    if to_transfer > input_amount.amount {
        return None;
    }
    // new amount on the sender's account
    let new_self_amount = input_amount.amount - to_transfer;

    let (remaining_amount, remaining_rand) =
        encrypt_amount(ctx, &PublicKey::from(sender_sk), new_self_amount, csprng);
    let (transfer_amount, transfer_rand) = encrypt_amount(ctx, receiver_pk, to_transfer, csprng);
    // FIXME: Now would come the proofs.
    Some(EncryptedAmountTransferData {
        remaining_amount,
        transfer_amount,
    })
}

/// Produce payload for the transaction to encrypt a portion of the public
/// balance. The arguments are
///
/// - global context with parameters for generating proofs
/// - secret key of the account (to produce a proof)
/// - amount to transfer to encrypted balance
pub fn make_encrypt_data<C: Curve, R: Rng>(
    ctx: &GlobalContext<C>,
    sender_sk: &SecretKey<C>,
    to_encrypt: Amount,
    csprng: &mut R,
) -> Option<EncryptAmountData<C>> {
    let (transfer_amount, transfer_rand) =
        encrypt_amount(ctx, &PublicKey::from(sender_sk), to_encrypt, csprng);
    // FIXME: Now would come the proofs.
    Some(EncryptAmountData {
        transfer_amount,
        to_encrypt,
    })
}

/// Produce payload for the transaction to decrypt a portion of the secret
/// balance. The arguments are
///
/// - global context with parameters for generating proofs
/// - secret key of the account (to produce a proof)
/// - current encrypted balance
/// - amount to transfer to public balance
pub fn make_decrypt_data<C: Curve, R: Rng>(
    ctx: &GlobalContext<C>,
    sender_sk: &SecretKey<C>,
    input_amount: &EncryptedAmountWithDecryption<C>,
    to_decrypt: Amount,
    csprng: &mut R,
) -> Option<DecryptAmountData<C>> {
    if to_decrypt > input_amount.amount {
        return None;
    }
    let remaining_amount = input_amount.amount - to_decrypt;
    let (remaining_amount, remaining_rand) =
        encrypt_amount(ctx, &PublicKey::from(sender_sk), remaining_amount, csprng);
    Some(DecryptAmountData {
        remaining_amount,
        reveal_amount: to_decrypt,
    })
}
