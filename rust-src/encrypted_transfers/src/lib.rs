//! This library provides the API needed by the chain, the wallet, and the
//! supporting tools to deal with encrypted amounts.
#[macro_use]
extern crate crypto_common_derive;

pub mod ffi;

use crypto_common::*;
use curve_arithmetic::*;
use elgamal::*;
use id::types::*;
use rand::*;

#[derive(Clone, Serialize, SerdeBase16Serialize)]
/// An encrypted amount, in two chunks. The JSON serialization of this is just
/// base16 encoded serialized chunks.
pub struct EncryptedAmount<C: Curve> {
    /// Encryption of the high-chunk (highest 32 bits).
    pub encryption_hi: Cipher<C>,
    /// Encryption of the high-chunk (lowest 32 bits).
    pub encryption_low: Cipher<C>,
}

/// Randomness used when producing an encrypted amount.
pub struct EncryptedAmountRandomness<C: Curve> {
    /// Randomness used to encrypt the high-chunk.
    pub randomness_hi: Randomness<C>,
    /// Randomness used to encrypt the low-chunk.
    pub randomness_low: Randomness<C>,
}

/// An encrypted amount that we know the index of.
#[derive(Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(serialize = "C: Curve", deserialize = "C: Curve"))]
#[serde(rename_all = "camelCase")]
pub struct IndexedEncryptedAmount<C: Curve> {
    /// The actual encrypted amount.
    pub encrypted_chunks: EncryptedAmount<C>,
    /// Index of the amount on the account.
    pub index: u64,
}

/// The type of public amounts on the chain.
pub type Amount = u64;

/// Size of the chunk for encrypted amounts.
pub const CHUNK_SIZE: ChunkSize = ChunkSize::ThirtyTwo;

/// Data that will go onto an encrypted amount transfer.
#[derive(Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(serialize = "C: Curve", deserialize = "C: Curve"))]
#[serde(rename_all = "camelCase")]
pub struct EncryptedAmountTransferData<C: Curve> {
    /// Encryption of the remaining amount.
    pub remaining_amount: EncryptedAmount<C>,
    /// Amount that will be sent.
    pub transfer_amount: EncryptedAmount<C>,
    /// The index such that the encrypted amount used in the transfer represents
    /// the aggregate of all encrypted amounts with indices < `index` existing
    /// on the account at the time. New encrypted amounts can only add new
    /// indices.
    pub index: u64,
    // TODO: Proofs.
}

/// Data that will go into a "transfer to encrypted balance" transaction.
#[derive(Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(serialize = "C: Curve", deserialize = "C: Curve"))]
#[serde(rename_all = "camelCase")]
pub struct EncryptAmountData<C: Curve> {
    /// Encryption of the amount to be transfered.
    pub transfer_amount: EncryptedAmount<C>,
    /// The actual amount to move from public to secret balance.
    pub to_encrypt: Amount,
    // TODO: Proofs.
}

/// Data that will go into a "transfer to public balance" transaction.
#[derive(Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(serialize = "C: Curve", deserialize = "C: Curve"))]
#[serde(rename_all = "camelCase")]
pub struct DecryptAmountData<C: Curve> {
    /// Encryption of the remaining amount.
    pub remaining_amount: EncryptedAmount<C>,
    /// Amount to reveal.
    pub reveal_amount: Amount,
    /// The index such that the encrypted amount used represents the aggregate
    /// of all encrypted amounts with indices < `index` existing on the account
    /// at the time. New encrypted amounts can only add new indices.
    pub index: u64,
    // TODO: Proofs.
}

/// Encrypted amount with a decrypted value.
///
/// Since decryption is an expensive process, we only do it once, and then store
/// the data.
///
/// Moreover these decryptions can be aggregated.
#[derive(Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(serialize = "C: Curve", deserialize = "C: Curve"))]
#[serde(rename_all = "camelCase")]
pub struct DecryptedAmount<C: Curve> {
    /// The encrypted amount.
    pub encrypted_chunks: EncryptedAmount<C>,
    /// The plaintext corresponding to the encrypted amount.
    pub amount: Amount,
    /// The index of the encrypted amount as listed on the account.
    pub index: u64,
}

/// An aggregated encrypted amount with a decrypted plaintext, collecting
/// encrypted amounts with decryption. The only real difference from the above
/// is the meaning of the index field.
#[derive(Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(serialize = "C: Curve", deserialize = "C: Curve"))]
#[serde(rename_all = "camelCase")]
pub struct AggregatedDecryptedAmount<C: Curve> {
    /// The aggregated encrypted amount.
    pub agg_encrypted_amount: EncryptedAmount<C>,
    /// The plaintext corresponding to the aggregated encrypted amount.
    pub agg_amount: Amount,
    /// Index such that the `agg_amount` is the sum of all encrypted amounts
    /// on an account with indices strictly below `agg_index`.
    pub agg_index: u64,
}

/// # Internal helper functions.

/// Encrypt a single amount using the given public key, returning the encrypted
/// amount as well as the randomness used in the encryption of chunks.
fn encrypt_amount<C: Curve, R: Rng>(
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
fn aggregate<C: Curve>(
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

/// Decrypt a single amount given the helper table.
///
/// This function assumes that the encryption of the amount was done correctly,
/// and that the chunks are therefore small enough.
///
/// It also assumes that the generator used to encrypt the amount is the same
/// one that is used to contruct the table.
///
/// If not, this function will (almost certainly) appear not to terminate.
fn decrypt_amount<C: Curve>(
    table: &BabyStepGiantStep<C>,
    sk: &SecretKey<C>,
    amount: &EncryptedAmount<C>,
) -> Amount {
    let hi_chunk = sk.decrypt_exponent(&amount.encryption_hi, table);
    let low_chunk = sk.decrypt_exponent(&amount.encryption_low, table);
    CHUNK_SIZE.chunks_to_u64([low_chunk, hi_chunk].iter().copied())
}

/// # Public API intended for use by the wallet.

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
    input_amount: &AggregatedDecryptedAmount<C>,
    to_transfer: Amount,
    csprng: &mut R,
) -> Option<EncryptedAmountTransferData<C>> {
    if to_transfer > input_amount.agg_amount {
        return None;
    }
    // new amount on the sender's account
    let new_self_amount = input_amount.agg_amount - to_transfer;

    let (remaining_amount, _remaining_rand) =
        encrypt_amount(ctx, &PublicKey::from(sender_sk), new_self_amount, csprng);
    let (transfer_amount, _transfer_rand) = encrypt_amount(ctx, receiver_pk, to_transfer, csprng);
    // FIXME: Now would come the proofs.
    Some(EncryptedAmountTransferData {
        remaining_amount,
        transfer_amount,
        index: input_amount.agg_index,
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
    let (transfer_amount, _transfer_rand) =
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
    input_amount: &AggregatedDecryptedAmount<C>,
    to_decrypt: Amount,
    csprng: &mut R,
) -> Option<DecryptAmountData<C>> {
    if to_decrypt > input_amount.agg_amount {
        return None;
    }
    let remaining_amount = input_amount.agg_amount - to_decrypt;
    let (remaining_amount, _remaining_rand) =
        encrypt_amount(ctx, &PublicKey::from(sender_sk), remaining_amount, csprng);
    // FIXME: A proof would come here
    Some(DecryptAmountData {
        remaining_amount,
        reveal_amount: to_decrypt,
        index: input_amount.agg_amount,
    })
}

/// Decrypt a given encrypted amount with a known index.
///
/// This function assumes that the encryption of the amount was done correctly,
/// and that the chunks are therefore small enough.
///
/// It also assumes that the generator used to encrypt the amount is the same
/// one that is used to contruct the table.
///
/// If not, this function will (almost certainly) appear not to terminate.
pub fn decrypt_single<C: Curve>(
    table: &BabyStepGiantStep<C>,
    sk: &SecretKey<C>,
    enc_amount: IndexedEncryptedAmount<C>,
) -> DecryptedAmount<C> {
    let amount = decrypt_amount(table, sk, &enc_amount.encrypted_chunks);
    DecryptedAmount {
        encrypted_chunks: enc_amount.encrypted_chunks,
        amount,
        index: enc_amount.index,
    }
}

impl<C: Curve> AggregatedDecryptedAmount<C> {
    pub fn add(&mut self, addition: &DecryptedAmount<C>) -> Option<()> {
        if self.agg_index == addition.index {
            self.agg_encrypted_amount =
                aggregate(&self.agg_encrypted_amount, &addition.encrypted_chunks);
            self.agg_amount = self.agg_amount.checked_add(addition.amount)?;
            self.agg_index = self.agg_index.checked_add(1)?;
            Some(())
        } else {
            None
        }
    }
}

/// Combine many decrypted amounts into a single aggregated decrypted amount.
/// This function will return `None` if there are gaps in decrypted amount
/// indices, as well as if there are no decrypted amounts to decrypt.
///
/// The mutable slice will be reordered.
pub fn combine<C: Curve>(
    dec_amounts: &mut [DecryptedAmount<C>],
) -> Option<AggregatedDecryptedAmount<C>> {
    // First sort all the given amounts by indices, so we can easily make sure
    // that there are no duplicates, and none skipped.
    dec_amounts.sort_unstable_by_key(|x| x.index);
    let (first, rest) = dec_amounts.split_first()?;
    let next_index = first.index.checked_add(1)?;
    let mut agg = AggregatedDecryptedAmount {
        agg_encrypted_amount: first.encrypted_chunks.clone(),
        agg_index:            next_index,
        agg_amount:           first.amount,
    };
    for dec_amount in rest {
        agg.add(dec_amount)?
    }
    Some(agg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::G1;

    // Test that decryption is the inverse to encryption.
    #[test]
    fn test_encrypt_decrypt() {
        let mut csprng = thread_rng();
        let context = GlobalContext::<G1>::generate(&mut csprng);

        let sk = SecretKey::generate(context.elgamal_generator(), &mut csprng);
        let pk = PublicKey::from(&sk);

        let amount = csprng.gen();

        let (enc_amount, _) = encrypt_amount(&context, &pk, amount, &mut csprng);

        let m = 1 << 16;
        let table = BabyStepGiantStep::new(context.encryption_in_exponent_generator(), m);

        let decrypted = decrypt_amount(&table, &sk, &enc_amount);
        assert_eq!(
            amount, decrypted,
            "Decrypted amount differs from the original."
        );
    }

    // Test that aggregation works, and resulting data can be decrypted.
    // This test can be a bit slow, taking a few seconds.
    #[test]
    fn test_combine() {
        let mut csprng = thread_rng();
        let context = GlobalContext::<G1>::generate(&mut csprng);

        let sk = SecretKey::generate(context.elgamal_generator(), &mut csprng);
        let pk = PublicKey::from(&sk);

        // we divide here by 3 to avoid overflow when summing them together.
        let amount_1 = csprng.gen::<u64>() / 3;
        let amount_2 = csprng.gen::<u64>() / 3;
        let amount_3 = csprng.gen::<u64>() / 3;

        let (enc_amount_1, _) = encrypt_amount(&context, &pk, amount_1, &mut csprng);
        let (enc_amount_2, _) = encrypt_amount(&context, &pk, amount_2, &mut csprng);
        let (enc_amount_3, _) = encrypt_amount(&context, &pk, amount_3, &mut csprng);

        let m = 1 << 16;
        let table = BabyStepGiantStep::new(context.encryption_in_exponent_generator(), m);

        let decrypted_1 = decrypt_amount(&table, &sk, &enc_amount_1);
        let decrypted_2 = decrypt_amount(&table, &sk, &enc_amount_2);
        let decrypted_3 = decrypt_amount(&table, &sk, &enc_amount_3);

        let dec_1 = DecryptedAmount {
            encrypted_chunks: enc_amount_1,
            amount:           decrypted_1,
            index:            0,
        };
        let dec_2 = DecryptedAmount {
            encrypted_chunks: enc_amount_2,
            amount:           decrypted_2,
            index:            1,
        };
        let dec_3 = DecryptedAmount {
            encrypted_chunks: enc_amount_3,
            amount:           decrypted_3,
            index:            2,
        };

        let mut dec_amounts = [dec_1, dec_2, dec_3];
        let agg = combine(&mut dec_amounts).expect("Could not combine decrypted amounts.");
        let decrypted = decrypt_amount(&table, &sk, &agg.agg_encrypted_amount);
        assert_eq!(
            amount_1 + amount_2 + amount_3,
            decrypted,
            "Decrypted aggregated encrypted amount differs from expected."
        );
    }
}
