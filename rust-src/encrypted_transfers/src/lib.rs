//! This library provides the API needed by the chain, the wallet, and the
//! supporting tools to deal with encrypted amounts.
#[macro_use]
extern crate crypto_common_derive;
#[macro_use]
extern crate itertools;

mod ffi;
pub mod proofs;
mod types;

use crate::types::*;
use crypto_common::types::Amount;
use curve_arithmetic::*;
use elgamal::*;
use id::types::*;
use merlin::Transcript;
use proofs::*;
use rand::*;
use random_oracle::*;

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
    let mut ciphers =
        encrypt_u64_in_chunks_given_generator(pk, u64::from(amount), CHUNK_SIZE, h, csprng);
    // these two are guaranteed to exist because we used `ChunkSize::ThirtyTwo`. The
    // encryptions are in little-endian limbs, so the last one is the encryption
    // of the high bits.
    let (encryption_hi, randomness_hi) = ciphers.pop().unwrap();
    let (encryption_low, randomness_low) = ciphers.pop().unwrap();

    let enc = EncryptedAmount {
        encryptions: [encryption_hi, encryption_low],
    };
    let rand = EncryptedAmountRandomness {
        randomness: [randomness_hi, randomness_low],
    };
    (enc, rand)
}

/// Make a dummy encryption of a single amount using the given public key and
/// randomness 0
pub fn dummy_encrypt_amount<C: Curve>(
    context: &GlobalContext<C>,
    amount: Amount,
) -> EncryptedAmount<C> {
    // The generator for encryption in the exponent is the second component of the
    // commitment key, the 'h'.
    let h = context.encryption_in_exponent_generator();
    let val = u64::from(amount);
    let chunks = CHUNK_SIZE
        .u64_to_chunks(val)
        .into_iter()
        .map(Value::<C>::from_u64)
        .collect::<Vec<_>>();
    let mut ciphers = Vec::with_capacity(chunks.len());
    for x in chunks {
        let cipher = Cipher(C::zero_point(), h.mul_by_scalar(&x));
        ciphers.push(cipher);
    }
    let encryption_hi = ciphers.pop().unwrap();
    let encryption_low = ciphers.pop().unwrap();

    EncryptedAmount {
        encryptions: [encryption_hi, encryption_low],
    }
}

/// Combine two encrypted amounts into one.
pub fn aggregate<C: Curve>(
    left: &EncryptedAmount<C>,
    right: &EncryptedAmount<C>,
) -> EncryptedAmount<C> {
    let encryption_hi = left.encryptions[0].combine(&right.encryptions[0]);
    let encryption_low = left.encryptions[1].combine(&right.encryptions[1]);
    EncryptedAmount {
        encryptions: [encryption_hi, encryption_low],
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
pub fn decrypt_amount<C: Curve>(
    table: &BabyStepGiantStep<C>,
    sk: &SecretKey<C>,
    amount: &EncryptedAmount<C>,
) -> Amount {
    let hi_chunk = sk.decrypt_exponent(&amount.encryptions[0], table);
    let low_chunk = sk.decrypt_exponent(&amount.encryptions[1], table);
    Amount::from(CHUNK_SIZE.chunks_to_u64([low_chunk, hi_chunk].iter().copied()))
}

impl<C: Curve> EncryptedAmount<C> {
    /// Join chunks of an encrypted amount into a single ciphertext.
    /// The resulting ciphertext will in general not be easily decryptable.
    pub fn join(&self) -> Cipher<C> {
        let scale = 1u64 << u8::from(CHUNK_SIZE);
        // NB: This relies on chunks being big-endian
        self.encryptions[0]
            .scale_u64(scale)
            .combine(&self.encryptions[1])
    }
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
    // FIXME: Put context into random oracle
    let ro = RandomOracle::domain("EncryptedTransfer");
    // FIXME: Put context into the transcript.
    let mut transcript = Transcript::new(r"EncryptedTransfer".as_ref());
    let pk_sender = &PublicKey::from(sender_sk);
    // FIXME: Make arguments more in line between gen_enc_trans and this.
    encexp::gen_enc_trans(
        ctx,
        ro,
        &mut transcript,
        pk_sender,
        sender_sk,
        receiver_pk,
        input_amount.agg_index,
        &input_amount.agg_encrypted_amount.join(),
        input_amount.agg_amount,
        to_transfer,
        csprng,
    )
}

pub fn verify_transfer_data<C: Curve>(
    ctx: &GlobalContext<C>,
    receiver_pk: &PublicKey<C>,
    sender_pk: &PublicKey<C>,
    before_amount: &EncryptedAmount<C>,
    transfer_data: &EncryptedAmountTransferData<C>,
) -> bool {
    // Fixme: Put context into the random oracle.
    let ro = RandomOracle::domain("EncryptedTransfer");
    let mut transcript = Transcript::new(r"EncryptedTransfer".as_ref());

    // FIXME: Revise order of arguments in verify_enc_trans to be more consistent
    // with the rest.
    encexp::verify_enc_trans(
        ctx,
        ro,
        &mut transcript,
        transfer_data,
        sender_pk,
        receiver_pk,
        &before_amount.join(),
    )
    .is_ok()
}

pub fn make_sec_to_pub_transfer_data<C: Curve, R: Rng>(
    ctx: &GlobalContext<C>,
    sk: &SecretKey<C>,
    input_amount: &AggregatedDecryptedAmount<C>,
    to_transfer: Amount,
    csprng: &mut R,
) -> Option<SecToPubAmountTransferData<C>> {
    // FIXME: Put context into random oracle
    let ro = RandomOracle::domain("SecToPubTransfer");
    // FIXME: Put context into the transcript.
    let mut transcript = Transcript::new(r"SecToPubTransfer".as_ref());
    let pk = &PublicKey::from(sk);
    // FIXME: Make arguments more in line between gen_sec_to_pub_trans and this.
    encexp::gen_sec_to_pub_trans(
        ctx,
        ro,
        &mut transcript,
        pk,
        sk,
        input_amount.agg_index,
        &input_amount.agg_encrypted_amount.join(),
        input_amount.agg_amount,
        to_transfer,
        csprng,
    )
}

pub fn verify_sec_to_pub_transfer_data<C: Curve>(
    ctx: &GlobalContext<C>,
    pk: &PublicKey<C>,
    before_amount: &EncryptedAmount<C>,
    transfer_data: &SecToPubAmountTransferData<C>,
) -> bool {
    // Fixme: Put context into the random oracle.
    let ro = RandomOracle::domain("SecToPubTransfer");
    let mut transcript = Transcript::new(r"EncryptedTransfer".as_ref());

    // FIXME: Revise order of arguments in verify_sec_to_pub_trans to be more
    // consistent with the rest.
    encexp::verify_sec_to_pub_trans(
        ctx,
        ro,
        &mut transcript,
        transfer_data,
        pk,
        &before_amount.join(),
    )
    .is_ok()
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
    let remaining_amount = u64::from(input_amount.agg_amount) - u64::from(to_decrypt);
    let (remaining_amount, _remaining_rand) = encrypt_amount(
        ctx,
        &PublicKey::from(sender_sk),
        Amount::from(remaining_amount),
        csprng,
    );
    // FIXME: A proof would come here
    Some(DecryptAmountData {
        remaining_amount,
        reveal_amount: to_decrypt,
        index: input_amount.agg_index,
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
            self.agg_amount =
                Amount::from(u64::from(self.agg_amount).checked_add(u64::from(addition.amount))?);
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
        let context = GlobalContext::<G1>::generate();

        let sk = SecretKey::generate(context.elgamal_generator(), &mut csprng);
        let pk = PublicKey::from(&sk);

        let amount = Amount::from(csprng.gen::<u64>());

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
        let context = GlobalContext::<G1>::generate();

        let sk = SecretKey::generate(context.elgamal_generator(), &mut csprng);
        let pk = PublicKey::from(&sk);

        // we divide here by 3 to avoid overflow when summing them together.
        let amount_1 = Amount::from(csprng.gen::<u64>() / 3);
        let amount_2 = Amount::from(csprng.gen::<u64>() / 3);
        let amount_3 = Amount::from(csprng.gen::<u64>() / 3);

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
            amount_1 + (amount_2 + amount_3),
            Some(decrypted),
            "Decrypted aggregated encrypted amount differs from expected."
        );
    }

    // Test that aggregation works, and resulting data can be decrypted.
    // This test can be a bit slow, taking a few seconds.
    #[test]
    fn test_scale() {
        let mut csprng = thread_rng();
        let context = GlobalContext::<G1>::generate();

        let sk = SecretKey::generate(context.elgamal_generator(), &mut csprng);
        let pk = PublicKey::from(&sk);

        // we divide here by 3 to avoid overflow when summing them together.
        let amount_1 = u64::from(csprng.gen::<u32>());
        let amount_1 = Amount::from(amount_1 << 2);

        let (enc_amount_1, _) = encrypt_amount(&context, &pk, amount_1, &mut csprng);

        let m = 1 << 16;
        let table = BabyStepGiantStep::new(context.encryption_in_exponent_generator(), m);

        let decrypted_1 = sk.decrypt_exponent(&enc_amount_1.join(), &table);
        assert_eq!(
            amount_1,
            Amount::from(decrypted_1),
            "Decrypted combined encrypted amount differs from expected."
        );
    }

    // Test that the dummy encryption can be decrypted
    #[test]
    fn test_dummy_encryption() {
        let mut csprng = thread_rng();
        let context = GlobalContext::<G1>::generate();
        let sk = SecretKey::generate(context.elgamal_generator(), &mut csprng);
        let amount = Amount::from(csprng.gen::<u64>());
        let dummy_encryption = dummy_encrypt_amount(&context, amount);
        let m = 1 << 16;
        let table = BabyStepGiantStep::new(context.encryption_in_exponent_generator(), m);

        let decrypted = decrypt_amount(&table, &sk, &dummy_encryption);
        assert_eq!(
            amount, decrypted,
            "Decrypted amount differs from the original."
        );
    }
}
