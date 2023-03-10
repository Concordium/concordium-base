//! This library provides the API needed by the chain, the wallet, and the
//! supporting tools to deal with encrypted amounts.
#[macro_use]
extern crate crypto_common_derive;
#[macro_use]
extern crate itertools;

mod ffi;
pub mod proofs;
pub mod types;

use crate::types::{CHUNK_SIZE as CHUNK_SIZE_ENC_TRANS, *};
use crypto_common::types::Amount;
use curve_arithmetic::*;
use elgamal::*;
use id::types::*;
use rand::*;
use random_oracle::*;

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
    let mut ciphers = encrypt_u64_in_chunks_given_generator(
        pk,
        amount.micro_ccd(),
        CHUNK_SIZE_ENC_TRANS,
        h,
        csprng,
    );
    // these two are guaranteed to exist because we used `ChunkSize::ThirtyTwo`. The
    // encryptions are in little-endian limbs, so the last one is the encryption
    // of the high bits.
    let (encryption_hi, randomness_hi) = ciphers.pop().unwrap();
    let (encryption_low, randomness_low) = ciphers.pop().unwrap();

    let enc = EncryptedAmount {
        encryptions: [encryption_low, encryption_hi],
    };
    let rand = EncryptedAmountRandomness {
        randomness: [randomness_low, randomness_hi],
    };
    (enc, rand)
}

/// Make an encryption of a single amount using a fixed randomness.
///
/// Since randomness is 0 this method does not depend on the public key,
/// only on the global context that defines the relevant generators for
/// encryption in the exponent.
pub fn encrypt_amount_with_fixed_randomness<C: Curve>(
    context: &GlobalContext<C>,
    amount: Amount,
) -> EncryptedAmount<C> {
    // The generator for encryption in the exponent is the second component of the
    // commitment key, the 'h'.
    let h = context.encryption_in_exponent_generator();
    let val = amount.micro_ccd();
    let chunks = CHUNK_SIZE_ENC_TRANS
        .u64_to_chunks(val)
        .into_iter()
        .map(Value::<C>::from)
        .collect::<Vec<_>>();
    let mut ciphers = Vec::with_capacity(chunks.len());
    for x in chunks {
        let cipher = Cipher(C::zero_point(), h.mul_by_scalar(&x));
        ciphers.push(cipher);
    }
    let encryption_hi = ciphers.pop().unwrap();
    let encryption_low = ciphers.pop().unwrap();

    EncryptedAmount {
        encryptions: [encryption_low, encryption_hi],
    }
}

/// Combine two encrypted amounts into one.
/// This is only meaningful if both encrypted amounts are encrypted with the
/// same public key, otherwise the result is meaningless.
pub fn aggregate<C: Curve>(
    left: &EncryptedAmount<C>,
    right: &EncryptedAmount<C>,
) -> EncryptedAmount<C> {
    let encryption_hi = left.encryptions[1].combine(&right.encryptions[1]);
    let encryption_low = left.encryptions[0].combine(&right.encryptions[0]);
    EncryptedAmount {
        encryptions: [encryption_low, encryption_hi],
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
    let low_chunk = sk.decrypt_exponent(&amount.encryptions[0], table);
    let hi_chunk = sk.decrypt_exponent(&amount.encryptions[1], table);
    Amount::from_micro_ccd(
        CHUNK_SIZE_ENC_TRANS.chunks_to_u64([low_chunk, hi_chunk].iter().copied()),
    )
}

impl<C: Curve> EncryptedAmount<C> {
    /// Join chunks of an encrypted amount into a single ciphertext.
    /// The resulting ciphertext will in general not be easily decryptable.
    pub fn join(&self) -> Cipher<C> {
        let scale = 1u64 << u8::from(CHUNK_SIZE_ENC_TRANS);
        // NB: This relies on chunks being little-endian
        self.encryptions[1]
            .scale_u64(scale)
            .combine(&self.encryptions[0])
    }
}

// # Public API intended for use by the wallet.

/// Produce the payload of an encrypted amount transaction.
///
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
    let sender_pk = &PublicKey::from(sender_sk);
    let mut ro = RandomOracle::domain("EncryptedTransfer");
    ro.append_message(b"ctx", &ctx);
    ro.append_message(b"receiver_pk", &receiver_pk);
    ro.append_message(b"sender_pk", &sender_pk);

    proofs::gen_enc_trans(
        ctx,
        &mut ro,
        sender_pk,
        sender_sk,
        receiver_pk,
        input_amount.agg_index,
        &input_amount.agg_encrypted_amount.join(),
        input_amount.agg_amount,
        to_transfer,
        csprng,
    )
}

/// Verify an encrypted amount transaction.
///
/// The arguments are
///
/// - global context with parameters for generating proofs, and generators for
///   encrypting amounts.
/// - public key of the receiver of the transfer
/// - public key of the sender of the transfer
/// - encryption of amount on sender account before transfer
/// - encrypted amount transaction,
///
/// The return value is going to be `true` if verification succeeds and `false`
/// if not.
pub fn verify_transfer_data<C: Curve>(
    ctx: &GlobalContext<C>,
    receiver_pk: &PublicKey<C>,
    sender_pk: &PublicKey<C>,
    before_amount: &EncryptedAmount<C>,
    transfer_data: &EncryptedAmountTransferData<C>,
) -> bool {
    // Fixme: Put context into the random oracle.
    let mut ro = RandomOracle::domain("EncryptedTransfer");
    ro.append_message(b"ctx", &ctx);
    ro.append_message(b"receiver_pk", &receiver_pk);
    ro.append_message(b"sender_pk", &sender_pk);

    // FIXME: Revise order of arguments in verify_enc_trans to be more consistent
    // with the rest.
    proofs::verify_enc_trans(
        ctx,
        &mut ro,
        transfer_data,
        sender_pk,
        receiver_pk,
        &before_amount.join(),
    )
    .is_ok()
}

/// Produce the payload of an secret to public amount transaction.
///
/// The arguments are
///
/// - global context with parameters for generating proofs, and generators for
///   encrypting amounts.
/// - secret key of the sender (who is also the receiver)
/// - input amount from which to send
/// - amount to send
///
/// The return value is going to be `None` if a transfer could not be produced.
/// This could be because the `to_transfer` is too large, or because of some
/// other data inconsistency that means a proof could not be produced.
pub fn make_sec_to_pub_transfer_data<C: Curve, R: Rng>(
    ctx: &GlobalContext<C>,
    sk: &SecretKey<C>,
    input_amount: &AggregatedDecryptedAmount<C>,
    to_transfer: Amount,
    csprng: &mut R,
) -> Option<SecToPubAmountTransferData<C>> {
    let pk = &PublicKey::from(sk);
    // FIXME: Put context into random oracle
    let mut ro = RandomOracle::domain("SecToPubTransfer");
    ro.append_message(b"ctx", &ctx);
    ro.append_message(b"pk", &pk);

    // FIXME: Make arguments more in line between gen_sec_to_pub_trans and this.
    proofs::gen_sec_to_pub_trans(
        ctx,
        &mut ro,
        pk,
        sk,
        input_amount.agg_index,
        &input_amount.agg_encrypted_amount.join(),
        input_amount.agg_amount,
        to_transfer,
        csprng,
    )
}

// # Public API intended for use by the wallet.

/// Verify a secret to public amount transaction.
///
/// The arguments are
///
/// - global context with parameters for generating proofs, and generators for
///   encrypting amounts.
/// - public key of the sender (who is also the receiver) of the transfer
/// - encryption of amount on sender account before transfer
/// - secret to public amount transaction
///
/// The return value is going to be `true` if verification succeeds and `false`
/// if not.

pub fn verify_sec_to_pub_transfer_data<C: Curve>(
    ctx: &GlobalContext<C>,
    pk: &PublicKey<C>,
    before_amount: &EncryptedAmount<C>,
    transfer_data: &SecToPubAmountTransferData<C>,
) -> bool {
    // Fixme: Put context into the random oracle.
    let mut ro = RandomOracle::domain("SecToPubTransfer");
    ro.append_message(b"ctx", &ctx);
    ro.append_message(b"pk", &pk);

    // FIXME: Revise order of arguments in verify_sec_to_pub_trans to be more
    // consistent with the rest.
    proofs::verify_sec_to_pub_trans(ctx, &mut ro, transfer_data, pk, &before_amount.join()).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::G1;

    // Test that decryption is the inverse to encryption.
    #[test]
    fn test_encrypt_decrypt() {
        let mut csprng = thread_rng();
        let context = GlobalContext::<G1>::generate(String::from("genesis_string"));

        let sk = SecretKey::generate(context.elgamal_generator(), &mut csprng);
        let pk = PublicKey::from(&sk);

        let amount = Amount::from_micro_ccd(csprng.gen::<u64>());

        let (enc_amount, _) = encrypt_amount(&context, &pk, amount, &mut csprng);

        let m = 1 << 16;
        let table = BabyStepGiantStep::new(context.encryption_in_exponent_generator(), m);

        let decrypted = decrypt_amount(&table, &sk, &enc_amount);
        assert_eq!(
            amount, decrypted,
            "Decrypted amount differs from the original."
        );
    }

    #[test]
    fn test_scale() {
        let mut csprng = thread_rng();
        let context = GlobalContext::<G1>::generate(String::from("genesis_string"));

        let sk = SecretKey::generate(context.elgamal_generator(), &mut csprng);
        let pk = PublicKey::from(&sk);

        // we divide here by 3 to avoid overflow when summing them together.
        let amount_1 = u64::from(csprng.gen::<u32>());
        let amount_1 = Amount::from_micro_ccd(amount_1 << 2);

        let (enc_amount_1, _) = encrypt_amount(&context, &pk, amount_1, &mut csprng);

        let m = 1 << 16;
        let table = BabyStepGiantStep::new(context.encryption_in_exponent_generator(), m);

        let decrypted_1 = sk.decrypt_exponent(&enc_amount_1.join(), &table);
        assert_eq!(
            amount_1,
            Amount::from_micro_ccd(decrypted_1),
            "Decrypted combined encrypted amount differs from expected."
        );
    }

    // Test that the encryption with fixed randomness = 0 can be decrypted
    #[test]
    fn test_encryption_randomness_zero() {
        let mut csprng = thread_rng();
        let context = GlobalContext::<G1>::generate(String::from("genesis_string"));
        let sk = SecretKey::generate(context.elgamal_generator(), &mut csprng);
        let amount = Amount::from_micro_ccd(csprng.gen::<u64>());
        let dummy_encryption = encrypt_amount_with_fixed_randomness(&context, amount);
        let m = 1 << 16;
        let table = BabyStepGiantStep::new(context.encryption_in_exponent_generator(), m);

        let decrypted = decrypt_amount(&table, &sk, &dummy_encryption);
        assert_eq!(
            amount, decrypted,
            "Decrypted amount differs from the original."
        );
    }

    #[allow(non_snake_case)]
    #[test]
    fn test_make_and_verify_transfer_data() {
        let mut csprng = thread_rng();
        let sk_sender: SecretKey<G1> = SecretKey::generate_all(&mut csprng);
        let pk_sender = PublicKey::from(&sk_sender);
        let sk_receiver: SecretKey<G1> = SecretKey::generate(&pk_sender.generator, &mut csprng);
        let pk_receiver = PublicKey::from(&sk_receiver);
        let s: u64 = csprng.gen(); // amount on account.

        let a = csprng.gen_range(0, s); // amount to send

        let m = 2; // 2 chunks
        let n = 32;
        let nm = n * m;

        let context = GlobalContext::<G1>::generate_size(String::from("genesis_string"), nm);
        let S_in_chunks =
            encrypt_amount(&context, &pk_sender, Amount::from_micro_ccd(s), &mut csprng);

        let index = csprng.gen::<u64>().into(); // index is only important for on-chain stuff, not for proofs.
        let input_amount = AggregatedDecryptedAmount {
            agg_amount:           Amount::from_micro_ccd(s),
            agg_encrypted_amount: S_in_chunks.0.clone(),
            agg_index:            index,
        };
        let transfer_data = make_transfer_data(
            &context,
            &pk_receiver,
            &sk_sender,
            &input_amount,
            Amount::from_micro_ccd(a),
            &mut csprng,
        )
        .unwrap();

        assert_eq!(
            verify_transfer_data(
                &context,
                &pk_receiver,
                &pk_sender,
                &S_in_chunks.0,
                &transfer_data
            ),
            true
        );
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_make_and_verify_sec_to_pub_transfer_data() {
        let mut csprng = thread_rng();
        let sk_sender: SecretKey<G1> = SecretKey::generate_all(&mut csprng);
        let pk_sender = PublicKey::from(&sk_sender);
        let s: u64 = csprng.gen(); // amount on account.

        let a = csprng.gen_range(0, s); // amount to send

        let m = 2; // 2 chunks
        let n = 32;
        let nm = n * m;

        let context = GlobalContext::<G1>::generate_size(String::from("genesis_string"), nm);
        let S_in_chunks =
            encrypt_amount(&context, &pk_sender, Amount::from_micro_ccd(s), &mut csprng);

        let index = csprng.gen::<u64>().into(); // index is only important for on-chain stuff, not for proofs.
        let input_amount = AggregatedDecryptedAmount {
            agg_amount:           Amount::from_micro_ccd(s),
            agg_encrypted_amount: S_in_chunks.0.clone(),
            agg_index:            index,
        };

        let transfer_data = make_sec_to_pub_transfer_data(
            &context,
            &sk_sender,
            &input_amount,
            Amount::from_micro_ccd(a),
            &mut csprng,
        )
        .unwrap();

        assert_eq!(
            verify_sec_to_pub_transfer_data(&context, &pk_sender, &S_in_chunks.0, &transfer_data),
            true
        );
    }
}
