//! This module provides common types and constants for encrypted transfers.

use crate::proofs::*;
use bulletproofs::range_proof::*;
use crypto_common::*;
use curve_arithmetic::*;
use elgamal::*;
use id::sigma_protocols::common::*;

#[derive(Clone, Serialize, SerdeBase16Serialize)]
/// An encrypted amount, in two chunks. The JSON serialization of this is just
/// base16 encoded serialized chunks.
///
/// The chunks are in big-endian order.
/// FIXME: They should be in little endian order.
pub struct EncryptedAmount<C: Curve> {
    pub encryptions: [Cipher<C>; 2],
}

impl<C: Curve> AsRef<[Cipher<C>; 2]> for EncryptedAmount<C> {
    fn as_ref(&self) -> &[Cipher<C>; 2] { &self.encryptions }
}

impl<C: Curve> AsRef<[Cipher<C>]> for EncryptedAmount<C> {
    fn as_ref(&self) -> &[Cipher<C>] { &self.encryptions.as_ref() }
}

/// Randomness used when producing an encrypted amount.
pub struct EncryptedAmountRandomness<C: Curve> {
    pub randomness: [Randomness<C>; 2],
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
    /// A collection of all the proofs.
    pub proof: EncryptedAmountTransferProof<C>,
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
/// Moreover these decryptions can be aggregated into
/// `AggregatedDecryptedAmount`s.
#[derive(Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(bound(serialize = "C: Curve", deserialize = "C: Curve"))]
#[serde(rename_all = "camelCase")]
pub struct DecryptedAmount<C: Curve> {
    /// The encrypted amount.
    pub encrypted_chunks: EncryptedAmount<C>,
    /// The plaintext corresponding to the encrypted amount.
    pub amount: Amount,
    /// The index of the encrypted amount as listed on the account.
    #[serde(default)]
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
    #[serde(default)]
    pub agg_index: u64,
}

/// # Proof datatypes

/// Proof that an encrypted transfer data is well-formed
#[derive(Serialize, SerdeBase16Serialize)]
pub struct EncryptedAmountTransferProof<C: Curve> {
    /// Proof that accounting is done correctly, i.e., remaining + transfer is
    /// the original amount.
    pub accounting: SigmaProof<enc_trans::Witness<C>>,
    /// Proof that the transfered amount is correctly encrypted, i.e., chunks
    /// small enough.
    pub transfer_amount_correct_encryption: RangeProof<C>,
    /// Proof that the remaining amount is correctly encrypted, i.e, chunks
    /// small enough.
    pub remaining_amount_correct_encryption: RangeProof<C>,
}
