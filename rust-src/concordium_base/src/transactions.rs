//! Definition of transactions and other transaction-like messages, together
//! with their serialization, signing, and similar auxiliary methods.

use crate::{
    base::{
        AccountThreshold, AggregateSigPairing, AmountFraction, BakerAggregationVerifyKey,
        BakerElectionVerifyKey, BakerKeyPairs, BakerSignatureVerifyKey, ContractAddress,
        CredentialRegistrationID, DelegationTarget, Energy, Nonce, OpenStatus, UrlText,
    },
    constants::*,
    hashes, smart_contracts, updates,
};
use crypto_common::{
    derive::{Serial, Serialize},
    types::{Amount, KeyIndex, KeyPair, Timestamp, TransactionSignature, TransactionTime, *},
    Buffer, Deserial, Get, ParseResult, Put, ReadBytesExt, SerdeDeserialize, SerdeSerialize,
    Serial,
};
use derive_more::*;
use encrypted_transfers::types::{EncryptedAmountTransferData, SecToPubAmountTransferData};
use id::types::{
    AccountAddress, AccountCredentialMessage, AccountKeys, CredentialDeploymentInfo,
    CredentialPublicKeys,
};
use rand::{CryptoRng, Rng};
use random_oracle::RandomOracle;
use sha2::Digest;
use std::{collections::BTreeMap, marker::PhantomData};
use thiserror::Error;

#[derive(SerdeSerialize, SerdeDeserialize, Serial, Debug, Clone, AsRef, Into)]
#[serde(transparent)]
/// A data that was registered on the chain.
pub struct Memo {
    #[serde(with = "crate::internal::byte_array_hex")]
    #[size_length = 2]
    bytes: Vec<u8>,
}

/// An error used to signal that an object was too big to be converted.
#[derive(Display, Error, Debug)]
pub struct TooBig;

impl TryFrom<Vec<u8>> for Memo {
    type Error = TooBig;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() <= crate::constants::MAX_MEMO_SIZE {
            Ok(Self { bytes: value })
        } else {
            Err(TooBig)
        }
    }
}

impl Deserial for Memo {
    fn deserial<R: crypto_common::ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let len: u16 = source.get()?;
        anyhow::ensure!(
            usize::from(len) <= crate::constants::MAX_MEMO_SIZE,
            "Memo too big.."
        );
        let bytes = crypto_common::deserial_bytes(source, len.into())?;
        Ok(Memo { bytes })
    }
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, Display)]
#[serde(rename_all = "camelCase")]
// Since all variants are fieldless, the default JSON serialization will convert
// all the variants to simple strings.
/// Types of account transactions.
pub enum TransactionType {
    /// Deploy a Wasm module.
    DeployModule,
    /// Initialize a smart contract instance.
    InitContract,
    /// Update a smart contract instance.
    Update,
    /// Transfer CCD from an account to another.
    Transfer,
    /// Register an account as a baker.
    AddBaker,
    /// Remove an account as a baker.
    RemoveBaker,
    /// Update the staked amount.
    UpdateBakerStake,
    /// Update whether the baker automatically restakes earnings.
    UpdateBakerRestakeEarnings,
    /// Update baker keys
    UpdateBakerKeys,
    /// Update given credential keys
    UpdateCredentialKeys,
    /// Transfer encrypted amount.
    EncryptedAmountTransfer,
    /// Transfer from public to encrypted balance of the same account.
    TransferToEncrypted,
    /// Transfer from encrypted to public balance of the same account.
    TransferToPublic,
    /// Transfer a CCD with a release schedule.
    TransferWithSchedule,
    /// Update the account's credentials.
    UpdateCredentials,
    /// Register some data on the chain.
    RegisterData,
    /// Same as transfer but with a memo field.
    TransferWithMemo,
    /// Same as encrypted transfer, but with a memo.
    EncryptedAmountTransferWithMemo,
    /// Same as transfer with schedule, but with an added memo.
    TransferWithScheduleAndMemo,
    ///  Configure an account's baker.
    ConfigureBaker,
    ///  Configure an account's stake delegation.
    ConfigureDelegation,
}

/// An error that occurs when trying to convert
/// an invalid i32 tag to a [TransactionType].
#[derive(Debug, Error)]
#[error("{0} is not a valid TransactionType tag.")]
pub struct TransactionTypeConversionError(pub i32);

impl TryFrom<i32> for TransactionType {
    type Error = TransactionTypeConversionError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => Self::DeployModule,
            1 => Self::InitContract,
            2 => Self::Update,
            3 => Self::Transfer,
            4 => Self::AddBaker,
            5 => Self::RemoveBaker,
            6 => Self::UpdateBakerStake,
            7 => Self::UpdateBakerRestakeEarnings,
            8 => Self::UpdateBakerKeys,
            9 => Self::UpdateCredentialKeys,
            10 => Self::EncryptedAmountTransfer,
            11 => Self::TransferToEncrypted,
            12 => Self::TransferToPublic,
            13 => Self::TransferWithSchedule,
            14 => Self::UpdateCredentials,
            15 => Self::RegisterData,
            16 => Self::TransferWithMemo,
            17 => Self::EncryptedAmountTransferWithMemo,
            18 => Self::TransferWithScheduleAndMemo,
            19 => Self::ConfigureBaker,
            20 => Self::ConfigureDelegation,
            n => return Err(TransactionTypeConversionError(n)),
        })
    }
}

#[derive(
    Debug, Copy, Clone, Serial, SerdeSerialize, SerdeDeserialize, Into, From, Display, Eq, PartialEq,
)]
#[serde(transparent)]
/// Type safe wrapper to record the size of the transaction payload.
pub struct PayloadSize {
    pub(crate) size: u32,
}

impl Deserial for PayloadSize {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let size: u32 = source.get()?;
        anyhow::ensure!(
            size <= MAX_PAYLOAD_SIZE,
            "Size of the payload exceeds maximum allowed."
        );
        Ok(PayloadSize { size })
    }
}

#[derive(Debug, Clone, Serialize, SerdeSerialize, SerdeDeserialize)]
#[serde(rename_all = "camelCase")]
/// Header of an account transaction that contains basic data to check whether
/// the sender and the transaction is valid.
pub struct TransactionHeader {
    /// Sender account of the transaction.
    pub sender:        AccountAddress,
    /// Sequence number of the transaction.
    pub nonce:         Nonce,
    /// Maximum amount of energy the transaction can take to execute.
    pub energy_amount: Energy,
    /// Size of the transaction payload. This is used to deserialize the
    /// payload.
    pub payload_size:  PayloadSize,
    /// Latest time the transaction can be included in a block.
    pub expiry:        TransactionTime,
}

#[derive(Debug, Clone, SerdeSerialize, SerdeDeserialize, Into, AsRef)]
#[serde(transparent)]
/// An account transaction payload that has not yet been deserialized.
/// This is a simple wrapper around Vec<u8> with bespoke serialization.
pub struct EncodedPayload {
    #[serde(with = "crate::internal::byte_array_hex")]
    pub(crate) payload: Vec<u8>,
}

#[derive(Debug, Error)]
#[error("The given byte array of size {actual}B exceeds maximum payload size {max}B")]
pub struct ExceedsPayloadSize {
    pub actual: usize,
    pub max:    u32,
}

impl TryFrom<Vec<u8>> for EncodedPayload {
    type Error = ExceedsPayloadSize;

    fn try_from(payload: Vec<u8>) -> Result<Self, Self::Error> {
        let actual = payload.len();
        if actual
            .try_into()
            .map_or(false, |x: u32| x <= MAX_PAYLOAD_SIZE)
        {
            Ok(Self { payload })
        } else {
            Err(ExceedsPayloadSize {
                actual,
                max: MAX_PAYLOAD_SIZE,
            })
        }
    }
}

impl EncodedPayload {
    /// Attempt to decode the [`EncodedPayload`] into a structured [`Payload`].
    /// This also checks that all data is used, i.e., that there are no
    /// remaining trailing bytes.
    pub fn decode(&self) -> ParseResult<Payload> {
        let mut source = std::io::Cursor::new(&self.payload);
        let payload = source.get()?;
        // ensure payload length matches the stated size.
        let consumed = source.position();
        anyhow::ensure!(
            consumed == self.payload.len() as u64,
            "Payload length information is inaccurate: {} bytes of input remaining.",
            self.payload.len() as u64 - consumed
        );
        Ok(payload)
    }
}

/// This serial instance does not have an inverse. It needs a context with the
/// length.
impl Serial for EncodedPayload {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.write_all(&self.payload)
            .expect("Writing to buffer should succeed.");
    }
}

/// Parse an encoded payload of specified length.
pub fn get_encoded_payload<R: ReadBytesExt>(
    source: &mut R,
    len: PayloadSize,
) -> ParseResult<EncodedPayload> {
    // The use of deserial_bytes is safe here (no execessive allocations) because
    // payload_size is limited
    let payload = crypto_common::deserial_bytes(source, u32::from(len) as usize)?;
    Ok(EncodedPayload { payload })
}

/// A helper trait so that we can treat payload and encoded payload in the same
/// place.
pub trait PayloadLike {
    /// Encode the transaction payload by serializing.
    fn encode(&self) -> EncodedPayload;
    /// Encode the payload directly to a buffer. This will in general be more
    /// efficient than `encode`. However this will only matter if serialization
    /// was to be done in a tight loop.
    fn encode_to_buffer<B: Buffer>(&self, out: &mut B);
}

impl PayloadLike for EncodedPayload {
    fn encode(&self) -> EncodedPayload { self.clone() }

    fn encode_to_buffer<B: Buffer>(&self, out: &mut B) {
        out.write_all(&self.payload)
            .expect("Writing to buffer is always safe.");
    }
}

#[derive(Debug, Clone, SerdeDeserialize, SerdeSerialize)]
#[serde(rename_all = "camelCase")]
/// An account transaction signed and paid for by a sender account.
/// The payload type is a generic parameter to support two kinds of payloads,
/// a fully deserialized [Payload] type, and an [EncodedPayload]. The latter is
/// useful since deserialization of some types of payloads is expensive. It is
/// thus useful to delay deserialization until after we have checked signatures
/// and the sender account information.
pub struct AccountTransaction<PayloadType> {
    pub signature: TransactionSignature,
    pub header:    TransactionHeader,
    pub payload:   PayloadType,
}

impl<P: PayloadLike> Serial for AccountTransaction<P> {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.put(&self.signature);
        out.put(&self.header);
        self.payload.encode_to_buffer(out)
    }
}

impl Deserial for AccountTransaction<EncodedPayload> {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let signature = source.get()?;
        let header: TransactionHeader = source.get()?;
        let payload = get_encoded_payload(source, header.payload_size)?;
        Ok(AccountTransaction {
            signature,
            header,
            payload,
        })
    }
}

impl Deserial for AccountTransaction<Payload> {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let signature = source.get()?;
        let header: TransactionHeader = source.get()?;
        let payload_len = u64::from(u32::from(header.payload_size));
        let mut limited = <&mut R as std::io::Read>::take(source, payload_len);
        let payload = limited.get()?;
        // ensure payload length matches the stated size.
        anyhow::ensure!(
            limited.limit() == 0,
            "Payload length information is inaccurate: {} bytes of input remaining.",
            limited.limit()
        );
        Ok(AccountTransaction {
            signature,
            header,
            payload,
        })
    }
}

impl<P: PayloadLike> AccountTransaction<P> {
    /// Verify signature on the transaction given the public keys.
    pub fn verify_transaction_signature(&self, keys: &impl HasAccountAccessStructure) -> bool {
        let hash = compute_transaction_sign_hash(&self.header, &self.payload);
        verify_signature_transaction_sign_hash(keys, &hash, &self.signature)
    }
}

/// Marker for `BakerKeysPayload` indicating the proofs contained in
/// `BakerKeysPayload` have been generated for an `AddBaker` transaction.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum AddBakerKeysMarker {}

/// Marker for `BakerKeysPayload` indicating the proofs contained in
/// `BakerKeysPayload` have been generated for an `UpdateBakerKeys` transaction.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum UpdateBakerKeysMarker {}

/// Marker for `ConfigureBakerKeysPayload` indicating the proofs contained in
/// `ConfigureBaker` have been generated for an `ConfigureBaker` transaction.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConfigureBakerKeysMarker {}

#[derive(Debug, Clone, SerdeDeserialize, SerdeSerialize)]
#[serde(rename_all = "camelCase")]
/// Auxiliary type that contains public keys and proof of ownership of those
/// keys. This is used in the `AddBaker` and `UpdateBakerKeys` transaction
/// types.
/// The proofs are either constructed for `AddBaker` or `UpdateBakerKeys` and
/// the generic `V` is used as a marker to distinguish this in the type. See the
/// markers: `AddBakerKeysMarker` and `UpdateBakerKeysMarker`.
pub struct BakerKeysPayload<V> {
    #[serde(skip)] // use default when deserializing
    phantom:                    PhantomData<V>,
    /// New public key for participating in the election lottery.
    pub election_verify_key:    BakerElectionVerifyKey,
    /// New public key for verifying this baker's signatures.
    pub signature_verify_key:   BakerSignatureVerifyKey,
    /// New public key for verifying this baker's signature on finalization
    /// records.
    pub aggregation_verify_key: BakerAggregationVerifyKey,
    /// Proof of knowledge of the secret key corresponding to the signature
    /// verification key.
    pub proof_sig:              eddsa_ed25519::Ed25519DlogProof,
    /// Proof of knowledge of the election secret key.
    pub proof_election:         eddsa_ed25519::Ed25519DlogProof,
    /// Proof of knowledge of the secret key for signing finalization
    /// records.
    pub proof_aggregation:      aggregate_sig::Proof<AggregateSigPairing>,
}

/// Baker keys payload containing proofs construct for a `AddBaker` transaction.
pub type BakerAddKeysPayload = BakerKeysPayload<AddBakerKeysMarker>;
/// Baker keys payload containing proofs construct for a `UpdateBakerKeys`
/// transaction.
pub type BakerUpdateKeysPayload = BakerKeysPayload<UpdateBakerKeysMarker>;

/// Baker keys payload containing proofs construct for a `ConfigureBaker`
/// transaction.
pub type ConfigureBakerKeysPayload = BakerKeysPayload<ConfigureBakerKeysMarker>;

impl<T> BakerKeysPayload<T> {
    /// Construct a BakerKeysPayload taking a prefix for the challenge.
    fn new_payload<R: Rng + CryptoRng>(
        baker_keys: &BakerKeyPairs,
        sender: AccountAddress,
        challenge_prefix: &[u8],
        csprng: &mut R,
    ) -> Self {
        let mut challenge = challenge_prefix.to_vec();

        sender.serial(&mut challenge);
        baker_keys.election_verify.serial(&mut challenge);
        baker_keys.signature_verify.serial(&mut challenge);
        baker_keys.aggregation_verify.serial(&mut challenge);

        let proof_election = eddsa_ed25519::prove_dlog_ed25519(
            csprng,
            &mut RandomOracle::domain(&challenge),
            &baker_keys.election_verify.verify_key,
            &baker_keys.election_sign.sign_key,
        );
        let proof_sig = eddsa_ed25519::prove_dlog_ed25519(
            csprng,
            &mut RandomOracle::domain(&challenge),
            &baker_keys.signature_verify.verify_key,
            &baker_keys.signature_sign.sign_key,
        );
        let proof_aggregation = baker_keys
            .aggregation_sign
            .prove(csprng, &mut RandomOracle::domain(&challenge));

        BakerKeysPayload {
            phantom: PhantomData::default(),
            election_verify_key: baker_keys.election_verify.clone(),
            signature_verify_key: baker_keys.signature_verify.clone(),
            aggregation_verify_key: baker_keys.aggregation_verify.clone(),
            proof_sig,
            proof_election,
            proof_aggregation,
        }
    }
}

impl BakerAddKeysPayload {
    /// Construct a BakerKeysPayload with proofs for adding a baker.
    pub fn new<T: Rng + CryptoRng>(
        baker_keys: &BakerKeyPairs,
        sender: AccountAddress,
        csprng: &mut T,
    ) -> Self {
        BakerKeysPayload::new_payload(baker_keys, sender, b"addBaker", csprng)
    }
}

impl BakerUpdateKeysPayload {
    /// Construct a BakerKeysPayload with proofs for updating baker keys.
    pub fn new<T: Rng + CryptoRng>(
        baker_keys: &BakerKeyPairs,
        sender: AccountAddress,
        csprng: &mut T,
    ) -> Self {
        BakerKeysPayload::new_payload(baker_keys, sender, b"updateBakerKeys", csprng)
    }
}

impl ConfigureBakerKeysPayload {
    /// Construct a BakerKeysPayload with proofs for updating baker keys.
    pub fn new<T: Rng + CryptoRng>(
        baker_keys: &BakerKeyPairs,
        sender: AccountAddress,
        csprng: &mut T,
    ) -> Self {
        BakerKeysPayload::new_payload(baker_keys, sender, b"configureBaker", csprng)
    }
}

#[derive(Debug, Clone, SerdeDeserialize, SerdeSerialize)]
#[serde(rename_all = "camelCase")]
/// Payload of the `AddBaker` transaction. This transaction registers the
/// account as a baker.
pub struct AddBakerPayload {
    /// The keys with which the baker registered.
    #[serde(flatten)]
    pub keys:             BakerAddKeysPayload,
    /// Initial baking stake.
    pub baking_stake:     Amount,
    /// Whether to add earnings to the stake automatically or not.
    pub restake_earnings: bool,
}

#[derive(Debug, Clone, SerdeDeserialize, SerdeSerialize)]
#[serde(rename_all = "camelCase")]
/// Data needed to initialize a smart contract.
pub struct InitContractPayload {
    /// Deposit this amount of CCD.
    pub amount:    Amount,
    /// Reference to the module from which to initialize the instance.
    pub mod_ref:   smart_contracts::ModuleRef,
    /// Name of the contract in the module.
    pub init_name: smart_contracts::OwnedContractName,
    /// Message to invoke the initialization method with.
    pub param:     smart_contracts::Parameter,
}

#[derive(Debug, Clone, SerdeDeserialize, SerdeSerialize)]
#[serde(rename_all = "camelCase")]
/// Data needed to update a smart contract instance.
pub struct UpdateContractPayload {
    /// Send the given amount of CCD together with the message to the
    /// contract instance.
    pub amount:       Amount,
    /// Address of the contract instance to invoke.
    pub address:      ContractAddress,
    /// Name of the method to invoke on the contract.
    pub receive_name: smart_contracts::OwnedReceiveName,
    /// Message to send to the contract instance.
    pub message:      smart_contracts::Parameter,
}

#[derive(Debug, Clone, SerdeDeserialize, SerdeSerialize, Default)]
#[serde(rename_all = "camelCase")]
/// Payload for configuring a baker. The different constructors cover
/// the different common cases.
/// The [Default] implementation produces an empty configure that will have no
/// effects.
pub struct ConfigureBakerPayload {
    /// The equity capital of the baker
    pub capital: Option<Amount>,
    /// Whether the baker's earnings are restaked
    pub restake_earnings: Option<bool>,
    /// Whether the pool is open for delegators
    pub open_for_delegation: Option<OpenStatus>,
    /// The key/proof pairs to verify the baker.
    pub keys_with_proofs: Option<ConfigureBakerKeysPayload>,
    /// The URL referencing the baker's metadata.
    pub metadata_url: Option<UrlText>,
    /// The commission the pool owner takes on transaction fees.
    pub transaction_fee_commission: Option<AmountFraction>,
    /// The commission the pool owner takes on baking rewards.
    pub baking_reward_commission: Option<AmountFraction>,
    /// The commission the pool owner takes on finalization rewards.
    pub finalization_reward_commission: Option<AmountFraction>,
}

impl ConfigureBakerPayload {
    pub fn new() -> Self { Self::default() }

    /// Construct a new payload to remove a baker.
    pub fn new_remove_baker() -> Self {
        Self {
            capital: Some(Amount::from_micro_ccd(0)),
            ..Self::new()
        }
    }

    /// Set the new baker capital.
    pub fn set_capital(&mut self, amount: Amount) -> &mut Self {
        self.capital = Some(amount);
        self
    }

    /// Set whether or not earnings are automatically added to the stake.
    pub fn set_restake_earnings(&mut self, restake_earnings: bool) -> &mut Self {
        self.restake_earnings = Some(restake_earnings);
        self
    }

    /// Update the delegation status of the pool.
    pub fn set_open_for_delegation(&mut self, open_for_delegation: OpenStatus) -> &mut Self {
        self.open_for_delegation = Some(open_for_delegation);
        self
    }

    /// Add keys to the payload. This will construct proofs of validity and
    /// insert the public keys into the payload.
    pub fn add_keys<T: Rng + CryptoRng>(
        &mut self,
        baker_keys: &BakerKeyPairs,
        sender: AccountAddress,
        csprng: &mut T,
    ) -> &mut Self {
        let keys_with_proofs =
            BakerKeysPayload::new_payload(baker_keys, sender, b"configureBaker", csprng);
        self.keys_with_proofs = Some(keys_with_proofs);
        self
    }

    /// Add metadata URL to the payload.
    pub fn set_metadata_url(&mut self, metadata_url: UrlText) -> &mut Self {
        self.metadata_url = Some(metadata_url);
        self
    }

    /// Set a new transaction fee commission.
    pub fn set_transaction_fee_commission(
        &mut self,
        transaction_fee_commission: AmountFraction,
    ) -> &mut Self {
        self.transaction_fee_commission = Some(transaction_fee_commission);
        self
    }

    /// Set a new baking reward commission.
    pub fn set_baking_reward_commission(
        &mut self,
        baking_reward_commission: AmountFraction,
    ) -> &mut Self {
        self.baking_reward_commission = Some(baking_reward_commission);
        self
    }

    /// Set a new finalization reward commission.
    pub fn set_finalization_reward_commission(
        &mut self,
        finalization_reward_commission: AmountFraction,
    ) -> &mut Self {
        self.finalization_reward_commission = Some(finalization_reward_commission);
        self
    }
}

#[derive(Debug, Clone, SerdeDeserialize, SerdeSerialize, Default)]
#[serde(rename_all = "camelCase")]
/// Payload for configuring delegation. The [Default] implementation produces an
/// empty configuration that will not change anything.
pub struct ConfigureDelegationPayload {
    /// The capital delegated to the pool.
    pub capital:           Option<Amount>,
    /// Whether the delegator's earnings are restaked.
    pub restake_earnings:  Option<bool>,
    /// The target of the delegation.
    pub delegation_target: Option<DelegationTarget>,
}

impl ConfigureDelegationPayload {
    /// Construct a new payload that has all the options unset.
    pub fn new() -> Self { Self::default() }

    /// Construct a new payload to remove a delegation.
    pub fn new_remove_delegation() -> Self {
        Self {
            capital: Some(Amount::from_micro_ccd(0)),
            ..Self::new()
        }
    }

    pub fn set_capital(&mut self, amount: Amount) -> &mut Self {
        self.capital = Some(amount);
        self
    }

    pub fn set_restake_earnings(&mut self, restake_earnings: bool) -> &mut Self {
        self.restake_earnings = Some(restake_earnings);
        self
    }

    pub fn set_delegation_target(&mut self, target: DelegationTarget) -> &mut Self {
        self.delegation_target = Some(target);
        self
    }
}

#[derive(SerdeSerialize, SerdeDeserialize, Serial, Debug, Clone, AsRef, Into, AsMut)]
#[serde(transparent)]
/// A data that was registered on the chain.
pub struct RegisteredData {
    #[serde(with = "crate::internal::byte_array_hex")]
    #[size_length = 2]
    bytes: Vec<u8>,
}

/// Registered data is too large.
#[derive(Debug, Error, Copy, Clone)]
#[error("Data is too large to be registered ({actual_size}).")]
pub struct TooLargeError {
    actual_size: usize,
}

impl TryFrom<Vec<u8>> for RegisteredData {
    type Error = TooLargeError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let actual_size = bytes.len();
        if actual_size <= crate::constants::MAX_REGISTERED_DATA_SIZE {
            Ok(RegisteredData { bytes })
        } else {
            Err(TooLargeError { actual_size })
        }
    }
}

impl From<[u8; 32]> for RegisteredData {
    fn from(data: [u8; 32]) -> Self {
        Self {
            bytes: data.to_vec(),
        }
    }
}

impl<M> From<crate::hashes::HashBytes<M>> for RegisteredData {
    fn from(data: crate::hashes::HashBytes<M>) -> Self {
        Self {
            bytes: data.as_ref().to_vec(),
        }
    }
}

impl Deserial for RegisteredData {
    fn deserial<R: crypto_common::ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let len: u16 = source.get()?;
        anyhow::ensure!(
            usize::from(len) <= crate::constants::MAX_REGISTERED_DATA_SIZE,
            "Data too big to register."
        );
        let bytes = crypto_common::deserial_bytes(source, len.into())?;
        Ok(RegisteredData { bytes })
    }
}

/// Mapping of credential indices to account credentials with proofs.
/// This structure is used when sending transactions that update credentials.
pub type AccountCredentialsMap = BTreeMap<
    CredentialIndex,
    CredentialDeploymentInfo<
        id::constants::IpPairing,
        id::constants::ArCurve,
        id::constants::AttributeKind,
    >,
>;

#[derive(Debug, Clone, SerdeDeserialize, SerdeSerialize)]
#[serde(rename_all = "camelCase")]
/// Payload of an account transaction.
pub enum Payload {
    /// Deploy a Wasm module with the given source.
    DeployModule {
        #[serde(rename = "mod")]
        module: smart_contracts::WasmModule,
    },
    /// Initialize a new smart contract instance.
    InitContract {
        #[serde(flatten)]
        payload: InitContractPayload,
    },
    /// Update a smart contract instance by invoking a specific function.
    Update {
        #[serde(flatten)]
        payload: UpdateContractPayload,
    },
    /// Transfer CCD to an account.
    Transfer {
        /// Address to send to.
        to_address: AccountAddress,
        /// Amount to send.
        amount:     Amount,
    },
    /// Register the sender account as a baker.
    AddBaker {
        #[serde(flatten)]
        payload: Box<AddBakerPayload>,
    },
    /// Deregister the account as a baker.
    RemoveBaker,
    /// Update baker's stake.
    UpdateBakerStake {
        /// The new stake.
        stake: Amount,
    },
    /// Modify whether to add earnings to the baker stake automatically or not.
    UpdateBakerRestakeEarnings {
        /// New value of the flag.
        restake_earnings: bool,
    },
    /// Update the baker's keys.
    UpdateBakerKeys {
        #[serde(flatten)]
        payload: Box<BakerUpdateKeysPayload>,
    },
    /// Update signing keys of a specific credential.
    UpdateCredentialKeys {
        /// Id of the credential whose keys are to be updated.
        cred_id: CredentialRegistrationID,
        /// The new public keys.
        keys:    CredentialPublicKeys,
    },
    /// Transfer an encrypted amount.
    EncryptedAmountTransfer {
        /// The recepient's address.
        to:   AccountAddress,
        /// The (encrypted) amount to transfer and proof of correctness of
        /// accounting.
        data: Box<EncryptedAmountTransferData<EncryptedAmountsCurve>>,
    },
    /// Transfer from public to encrypted balance of the sender account.
    TransferToEncrypted {
        /// The amount to transfer.
        amount: Amount,
    },
    /// Transfer an amount from encrypted to the public balance of the account.
    TransferToPublic {
        /// The amount to transfer and proof of correctness of accounting.
        #[serde(flatten)]
        data: Box<SecToPubAmountTransferData<EncryptedAmountsCurve>>,
    },
    /// Transfer an amount with schedule.
    TransferWithSchedule {
        /// The recepient.
        to:       AccountAddress,
        /// The release schedule. This can be at most 255 elements.
        schedule: Vec<(Timestamp, Amount)>,
    },
    /// Update the account's credentials.
    UpdateCredentials {
        /// New credentials to add.
        new_cred_infos:  AccountCredentialsMap,
        /// Ids of credentials to remove.
        remove_cred_ids: Vec<CredentialRegistrationID>,
        /// The new account threshold.
        new_threshold:   AccountThreshold,
    },
    /// Register the given data on the chain.
    RegisterData {
        /// The data to register.
        data: RegisteredData,
    },
    /// Transfer CCD to an account with an additional memo.
    TransferWithMemo {
        /// Address to send to.
        to_address: AccountAddress,
        /// Memo to include in the transfer.
        memo:       Memo,
        /// Amount to send.
        amount:     Amount,
    },
    /// Transfer an encrypted amount.
    EncryptedAmountTransferWithMemo {
        /// The recepient's address.
        to:   AccountAddress,
        /// Memo to include in the transfer.
        memo: Memo,
        /// The (encrypted) amount to transfer and proof of correctness of
        /// accounting.
        data: Box<EncryptedAmountTransferData<EncryptedAmountsCurve>>,
    },
    /// Transfer an amount with schedule.
    TransferWithScheduleAndMemo {
        /// The recepient.
        to:       AccountAddress,
        /// Memo to include in the transfer.
        memo:     Memo,
        /// The release schedule. This can be at most 255 elements.
        schedule: Vec<(Timestamp, Amount)>,
    },
    /// Configure a baker on an account.
    ConfigureBaker {
        #[serde(flatten)]
        data: Box<ConfigureBakerPayload>,
    },
    ///  Configure an account's stake delegation.
    ConfigureDelegation {
        #[serde(flatten)]
        data: ConfigureDelegationPayload,
    },
}

impl Payload {
    /// Resolve the [TransactionType] corresponding to the variant of the
    /// Payload.
    pub fn transaction_type(&self) -> TransactionType {
        match self {
            Payload::DeployModule { .. } => TransactionType::DeployModule,
            Payload::InitContract { .. } => TransactionType::InitContract,
            Payload::Update { .. } => TransactionType::Update,
            Payload::Transfer { .. } => TransactionType::Transfer,
            Payload::AddBaker { .. } => TransactionType::AddBaker,
            Payload::RemoveBaker { .. } => TransactionType::RemoveBaker,
            Payload::UpdateBakerStake { .. } => TransactionType::UpdateBakerStake,
            Payload::UpdateBakerRestakeEarnings { .. } => {
                TransactionType::UpdateBakerRestakeEarnings
            }
            Payload::UpdateBakerKeys { .. } => TransactionType::UpdateBakerKeys,
            Payload::UpdateCredentialKeys { .. } => TransactionType::UpdateCredentialKeys,
            Payload::EncryptedAmountTransfer { .. } => TransactionType::EncryptedAmountTransfer,
            Payload::TransferToEncrypted { .. } => TransactionType::TransferToEncrypted,
            Payload::TransferToPublic { .. } => TransactionType::TransferToPublic,
            Payload::TransferWithSchedule { .. } => TransactionType::TransferWithSchedule,
            Payload::UpdateCredentials { .. } => TransactionType::UpdateCredentials,
            Payload::RegisterData { .. } => TransactionType::RegisterData,
            Payload::TransferWithMemo { .. } => TransactionType::TransferWithMemo,
            Payload::EncryptedAmountTransferWithMemo { .. } => {
                TransactionType::EncryptedAmountTransferWithMemo
            }
            Payload::TransferWithScheduleAndMemo { .. } => {
                TransactionType::TransferWithScheduleAndMemo
            }
            Payload::ConfigureBaker { .. } => TransactionType::ConfigureBaker,
            Payload::ConfigureDelegation { .. } => TransactionType::ConfigureDelegation,
        }
    }
}

impl Serial for Payload {
    fn serial<B: Buffer>(&self, out: &mut B) {
        match &self {
            Payload::DeployModule { module } => {
                out.put(&0u8);
                out.put(module);
            }
            Payload::InitContract { payload } => {
                out.put(&1u8);
                out.put(payload)
            }
            Payload::Update { payload } => {
                out.put(&2u8);
                out.put(payload)
            }
            Payload::Transfer { to_address, amount } => {
                out.put(&3u8);
                out.put(to_address);
                out.put(amount);
            }
            Payload::AddBaker { payload } => {
                out.put(&4u8);
                out.put(payload);
            }
            Payload::RemoveBaker => {
                out.put(&5u8);
            }
            Payload::UpdateBakerStake { stake } => {
                out.put(&6u8);
                out.put(stake);
            }
            Payload::UpdateBakerRestakeEarnings { restake_earnings } => {
                out.put(&7u8);
                out.put(restake_earnings);
            }
            Payload::UpdateBakerKeys { payload } => {
                out.put(&8u8);
                out.put(payload)
            }
            Payload::UpdateCredentialKeys { cred_id, keys } => {
                out.put(&13u8);
                out.put(cred_id);
                out.put(keys);
            }
            Payload::EncryptedAmountTransfer { to, data } => {
                out.put(&16u8);
                out.put(to);
                out.put(data);
            }
            Payload::TransferToEncrypted { amount } => {
                out.put(&17u8);
                out.put(amount);
            }
            Payload::TransferToPublic { data } => {
                out.put(&18u8);
                out.put(data);
            }
            Payload::TransferWithSchedule { to, schedule } => {
                out.put(&19u8);
                out.put(to);
                out.put(&(schedule.len() as u8));
                crypto_common::serial_vector_no_length(schedule, out);
            }
            Payload::UpdateCredentials {
                new_cred_infos,
                remove_cred_ids,
                new_threshold,
            } => {
                out.put(&20u8);
                out.put(&(new_cred_infos.len() as u8));
                crypto_common::serial_map_no_length(new_cred_infos, out);
                out.put(&(remove_cred_ids.len() as u8));
                crypto_common::serial_vector_no_length(remove_cred_ids, out);
                out.put(new_threshold);
            }
            Payload::RegisterData { data } => {
                out.put(&21u8);
                out.put(data);
            }
            Payload::TransferWithMemo {
                to_address,
                memo,
                amount,
            } => {
                out.put(&22u8);
                out.put(to_address);
                out.put(memo);
                out.put(amount);
            }
            Payload::EncryptedAmountTransferWithMemo { to, memo, data } => {
                out.put(&23u8);
                out.put(to);
                out.put(memo);
                out.put(data);
            }
            Payload::TransferWithScheduleAndMemo { to, memo, schedule } => {
                out.put(&24u8);
                out.put(to);
                out.put(memo);
                out.put(&(schedule.len() as u8));
                crypto_common::serial_vector_no_length(schedule, out);
            }
            Payload::ConfigureBaker { data } => {
                out.put(&25u8);
                let set_if = |n, b| if b { 1u16 << n } else { 0 };
                let bitmap: u16 = set_if(0, data.capital.is_some())
                    | set_if(1, data.restake_earnings.is_some())
                    | set_if(2, data.open_for_delegation.is_some())
                    | set_if(3, data.keys_with_proofs.is_some())
                    | set_if(4, data.metadata_url.is_some())
                    | set_if(5, data.transaction_fee_commission.is_some())
                    | set_if(6, data.baking_reward_commission.is_some())
                    | set_if(7, data.finalization_reward_commission.is_some());
                out.put(&bitmap);
                if let Some(capital) = &data.capital {
                    out.put(capital);
                }
                if let Some(restake_earnings) = &data.restake_earnings {
                    out.put(restake_earnings);
                }
                if let Some(open_for_delegation) = &data.open_for_delegation {
                    out.put(open_for_delegation);
                }
                if let Some(keys_with_proofs) = &data.keys_with_proofs {
                    // this is serialized manually since the serialization in Haskell is not
                    // consistent with the serialization of baker add
                    // transactions. The order of fields is different.
                    out.put(&keys_with_proofs.election_verify_key);
                    out.put(&keys_with_proofs.proof_election);
                    out.put(&keys_with_proofs.signature_verify_key);
                    out.put(&keys_with_proofs.proof_sig);
                    out.put(&keys_with_proofs.aggregation_verify_key);
                    out.put(&keys_with_proofs.proof_aggregation);
                }
                if let Some(metadata_url) = &data.metadata_url {
                    out.put(metadata_url);
                }
                if let Some(transaction_fee_commission) = &data.transaction_fee_commission {
                    out.put(transaction_fee_commission);
                }
                if let Some(baking_reward_commission) = &data.baking_reward_commission {
                    out.put(baking_reward_commission);
                }
                if let Some(finalization_reward_commission) = &data.finalization_reward_commission {
                    out.put(finalization_reward_commission);
                }
            }
            Payload::ConfigureDelegation {
                data:
                    ConfigureDelegationPayload {
                        capital,
                        restake_earnings,
                        delegation_target,
                    },
            } => {
                out.put(&26u8);
                let set_if = |n, b| if b { 1u16 << n } else { 0 };
                let bitmap: u16 = set_if(0, capital.is_some())
                    | set_if(1, restake_earnings.is_some())
                    | set_if(2, delegation_target.is_some());
                out.put(&bitmap);
                if let Some(capital) = capital {
                    out.put(capital);
                }
                if let Some(restake_earnings) = restake_earnings {
                    out.put(restake_earnings);
                }
                if let Some(delegation_target) = delegation_target {
                    out.put(delegation_target);
                }
            }
        }
    }
}

impl Deserial for Payload {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let tag: u8 = source.get()?;
        match tag {
            0 => {
                let module = source.get()?;
                Ok(Payload::DeployModule { module })
            }
            1 => {
                let payload = source.get()?;
                Ok(Payload::InitContract { payload })
            }
            2 => {
                let payload = source.get()?;
                Ok(Payload::Update { payload })
            }
            3 => {
                let to_address = source.get()?;
                let amount = source.get()?;
                Ok(Payload::Transfer { to_address, amount })
            }
            4 => {
                let payload_data = source.get()?;
                Ok(Payload::AddBaker {
                    payload: Box::new(payload_data),
                })
            }
            5 => Ok(Payload::RemoveBaker),
            6 => {
                let stake = source.get()?;
                Ok(Payload::UpdateBakerStake { stake })
            }
            7 => {
                let restake_earnings = source.get()?;
                Ok(Payload::UpdateBakerRestakeEarnings { restake_earnings })
            }
            8 => {
                let payload_data = source.get()?;
                Ok(Payload::UpdateBakerKeys {
                    payload: Box::new(payload_data),
                })
            }
            13 => {
                let cred_id = source.get()?;
                let keys = source.get()?;
                Ok(Payload::UpdateCredentialKeys { cred_id, keys })
            }
            16 => {
                let to = source.get()?;
                let data = source.get()?;
                Ok(Payload::EncryptedAmountTransfer { to, data })
            }
            17 => {
                let amount = source.get()?;
                Ok(Payload::TransferToEncrypted { amount })
            }
            18 => {
                let data_data = source.get()?;
                Ok(Payload::TransferToPublic {
                    data: Box::new(data_data),
                })
            }
            19 => {
                let to = source.get()?;
                let len: u8 = source.get()?;
                let schedule = crypto_common::deserial_vector_no_length(source, len.into())?;
                Ok(Payload::TransferWithSchedule { to, schedule })
            }
            20 => {
                let cred_infos_len: u8 = source.get()?;
                let new_cred_infos =
                    crypto_common::deserial_map_no_length(source, cred_infos_len.into())?;
                let remove_cred_ids_len: u8 = source.get()?;
                let remove_cred_ids =
                    crypto_common::deserial_vector_no_length(source, remove_cred_ids_len.into())?;
                let new_threshold = source.get()?;
                Ok(Payload::UpdateCredentials {
                    new_cred_infos,
                    remove_cred_ids,
                    new_threshold,
                })
            }
            21 => {
                let data = source.get()?;
                Ok(Payload::RegisterData { data })
            }
            22 => {
                let to_address = source.get()?;
                let memo = source.get()?;
                let amount = source.get()?;
                Ok(Payload::TransferWithMemo {
                    to_address,
                    memo,
                    amount,
                })
            }
            23 => {
                let to = source.get()?;
                let memo = source.get()?;
                let data = source.get()?;
                Ok(Payload::EncryptedAmountTransferWithMemo { to, memo, data })
            }
            24 => {
                let to = source.get()?;
                let memo = source.get()?;
                let len: u8 = source.get()?;
                let schedule = crypto_common::deserial_vector_no_length(source, len.into())?;
                Ok(Payload::TransferWithScheduleAndMemo { to, memo, schedule })
            }
            25 => {
                let bitmap: u16 = source.get()?;
                let mut capital = None;
                let mut restake_earnings = None;
                let mut open_for_delegation = None;
                let mut keys_with_proofs = None;
                let mut metadata_url = None;
                let mut transaction_fee_commission = None;
                let mut baking_reward_commission = None;
                let mut finalization_reward_commission = None;
                if bitmap & 1 != 0 {
                    capital = Some(source.get()?);
                }
                if bitmap & (1 << 1) != 0 {
                    restake_earnings = Some(source.get()?);
                }
                if bitmap & (1 << 2) != 0 {
                    open_for_delegation = Some(source.get()?);
                }
                if bitmap & (1 << 3) != 0 {
                    // this is serialized manually since the serialization in Haskell is not
                    // consistent with the serialization of baker add
                    // transactions. The order of fields is different.
                    let election_verify_key = source.get()?;
                    let proof_election = source.get()?;
                    let signature_verify_key = source.get()?;
                    let proof_sig = source.get()?;
                    let aggregation_verify_key = source.get()?;
                    let proof_aggregation = source.get()?;
                    keys_with_proofs = Some(BakerKeysPayload {
                        phantom: PhantomData,
                        election_verify_key,
                        signature_verify_key,
                        aggregation_verify_key,
                        proof_sig,
                        proof_election,
                        proof_aggregation,
                    });
                }
                if bitmap & (1 << 4) != 0 {
                    metadata_url = Some(source.get()?);
                }
                if bitmap & (1 << 5) != 0 {
                    transaction_fee_commission = Some(source.get()?);
                }
                if bitmap & (1 << 6) != 0 {
                    baking_reward_commission = Some(source.get()?);
                }
                if bitmap & (1 << 7) != 0 {
                    finalization_reward_commission = Some(source.get()?);
                }
                let data = Box::new(ConfigureBakerPayload {
                    capital,
                    restake_earnings,
                    open_for_delegation,
                    keys_with_proofs,
                    metadata_url,
                    transaction_fee_commission,
                    baking_reward_commission,
                    finalization_reward_commission,
                });
                Ok(Payload::ConfigureBaker { data })
            }
            26 => {
                let mut data = ConfigureDelegationPayload::default();
                let bitmap: u16 = source.get()?;
                anyhow::ensure!(
                    bitmap & 0b111 == bitmap,
                    "Incorrect bitmap for configure delegation."
                );
                if bitmap & 1 != 0 {
                    data.capital = Some(source.get()?);
                }
                if bitmap & (1 << 1) != 0 {
                    data.restake_earnings = Some(source.get()?);
                }
                if bitmap & (1 << 2) != 0 {
                    data.delegation_target = Some(source.get()?);
                }
                Ok(Payload::ConfigureDelegation { data })
            }
            _ => {
                anyhow::bail!("Unsupported transaction payload tag {}", tag)
            }
        }
    }
}

impl PayloadLike for Payload {
    fn encode(&self) -> EncodedPayload {
        let payload = crypto_common::to_bytes(&self);
        EncodedPayload { payload }
    }

    fn encode_to_buffer<B: Buffer>(&self, out: &mut B) { out.put(&self) }
}

impl EncodedPayload {
    pub fn size(&self) -> PayloadSize {
        let size = self.payload.len() as u32;
        PayloadSize { size }
    }
}

/// Compute the transaction sign hash from an encoded payload and header.
pub fn compute_transaction_sign_hash(
    header: &TransactionHeader,
    payload: &impl PayloadLike,
) -> hashes::TransactionSignHash {
    let mut hasher = sha2::Sha256::new();
    hasher.put(header);
    payload.encode_to_buffer(&mut hasher);
    hashes::HashBytes::new(hasher.result())
}

/// Abstraction of private keys.
pub trait TransactionSigner {
    /// Sign the specified transaction hash, allocating and returning the
    /// signatures.
    fn sign_transaction_hash(
        &self,
        hash_to_sign: &hashes::TransactionSignHash,
    ) -> TransactionSignature;
}

/// A signing implementation that knows the number of keys up-front.
pub trait ExactSizeTransactionSigner: TransactionSigner {
    /// Return the number of keys that the signer will sign with.
    /// This must match what [TransactionSigner::sign_transaction_hash] returns.
    fn num_keys(&self) -> u32;
}

/// This signs with the first `threshold` credentials and for each
/// credential with the first threshold keys for that credential.
impl TransactionSigner for AccountKeys {
    fn sign_transaction_hash(
        &self,
        hash_to_sign: &hashes::TransactionSignHash,
    ) -> TransactionSignature {
        let iter = self
            .keys
            .iter()
            .take(usize::from(u8::from(self.threshold)))
            .map(|(k, v)| {
                (k, {
                    let num = u8::from(v.threshold);
                    v.keys.iter().take(num.into())
                })
            });
        let mut signatures = BTreeMap::<CredentialIndex, BTreeMap<KeyIndex, _>>::new();
        for (ci, cred_keys) in iter {
            let cred_sigs = cred_keys
                .into_iter()
                .map(|(ki, kp)| (*ki, kp.sign(hash_to_sign.as_ref())))
                .collect::<BTreeMap<_, _>>();
            signatures.insert(*ci, cred_sigs);
        }
        TransactionSignature { signatures }
    }
}

impl ExactSizeTransactionSigner for AccountKeys {
    fn num_keys(&self) -> u32 {
        self.keys
            .values()
            .take(usize::from(u8::from(self.threshold)))
            .map(|v| u32::from(u8::from(v.threshold)))
            .sum::<u32>()
    }
}

impl TransactionSigner for BTreeMap<CredentialIndex, BTreeMap<KeyIndex, KeyPair>> {
    fn sign_transaction_hash(
        &self,
        hash_to_sign: &hashes::TransactionSignHash,
    ) -> TransactionSignature {
        let mut signatures = BTreeMap::<CredentialIndex, BTreeMap<KeyIndex, _>>::new();
        for (ci, cred_keys) in self {
            let cred_sigs = cred_keys
                .iter()
                .map(|(ki, kp)| (*ki, kp.sign(hash_to_sign.as_ref())))
                .collect::<BTreeMap<_, _>>();
            signatures.insert(*ci, cred_sigs);
        }
        TransactionSignature { signatures }
    }
}

impl ExactSizeTransactionSigner for BTreeMap<CredentialIndex, BTreeMap<KeyIndex, KeyPair>> {
    fn num_keys(&self) -> u32 { self.values().map(|v| v.len() as u32).sum::<u32>() }
}

/// Sign the header and payload, construct the transaction, and return it.
pub fn sign_transaction<S: TransactionSigner, P: PayloadLike>(
    signer: &S,
    header: TransactionHeader,
    payload: P,
) -> AccountTransaction<P> {
    let hash_to_sign = compute_transaction_sign_hash(&header, &payload);
    let signature = signer.sign_transaction_hash(&hash_to_sign);
    AccountTransaction {
        signature,
        header,
        payload,
    }
}

/// Implementations of this trait are structures which can produce public keys
/// with which transaction signatures can be verified.
pub trait HasAccountAccessStructure {
    fn threshold(&self) -> AccountThreshold;
    fn credential_keys(&self, idx: CredentialIndex) -> Option<&CredentialPublicKeys>;
}

#[derive(Debug, Clone)]
/// The most straighforward account access structure is a map of public keys
/// with the account threshold.
pub struct AccountAccessStructure {
    /// The number of credentials that needed to sign a transaction.
    pub threshold: AccountThreshold,
    /// Keys indexed by credential.
    pub keys:      BTreeMap<CredentialIndex, CredentialPublicKeys>,
}

impl HasAccountAccessStructure for AccountAccessStructure {
    fn threshold(&self) -> AccountThreshold { self.threshold }

    fn credential_keys(&self, idx: CredentialIndex) -> Option<&CredentialPublicKeys> {
        self.keys.get(&idx)
    }
}

/// Verify a signature on the transaction sign hash. This is a low-level
/// operation that is useful to avoid recomputing the transaction hash.
pub fn verify_signature_transaction_sign_hash(
    keys: &impl HasAccountAccessStructure,
    hash: &hashes::TransactionSignHash,
    signature: &TransactionSignature,
) -> bool {
    if usize::from(u8::from(keys.threshold())) > signature.signatures.len() {
        return false;
    }
    // There are enough signatures.
    for (&ci, cred_sigs) in signature.signatures.iter() {
        if let Some(cred_keys) = keys.credential_keys(ci) {
            if usize::from(u8::from(cred_keys.threshold)) > cred_sigs.len() {
                return false;
            }
            for (&ki, sig) in cred_sigs {
                if let Some(pk) = cred_keys.get(ki) {
                    if !pk.verify(hash, sig) {
                        return false;
                    }
                } else {
                    return false;
                }
            }
        } else {
            return false;
        }
    }
    true
}

#[derive(Debug, Clone)]
/// A block item are data items that are transmitted on the network either as
/// separate messages, or as part of blocks. They are the only user-generated
/// (as opposed to protocol-generated) message.
pub enum BlockItem<PayloadType> {
    /// Account transactions are messages which are signed and paid for by an
    /// account.
    AccountTransaction(AccountTransaction<PayloadType>),
    /// Credential deployments create new accounts. They are not paid for
    /// directly by the sender. Instead, bakers are rewarded by the protocol for
    /// including them.
    CredentialDeployment(
        Box<
            AccountCredentialMessage<
                id::constants::IpPairing,
                id::constants::ArCurve,
                id::constants::AttributeKind,
            >,
        >,
    ),
    UpdateInstruction(updates::UpdateInstruction),
}

impl<PayloadType> From<AccountTransaction<PayloadType>> for BlockItem<PayloadType> {
    fn from(at: AccountTransaction<PayloadType>) -> Self { Self::AccountTransaction(at) }
}

impl<PayloadType>
    From<
        AccountCredentialMessage<
            id::constants::IpPairing,
            id::constants::ArCurve,
            id::constants::AttributeKind,
        >,
    > for BlockItem<PayloadType>
{
    fn from(
        at: AccountCredentialMessage<
            id::constants::IpPairing,
            id::constants::ArCurve,
            id::constants::AttributeKind,
        >,
    ) -> Self {
        Self::CredentialDeployment(Box::new(at))
    }
}

impl<PayloadType> From<updates::UpdateInstruction> for BlockItem<PayloadType> {
    fn from(ui: updates::UpdateInstruction) -> Self { Self::UpdateInstruction(ui) }
}

impl<PayloadType> BlockItem<PayloadType> {
    /// Compute the hash of the block item that identifies the block item on the
    /// chain.
    pub fn hash(&self) -> hashes::TransactionHash
    where
        BlockItem<PayloadType>: Serial, {
        let mut hasher = sha2::Sha256::new();
        hasher.put(&self);
        hashes::HashBytes::new(hasher.result())
    }
}

impl<V> Serial for BakerKeysPayload<V> {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.put(&self.election_verify_key);
        out.put(&self.signature_verify_key);
        out.put(&self.aggregation_verify_key);
        out.put(&self.proof_sig);
        out.put(&self.proof_election);
        out.put(&self.proof_aggregation);
    }
}

impl<V> Deserial for BakerKeysPayload<V> {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let election_verify_key = source.get()?;
        let signature_verify_key = source.get()?;
        let aggregation_verify_key = source.get()?;
        let proof_sig = source.get()?;
        let proof_election = source.get()?;
        let proof_aggregation = source.get()?;
        Ok(Self {
            phantom: PhantomData::default(),
            election_verify_key,
            signature_verify_key,
            aggregation_verify_key,
            proof_sig,
            proof_election,
            proof_aggregation,
        })
    }
}

impl Serial for AddBakerPayload {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.put(&self.keys);
        out.put(&self.baking_stake);
        out.put(&self.restake_earnings);
    }
}

impl Deserial for AddBakerPayload {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let keys = source.get()?;
        let baking_stake = source.get()?;
        let restake_earnings = source.get()?;
        Ok(Self {
            keys,
            baking_stake,
            restake_earnings,
        })
    }
}

impl Serial for InitContractPayload {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.put(&self.amount);
        out.put(&self.mod_ref);
        out.put(&self.init_name);
        out.put(&self.param);
    }
}

impl Deserial for InitContractPayload {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let amount = source.get()?;
        let mod_ref = source.get()?;
        let init_name = source.get()?;
        let param = source.get()?;
        Ok(InitContractPayload {
            amount,
            mod_ref,
            init_name,
            param,
        })
    }
}

impl Serial for UpdateContractPayload {
    fn serial<B: Buffer>(&self, out: &mut B) {
        out.put(&self.amount);
        out.put(&self.address);
        out.put(&self.receive_name);
        out.put(&self.message);
    }
}

impl Deserial for UpdateContractPayload {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let amount = source.get()?;
        let address = source.get()?;
        let receive_name = source.get()?;
        let message = source.get()?;
        Ok(UpdateContractPayload {
            amount,
            address,
            receive_name,
            message,
        })
    }
}

impl<P: PayloadLike> Serial for BlockItem<P> {
    fn serial<B: Buffer>(&self, out: &mut B) {
        match &self {
            BlockItem::AccountTransaction(at) => {
                out.put(&0u8);
                out.put(at)
            }
            BlockItem::CredentialDeployment(acdi) => {
                out.put(&1u8);
                out.put(acdi);
            }
            BlockItem::UpdateInstruction(ui) => {
                out.put(&2u8);
                out.put(ui);
            }
        }
    }
}

impl Deserial for BlockItem<EncodedPayload> {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let tag: u8 = source.get()?;
        match tag {
            0 => {
                let at = source.get()?;
                Ok(BlockItem::AccountTransaction(at))
            }
            1 => {
                let acdi = source.get()?;
                Ok(BlockItem::CredentialDeployment(acdi))
            }
            2 => {
                let ui = source.get()?;
                Ok(BlockItem::UpdateInstruction(ui))
            }
            _ => anyhow::bail!("Unsupported block item type: {}.", tag),
        }
    }
}

/// Energy costs of transactions.
pub mod cost {
    use id::types::CredentialType;

    use super::*;

    /// The B constant for NRG assignment. This scales the effect of the number
    /// of signatures on the energy.
    pub const A: u64 = 100;

    /// The A constant for NRG assignment. This scales the effect of transaction
    /// size on the energy.
    pub const B: u64 = 1;

    /// Base cost of a transaction is the minimum cost that accounts for
    /// transaction size and signature checking. In addition to base cost
    /// each transaction has a transaction-type specific cost.
    pub fn base_cost(transaction_size: u64, num_signatures: u32) -> Energy {
        Energy::from(B * transaction_size + A * u64::from(num_signatures))
    }

    /// Additional cost of a normal, account to account, transfer.
    pub const SIMPLE_TRANSFER: Energy = Energy { energy: 300 };

    /// Additional cost of an encrypted transfer.
    pub const ENCRYPTED_TRANSFER: Energy = Energy { energy: 27000 };

    /// Additional cost of a transfer from public to encrypted balance.
    pub const TRANSFER_TO_ENCRYPTED: Energy = Energy { energy: 600 };

    /// Additional cost of a transfer from encrypted to public balance.
    pub const TRANSFER_TO_PUBLIC: Energy = Energy { energy: 14850 };

    /// Cost of a scheduled transfer, parametrized by the number of releases.
    pub fn scheduled_transfer(num_releases: u16) -> Energy {
        Energy::from(u64::from(num_releases) * (300 + 64))
    }

    /// Additional cost of registerding the account as a baker.
    pub const ADD_BAKER: Energy = Energy { energy: 4050 };

    /// Additional cost of updating baker's keys.
    pub const UPDATE_BAKER_KEYS: Energy = Energy { energy: 4050 };

    /// Additional cost of updating the baker's stake, either increasing or
    /// lowering it.
    pub const UPDATE_BAKER_STAKE: Energy = Energy { energy: 300 };

    /// Additional cost of updating the baker's restake flag.
    pub const UPDATE_BAKER_RESTAKE: Energy = Energy { energy: 300 };

    /// Additional cost of removing a baker.
    pub const REMOVE_BAKER: Energy = Energy { energy: 300 };

    /// Additional cost of updating existing credential keys. Parametrised by
    /// amount of existing credentials and new keys. Due to the way the
    /// accounts are stored a new copy of all credentials will be created,
    /// so we need to account for that storage increase.
    pub fn update_credential_keys(num_credentials_before: u16, num_keys: u16) -> Energy {
        Energy {
            energy: 500u64 * u64::from(num_credentials_before) + 100 * u64::from(num_keys),
        }
    }

    /// Additional cost of updating account's credentials, parametrized by
    /// - the number of credentials on the account before the update
    /// - list of keys of credentials to be added.
    pub fn update_credentials(num_credentials_before: u16, num_keys: &[u16]) -> Energy {
        UPDATE_CREDENTIALS_BASE + update_credentials_variable(num_credentials_before, num_keys)
    }

    /// Additional cost of registering a piece of data.
    pub const REGISTER_DATA: Energy = Energy { energy: 300 };

    /// Additional cost of configuring a baker if new keys are registered.
    pub const CONFIGURE_BAKER_WITH_KEYS: Energy = Energy { energy: 4050 };

    /// Additional cost of configuring a baker if new keys are **not**
    /// registered.
    pub const CONFIGURE_BAKER_WITHOUT_KEYS: Energy = Energy { energy: 300 };

    /// Additional cost of configuring delegation.
    pub const CONFIGURE_DELEGATION: Energy = Energy { energy: 300 };

    /// Additional cost of deploying a smart contract module, parametrized by
    /// the size of the module, which is defined to be the size of
    /// the binary `.wasm` file that is sent as part of the transaction.
    pub fn deploy_module(module_size: u64) -> Energy { Energy::from(module_size / 10) }

    /// There is a non-trivial amount of lookup
    /// that needs to be done before we can start any checking. This ensures
    /// that those lookups are not a problem. If the credential updates are
    /// genuine then this cost is going to be negligible compared to
    /// verifying the credential.
    const UPDATE_CREDENTIALS_BASE: Energy = Energy { energy: 500 };

    /// Additional cost of deploying a credential of the given type and with the
    /// given number of keys.
    pub fn deploy_credential(ty: CredentialType, num_keys: u16) -> Energy {
        match ty {
            CredentialType::Initial => Energy::from(1000 + 100 * u64::from(num_keys)),
            CredentialType::Normal => Energy::from(54000 + 100 * u64::from(num_keys)),
        }
    }

    /// Helper function. This together with [`UPDATE_CREDENTIALS_BASE`]
    /// determines the cost of updating credentials on an account.
    fn update_credentials_variable(num_credentials_before: u16, num_keys: &[u16]) -> Energy {
        // the 500 * num_credentials_before is to account for transactions which do
        // nothing, e.g., don't add don't remove, and don't update the
        // threshold. These still have a cost since the way the accounts are
        // stored it will update the stored account data, which does take up
        // quite a bit of space per credential.
        let energy: u64 = 500 * u64::from(num_credentials_before)
            + num_keys
                .iter()
                .map(|&nk| u64::from(deploy_credential(CredentialType::Normal, nk)))
                .sum::<u64>();
        Energy::from(energy)
    }
}

/// High level wrappers for making transactions with minimal user input.
/// These wrappers handle encoding, setting energy costs when those are fixed
/// for transaction.
/// See also the [send] module above which combines construction with signing.
pub mod construct {
    use super::*;

    /// A transaction that is prepared to be signed.
    /// The serde instance serializes the structured payload and skips
    /// serializing the encoded one.
    #[derive(Debug, Clone, SerdeSerialize)]
    #[serde(rename_all = "camelCase")]
    pub struct PreAccountTransaction {
        pub header:       TransactionHeader,
        /// The payload.
        pub payload:      Payload,
        /// The encoded payload. This is already serialized payload that is
        /// constructed during construction of the prepared transaction
        /// since we need it to compute the cost.
        #[serde(skip_serializing)]
        pub encoded:      EncodedPayload,
        /// Hash of the transaction to sign.
        pub hash_to_sign: hashes::TransactionSignHash,
    }

    impl PreAccountTransaction {
        /// Sign the transaction with the provided signer. Note that this signer
        /// must match the account address and the number of keys that
        /// were used in construction, otherwise the transaction will be
        /// invalid.
        pub fn sign(self, signer: &impl TransactionSigner) -> AccountTransaction<EncodedPayload> {
            sign_transaction(signer, self.header, self.encoded)
        }
    }

    /// Serialize only the header and payload, so that this can be deserialized
    /// as a transaction body.
    impl Serial for PreAccountTransaction {
        fn serial<B: Buffer>(&self, out: &mut B) {
            self.header.serial(out);
            self.encoded.serial(out);
        }
    }

    impl Deserial for PreAccountTransaction {
        fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
            let header: TransactionHeader = source.get()?;
            let encoded = get_encoded_payload(source, header.payload_size)?;
            let payload = encoded.decode()?;
            let hash_to_sign = compute_transaction_sign_hash(&header, &encoded);
            Ok(Self {
                header,
                payload,
                encoded,
                hash_to_sign,
            })
        }
    }

    /// Helper structure to store the intermediate state of a transaction.
    /// The problem this helps solve is that to compute the exact energy
    /// requirements for the transaction we need to know its exact size when
    /// serialized. For some we could compute this manually, but in general it
    /// is less error prone to serialize and get the length. To avoid doing
    /// double work we first serialize with a dummy `energy_amount` value, then
    /// in the [TransactionBuilder::finalize] method we compute the correct
    /// energy amount and overwrite it in the transaction, before signing
    /// it.
    /// This is deliberately made private so that the inconsistent internal
    /// state does not leak.
    struct TransactionBuilder {
        header:  TransactionHeader,
        payload: Payload,
        encoded: EncodedPayload,
    }

    /// Size of a transaction header. This is currently always 60 bytes.
    /// Future chain updates might revise this, but this is a big change so this
    /// is expected to change seldomly.
    pub const TRANSACTION_HEADER_SIZE: u64 = 32 + 8 + 8 + 4 + 8;

    impl TransactionBuilder {
        pub fn new(
            sender: AccountAddress,
            nonce: Nonce,
            expiry: TransactionTime,
            payload: Payload,
        ) -> Self {
            let encoded = payload.encode();
            let header = TransactionHeader {
                sender,
                nonce,
                energy_amount: 0.into(),
                payload_size: encoded.size(),
                expiry,
            };
            Self {
                header,
                payload,
                encoded,
            }
        }

        #[inline]
        fn size(&self) -> u64 {
            TRANSACTION_HEADER_SIZE + u64::from(u32::from(self.header.payload_size))
        }

        #[inline]
        pub fn construct(mut self, f: impl FnOnce(u64) -> Energy) -> PreAccountTransaction {
            let size = self.size();
            self.header.energy_amount = f(size);
            let hash_to_sign = compute_transaction_sign_hash(&self.header, &self.encoded);
            PreAccountTransaction {
                header: self.header,
                payload: self.payload,
                encoded: self.encoded,
                hash_to_sign,
            }
        }
    }

    /// Construct a transfer transaction.
    pub fn transfer(
        num_sigs: u32,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        receiver: AccountAddress,
        amount: Amount,
    ) -> PreAccountTransaction {
        let payload = Payload::Transfer {
            to_address: receiver,
            amount,
        };
        make_transaction(
            sender,
            nonce,
            expiry,
            GivenEnergy::Add {
                num_sigs,
                energy: cost::SIMPLE_TRANSFER,
            },
            payload,
        )
    }

    /// Construct a transfer transaction with a memo.
    pub fn transfer_with_memo(
        num_sigs: u32,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        receiver: AccountAddress,
        amount: Amount,
        memo: Memo,
    ) -> PreAccountTransaction {
        let payload = Payload::TransferWithMemo {
            to_address: receiver,
            memo,
            amount,
        };
        make_transaction(
            sender,
            nonce,
            expiry,
            GivenEnergy::Add {
                num_sigs,
                energy: cost::SIMPLE_TRANSFER,
            },
            payload,
        )
    }

    /// Make an encrypted transfer. The payload can be constructed using
    /// [encrypted_transfers::make_transfer_data].
    pub fn encrypted_transfer(
        num_sigs: u32,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        receiver: AccountAddress,
        data: EncryptedAmountTransferData<EncryptedAmountsCurve>,
    ) -> PreAccountTransaction {
        let payload = Payload::EncryptedAmountTransfer {
            to:   receiver,
            data: Box::new(data),
        };
        make_transaction(
            sender,
            nonce,
            expiry,
            GivenEnergy::Add {
                num_sigs,
                energy: cost::ENCRYPTED_TRANSFER,
            },
            payload,
        )
    }

    /// Make an encrypted transfer with a memo. The payload can be constructed
    /// using [encrypted_transfers::make_transfer_data].
    pub fn encrypted_transfer_with_memo(
        num_sigs: u32,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        receiver: AccountAddress,
        data: EncryptedAmountTransferData<EncryptedAmountsCurve>,
        memo: Memo,
    ) -> PreAccountTransaction {
        // FIXME: This payload could be returned as well since it is only borrowed.
        let payload = Payload::EncryptedAmountTransferWithMemo {
            to: receiver,
            memo,
            data: Box::new(data),
        };
        make_transaction(
            sender,
            nonce,
            expiry,
            GivenEnergy::Add {
                num_sigs,
                energy: cost::ENCRYPTED_TRANSFER,
            },
            payload,
        )
    }

    /// Transfer the given amount from public to encrypted balance of the given
    /// account.
    pub fn transfer_to_encrypted(
        num_sigs: u32,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        amount: Amount,
    ) -> PreAccountTransaction {
        let payload = Payload::TransferToEncrypted { amount };
        make_transaction(
            sender,
            nonce,
            expiry,
            GivenEnergy::Add {
                num_sigs,
                energy: cost::TRANSFER_TO_ENCRYPTED,
            },
            payload,
        )
    }

    /// Transfer the given amount from encrypted to public balance of the given
    /// account. The payload may be constructed using
    /// [encrypted_transfers::make_sec_to_pub_transfer_data]
    pub fn transfer_to_public(
        num_sigs: u32,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        data: SecToPubAmountTransferData<EncryptedAmountsCurve>,
    ) -> PreAccountTransaction {
        // FIXME: This payload could be returned as well since it is only borrowed.
        let payload = Payload::TransferToPublic {
            data: Box::new(data),
        };
        make_transaction(
            sender,
            nonce,
            expiry,
            GivenEnergy::Add {
                num_sigs,
                energy: cost::TRANSFER_TO_PUBLIC,
            },
            payload,
        )
    }

    /// Construct a transfer with schedule transaction, sending to the given
    /// account.
    pub fn transfer_with_schedule(
        num_sigs: u32,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        receiver: AccountAddress,
        schedule: Vec<(Timestamp, Amount)>,
    ) -> PreAccountTransaction {
        let num_releases = schedule.len() as u16;
        let payload = Payload::TransferWithSchedule {
            to: receiver,
            schedule,
        };
        make_transaction(
            sender,
            nonce,
            expiry,
            GivenEnergy::Add {
                num_sigs,
                energy: cost::scheduled_transfer(num_releases),
            },
            payload,
        )
    }

    /// Construct a transfer with schedule and memo transaction, sending to the
    /// given account.
    pub fn transfer_with_schedule_and_memo(
        num_sigs: u32,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        receiver: AccountAddress,
        schedule: Vec<(Timestamp, Amount)>,
        memo: Memo,
    ) -> PreAccountTransaction {
        let num_releases = schedule.len() as u16;
        let payload = Payload::TransferWithScheduleAndMemo {
            to: receiver,
            memo,
            schedule,
        };
        make_transaction(
            sender,
            nonce,
            expiry,
            GivenEnergy::Add {
                num_sigs,
                energy: cost::scheduled_transfer(num_releases),
            },
            payload,
        )
    }

    /// Register the sender account as a baker.
    ///
    /// **Note that this transaction only applies to protocol versions 1-3.**
    /// Use [`configure_baker`](Self::configure_baker) instead for protocols
    /// after 4.
    #[deprecated(
        since = "2.0.0",
        note = "This transaction only applies to protocol versions 1-3. Use configure_baker \
                instead."
    )]
    #[doc(hidden)]
    pub fn add_baker(
        num_sigs: u32,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        baking_stake: Amount,
        restake_earnings: bool,
        keys: BakerAddKeysPayload,
    ) -> PreAccountTransaction {
        let payload = Payload::AddBaker {
            payload: Box::new(AddBakerPayload {
                keys,
                baking_stake,
                restake_earnings,
            }),
        };
        make_transaction(
            sender,
            nonce,
            expiry,
            GivenEnergy::Add {
                num_sigs,
                energy: cost::ADD_BAKER,
            },
            payload,
        )
    }

    /// Update keys of the baker associated with the sender account.
    ///
    /// **Note that this transaction only applies to protocol versions 1-3.**
    /// Use [`configure_baker`](Self::configure_baker) instead for protocols
    /// after 4.
    #[deprecated(
        since = "2.0.0",
        note = "This transaction only applies to protocol versions 1-3. Use configure_baker \
                instead."
    )]
    #[doc(hidden)]
    pub fn update_baker_keys(
        num_sigs: u32,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        keys: BakerUpdateKeysPayload,
    ) -> PreAccountTransaction {
        // FIXME: This payload could be returned as well since it is only borrowed.
        let payload = Payload::UpdateBakerKeys {
            payload: Box::new(keys),
        };
        make_transaction(
            sender,
            nonce,
            expiry,
            GivenEnergy::Add {
                num_sigs,
                energy: cost::UPDATE_BAKER_KEYS,
            },
            payload,
        )
    }

    /// Deregister the account as a baker.
    ///
    /// **Note that this transaction only applies to protocol versions 1-3.**
    /// Use [`configure_baker`](Self::configure_baker) instead for protocols
    /// after 4.
    #[deprecated(
        since = "2.0.0",
        note = "This transaction only applies to protocol versions 1-3. Use configure_baker \
                instead."
    )]
    #[doc(hidden)]
    pub fn remove_baker(
        num_sigs: u32,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
    ) -> PreAccountTransaction {
        // FIXME: This payload could be returned as well since it is only borrowed.
        let payload = Payload::RemoveBaker;
        make_transaction(
            sender,
            nonce,
            expiry,
            GivenEnergy::Add {
                num_sigs,
                energy: cost::REMOVE_BAKER,
            },
            payload,
        )
    }

    /// Update the amount the account stakes for being a baker.
    ///
    /// **Note that this transaction only applies to protocol versions 1-3.**
    /// Use [`configure_baker`](Self::configure_baker) instead for protocols
    /// after 4.
    #[deprecated(
        since = "2.0.0",
        note = "This transaction only applies to protocol versions 1-3. Use configure_baker \
                instead."
    )]
    #[doc(hidden)]
    pub fn update_baker_stake(
        num_sigs: u32,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        new_stake: Amount,
    ) -> PreAccountTransaction {
        // FIXME: This payload could be returned as well since it is only borrowed.
        let payload = Payload::UpdateBakerStake { stake: new_stake };
        make_transaction(
            sender,
            nonce,
            expiry,
            GivenEnergy::Add {
                num_sigs,
                energy: cost::UPDATE_BAKER_STAKE,
            },
            payload,
        )
    }

    /// Update whether the earnings are automatically added to the baker's stake
    /// or not.
    ///
    /// **Note that this transaction only applies to protocol versions 1-3.**
    /// Use [`configure_baker`](Self::configure_baker) instead for protocols
    /// after 4.
    #[deprecated(
        since = "2.0.0",
        note = "This transaction only applies to protocol versions 1-3. Use configure_baker \
                instead."
    )]
    #[doc(hidden)]
    pub fn update_baker_restake_earnings(
        num_sigs: u32,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        restake_earnings: bool,
    ) -> PreAccountTransaction {
        // FIXME: This payload could be returned as well since it is only borrowed.
        let payload = Payload::UpdateBakerRestakeEarnings { restake_earnings };
        make_transaction(
            sender,
            nonce,
            expiry,
            GivenEnergy::Add {
                num_sigs,
                energy: cost::UPDATE_BAKER_RESTAKE,
            },
            payload,
        )
    }

    /// Construct a transction to register the given piece of data.
    pub fn register_data(
        num_sigs: u32,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        data: RegisteredData,
    ) -> PreAccountTransaction {
        let payload = Payload::RegisterData { data };
        make_transaction(
            sender,
            nonce,
            expiry,
            GivenEnergy::Add {
                num_sigs,
                energy: cost::REGISTER_DATA,
            },
            payload,
        )
    }

    /// Deploy the given Wasm module. The module is given as a binary source,
    /// and no processing is done to the module.
    pub fn deploy_module(
        num_sigs: u32,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        module: smart_contracts::WasmModule,
    ) -> PreAccountTransaction {
        let module_size = module.source.size();
        let payload = Payload::DeployModule { module };
        make_transaction(
            sender,
            nonce,
            expiry,
            GivenEnergy::Add {
                num_sigs,
                energy: cost::deploy_module(module_size),
            },
            payload,
        )
    }

    /// Initialize a smart contract, giving it the given amount of energy for
    /// execution. The unique parameters are
    /// - `energy` -- the amount of energy that can be used for contract
    ///   execution. The base energy amount for transaction verification will be
    ///   added to this cost.
    pub fn init_contract(
        num_sigs: u32,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        payload: InitContractPayload,
        energy: Energy,
    ) -> PreAccountTransaction {
        let payload = Payload::InitContract { payload };
        make_transaction(
            sender,
            nonce,
            expiry,
            GivenEnergy::Add { num_sigs, energy },
            payload,
        )
    }

    /// Update a smart contract intance, giving it the given amount of energy
    /// for execution. The unique parameters are
    /// - `energy` -- the amount of energy that can be used for contract
    ///   execution. The base energy amount for transaction verification will be
    ///   added to this cost.
    pub fn update_contract(
        num_sigs: u32,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        payload: UpdateContractPayload,
        energy: Energy,
    ) -> PreAccountTransaction {
        let payload = Payload::Update { payload };
        make_transaction(
            sender,
            nonce,
            expiry,
            GivenEnergy::Add { num_sigs, energy },
            payload,
        )
    }

    /// Configure the account as a baker. Only valid for protocol version 4 and
    /// up.
    pub fn configure_baker(
        num_sigs: u32,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        payload: ConfigureBakerPayload,
    ) -> PreAccountTransaction {
        let energy = if payload.keys_with_proofs.is_some() {
            cost::CONFIGURE_BAKER_WITH_KEYS
        } else {
            cost::CONFIGURE_BAKER_WITHOUT_KEYS
        };
        let payload = Payload::ConfigureBaker {
            data: Box::new(payload),
        };
        make_transaction(
            sender,
            nonce,
            expiry,
            GivenEnergy::Add { num_sigs, energy },
            payload,
        )
    }

    /// Configure the account as a delegator. Only valid for protocol version 4
    /// and up.
    pub fn configure_delegation(
        num_sigs: u32,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        payload: ConfigureDelegationPayload,
    ) -> PreAccountTransaction {
        let payload = Payload::ConfigureDelegation { data: payload };
        make_transaction(
            sender,
            nonce,
            expiry,
            GivenEnergy::Add {
                num_sigs,
                energy: cost::CONFIGURE_DELEGATION,
            },
            payload,
        )
    }

    /// Construct a transaction to update keys of a single credential on an
    /// account. The transaction specific arguments are
    ///
    /// - `num_existing_credentials` - the number of existing credentials on the
    ///   account. This will affect the estimated transaction cost. It is safe
    ///   to over-approximate this.
    /// - `cred_id` - `credId` of a credential whose keys are to be updated.
    /// - `keys` - the new keys associated with the credential.
    pub fn update_credential_keys(
        num_sigs: u32,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        num_existing_credentials: u16,
        cred_id: CredentialRegistrationID,
        keys: CredentialPublicKeys,
    ) -> PreAccountTransaction {
        let num_cred_keys = keys.keys.len() as u16;
        let payload = Payload::UpdateCredentialKeys { cred_id, keys };
        make_transaction(
            sender,
            nonce,
            expiry,
            GivenEnergy::Add {
                energy: cost::update_credential_keys(num_existing_credentials, num_cred_keys),
                num_sigs,
            },
            payload,
        )
    }

    /// Construct a transaction to update credentials on an account.
    /// The transaction specific arguments are
    ///
    /// - `num_existing_credentials` - the number of existing credentials on the
    ///   account. This will affect the estimated transaction cost. It is safe
    ///   to over-approximate this.
    /// - `new_credentials` - the new credentials to be deployed to the account
    ///   with the desired indices. The credential with index 0 cannot be
    ///   replaced.
    /// - `remove_credentials` - the list of credentials, by `credId`'s, to be
    ///   removed
    /// - `new_threshold` - the new account threshold.
    #[allow(clippy::too_many_arguments)]
    pub fn update_credentials(
        num_sigs: u32,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        num_existing_credentials: u16,
        new_credentials: AccountCredentialsMap,
        remove_credentials: Vec<CredentialRegistrationID>,
        new_threshold: AccountThreshold,
    ) -> PreAccountTransaction {
        let num_cred_keys = new_credentials
            .iter()
            .map(|(_, v)| v.values.cred_key_info.keys.len() as u16)
            .collect::<Vec<_>>();
        let payload = Payload::UpdateCredentials {
            new_cred_infos: new_credentials,
            remove_cred_ids: remove_credentials,
            new_threshold,
        };
        make_transaction(
            sender,
            nonce,
            expiry,
            GivenEnergy::Add {
                energy: cost::update_credentials(num_existing_credentials, &num_cred_keys),
                num_sigs,
            },
            payload,
        )
    }

    /// An upper bound on the amount of energy to spend on a transaction.
    /// Transaction costs have two components, one is based on the size of the
    /// transaction and the number of signatures, and then there is a
    /// transaction specific one. This construction helps handle the fixed
    /// costs and allows the user to focus only on the transaction specific
    /// ones. The most important case for this are smart contract
    /// initialisations and updates.
    pub enum GivenEnergy {
        /// Use this exact amount of energy.
        Absolute(Energy),
        /// Add the given amount of energy to the base amount.
        /// The base amount covers transaction size and signature checking.
        Add { energy: Energy, num_sigs: u32 },
    }

    /// A convenience wrapper around `sign_transaction` that construct the
    /// transaction and signs it. Compared to transaction-type-specific wrappers
    /// above this allows selecting the amount of energy
    pub fn make_transaction(
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        energy: GivenEnergy,
        payload: Payload,
    ) -> PreAccountTransaction {
        let builder = TransactionBuilder::new(sender, nonce, expiry, payload);
        let cost = |size| match energy {
            GivenEnergy::Absolute(energy) => energy,
            GivenEnergy::Add { num_sigs, energy } => cost::base_cost(size, num_sigs) + energy,
        };
        builder.construct(cost)
    }
}

/// High level wrappers for making transactions with minimal user input.
/// These wrappers handle encoding, setting energy costs when those are fixed
/// for transaction.
pub mod send {
    use super::*;

    /// Construct a transfer transaction.
    pub fn transfer(
        signer: &impl ExactSizeTransactionSigner,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        receiver: AccountAddress,
        amount: Amount,
    ) -> AccountTransaction<EncodedPayload> {
        construct::transfer(signer.num_keys(), sender, nonce, expiry, receiver, amount).sign(signer)
    }

    /// Construct a transfer transaction with a memo.
    pub fn transfer_with_memo(
        signer: &impl ExactSizeTransactionSigner,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        receiver: AccountAddress,
        amount: Amount,
        memo: Memo,
    ) -> AccountTransaction<EncodedPayload> {
        construct::transfer_with_memo(
            signer.num_keys(),
            sender,
            nonce,
            expiry,
            receiver,
            amount,
            memo,
        )
        .sign(signer)
    }

    /// Make an encrypted transfer. The payload can be constructed using
    /// [encrypted_transfers::make_transfer_data].
    pub fn encrypted_transfer(
        signer: &impl ExactSizeTransactionSigner,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        receiver: AccountAddress,
        data: EncryptedAmountTransferData<EncryptedAmountsCurve>,
    ) -> AccountTransaction<EncodedPayload> {
        construct::encrypted_transfer(signer.num_keys(), sender, nonce, expiry, receiver, data)
            .sign(signer)
    }

    /// Make an encrypted transfer with a memo. The payload can be constructed
    /// using [encrypted_transfers::make_transfer_data].
    pub fn encrypted_transfer_with_memo(
        signer: &impl ExactSizeTransactionSigner,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        receiver: AccountAddress,
        data: EncryptedAmountTransferData<EncryptedAmountsCurve>,
        memo: Memo,
    ) -> AccountTransaction<EncodedPayload> {
        construct::encrypted_transfer_with_memo(
            signer.num_keys(),
            sender,
            nonce,
            expiry,
            receiver,
            data,
            memo,
        )
        .sign(signer)
    }

    /// Transfer the given amount from public to encrypted balance of the given
    /// account.
    pub fn transfer_to_encrypted(
        signer: &impl ExactSizeTransactionSigner,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        amount: Amount,
    ) -> AccountTransaction<EncodedPayload> {
        construct::transfer_to_encrypted(signer.num_keys(), sender, nonce, expiry, amount)
            .sign(signer)
    }

    /// Transfer the given amount from encrypted to public balance of the given
    /// account. The payload may be constructed using
    /// [encrypted_transfers::make_sec_to_pub_transfer_data]
    pub fn transfer_to_public(
        signer: &impl ExactSizeTransactionSigner,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        data: SecToPubAmountTransferData<EncryptedAmountsCurve>,
    ) -> AccountTransaction<EncodedPayload> {
        construct::transfer_to_public(signer.num_keys(), sender, nonce, expiry, data).sign(signer)
    }

    /// Construct a transfer with schedule transaction, sending to the given
    /// account.
    pub fn transfer_with_schedule(
        signer: &impl ExactSizeTransactionSigner,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        receiver: AccountAddress,
        schedule: Vec<(Timestamp, Amount)>,
    ) -> AccountTransaction<EncodedPayload> {
        construct::transfer_with_schedule(
            signer.num_keys(),
            sender,
            nonce,
            expiry,
            receiver,
            schedule,
        )
        .sign(signer)
    }

    /// Construct a transfer with schedule and memo transaction, sending to the
    /// given account.
    pub fn transfer_with_schedule_and_memo(
        signer: &impl ExactSizeTransactionSigner,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        receiver: AccountAddress,
        schedule: Vec<(Timestamp, Amount)>,
        memo: Memo,
    ) -> AccountTransaction<EncodedPayload> {
        construct::transfer_with_schedule_and_memo(
            signer.num_keys(),
            sender,
            nonce,
            expiry,
            receiver,
            schedule,
            memo,
        )
        .sign(signer)
    }

    /// Register the sender account as a baker.
    ///
    /// **Note that this transaction only applies to protocol versions 1-3.**
    /// Use [`configure_baker`](Self::configure_baker) instead for protocols
    /// after 4.
    #[deprecated(
        since = "2.0.0",
        note = "This transaction only applies to protocol versions 1-3. Use configure_baker \
                instead."
    )]
    #[doc(hidden)]
    #[allow(deprecated)]
    pub fn add_baker(
        signer: &impl ExactSizeTransactionSigner,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        baking_stake: Amount,
        restake_earnings: bool,
        keys: BakerAddKeysPayload,
    ) -> AccountTransaction<EncodedPayload> {
        construct::add_baker(
            signer.num_keys(),
            sender,
            nonce,
            expiry,
            baking_stake,
            restake_earnings,
            keys,
        )
        .sign(signer)
    }

    /// Update keys of the baker associated with the sender account.
    ///
    /// **Note that this transaction only applies to protocol versions 1-3.**
    /// Use [`configure_baker`](Self::configure_baker) instead for protocols
    /// after 4.
    #[deprecated(
        since = "2.0.0",
        note = "This transaction only applies to protocol versions 1-3. Use configure_baker \
                instead."
    )]
    #[doc(hidden)]
    #[allow(deprecated)]
    pub fn update_baker_keys(
        signer: &impl ExactSizeTransactionSigner,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        keys: BakerUpdateKeysPayload,
    ) -> AccountTransaction<EncodedPayload> {
        construct::update_baker_keys(signer.num_keys(), sender, nonce, expiry, keys).sign(signer)
    }

    /// Deregister the account as a baker.
    ///
    /// **Note that this transaction only applies to protocol versions 1-3.**
    /// Use [`configure_baker`](Self::configure_baker) instead for protocols
    /// after 4.
    #[deprecated(
        since = "2.0.0",
        note = "This transaction only applies to protocol versions 1-3. Use configure_baker \
                instead."
    )]
    #[doc(hidden)]
    #[allow(deprecated)]
    pub fn remove_baker(
        signer: &impl ExactSizeTransactionSigner,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
    ) -> AccountTransaction<EncodedPayload> {
        construct::remove_baker(signer.num_keys(), sender, nonce, expiry).sign(signer)
    }

    /// Update the amount the account stakes for being a baker.
    #[deprecated(
        since = "2.0.0",
        note = "This transaction only applies to protocol versions 1-3. Use configure_baker \
                instead."
    )]
    #[doc(hidden)]
    #[allow(deprecated)]
    pub fn update_baker_stake(
        signer: &impl ExactSizeTransactionSigner,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        new_stake: Amount,
    ) -> AccountTransaction<EncodedPayload> {
        construct::update_baker_stake(signer.num_keys(), sender, nonce, expiry, new_stake)
            .sign(signer)
    }

    /// Update whether the earnings are automatically added to the baker's stake
    /// or not.
    #[deprecated(
        since = "2.0.0",
        note = "This transaction only applies to protocol versions 1-3. Use configure_baker \
                instead."
    )]
    #[doc(hidden)]
    #[allow(deprecated)]
    pub fn update_baker_restake_earnings(
        signer: &impl ExactSizeTransactionSigner,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        restake_earnings: bool,
    ) -> AccountTransaction<EncodedPayload> {
        construct::update_baker_restake_earnings(
            signer.num_keys(),
            sender,
            nonce,
            expiry,
            restake_earnings,
        )
        .sign(signer)
    }

    /// Configure the account as a baker. Only valid for protocol version 4 and
    /// up.
    pub fn configure_baker(
        signer: &impl ExactSizeTransactionSigner,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        payload: ConfigureBakerPayload,
    ) -> AccountTransaction<EncodedPayload> {
        construct::configure_baker(signer.num_keys(), sender, nonce, expiry, payload).sign(signer)
    }

    /// Configure the account as a delegator. Only valid for protocol version 4
    /// and up.
    pub fn configure_delegation(
        signer: &impl ExactSizeTransactionSigner,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        payload: ConfigureDelegationPayload,
    ) -> AccountTransaction<EncodedPayload> {
        construct::configure_delegation(signer.num_keys(), sender, nonce, expiry, payload)
            .sign(signer)
    }

    /// Construct a transaction to update keys of a single credential on an
    /// account. The transaction specific arguments are
    ///
    /// - `num_existing_credentials` - the number of existing credentials on the
    ///   account. This will affect the estimated transaction cost. It is safe
    ///   to over-approximate this.
    /// - `cred_id` - `credId` of a credential whose keys are to be updated.
    /// - `keys` - the new keys associated with the credential.
    pub fn update_credential_keys(
        signer: &impl ExactSizeTransactionSigner,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        num_existing_credentials: u16,
        cred_id: CredentialRegistrationID,
        keys: CredentialPublicKeys,
    ) -> AccountTransaction<EncodedPayload> {
        construct::update_credential_keys(
            signer.num_keys(),
            sender,
            nonce,
            expiry,
            num_existing_credentials,
            cred_id,
            keys,
        )
        .sign(signer)
    }

    /// Construct a transaction to update credentials on an account.
    /// The transaction specific arguments are
    ///
    /// - `num_existing_credentials` - the number of existing credentials on the
    ///   account. This will affect the estimated transaction cost. It is safe
    ///   to over-approximate this.
    /// - `new_credentials` - the new credentials to be deployed to the account
    ///   with the desired indices. The credential with index 0 cannot be
    ///   replaced.
    /// - `remove_credentials` - the list of credentials, by `credId`'s, to be
    ///   removed
    /// - `new_threshold` - the new account threshold.
    #[allow(clippy::too_many_arguments)]
    pub fn update_credentials(
        signer: &impl ExactSizeTransactionSigner,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        num_existing_credentials: u16,
        new_credentials: AccountCredentialsMap,
        remove_credentials: Vec<CredentialRegistrationID>,
        new_threshold: AccountThreshold,
    ) -> AccountTransaction<EncodedPayload> {
        construct::update_credentials(
            signer.num_keys(),
            sender,
            nonce,
            expiry,
            num_existing_credentials,
            new_credentials,
            remove_credentials,
            new_threshold,
        )
        .sign(signer)
    }

    /// Construct a transction to register the given piece of data.
    pub fn register_data(
        signer: &impl ExactSizeTransactionSigner,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        data: RegisteredData,
    ) -> AccountTransaction<EncodedPayload> {
        construct::register_data(signer.num_keys(), sender, nonce, expiry, data).sign(signer)
    }

    /// Deploy the given Wasm module. The module is given as a binary source,
    /// and no processing is done to the module.
    pub fn deploy_module(
        signer: &impl ExactSizeTransactionSigner,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        module: smart_contracts::WasmModule,
    ) -> AccountTransaction<EncodedPayload> {
        construct::deploy_module(signer.num_keys(), sender, nonce, expiry, module).sign(signer)
    }

    /// Initialize a smart contract, giving it the given amount of energy for
    /// execution. The unique parameters are
    /// - `energy` -- the amount of energy that can be used for contract
    ///   execution. The base energy amount for transaction verification will be
    ///   added to this cost.
    pub fn init_contract(
        signer: &impl ExactSizeTransactionSigner,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        payload: InitContractPayload,
        energy: Energy,
    ) -> AccountTransaction<EncodedPayload> {
        construct::init_contract(signer.num_keys(), sender, nonce, expiry, payload, energy)
            .sign(signer)
    }

    /// Update a smart contract intance, giving it the given amount of energy
    /// for execution. The unique parameters are
    /// - `energy` -- the amount of energy that can be used for contract
    ///   execution. The base energy amount for transaction verification will be
    ///   added to this cost.
    pub fn update_contract(
        signer: &impl ExactSizeTransactionSigner,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        payload: UpdateContractPayload,
        energy: Energy,
    ) -> AccountTransaction<EncodedPayload> {
        construct::update_contract(signer.num_keys(), sender, nonce, expiry, payload, energy)
            .sign(signer)
    }

    #[derive(Debug, Copy, Clone)]
    /// An upper bound on the amount of energy to spend on a transaction.
    /// Transaction costs have two components, one is based on the size of the
    /// transaction and the number of signatures, and then there is a
    /// transaction specific one. This construction helps handle the fixed
    /// costs and allows the user to focus only on the transaction specific
    /// ones. The most important case for this are smart contract
    /// initialisations and updates.
    pub enum GivenEnergy {
        /// Use this exact amount of energy.
        Absolute(Energy),
        /// Add the given amount of energy to the base amount.
        /// The base amount covers transaction size and signature checking.
        Add(Energy),
    }

    /// A convenience wrapper around `sign_transaction` that construct the
    /// transaction and signs it. Compared to transaction-type-specific wrappers
    /// above this allows selecting the amount of energy
    pub fn make_and_sign_transaction(
        signer: &impl ExactSizeTransactionSigner,
        sender: AccountAddress,
        nonce: Nonce,
        expiry: TransactionTime,
        energy: GivenEnergy,
        payload: Payload,
    ) -> AccountTransaction<EncodedPayload> {
        match energy {
            GivenEnergy::Absolute(energy) => construct::make_transaction(
                sender,
                nonce,
                expiry,
                construct::GivenEnergy::Absolute(energy),
                payload,
            )
            .sign(signer),
            GivenEnergy::Add(energy) => construct::make_transaction(
                sender,
                nonce,
                expiry,
                construct::GivenEnergy::Add {
                    energy,
                    num_sigs: signer.num_keys(),
                },
                payload,
            )
            .sign(signer),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::hashes::TransactionSignHash;
    use id::types::{SignatureThreshold, VerifyKey};
    use rand::Rng;
    use std::convert::TryFrom;

    use super::*;
    #[test]
    fn test_transaction_signature_check() {
        let mut rng = rand::thread_rng();
        let mut keys = BTreeMap::<CredentialIndex, BTreeMap<KeyIndex, KeyPair>>::new();
        let bound: usize = rng.gen_range(1, 20);
        for _ in 0..bound {
            let c_idx = CredentialIndex::from(rng.gen::<u8>());
            if keys.get(&c_idx).is_none() {
                let inner_bound: usize = rng.gen_range(1, 20);
                let mut cred_keys = BTreeMap::new();
                for _ in 0..inner_bound {
                    let k_idx = KeyIndex::from(rng.gen::<u8>());
                    cred_keys.insert(k_idx, KeyPair::generate(&mut rng));
                }
                keys.insert(c_idx, cred_keys);
            }
        }
        let hash = TransactionSignHash::new(rng.gen());
        let sig = keys.sign_transaction_hash(&hash);
        let threshold =
            AccountThreshold::try_from(rng.gen_range(1, (keys.len() + 1) as u8)).unwrap();
        let pub_keys = keys
            .iter()
            .map(|(&ci, keys)| {
                let threshold = SignatureThreshold(rng.gen_range(1, keys.len() + 1) as u8);
                let keys = keys
                    .iter()
                    .map(|(&ki, kp)| (ki, VerifyKey::from(kp)))
                    .collect();
                (ci, CredentialPublicKeys { keys, threshold })
            })
            .collect::<BTreeMap<_, _>>();
        let mut access_structure = AccountAccessStructure {
            threshold,
            keys: pub_keys,
        };
        assert!(
            verify_signature_transaction_sign_hash(&access_structure, &hash, &sig),
            "Transaction signature must validate."
        );

        access_structure.threshold = AccountThreshold::try_from((keys.len() + 1) as u8).unwrap();

        assert!(
            !verify_signature_transaction_sign_hash(&access_structure, &hash, &sig),
            "Transaction signature must not validate with invalid threshold."
        );
    }
}
