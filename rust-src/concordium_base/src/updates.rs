//! Definitions and functionality related to chain updates.
use std::{
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
};

use crate::{base::*, hashes, transactions::PayloadSize};
use crypto_common::{
    derive, deserial_bytes, deserial_map_no_length, deserial_set_no_length, deserial_string,
    deserial_vector_no_length, types::*, Buffer, Deserial, Get, ParseResult, ReadBytesExt,
    SerdeDeserialize, SerdeSerialize, Serial,
};
use derive_more::*;

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
/// A generic protocol update. This is essentially an announcement of the
/// update. The details of the update will be communicated in some off-chain
/// way, and bakers will need to update their node software to support the
/// update.
pub struct ProtocolUpdate {
    pub message: String,
    #[serde(rename = "specificationURL")]
    pub specification_url: String,
    pub specification_hash: hashes::Hash,
    #[serde(with = "crate::internal::byte_array_hex")]
    pub specification_auxiliary_data: Vec<u8>,
}

impl Serial for ProtocolUpdate {
    fn serial<B: Buffer>(&self, out: &mut B) {
        let data_len = self.message.as_bytes().len()
            + 8
            + self.specification_url.as_bytes().len()
            + 8
            + 32
            + self.specification_auxiliary_data.len();
        (data_len as u64).serial(out);
        (self.message.as_bytes().len() as u64).serial(out);
        out.write_all(self.message.as_bytes())
            .expect("Serialization to a buffer always succeeds.");
        (self.specification_url.as_bytes().len() as u64).serial(out);
        out.write_all(self.specification_url.as_bytes())
            .expect("Serialization to a buffer always succeeds.");
        self.specification_hash.serial(out);
        out.write_all(&self.specification_auxiliary_data)
            .expect("Serialization to a buffer always succeeds.")
    }
}

impl Deserial for ProtocolUpdate {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let data_len = u64::deserial(source)?;
        let mut limited = <&mut R as std::io::Read>::take(source, data_len);
        let message_len = u64::deserial(&mut limited)?;
        let message = if message_len <= 4096 {
            // protect against DOS by memory exhaustion
            deserial_string(&mut limited, message_len as usize)?
        } else {
            String::from_utf8(deserial_vector_no_length(
                &mut limited,
                message_len as usize,
            )?)?
        };
        let url_len = u64::deserial(&mut limited)?;
        let specification_url = if message_len <= 4096 {
            deserial_string(&mut limited, url_len as usize)?
        } else {
            String::from_utf8(deserial_vector_no_length(&mut limited, url_len as usize)?)?
        };
        let specification_hash = limited.get()?;
        let remaining = limited.limit();
        let specification_auxiliary_data = if remaining <= 4096 {
            deserial_bytes(&mut limited, remaining as usize)?
        } else {
            deserial_vector_no_length(&mut limited, remaining as usize)?
        };
        Ok(Self {
            message,
            specification_url,
            specification_hash,
            specification_auxiliary_data,
        })
    }
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize, derive::Serial, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(try_from = "transaction_fee_distribution::TransactionFeeDistributionUnchecked")]
/// Update the transaction fee distribution to the specified value.
pub struct TransactionFeeDistribution {
    /// The fraction that goes to the baker of the block.
    pub baker:       AmountFraction,
    /// The fraction that goes to the gas account. The remaining fraction will
    /// go to the foundation.
    pub gas_account: AmountFraction,
}

impl Deserial for TransactionFeeDistribution {
    fn deserial<R: crypto_common::ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let baker: AmountFraction = source.get()?;
        let gas_account: AmountFraction = source.get()?;
        anyhow::ensure!(
            (baker + gas_account).is_some(),
            "Reward fractions exceed 100%."
        );
        Ok(Self { baker, gas_account })
    }
}

mod transaction_fee_distribution {
    use super::*;
    #[derive(SerdeDeserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct TransactionFeeDistributionUnchecked {
        baker:       AmountFraction,
        gas_account: AmountFraction,
    }

    impl TryFrom<TransactionFeeDistributionUnchecked> for TransactionFeeDistribution {
        type Error = &'static str;

        fn try_from(value: TransactionFeeDistributionUnchecked) -> Result<Self, Self::Error> {
            if (value.baker + value.gas_account).is_some() {
                Ok(TransactionFeeDistribution {
                    baker:       value.baker,
                    gas_account: value.gas_account,
                })
            } else {
                Err("Transaction fee fractions exceed 100%.")
            }
        }
    }
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize, derive::Serialize, Clone)]
#[serde(rename_all = "camelCase")]
/// The reward fractions related to the gas account and inclusion of special
/// transactions.
pub struct GASRewards {
    /// `BakerPrevTransFrac`: fraction of the previous gas account paid to the
    /// baker.
    pub baker:              AmountFraction,
    /// `FeeAddFinalisationProof`: fraction paid for including a finalization
    /// proof in a block.
    pub finalization_proof: AmountFraction,
    /// `FeeAccountCreation`: fraction paid for including each account creation
    /// transaction in a block.
    pub account_creation:   AmountFraction,
    /// `FeeUpdate`: fraction paid for including an update transaction in a
    /// block.
    pub chain_update:       AmountFraction,
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize, Clone)]
#[serde(tag = "typeOfUpdate", content = "updatePayload")]
#[serde(rename_all = "camelCase")]
/// An update with root keys of some other set of governance keys, or the root
/// keys themselves. Each update is a separate transaction.
pub enum RootUpdate {
    RootKeysUpdate(HigherLevelAccessStructure<RootKeysKind>),
    Level1KeysUpdate(HigherLevelAccessStructure<Level1KeysKind>),
    Level2KeysUpdate(Box<Authorizations<ChainParameterVersion0>>),
    Level2KeysUpdateV1(Box<Authorizations<ChainParameterVersion1>>),
}

impl Serial for RootUpdate {
    fn serial<B: Buffer>(&self, out: &mut B) {
        match self {
            RootUpdate::RootKeysUpdate(ruk) => {
                0u8.serial(out);
                ruk.serial(out)
            }
            RootUpdate::Level1KeysUpdate(l1k) => {
                1u8.serial(out);
                l1k.serial(out)
            }
            RootUpdate::Level2KeysUpdate(l2k) => {
                2u8.serial(out);
                l2k.serial(out)
            }
            RootUpdate::Level2KeysUpdateV1(l2k) => {
                3u8.serial(out);
                l2k.serial(out)
            }
        }
    }
}

impl Deserial for RootUpdate {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        match u8::deserial(source)? {
            0u8 => Ok(RootUpdate::RootKeysUpdate(source.get()?)),
            1u8 => Ok(RootUpdate::Level1KeysUpdate(source.get()?)),
            2u8 => Ok(RootUpdate::Level2KeysUpdate(source.get()?)),
            3u8 => Ok(RootUpdate::Level2KeysUpdateV1(source.get()?)),
            tag => anyhow::bail!("Unknown RootUpdate tag {}", tag),
        }
    }
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize, Clone)]
#[serde(tag = "typeOfUpdate", content = "updatePayload")]
#[serde(rename_all = "camelCase")]
/// An update with level 1 keys of either level 1 or level 2 keys. Each of the
/// updates must be a separate transaction.
pub enum Level1Update {
    Level1KeysUpdate(HigherLevelAccessStructure<Level1KeysKind>),
    Level2KeysUpdate(Box<Authorizations<ChainParameterVersion0>>),
    Level2KeysUpdateV1(Box<Authorizations<ChainParameterVersion1>>),
}

impl Serial for Level1Update {
    fn serial<B: Buffer>(&self, out: &mut B) {
        match self {
            Level1Update::Level1KeysUpdate(l1k) => {
                0u8.serial(out);
                l1k.serial(out)
            }
            Level1Update::Level2KeysUpdate(l2k) => {
                1u8.serial(out);
                l2k.serial(out)
            }
            Level1Update::Level2KeysUpdateV1(l2k) => {
                2u8.serial(out);
                l2k.serial(out)
            }
        }
    }
}

impl Deserial for Level1Update {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        match u8::deserial(source)? {
            0u8 => Ok(Level1Update::Level1KeysUpdate(source.get()?)),
            1u8 => Ok(Level1Update::Level2KeysUpdate(source.get()?)),
            2u8 => Ok(Level1Update::Level2KeysUpdateV1(source.get()?)),
            tag => anyhow::bail!("Unknown Level1Update tag {}", tag),
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
#[doc(hidden)]
/// A tag for added type safety when using HigherLevelKeys.
/// This type deliberately has no values. It is meant to exist purely as a
/// type-level marker.
pub enum RootKeysKind {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
#[doc(hidden)]
/// A tag for added type safety when using HigherLevelKeys.
/// This type deliberately has no values. It is meant to exist purely as a
/// type-level marker.
pub enum Level1KeysKind {}

#[derive(Debug, SerdeSerialize, SerdeDeserialize, derive::Serial, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(bound = "Kind: Sized")]
/// Either root, level1, or level 2 access structure. They all have the same
/// structure, keys and a threshold. The phantom type parameter is used for
/// added type safety to distinguish different access structures in different
/// contexts.
pub struct HigherLevelAccessStructure<Kind> {
    #[size_length = 2]
    pub keys:      Vec<UpdatePublicKey>,
    pub threshold: UpdateKeysThreshold,
    #[serde(skip)] // use default when deserializing
    pub _phantom:  PhantomData<Kind>,
}

impl<Kind> Deserial for HigherLevelAccessStructure<Kind> {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let keys_len: u16 = source.get()?;
        let keys = deserial_vector_no_length(source, keys_len as usize)?;
        let threshold: UpdateKeysThreshold = source.get()?;
        anyhow::ensure!(
            threshold.threshold.get() <= keys_len,
            "Threshold too large."
        );
        Ok(Self {
            keys,
            threshold,
            _phantom: Default::default(),
        })
    }
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize, derive::Serial, Clone)]
#[serde(rename_all = "camelCase")]
/// And access structure for performing chain updates. The access structure is
/// only meaningful in the context of a list of update keys to which the indices
/// refer to.
pub struct AccessStructure {
    #[set_size_length = 2]
    pub authorized_keys: BTreeSet<UpdateKeysIndex>,
    pub threshold:       UpdateKeysThreshold,
}

impl Deserial for AccessStructure {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let authorized_keys_len: u16 = source.get()?;
        let authorized_keys = deserial_set_no_length(source, authorized_keys_len as usize)?;
        let threshold: UpdateKeysThreshold = source.get()?;
        anyhow::ensure!(
            threshold.threshold.get() <= authorized_keys_len,
            "Threshold too large."
        );
        Ok(Self {
            authorized_keys,
            threshold,
        })
    }
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize, Clone, derive::Serialize)]
#[serde(rename_all = "camelCase")]
/// Access structures for each of the different possible chain updates, togehter
/// with the context giving all the possible keys.
pub struct AuthorizationsV0 {
    #[size_length = 2]
    /// The list of all keys that are currently authorized to perform updates.
    pub keys: Vec<UpdatePublicKey>,
    /// Access structure for emergency updates.
    pub emergency: AccessStructure,
    /// Access structure for protocol updates.
    pub protocol: AccessStructure,
    /// Access structure for updating the election difficulty.
    pub election_difficulty: AccessStructure,
    /// Access structure for updating the euro to energy exchange rate.
    pub euro_per_energy: AccessStructure,
    #[serde(rename = "microGTUPerEuro")]
    /// Access structure for updating the microccd per euro exchange rate.
    pub micro_gtu_per_euro: AccessStructure,
    /// Access structure for updating the foundation account address.
    pub foundation_account: AccessStructure,
    /// Access structure for updating the mint distribution parameters.
    pub mint_distribution: AccessStructure,
    /// Access structure for updating the transaction fee distribution.
    pub transaction_fee_distribution: AccessStructure,
    #[serde(rename = "paramGASRewards")]
    /// Access structure for updating the gas reward distribution parameters.
    pub param_gas_rewards: AccessStructure,
    /// Access structure for updating the pool parameters. For V0 this is only
    /// the baker stake threshold, for V1 there are more.
    pub pool_parameters: AccessStructure,
    /// Access structure for adding new anonymity revokers.
    pub add_anonymity_revoker: AccessStructure,
    /// Access structure for adding new identity providers.
    pub add_identity_provider: AccessStructure,
}

impl AuthorizationsV0 {
    /// Find key indices given a set of keys and an access structure.
    /// If any of the given `actual_keys` are not authorized in the access
    /// structure [`None`] will be returned.
    /// If there are duplicate keys among `actual_keys` this function also
    /// returns [`None`].
    pub fn construct_update_signer<K>(
        &self,
        update_key_indices: &AccessStructure,
        actual_keys: impl IntoIterator<Item = K>,
    ) -> Option<BTreeMap<UpdateKeysIndex, K>>
    where
        UpdatePublicKey: for<'a> From<&'a K>, {
        construct_update_signer_worker(&self.keys, update_key_indices, actual_keys)
    }
}

// See [AuthorizationsV0::construct_update_signer] for documentation.
fn construct_update_signer_worker<K>(
    keys: &[UpdatePublicKey],
    update_key_indices: &AccessStructure,
    actual_keys: impl IntoIterator<Item = K>,
) -> Option<BTreeMap<UpdateKeysIndex, K>>
where
    UpdatePublicKey: for<'a> From<&'a K>, {
    let mut signer = BTreeMap::new();
    for kp in actual_keys {
        let known_key = &UpdatePublicKey::from(&kp);
        if let Some(i) = keys.iter().position(|public| public == known_key) {
            let idx = UpdateKeysIndex { index: i as u16 };
            if update_key_indices.authorized_keys.contains(&idx) {
                if signer.insert(idx, kp).is_some() {
                    return None;
                }
            } else {
                return None;
            }
        } else {
            return None;
        }
    }
    Some(signer)
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize, Clone, derive::Serialize)]
#[serde(rename_all = "camelCase")]
/// Access structures for each of the different possible chain updates, togehter
/// with the context giving all the possible keys.
pub struct AuthorizationsV1 {
    #[serde(flatten)]
    pub v0:                  AuthorizationsV0,
    /// Keys for changing cooldown periods related to baking and delegating.
    pub cooldown_parameters: AccessStructure,
    /// Keys for changing the lenghts of the reward period.
    pub time_parameters:     AccessStructure,
}

impl AuthorizationsV1 {
    /// Find key indices given a set of keys and an access structure.
    /// If any of the given `actual_keys` are not authorized in the access
    /// structure [`None`] will be returned.
    /// If there are duplicate keys among `actual_keys` this function also
    /// returns [`None`].
    pub fn construct_update_signer<K>(
        &self,
        update_key_indices: &AccessStructure,
        actual_keys: impl IntoIterator<Item = K>,
    ) -> Option<BTreeMap<UpdateKeysIndex, K>>
    where
        UpdatePublicKey: for<'a> From<&'a K>, {
        construct_update_signer_worker(&self.v0.keys, update_key_indices, actual_keys)
    }
}

/// Together with [`Authorizations`] this defines a type family allowing us to
/// map [`ChainParameterVersion0`] and [`ChainParameterVersion1`] to the
/// corresponding `Authorizations` version.
pub trait AuthorizationsFamily {
    type Output: std::fmt::Debug;
}

impl AuthorizationsFamily for ChainParameterVersion0 {
    type Output = AuthorizationsV0;
}

impl AuthorizationsFamily for ChainParameterVersion1 {
    type Output = AuthorizationsV1;
}

/// A mapping of chain parameter versions to authorization versions.
pub type Authorizations<CPV> = <CPV as AuthorizationsFamily>::Output;

#[derive(SerdeSerialize, SerdeDeserialize, derive::Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
/// Parameters related to becoming a baker that apply to protocol versions 1-3.
pub struct BakerParameters {
    /// Minimum amount of CCD that an account must stake to become a baker.
    pub minimum_threshold_for_baking: Amount,
}

#[derive(Debug, derive::Serialize, SerdeSerialize, SerdeDeserialize, Copy, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CooldownParameters {
    /// Number of seconds that pool owners must cooldown
    /// when reducing their equity capital or closing the pool.
    pub pool_owner_cooldown: DurationSeconds,
    /// Number of seconds that a delegator must cooldown
    /// when reducing their delegated stake.
    pub delegator_cooldown:  DurationSeconds,
}

/// Length of a reward period in epochs.
/// Must always be a strictly positive integer.
#[derive(
    Copy,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Debug,
    FromStr,
    Display,
    From,
    Into,
    SerdeSerialize,
    SerdeDeserialize,
    derive::Serialize,
)]
#[serde(transparent)]
pub struct RewardPeriodLength {
    pub(crate) reward_period_epochs: Epoch,
}

#[derive(Debug, SerdeSerialize, SerdeDeserialize, derive::Serialize, Copy, Clone)]
#[serde(rename_all = "camelCase")]
/// The time parameters are introduced as of protocol version 4, and consist of
/// the reward period length and the mint rate per payday. These are coupled as
/// a change to either affects the overall rate of minting.
pub struct TimeParameters {
    pub reward_period_length: RewardPeriodLength,
    pub mint_per_payday:      MintRate,
}

#[derive(Debug, derive::Serialize, SerdeSerialize, SerdeDeserialize, Clone)]
#[serde(rename_all = "camelCase")]
/// Parameters related to staking pools. This applies to protocol version 4 and
/// up.
pub struct PoolParameters {
    /// Fraction of finalization rewards charged by the passive delegation.
    pub passive_finalization_commission: AmountFraction,
    /// Fraction of baking rewards charged by the passive delegation.
    pub passive_baking_commission:       AmountFraction,
    /// Fraction of transaction rewards charged by the L-pool.
    pub passive_transaction_commission:  AmountFraction,
    /// Bounds on the commission rates that may be charged by bakers.
    #[serde(flatten)]
    pub commission_bounds:               CommissionRanges,
    /// Minimum equity capital required for a new baker.
    pub minimum_equity_capital:          Amount,
    /// Maximum fraction of the total staked capital of that a new baker can
    /// have.
    pub capital_bound:                   CapitalBound,
    /// The maximum leverage that a baker can have as a ratio of total stake
    /// to equity capital.
    pub leverage_bound:                  LeverageFactor,
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone)]
#[serde(tag = "updateType", content = "update")]
/// The type of an update payload.
pub enum UpdatePayload {
    #[serde(rename = "protocol")]
    Protocol(ProtocolUpdate),
    #[serde(rename = "electionDifficulty")]
    ElectionDifficulty(ElectionDifficulty),
    #[serde(rename = "euroPerEnergy")]
    EuroPerEnergy(ExchangeRate),
    #[serde(rename = "microGTUPerEuro")]
    MicroGTUPerEuro(ExchangeRate), // TODO: Rename to CCD when switching to gRPC v2.
    #[serde(rename = "foundationAccount")]
    FoundationAccount(AccountAddress),
    #[serde(rename = "mintDistribution")]
    MintDistribution(MintDistribution<ChainParameterVersion0>),
    #[serde(rename = "transactionFeeDistribution")]
    TransactionFeeDistribution(TransactionFeeDistribution),
    #[serde(rename = "gASRewards")]
    GASRewards(GASRewards),
    #[serde(rename = "bakerStakeThreshold")]
    BakerStakeThreshold(BakerParameters),
    #[serde(rename = "root")]
    Root(RootUpdate),
    #[serde(rename = "level1")]
    Level1(Level1Update),
    #[serde(rename = "addAnonymityRevoker")]
    AddAnonymityRevoker(Box<id::types::ArInfo<id::constants::ArCurve>>),
    #[serde(rename = "addIdentityProvider")]
    AddIdentityProvider(Box<id::types::IpInfo<id::constants::IpPairing>>),
    #[serde(rename = "cooldownParametersCPV1")]
    CooldownParametersCPV1(CooldownParameters),
    #[serde(rename = "poolParametersCPV1")]
    PoolParametersCPV1(PoolParameters),
    #[serde(rename = "timeParametersCPV1")]
    TimeParametersCPV1(TimeParameters),
    #[serde(rename = "mintDistributionCPV1")]
    MintDistributionCPV1(MintDistribution<ChainParameterVersion1>),
}

#[derive(SerdeSerialize, SerdeDeserialize, Debug, Clone, Copy)]
#[serde(rename_all = "camelCase")]
// Since all variants are fieldless, the default JSON serialization will convert
// all the variants to simple strings.
/// Enumeration of the types of updates that are possible.
pub enum UpdateType {
    /// Update the chain protocol
    UpdateProtocol,
    /// Update the election difficulty
    UpdateElectionDifficulty,
    /// Update the euro per energy exchange rate
    UpdateEuroPerEnergy,
    /// Update the microCCD per euro exchange rate
    UpdateMicroGTUPerEuro,
    /// Update the address of the foundation account
    UpdateFoundationAccount,
    /// Update the distribution of newly minted CCD
    UpdateMintDistribution,
    /// Update the distribution of transaction fees
    UpdateTransactionFeeDistribution,
    /// Update the GAS rewards
    UpdateGASRewards,
    /// Add new anonymity revoker
    UpdateAddAnonymityRevoker,
    /// Add new identity provider
    UpdateAddIdentityProvider,
    /// Update the root keys
    UpdateRootKeys,
    /// Update the level 1 keys
    UpdateLevel1Keys,
    /// Update the level 2 keys
    UpdateLevel2Keys,
    /// Update the baker pool parameters. In protocol versions <= 3 this
    /// corresponds to the the update of the baker stake threshold. In
    /// protocol version 4 and up this includes other pool parameters.
    UpdatePoolParameters,
    /// Update for cooldown parameters. Only applies to protocol version
    /// [`P4`](ProtocolVersion::P4) and up.
    UpdateCooldownParameters,
    /// Update of the time parameters. Only applies to protocol version
    /// [`P4`](ProtocolVersion::P4) and up.
    UpdateTimeParameters,
}

impl UpdatePayload {
    pub fn update_type(&self) -> UpdateType {
        use UpdateType::*;
        match self {
            UpdatePayload::Protocol(_) => UpdateProtocol,
            UpdatePayload::ElectionDifficulty(_) => UpdateElectionDifficulty,
            UpdatePayload::EuroPerEnergy(_) => UpdateEuroPerEnergy,
            UpdatePayload::MicroGTUPerEuro(_) => UpdateMicroGTUPerEuro,
            UpdatePayload::FoundationAccount(_) => UpdateFoundationAccount,
            UpdatePayload::MintDistribution(_) => UpdateMintDistribution,
            UpdatePayload::TransactionFeeDistribution(_) => UpdateTransactionFeeDistribution,
            UpdatePayload::GASRewards(_) => UpdateGASRewards,
            UpdatePayload::BakerStakeThreshold(_) => UpdatePoolParameters,
            UpdatePayload::Root(_) => UpdateRootKeys,
            UpdatePayload::Level1(_) => UpdateLevel1Keys,
            UpdatePayload::AddAnonymityRevoker(_) => UpdateAddAnonymityRevoker,
            UpdatePayload::AddIdentityProvider(_) => UpdateAddIdentityProvider,
            UpdatePayload::CooldownParametersCPV1(_) => UpdateCooldownParameters,
            UpdatePayload::PoolParametersCPV1(_) => UpdatePoolParameters,
            UpdatePayload::TimeParametersCPV1(_) => UpdateTimeParameters,
            UpdatePayload::MintDistributionCPV1(_) => UpdateMintDistribution,
        }
    }
}

#[derive(Debug, Clone, derive::Serialize)]
pub struct UpdateInstruction {
    pub header:     UpdateHeader,
    pub payload:    UpdatePayload,
    pub signatures: UpdateInstructionSignature,
}

/// Implementors of this trait can sign update instructions.
pub trait UpdateSigner {
    /// Sign the specified transaction hash, allocating and returning the
    /// signatures.
    fn sign_update_hash(&self, hash_to_sign: &hashes::UpdateSignHash)
        -> UpdateInstructionSignature;
}

impl UpdateSigner for &BTreeMap<UpdateKeysIndex, UpdateKeyPair> {
    fn sign_update_hash(
        &self,
        hash_to_sign: &hashes::UpdateSignHash,
    ) -> UpdateInstructionSignature {
        let signatures = self
            .iter()
            .map(|(ki, kp)| (*ki, kp.sign(hash_to_sign.as_ref())))
            .collect::<BTreeMap<_, _>>();
        UpdateInstructionSignature { signatures }
    }
}

impl UpdateSigner for &[(UpdateKeysIndex, UpdateKeyPair)] {
    fn sign_update_hash(
        &self,
        hash_to_sign: &hashes::UpdateSignHash,
    ) -> UpdateInstructionSignature {
        let signatures = self
            .iter()
            .map(|(ki, kp)| (*ki, kp.sign(hash_to_sign.as_ref())))
            .collect::<BTreeMap<_, _>>();
        UpdateInstructionSignature { signatures }
    }
}

#[derive(Debug, Clone, Copy, derive::Serialize)]
/// A header common to all update instructions.
pub struct UpdateHeader {
    /// Sequence number of the update. Each update queue maintains its own
    /// sequence number.
    pub seq_number:     UpdateSequenceNumber,
    /// An effective time of the update. 0 is used to mean "immediate".
    pub effective_time: TransactionTime,
    /// Timeout of the update. The timeout must not be after the effective time.
    pub timeout:        TransactionTime,
    /// Size of the update instruction payload.
    pub payload_size:   PayloadSize,
}

#[derive(Debug, Clone, derive::Serial, Into)]
/// Signature of an update instruction.
pub struct UpdateInstructionSignature {
    #[map_size_length = 2]
    pub signatures: BTreeMap<UpdateKeysIndex, Signature>,
}

impl Deserial for UpdateInstructionSignature {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        let len = u16::deserial(source)?;
        anyhow::ensure!(len != 0, "There must be at least one signature.");
        let signatures = deserial_map_no_length(source, len as usize)?;
        Ok(Self { signatures })
    }
}

/// A module that provides helpers for constructing and signing update
/// instructions.
pub mod update {
    use sha2::Digest;
    use std::io::Write;

    use super::*;
    fn compute_sign_hash(
        header: &UpdateHeader,
        payload: &[u8], // serialized payload
    ) -> hashes::UpdateSignHash {
        let mut hasher = sha2::Sha256::new();
        header.serial(&mut hasher);
        hasher
            .write_all(payload)
            .expect("Writing to hasher does not fail.");
        <[u8; 32]>::from(hasher.finalize()).into()
    }

    /// Construct an update instruction and sign it.
    pub fn update(
        signer: impl UpdateSigner,
        seq_number: UpdateSequenceNumber,
        effective_time: TransactionTime,
        timeout: TransactionTime,
        payload: UpdatePayload,
    ) -> UpdateInstruction {
        let serialized_payload = crypto_common::to_bytes(&payload);
        let header = UpdateHeader {
            seq_number,
            effective_time,
            timeout,
            payload_size: PayloadSize {
                size: serialized_payload.len() as u32,
            },
        };
        let signatures = signer.sign_update_hash(&compute_sign_hash(&header, &serialized_payload));
        UpdateInstruction {
            header,
            payload,
            signatures,
        }
    }
}

impl Serial for UpdatePayload {
    fn serial<B: Buffer>(&self, out: &mut B) {
        match self {
            UpdatePayload::Protocol(pu) => {
                1u8.serial(out);
                pu.serial(out)
            }
            UpdatePayload::ElectionDifficulty(ed) => {
                2u8.serial(out);
                ed.serial(out);
            }
            UpdatePayload::EuroPerEnergy(ee) => {
                3u8.serial(out);
                ee.serial(out);
            }
            UpdatePayload::MicroGTUPerEuro(me) => {
                4u8.serial(out);
                me.serial(out);
            }
            UpdatePayload::FoundationAccount(fa) => {
                5u8.serial(out);
                fa.serial(out);
            }
            UpdatePayload::MintDistribution(md) => {
                6u8.serial(out);
                md.serial(out);
            }
            UpdatePayload::TransactionFeeDistribution(tf) => {
                7u8.serial(out);
                tf.serial(out);
            }
            UpdatePayload::GASRewards(gr) => {
                8u8.serial(out);
                gr.serial(out);
            }
            UpdatePayload::BakerStakeThreshold(bs) => {
                9u8.serial(out);
                bs.serial(out)
            }
            UpdatePayload::Root(ru) => {
                10u8.serial(out);
                ru.serial(out)
            }
            UpdatePayload::Level1(l1) => {
                11u8.serial(out);
                l1.serial(out)
            }
            UpdatePayload::AddAnonymityRevoker(add_ar) => {
                12u8.serial(out);
                add_ar.serial(out)
            }
            UpdatePayload::AddIdentityProvider(add_ip) => {
                13u8.serial(out);
                add_ip.serial(out)
            }
            UpdatePayload::CooldownParametersCPV1(cp) => {
                14u8.serial(out);
                cp.serial(out)
            }
            UpdatePayload::PoolParametersCPV1(pp) => {
                15u8.serial(out);
                pp.serial(out)
            }
            UpdatePayload::TimeParametersCPV1(tp) => {
                16u8.serial(out);
                tp.serial(out)
            }
            UpdatePayload::MintDistributionCPV1(md) => {
                17u8.serial(out);
                md.serial(out)
            }
        }
    }
}

impl Deserial for UpdatePayload {
    fn deserial<R: ReadBytesExt>(source: &mut R) -> ParseResult<Self> {
        match u8::deserial(source)? {
            1u8 => Ok(UpdatePayload::Protocol(source.get()?)),
            2u8 => Ok(UpdatePayload::ElectionDifficulty(source.get()?)),
            3u8 => Ok(UpdatePayload::EuroPerEnergy(source.get()?)),
            4u8 => Ok(UpdatePayload::MicroGTUPerEuro(source.get()?)),
            5u8 => Ok(UpdatePayload::FoundationAccount(source.get()?)),
            6u8 => Ok(UpdatePayload::MintDistribution(source.get()?)),
            7u8 => Ok(UpdatePayload::TransactionFeeDistribution(source.get()?)),
            8u8 => Ok(UpdatePayload::GASRewards(source.get()?)),
            9u8 => Ok(UpdatePayload::BakerStakeThreshold(source.get()?)),
            10u8 => Ok(UpdatePayload::Root(source.get()?)),
            11u8 => Ok(UpdatePayload::Level1(source.get()?)),
            12u8 => Ok(UpdatePayload::AddAnonymityRevoker(source.get()?)),
            13u8 => Ok(UpdatePayload::AddIdentityProvider(source.get()?)),
            14u8 => Ok(UpdatePayload::CooldownParametersCPV1(source.get()?)),
            15u8 => Ok(UpdatePayload::PoolParametersCPV1(source.get()?)),
            16u8 => Ok(UpdatePayload::TimeParametersCPV1(source.get()?)),
            17u8 => Ok(UpdatePayload::MintDistributionCPV1(source.get()?)),
            tag => anyhow::bail!("Unknown update payload tag {}", tag),
        }
    }
}
