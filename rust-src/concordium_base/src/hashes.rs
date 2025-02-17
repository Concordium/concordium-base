//! Different types of hashes based on SHA256.

pub use concordium_contracts_common::hashes::*;

#[doc(hidden)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
/// Used as a phantom type to indicate a hash is a block hash.
pub enum BlockMarker {}

#[doc(hidden)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
/// Used as a phantom type to indicate a hash is a transaction hash.
pub enum TransactionMarker {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
/// Used as a phantom type to indicate a hash is a transaction sign hash, i.e.,
/// the hash that is signed.
pub enum TransactionSignMarker {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
/// Used as a phantom type to indicate a hash is an update sign hash, i.e.,
/// the hash that is signed to make an update instruction.
pub enum UpdateSignMarker {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
/// Used as a phantom type to indicate a hash is a block state hash.
pub enum StateMarker {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
/// Used as a phantom type to indicate a hash is a leadership election
/// nonce.
pub enum ElectionNonceMarker {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
/// Used as a phantom type to indicate a hash is a successor proof of an
/// epoch finalization entry.
pub enum SuccessorProofMarker {}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
/// Used as a phantom type to indicate a hash of a finalization committee,
/// derived from the weights and aggregation keys of the finalizers.
pub enum FinalizationCommitteeMarker {}

/// The leadership election nonce is an unpredictable value updated once an
/// epoch to make sure that bakers cannot predict too far in the future when
/// they will win blocks.
pub type LeadershipElectionNonce = HashBytes<ElectionNonceMarker>;
/// Hash of a block.
pub type BlockHash = HashBytes<BlockMarker>;
/// Hash of a transaction.
pub type TransactionHash = HashBytes<TransactionMarker>;
/// Hash that is signed by the account holder's keys to make a transaction
/// signature.
pub type TransactionSignHash = HashBytes<TransactionSignMarker>;
/// Hash that is signed by the governance keys to make an update instruction
/// signature.
pub type UpdateSignHash = HashBytes<UpdateSignMarker>;
/// Hash of the block state that is included in a block.
pub type StateHash = HashBytes<StateMarker>;
/// Hash that is a successor proof of an epoch finalization entry.
pub type SuccessorProof = HashBytes<SuccessorProofMarker>;
/// Hash of a finalization committee.
pub type FinalizationCommitteeHash = HashBytes<FinalizationCommitteeMarker>;
