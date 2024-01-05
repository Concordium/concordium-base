use crate::{
    base::{BakerAggregationVerifyKey, ProtocolVersion},
    common::{Deserial, Serialize},
    hashes::{BlockHash, HashBytes},
};
use sha2::{Digest, Sha256};
use std::{io::Cursor, marker::PhantomData};

/// A generic merkle proof.
///
/// It is a vector of branches which are all concatenated when computing the
/// root hash.
pub type GenericMerkleProof = Vec<MerkleBranch>;

/// Branch in a generic merkle proof.
#[derive(Debug)]
pub enum MerkleBranch {
    /// Data bytes which can be deserialized into a value, such as information
    /// or hashes.
    RawData(Vec<u8>),
    /// A sub merkle proof where the hash of this subproof should be used when
    /// computing the root hash.
    SubProof(GenericMerkleProof),
}

#[derive(Debug, thiserror::Error)]
pub enum MerkleProofError {
    #[error("failed to deserialise the merkle proof: {0}")]
    InvalidFormat(#[from] ConvertMerkleProofError),
    #[error(
        "computed block hash did not match the expected.\n  expected: {expected}\n  computed: \
         {computed}"
    )]
    UnexpectedBlockHash {
        expected: BlockHash,
        computed: BlockHash,
    },
}

pub type MerkleProofResult<A> = Result<A, MerkleProofError>;

/// Type representing a merkle proof assumed to contain the information `Info`.
///
/// This is just a type wrapper around `GenericMerkleProof` to improve type
/// safety.
#[derive(Debug)]
#[repr(transparent)]
pub struct MerkleProof<Info> {
    /// The actual merkle proof.
    pub proof: GenericMerkleProof,
    _marker:   PhantomData<Info>,
}

impl<M> MerkleProof<M> {
    /// Wrap a generic merkle proof into some assumption about the information
    /// within.
    pub fn new(proof: GenericMerkleProof) -> Self {
        Self {
            proof,
            _marker: PhantomData::default(),
        }
    }

    /// Compute the block hash (root hash) of the merkle proof.
    pub fn compute_block_hash(&self) -> BlockHash {
        let mut stack = vec![(Sha256::new(), self.proof.iter())];
        loop {
            // Unwrap is safe, since loop should break before the stack becomes empty.
            let (hasher, iter) = stack.last_mut().unwrap();
            match iter.next() {
                Some(MerkleBranch::RawData(data)) => hasher.update(data),
                Some(MerkleBranch::SubProof(branches)) => {
                    stack.push((Sha256::new(), branches.iter()));
                }
                None => {
                    let (hasher, _) = stack.pop().unwrap();
                    let subhash = hasher.finalize();
                    if stack.is_empty() {
                        return BlockHash::new(subhash.into());
                    }
                    // Unwrap is safe, since stack not empty was checked above.
                    let (parent_hasher, _) = stack.last_mut().unwrap();
                    parent_hasher.update(subhash)
                }
            }
        }
    }
}

pub type ProtocolVersionMerkleProof = MerkleProof<ProtocolVersion>;

impl ProtocolVersionMerkleProof {
    pub fn verify(&self, expected_block_hash: BlockHash) -> MerkleProofResult<ProtocolVersion> {
        let computed_block_hash = self.compute_block_hash();
        if expected_block_hash == computed_block_hash {
            let parsed = ProtocolVersionProof::try_from(&self.proof)?;
            Ok(parsed.left.value)
        } else {
            Err(MerkleProofError::UnexpectedBlockHash {
                expected: expected_block_hash,
                computed: computed_block_hash,
            })
        }
    }
}

/// Information provided as part of the light block merkle proof.
#[derive(Debug)]
pub struct LightBlockCommitteesInfo {
    /// The protocol version of the block.
    pub protocol_version: ProtocolVersion,
    /// The current finalization committee.
    pub current:          FinalizationCommittee,
    /// The next finalization committee.
    pub next:             FinalizationCommittee,
}

#[derive(Debug, Serialize)]
#[repr(transparent)]
/// List of finalizers in the committee.
pub struct FinalizationCommittee {
    pub members: Vec<FinalizerInfo>,
}

/// Information of a specific finalizer.
#[derive(Debug, Serialize)]
pub struct FinalizerInfo {
    /// Weight of the finalizer.
    pub weight:         u64,
    /// Verify key used by the finalizer.
    pub bls_verify_key: BakerAggregationVerifyKey,
}

/// Marked merkle proof type representing a light block merkle proof.
/// See [`LightBlockCommitteesInfo`] for the information provided in the proof.
pub type LightBlockCommitteeMerkleProof = MerkleProof<LightBlockCommitteesInfo>;

impl LightBlockCommitteeMerkleProof {
    /// Verify and exact the light block information provided as part of the
    /// proof.
    pub fn verify(
        &self,
        expected_block_hash: BlockHash,
    ) -> MerkleProofResult<LightBlockCommitteesInfo> {
        let computed_block_hash = self.compute_block_hash();
        if expected_block_hash == computed_block_hash {
            let parsed = LightBlockCommitteesProof::try_from(&self.proof)?;
            let committees = parsed
                .right
                .sub_proof
                .right
                .sub_proof
                .right
                .sub_proof
                .right
                .sub_proof
                .right
                .sub_proof
                .right
                .sub_proof;
            Ok(LightBlockCommitteesInfo {
                protocol_version: parsed.left.value,
                current:          committees.left.value,
                next:             committees.right.value,
            })
        } else {
            Err(MerkleProofError::UnexpectedBlockHash {
                expected: expected_block_hash,
                computed: computed_block_hash,
            })
        }
    }
}

/// Type represent the structure of a merkle proof only containing the
/// ProtocolVersion.
type ProtocolVersionProof = BlockHashProof<MerkleHash>;
/// Type represent the structure of a merkle proof containing the
/// ProtocolVersion, the current and next finalization committee.
type LightBlockCommitteesProof = BlockHashProof<HeaderQuasi>;

// Types representing the underlying merklelized structure of the block hash.

type BlockHashProof<R> = Node2<Data<ProtocolVersion>, R>;
type HeaderQuasi = SubProof<Node2<Header, Quasi>>;
type Header = MerkleHash;
type Quasi = SubProof<Node2<Metadata, BlockData>>;
type Metadata = MerkleHash;
type BlockData = SubProof<Node2<Transactions, BlockResult>>;
type Transactions = MerkleHash;
type BlockResult = SubProof<Node2<Outcomes, LightBlockInfo>>;
type Outcomes = SubProof<Node2<TransactionOutcomes, BlockState>>;
type TransactionOutcomes = MerkleHash;
type BlockState = MerkleHash;
type LightBlockInfo = SubProof<Node2<BlockHeightInfo, CurrentAndNextFinalizationCommittee>>;
type BlockHeightInfo = MerkleHash;
type CurrentAndNextFinalizationCommittee =
    SubProof<Node2<CurrentFinalizationCommittee, NextFinalizationCommittee>>;
type CurrentFinalizationCommittee = Data<FinalizationCommittee>;
type NextFinalizationCommittee = Data<FinalizationCommittee>;

#[derive(Debug, thiserror::Error)]
pub enum ConvertMerkleProofError {
    #[error(
        "The provided proof did not contain the expected information, expected {expected} \
         branches but got {actual}."
    )]
    InvalidBranchLength {
        /// The expected len of the vector containing branches.
        expected: usize,
        /// The actual len of the vector containing branches.
        actual:   usize,
    },
    #[error("Unexpected sub proof, expected raw data.")]
    UnexpectedSubProof,
    #[error("Unexpected raw data, expected sub proof.")]
    UnexpectedRawData,
    #[error("Failed to parse raw data")]
    InvalidRawData(#[from] anyhow::Error),
}

/// Marker type for HashBytes representing a hash which is part of a merkle
/// proof.
enum MerkleHashMarker {}
/// Hash which is part of a merkle proof.
type MerkleHash = HashBytes<MerkleHashMarker>;

/// Merkle node with 2 branches where the field `left` is considered the first
/// branch and `right` is the second.
///
/// This type is a helper for defining the structure of a merkle proof needed
/// for validation and to parse out the content of the proof.
#[derive(Debug)]
struct Node2<Left, Right> {
    left:  Left,
    right: Right,
}

/// Merkle branch with subproof.
///
/// This type is a helper for defining the structure of a merkle proof needed
/// for validation and to parse out the content of the proof.
#[derive(Debug)]
#[repr(transparent)]
struct SubProof<A> {
    sub_proof: A,
}

/// Merkle branch with raw data which can be deserialized.
///
/// This type is a helper for defining the structure of a merkle proof needed
/// for validation and to parse out the content of the proof.
#[derive(Debug)]
#[repr(transparent)]
struct Data<A> {
    value: A,
}

impl<'a, L, R> TryFrom<&'a GenericMerkleProof> for Node2<L, R>
where
    L: TryFrom<&'a MerkleBranch, Error = ConvertMerkleProofError>,
    R: TryFrom<&'a MerkleBranch, Error = ConvertMerkleProofError>,
{
    type Error = ConvertMerkleProofError;

    fn try_from(value: &'a GenericMerkleProof) -> Result<Self, Self::Error> {
        if value.len() != 2 {
            return Err(ConvertMerkleProofError::InvalidBranchLength {
                expected: 2,
                actual:   value.len(),
            });
        }
        let left = L::try_from(&value[0])?;
        let right = R::try_from(&value[1])?;
        Ok(Node2 { left, right })
    }
}

impl TryFrom<&MerkleBranch> for MerkleHash {
    type Error = ConvertMerkleProofError;

    fn try_from(value: &MerkleBranch) -> Result<Self, Self::Error> {
        let v = Data::<MerkleHash>::try_from(value)?;
        Ok(v.value)
    }
}

impl<'a, A> TryFrom<&'a MerkleBranch> for SubProof<A>
where
    A: TryFrom<&'a GenericMerkleProof, Error = ConvertMerkleProofError>,
{
    type Error = ConvertMerkleProofError;

    fn try_from(value: &'a MerkleBranch) -> Result<Self, Self::Error> {
        let MerkleBranch::SubProof(sub_proof) = value else {
            return Err(ConvertMerkleProofError::UnexpectedRawData);
        };
        let sub_proof = A::try_from(sub_proof)?;
        Ok(Self { sub_proof })
    }
}

impl<A> TryFrom<&MerkleBranch> for Data<A>
where
    A: Deserial,
{
    type Error = ConvertMerkleProofError;

    fn try_from(value: &MerkleBranch) -> Result<Self, Self::Error> {
        let MerkleBranch::RawData(data) = value else {
            return Err(ConvertMerkleProofError::UnexpectedSubProof);
        };
        let value = A::deserial(&mut Cursor::new(&data))?;
        Ok(Self { value })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::to_bytes;

    #[test]
    fn test_verify_protocol_version() {
        use MerkleBranch::*;
        let actual_protocol_version = ProtocolVersion::P7;
        let proof = ProtocolVersionMerkleProof::new(vec![
            RawData(to_bytes(&actual_protocol_version)),
            RawData([0u8; 32].to_vec()),
        ]);

        let expected = "72f3eb9aeaf8283011ce6e437fdecd65eace8f52cc4b1a06a4bc9b8f112c570d"
            .parse()
            .expect("Failed to parse block hash");
        let proof_protocol_version = proof.verify(expected).expect("Unable to verify proof.");

        assert_eq!(
            proof_protocol_version, actual_protocol_version,
            "Mismatching protocol version."
        )
    }

    #[test]
    fn test_verify_finalizers() {
        use MerkleBranch::*;
        let actual_protocol_version = ProtocolVersion::P7;
        let actual_current_committee = FinalizationCommittee { members: vec![] };
        let actual_next_committee = FinalizationCommittee { members: vec![] };
        let proof = LightBlockCommitteeMerkleProof::new(vec![
            RawData(to_bytes(&actual_protocol_version)),
            SubProof(vec![
                RawData([0u8; 32].to_vec()),
                SubProof(vec![
                    RawData([0u8; 32].to_vec()),
                    SubProof(vec![
                        RawData([0u8; 32].to_vec()),
                        SubProof(vec![
                            RawData([0u8; 32].to_vec()),
                            SubProof(vec![
                                RawData([0u8; 32].to_vec()),
                                SubProof(vec![
                                    RawData(to_bytes(&actual_current_committee)),
                                    RawData(to_bytes(&actual_next_committee)),
                                ]),
                            ]),
                        ]),
                    ]),
                ]),
            ]),
        ]);

        let expected = "2336a45ff212539c0df454bffa3f1b090489cb11faf24326d18074d7a032fc06"
            .parse()
            .expect("Failed to parse block hash");
        let proof_content = proof.verify(expected).expect("Unable to verify proof.");

        assert_eq!(
            proof_content.protocol_version, actual_protocol_version,
            "Mismatching protocol version."
        )
    }
}
