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
#[derive(Debug, Clone, PartialEq)]
#[repr(transparent)]
pub struct GenericMerkleProof {
    pub branches: Vec<MerkleBranch>,
}

impl GenericMerkleProof {
    pub fn new(branches: Vec<MerkleBranch>) -> Self { GenericMerkleProof { branches } }

    fn with_two_branches(&self) -> Result<(&MerkleBranch, &MerkleBranch), ConvertMerkleProofError> {
        if self.branches.len() != 2 {
            Err(ConvertMerkleProofError::InvalidBranchLength {
                expected: 2,
                actual:   self.branches.len(),
            })
        } else {
            Ok((&self.branches[0], &self.branches[1]))
        }
    }
}

/// Branch in a generic merkle proof.
#[derive(Debug, Clone, PartialEq)]
pub enum MerkleBranch {
    /// Data bytes which can be deserialized into a value, such as information
    /// or hashes.
    RawData(Vec<u8>),
    /// A sub merkle proof where the hash of this subproof should be used when
    /// computing the root hash.
    SubProof(GenericMerkleProof),
}

impl MerkleBranch {
    /// Get the raw data from the branch, producing an error if the branch
    /// contains a subproof.
    fn raw_data(&self) -> Result<&Vec<u8>, ConvertMerkleProofError> {
        if let MerkleBranch::RawData(data) = self {
            Ok(data)
        } else {
            Err(ConvertMerkleProofError::ExpectedRawData)
        }
    }

    /// Get and deserialize the data from the branch, producing an error if the
    /// branch contains a subproof.
    fn deserial_data<A: Deserial>(&self) -> Result<A, ConvertMerkleProofError> {
        let data = A::deserial(&mut Cursor::new(self.raw_data()?))?;
        Ok(data)
    }

    /// Get sub proof from the branch, producing an error if the branch contains
    /// raw data.
    fn sub_proof(&self) -> Result<&GenericMerkleProof, ConvertMerkleProofError> {
        if let MerkleBranch::SubProof(sub_proof) = self {
            Ok(sub_proof)
        } else {
            Err(ConvertMerkleProofError::ExpectedSubProof)
        }
    }

    #[cfg(test)]
    fn make_raw_data<A: crate::common::Serial>(a: &A) -> MerkleBranch {
        MerkleBranch::RawData(crate::common::to_bytes(a))
    }
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
        let mut stack = vec![(Sha256::new(), self.proof.branches.iter())];
        loop {
            // Unwrap is safe, since loop should break before the stack becomes empty.
            let (hasher, iter) = stack.last_mut().unwrap();
            match iter.next() {
                Some(MerkleBranch::RawData(data)) => hasher.update(data),
                Some(MerkleBranch::SubProof(sub_proof)) => {
                    stack.push((Sha256::new(), sub_proof.branches.iter()));
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

impl TryFrom<&GenericMerkleProof> for FinalizationCommittee {
    type Error = ConvertMerkleProofError;

    fn try_from(proof: &GenericMerkleProof) -> Result<Self, Self::Error> {
        type Structure = LfmbtU32<FinalizerInfo>;
        let parsed = Structure::try_from(proof)?;
        Ok(FinalizationCommittee {
            members: parsed.items,
        })
    }
}

impl TryFrom<&GenericMerkleProof> for FinalizerInfo {
    type Error = ConvertMerkleProofError;

    fn try_from(proof: &GenericMerkleProof) -> Result<Self, Self::Error> {
        type Structure = Node2<Data<u64>, Data<BakerAggregationVerifyKey>>;
        let parsed = Structure::try_from(proof)?;
        Ok(FinalizerInfo {
            weight:         parsed.left.value,
            bls_verify_key: parsed.right.value,
        })
    }
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
                current:          committees.left.sub_proof,
                next:             committees.right.sub_proof,
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
type Outcomes = MerkleHash;
// type Outcomes =  SubProof<Node2<TransactionOutcomes, BlockState>>;
// type TransactionOutcomes = MerkleHash;
// type BlockState = MerkleHash;
type LightBlockInfo = SubProof<Node2<BlockHeightInfo, CurrentAndNextFinalizationCommittee>>;
type BlockHeightInfo = MerkleHash;
type CurrentAndNextFinalizationCommittee =
    SubProof<Node2<CurrentFinalizationCommittee, NextFinalizationCommittee>>;
type CurrentFinalizationCommittee = SubProof<FinalizationCommittee>;
type NextFinalizationCommittee = SubProof<FinalizationCommittee>;

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
    #[error("Failed to convert branch {index}:\n{error}")]
    InvalidBranch {
        index: usize,
        error: Box<ConvertMerkleProofError>,
    },
    #[error("Failed to convert LFMBT (u32):\n{error}")]
    InvalidLfbtU32 { error: Box<ConvertMerkleProofError> },
    #[error("Expected raw data.")]
    ExpectedRawData,
    #[error("Expected a sub proof.")]
    ExpectedSubProof,
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
#[derive(Debug, Clone, Copy)]
struct Node2<Left, Right> {
    left:  Left,
    right: Right,
}

/// Merkle branch with subproof.
///
/// This type is a helper for defining the structure of a merkle proof needed
/// for validation and to parse out the content of the proof.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
struct SubProof<A> {
    sub_proof: A,
}

/// Merkle branch with raw data which can be deserialized.
///
/// This type is a helper for defining the structure of a merkle proof needed
/// for validation and to parse out the content of the proof.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
struct Data<A> {
    value: A,
}

/// Merkle proof constructed from a LFMBT hashed list, prefixed with a length
/// using a u32 (BE).
#[derive(Debug, Clone)]
#[repr(transparent)]
struct LfmbtU32<A> {
    items: Vec<A>,
}

impl<'a, L, R> TryFrom<&'a GenericMerkleProof> for Node2<L, R>
where
    L: TryFrom<&'a MerkleBranch, Error = ConvertMerkleProofError>,
    R: TryFrom<&'a MerkleBranch, Error = ConvertMerkleProofError>,
{
    type Error = ConvertMerkleProofError;

    fn try_from(proof: &'a GenericMerkleProof) -> Result<Self, Self::Error> {
        let (left_branch, right_branch) = proof.with_two_branches()?;

        let left =
            L::try_from(left_branch).map_err(|error| ConvertMerkleProofError::InvalidBranch {
                index: 0,
                error: Box::new(error),
            })?;
        let right =
            R::try_from(right_branch).map_err(|error| ConvertMerkleProofError::InvalidBranch {
                index: 1,
                error: Box::new(error),
            })?;
        Ok(Node2 { left, right })
    }
}

impl TryFrom<&MerkleBranch> for MerkleHash {
    type Error = ConvertMerkleProofError;

    fn try_from(value: &MerkleBranch) -> Result<Self, Self::Error> { value.deserial_data() }
}

impl<'a, A> TryFrom<&'a MerkleBranch> for SubProof<A>
where
    A: TryFrom<&'a GenericMerkleProof, Error = ConvertMerkleProofError>,
{
    type Error = ConvertMerkleProofError;

    fn try_from(value: &'a MerkleBranch) -> Result<Self, Self::Error> {
        let MerkleBranch::SubProof(sub_proof) = value else {
            return Err(ConvertMerkleProofError::ExpectedSubProof);
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

    fn try_from(branch: &MerkleBranch) -> Result<Self, Self::Error> {
        let value = branch.deserial_data()?;
        Ok(Self { value })
    }
}

impl<'a, A> TryFrom<&'a GenericMerkleProof> for LfmbtU32<A>
where
    A: TryFrom<&'a GenericMerkleProof, Error = ConvertMerkleProofError>,
{
    type Error = ConvertMerkleProofError;

    fn try_from(proof: &'a GenericMerkleProof) -> Result<Self, Self::Error> {
        let (size_branch, values_branch) = proof.with_two_branches()?;

        let size: u32 =
            size_branch
                .deserial_data()
                .map_err(|err| ConvertMerkleProofError::InvalidLfbtU32 {
                    error: Box::new(err),
                })?;

        let mut items = Vec::new();
        let mut stack = vec![(size, values_branch)];
        while let Some((size, branch)) = stack.pop() {
            if size == 0 {
                // Ensure the branch contains a hash in this case.
                let _: MerkleHash = branch.deserial_data().map_err(|err| {
                    ConvertMerkleProofError::InvalidLfbtU32 {
                        error: Box::new(err),
                    }
                })?;
            } else if size == 1 {
                let item_proof =
                    branch
                        .sub_proof()
                        .map_err(|err| ConvertMerkleProofError::InvalidLfbtU32 {
                            error: Box::new(err),
                        })?;
                let item = A::try_from(item_proof)?;
                items.push(item);
            } else {
                let (left_branch, right_branch) = branch
                    .sub_proof()
                    .map_err(|err| ConvertMerkleProofError::InvalidLfbtU32 {
                        error: Box::new(err),
                    })?
                    .with_two_branches()
                    .map_err(|err| ConvertMerkleProofError::InvalidLfbtU32 {
                        error: Box::new(err),
                    })?;

                let left_size = lower_power_of_two(size);
                let right_size = size - left_size;

                // Notice we push the right size first and left last here, this is to ensure the
                // next in the loop is the left branch, thus traversing the tree in left most
                // depth first. This is nescessary to ensure the right order of the items.
                stack.push((right_size, right_branch));
                stack.push((left_size, left_branch));
            }
        }
        Ok(Self { items })
    }
}

/// Compute the power of two which is one lower than the one needed for
/// representing the provided value.
fn lower_power_of_two(value: u32) -> u32 {
    if let Some(power) = value.checked_next_power_of_two() {
        power - 1
    } else {
        32
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
        let proof = ProtocolVersionMerkleProof::new(GenericMerkleProof::new(vec![
            RawData(to_bytes(&actual_protocol_version)),
            RawData([0u8; 32].to_vec()),
        ]));

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
        let proof = LightBlockCommitteeMerkleProof::new(GenericMerkleProof::new(vec![
            RawData(to_bytes(&actual_protocol_version)),
            SubProof(GenericMerkleProof::new(vec![
                // HeaderQuasi
                RawData([0u8; 32].to_vec()), // Header
                SubProof(GenericMerkleProof::new(vec![
                    // Quasi
                    RawData([0u8; 32].to_vec()), // Metadata
                    SubProof(GenericMerkleProof::new(vec![
                        // BlockData
                        RawData([0u8; 32].to_vec()), // Transactions
                        SubProof(GenericMerkleProof::new(vec![
                            // BlockResult
                            RawData([0u8; 32].to_vec()), // Outcomes
                            SubProof(GenericMerkleProof::new(vec![
                                // LightBlockInfo
                                RawData([0u8; 32].to_vec()), // BlockHeightInfo
                                SubProof(GenericMerkleProof::new(vec![
                                    // CurrentAndNextFinalizationCommittee
                                    SubProof(GenericMerkleProof::new(vec![
                                        MerkleBranch::make_raw_data(&0u32), // Tree length
                                        RawData([0u8; 32].to_vec()),        // Empty tree hash
                                    ])),
                                    SubProof(GenericMerkleProof::new(vec![
                                        MerkleBranch::make_raw_data(&0u32), // Tree length
                                        RawData([0u8; 32].to_vec()),        // Empty tree hash
                                    ])),
                                ])),
                            ])),
                        ])),
                    ])),
                ])),
            ])),
        ]));

        println!("{}", proof.compute_block_hash());

        let expected = "3bd669908f5f8f5051495d0b8d2e5f544d2d61c726da976f4c2d952a6503ccf6"
            .parse()
            .expect("Failed to parse block hash");

        let proof_content = proof
            .verify(expected)
            .map_err(|err| err.to_string())
            .expect("Unable to verify proof.");

        assert_eq!(
            proof_content.protocol_version, actual_protocol_version,
            "Mismatching protocol version."
        )
    }
}
