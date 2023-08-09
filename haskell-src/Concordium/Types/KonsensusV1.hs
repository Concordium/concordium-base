-- |Types that are relevant only for endpoints exposed in ConsensusV1.
module Concordium.Types.KonsensusV1 where

import qualified Data.ByteString as BS

import qualified Concordium.Crypto.BlsSignature as Bls
import Concordium.Crypto.FFIHelpers
import qualified Concordium.Crypto.SHA256 as Hash
import Concordium.Types

-- | A quorum certificate, to be formed when enough finalizers have signed the same 'QuorumSignatureMessage'.
data QuorumCertificate = QuorumCertificate
    { -- |Hash of the block this certificate refers to.
      qcBlock :: !BlockHash,
      -- |Round of the block this certificate refers to.
      qcRound :: !Round,
      -- |Epoch of the block this certificate refers to.
      qcEpoch :: !Epoch,
      -- |Aggregate signature on the 'QuorumSignatureMessage' with the block hash 'qcBlock'.
      qcAggregateSignature :: !Bls.Signature,
      -- |The set of finalizers whose signature is in 'qcAggregateSignature'.
      qcSignatories :: ![BakerId]
    }
    deriving (Eq, Show)

-- |The finalizers (identified by their 'BakerId's)
-- that signed off for in the @frRound@.
data FinalizerRound = FinalizerRound
    { -- |The round.
      frRound :: !Round,
      -- |The finalizers who signed off in the round.
      frFinalizers :: ![BakerId]
    }
    deriving (Eq, Show)

data TimeoutCertificate = TimeoutCertificate
    { -- |The round that has timed-out.
      tcRound :: !Round,
      -- |The minimum epoch for which we include signatures.
      tcMinEpoch :: !Epoch,
      -- |The rounds for which finalizers have their best QCs in the epoch 'tcMinEpoch'.
      tcFinalizerQCRoundsFirstEpoch :: ![FinalizerRound],
      -- |The rounds for which finalizers have their best QCs in the epoch @tcMinEpoch + 1@.
      tcFinalizerQCRoundsSecondEpoch :: ![FinalizerRound],
      -- |Aggregate of the finalizers' 'TimeoutSignature's on the round and QC round.
      tcAggregateSignature :: !Bls.Signature
    }
    deriving (Eq, Show)

-- |Get the 'BS.ByteString' of the provided 'Bls.Signature'.
blsSignatureBytes :: Bls.Signature -> BS.ByteString
blsSignatureBytes (Bls.Signature sigPtr) = toBytesHelper Bls.toBytesSignature sigPtr

-- |The epoch finalization entry is the proof required in order to
-- advance to a new epoch.
data EpochFinalizationEntry = EpochFinalizationEntry
    { -- |The qc that is finalized by the successor qc.
      efeFinalizedQC :: !QuorumCertificate,
      -- |The qc that finalizes @efeFinalizedQC@.
      efeSuccessorQC :: !QuorumCertificate,
      -- |A proof that the successor qc points to a block
      -- which is an immediate successor of the block that
      -- @efeFinalizedQC@ points to.
      efeSuccessorProof :: !Hash.Hash
    }

-- |Block certificates for a block in 'ConsensusV1'.
data BlockCertificates = BlockCertificates
    { -- |Quorum certificate for the block.
      -- This is only present if the block is not a genesis block.
      bcQuorumCertificate :: !(Maybe QuorumCertificate),
      -- |Timeout certificate for the block.
      -- Present if the round prior to the round of the block
      -- timed out.
      bcTimeoutCertificate :: !(Maybe TimeoutCertificate),
      -- |Epoch finalization entry for the block.
      -- Present if the block is the first block in an epoch,
      -- hence concludes the prior epoch.
      bcEpochFinalizationEntry :: !(Maybe EpochFinalizationEntry)
    }
