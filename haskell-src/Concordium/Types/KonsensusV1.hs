-- |Types that are relevant only for ConsensusV1.
-- Common for types defined here is that they are exposed through the node API,
-- otherwise definitions should be defined in the node.
module Concordium.Types.KonsensusV1 where

import Control.Monad
import qualified Data.Map.Strict as Map
import Data.Serialize

import qualified Concordium.Crypto.BlsSignature as Bls
import qualified Concordium.Crypto.SHA256 as Hash
import Concordium.Types
import Concordium.Types.HashableTo
import Concordium.Utils.Serialization

-- |Signature by a finalizer on a 'QuorumSignatureMessage', or an aggregation of signatures on a
-- common message.
newtype QuorumSignature = QuorumSignature {theQuorumSignature :: Bls.Signature}
    deriving (Eq, Ord, Show, Serialize, Semigroup, Monoid)

-- | A quorum certificate, to be formed when enough finalizers have signed the same 'QuorumSignatureMessage'.
data QuorumCertificate' finalizerSet = QuorumCertificate
    { -- |Hash of the block this certificate refers to.
      qcBlock :: !BlockHash,
      -- |Round of the block this certificate refers to.
      qcRound :: !Round,
      -- |Epoch of the block this certificate refers to.
      qcEpoch :: !Epoch,
      -- |Aggregate signature on the 'QuorumSignatureMessage' with the block hash 'qcBlock'.
      qcAggregateSignature :: !QuorumSignature,
      -- |The set of finalizers whose signature is in 'qcAggregateSignature'.
      qcSignatories :: !finalizerSet
    }
    deriving (Eq, Show)

class EmptyFinalizerSet set where
    finalizerSetEmpty :: set

-- |For generating a genesis quorum certificate with empty signature and empty finalizer set.
genesisQuorumCertificate :: EmptyFinalizerSet finalizerSet => BlockHash -> QuorumCertificate' finalizerSet
genesisQuorumCertificate genesisHash = QuorumCertificate genesisHash 0 0 mempty finalizerSetEmpty

instance Serialize finalizerSet => Serialize (QuorumCertificate' finalizerSet) where
    put QuorumCertificate{..} = do
        put qcBlock
        put qcRound
        put qcEpoch
        put qcAggregateSignature
        put qcSignatories
    get = do
        qcBlock <- get
        qcRound <- get
        qcEpoch <- get
        qcAggregateSignature <- get
        qcSignatories <- get
        return QuorumCertificate{..}

instance Serialize finalizerSet => HashableTo Hash.Hash (QuorumCertificate' finalizerSet) where
    getHash = Hash.hash . encode

-- |Data structure recording which finalizers have quorum certificates for which rounds.
--
-- Invariant: @Map.size theFinalizerRounds <= fromIntegral (maxBound :: Word32)@.
newtype FinalizerRounds' finalizerSet = FinalizerRounds {theFinalizerRounds :: Map.Map Round finalizerSet}
    deriving (Eq, Show)

instance Serialize finalizerSet => Serialize (FinalizerRounds' finalizerSet) where
    put (FinalizerRounds fr) = do
        putWord32be $ fromIntegral $ Map.size fr
        putSafeSizedMapOf put put fr
    get = do
        count <- getWord32be
        FinalizerRounds <$> getSafeSizedMapOf count get get

-- |Unpack a 'FinalizerRounds' as a list of rounds and finalizer sets, in ascending order of
-- round.
finalizerRoundsList :: FinalizerRounds' finalizerSet -> [(Round, finalizerSet)]
finalizerRoundsList = Map.toAscList . theFinalizerRounds

-- |Signature by a finalizer on a 'TimeoutSignatureMessage', or an aggregation of such signatures.
newtype TimeoutSignature = TimeoutSignature {theTimeoutSignature :: Bls.Signature}
    deriving (Eq, Ord, Show, Serialize, Semigroup, Monoid)

-- |A timeout certificate aggregates signatures on timeout messages for the same round.
-- Finalizers may have different QC rounds.
--
-- Invariant: If 'tcFinalizerQCRoundsSecondEpoch' is not empty, then so is
-- 'tcFinalizerQCRoundsFirstEpoch'.
data TimeoutCertificate' finalizerSet = TimeoutCertificate
    { -- |The round that has timed-out.
      tcRound :: !Round,
      -- |The minimum epoch for which we include signatures.
      tcMinEpoch :: !Epoch,
      -- |The rounds for which finalizers have their best QCs in the epoch 'tcMinEpoch'.
      tcFinalizerQCRoundsFirstEpoch :: !(FinalizerRounds' finalizerSet),
      -- |The rounds for which finalizers have their best QCs in the epoch @tcMinEpoch + 1@.
      tcFinalizerQCRoundsSecondEpoch :: !(FinalizerRounds' finalizerSet),
      -- |Aggregate of the finalizers' 'TimeoutSignature's on the round and QC round.
      tcAggregateSignature :: !TimeoutSignature
    }
    deriving (Eq, Show)

instance Serialize finalizerSet => Serialize (TimeoutCertificate' finalizerSet) where
    put TimeoutCertificate{..} = do
        put tcRound
        put tcMinEpoch
        put tcAggregateSignature
        put tcFinalizerQCRoundsFirstEpoch
        put tcFinalizerQCRoundsSecondEpoch
    get = label "TimeoutCertificate" $ do
        tcRound <- get
        tcMinEpoch <- get
        tcAggregateSignature <- get
        tcFinalizerQCRoundsFirstEpoch <- get
        tcFinalizerQCRoundsSecondEpoch <- get
        when (null (theFinalizerRounds tcFinalizerQCRoundsFirstEpoch)) $
            unless (null (theFinalizerRounds tcFinalizerQCRoundsSecondEpoch)) $
                fail "tcMinEpoch is not the minimum epoch"
        return TimeoutCertificate{..}

-- |Returns 'True' if and only if the finalizers are exclusively in 'tcFinalizerQCRoundsFirstEpoch'
-- in a 'TimeoutCertificate'.
tcIsSingleEpoch :: TimeoutCertificate' finalizerSet -> Bool
tcIsSingleEpoch = null . theFinalizerRounds . tcFinalizerQCRoundsSecondEpoch

-- |The maximum epoch for which a 'TimeoutCertificate' includes signatures.
-- (This will be 'tcMinEpoch' in the case that the certificate contains no signatures.)
tcMaxEpoch :: TimeoutCertificate' finalizerSet -> Epoch
tcMaxEpoch tc
    | tcIsSingleEpoch tc = tcMinEpoch tc
    | otherwise = tcMinEpoch tc + 1

-- |The maximum round for which a 'TimeoutCertificate' includes signatures.
-- (This will be 0 if the certificate contains no signatures.)
tcMaxRound :: TimeoutCertificate' finalizerSet -> Round
tcMaxRound tc =
    max
        (maxRound (tcFinalizerQCRoundsFirstEpoch tc))
        (maxRound (tcFinalizerQCRoundsSecondEpoch tc))
  where
    maxRound (FinalizerRounds r) = maybe 0 fst (Map.lookupMax r)
