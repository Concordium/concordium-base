-- |Types that are relevant only for ConsensusV1.
-- Common for types defined here is that they are exposed through the node API,
-- otherwise definitions should be defined in the node.
module Concordium.Types.KonsensusV1 where

import Control.Monad
import Data.Bits
import qualified Data.ByteString as BS
import Data.List (foldl')
import qualified Data.Map.Strict as Map
import Data.Serialize
import Data.Word
import Numeric.Natural

import qualified Concordium.Crypto.BlsSignature as Bls
import Concordium.Crypto.FFIHelpers
import qualified Concordium.Crypto.SHA256 as Hash
import Concordium.Types
import Concordium.Types.HashableTo
import Concordium.Utils.Serialization

-- |Signature by a finalizer on a 'QuorumSignatureMessage', or an aggregation of signatures on a
-- common message.
newtype QuorumSignature = QuorumSignature {theQuorumSignature :: Bls.Signature}
    deriving (Eq, Ord, Show, Serialize, Semigroup, Monoid)

quorumSignatureBytes :: QuorumSignature -> BS.ByteString
quorumSignatureBytes (QuorumSignature (Bls.Signature sigPtr)) = toBytesHelper Bls.toBytesSignature sigPtr

-- |Index of a finalizer in the finalization committee vector.
newtype FinalizerIndex = FinalizerIndex {theFinalizerIndex :: Word32}
    deriving (Eq, Ord, Show, Enum, Bounded, Serialize)

-- |A set of 'FinalizerIndex'es.
-- This is represented as a bit vector, where the bit @i@ is set iff the finalizer index @i@ is
-- in the set.
newtype FinalizerSet = FinalizerSet {theFinalizerSet :: Natural}
    deriving (Eq)

-- |Convert a 'FinalizerSet' to a list of 'FinalizerIndex', in ascending order.
finalizerList :: FinalizerSet -> [FinalizerIndex]
finalizerList = unroll 0 . theFinalizerSet
  where
    unroll _ 0 = []
    unroll i x
        | testBit x 0 = FinalizerIndex i : r
        | otherwise = r
      where
        r = unroll (i + 1) (shiftR x 1)

-- |The empty set of finalizers
emptyFinalizerSet :: FinalizerSet
emptyFinalizerSet = FinalizerSet 0

-- |Add a finalizer to a 'FinalizerSet'.
addFinalizer :: FinalizerSet -> FinalizerIndex -> FinalizerSet
addFinalizer (FinalizerSet setOfFinalizers) (FinalizerIndex i) = FinalizerSet $ setBit setOfFinalizers (fromIntegral i)

-- |Test whether a given finalizer index is present in a finalizer set.
memberFinalizerSet :: FinalizerIndex -> FinalizerSet -> Bool
memberFinalizerSet (FinalizerIndex fi) (FinalizerSet setOfFinalizers) =
    testBit setOfFinalizers (fromIntegral fi)

-- |Convert a list of [FinalizerIndex] to a 'FinalizerSet'.
finalizerSet :: [FinalizerIndex] -> FinalizerSet
finalizerSet = foldl' addFinalizer (FinalizerSet 0)

-- |Test if the first finalizer set is a subset of the second.
subsetFinalizerSet :: FinalizerSet -> FinalizerSet -> Bool
subsetFinalizerSet (FinalizerSet s1) (FinalizerSet s2) = s1 .&. s2 == s1

instance Show FinalizerSet where
    show = show . finalizerList

-- |The serialization of a 'FinalizerSet' consists of a length (Word32, big-endian), followed by
-- that many bytes, the first of which (if any) must be non-zero. These bytes encode the bit-vector
-- in big-endian. This enforces that the serialization of a finalizer set is unique.
instance Serialize FinalizerSet where
    put fs = do
        let (byteCount, putBytes) = unroll 0 (return ()) (theFinalizerSet fs)
        putWord32be byteCount
        putBytes
      where
        unroll :: Word32 -> Put -> Natural -> (Word32, Put)
        -- Compute the number of bytes and construct a 'Put' that serializes in big-endian.
        -- We do this by adding the low order byte to the accumulated 'Put' (at the start)
        -- and recursing with the bitvector shifted right 8 bits.
        unroll bc cont 0 = (bc, cont)
        unroll bc cont n = unroll (bc + 1) (putWord8 (fromIntegral n) >> cont) (shiftR n 8)
    get = label "FinalizerSet" $ do
        byteCount <- getWord32be
        FinalizerSet <$> roll1 byteCount
      where
        roll1 0 = return 0
        roll1 bc = do
            b <- getWord8
            when (b == 0) $ fail "unexpected 0 byte"
            roll (bc - 1) (fromIntegral b)
        roll 0 n = return n
        roll bc n = do
            b <- getWord8
            roll (bc - 1) (shiftL n 8 .|. fromIntegral b)

-- | A quorum certificate, to be formed when enough finalizers have signed the same 'QuorumSignatureMessage'.
data QuorumCertificate = QuorumCertificate
    { -- |Hash of the block this certificate refers to.
      qcBlock :: !BlockHash,
      -- |Round of the block this certificate refers to.
      qcRound :: !Round,
      -- |Epoch of the block this certificate refers to.
      qcEpoch :: !Epoch,
      -- |Aggregate signature on the 'QuorumSignatureMessage' with the block hash 'qcBlock'.
      qcAggregateSignature :: !QuorumSignature,
      -- |The set of finalizers whose signature is in 'qcAggregateSignature'.
      qcSignatories :: !FinalizerSet
    }
    deriving (Eq, Show)

-- |For generating a genesis quorum certificate with empty signature and empty finalizer set.
genesisQuorumCertificate :: BlockHash -> QuorumCertificate
genesisQuorumCertificate genesisHash = QuorumCertificate genesisHash 0 0 mempty $ FinalizerSet 0

instance Serialize QuorumCertificate where
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

instance HashableTo Hash.Hash QuorumCertificate where
    getHash = Hash.hash . encode

-- |Data structure recording which finalizers have quorum certificates for which rounds.
--
-- Invariant: @Map.size theFinalizerRounds <= fromIntegral (maxBound :: Word32)@.
newtype FinalizerRounds = FinalizerRounds {theFinalizerRounds :: Map.Map Round FinalizerSet}
    deriving (Eq, Show)

instance Serialize FinalizerRounds where
    put (FinalizerRounds fr) = do
        putWord32be $ fromIntegral $ Map.size fr
        putSafeSizedMapOf put put fr
    get = do
        count <- getWord32be
        FinalizerRounds <$> getSafeSizedMapOf count get get

-- |Unpack a 'FinalizerRounds' as a list of rounds and finalizer sets, in ascending order of
-- round.
finalizerRoundsList :: FinalizerRounds -> [(Round, FinalizerSet)]
finalizerRoundsList = Map.toAscList . theFinalizerRounds

-- |Signature by a finalizer on a 'TimeoutSignatureMessage', or an aggregation of such signatures.
newtype TimeoutSignature = TimeoutSignature {theTimeoutSignature :: Bls.Signature}
    deriving (Eq, Ord, Show, Serialize, Semigroup, Monoid)

timeoutSignatureBytes :: TimeoutSignature -> BS.ByteString
timeoutSignatureBytes (TimeoutSignature (Bls.Signature sigPtr)) = toBytesHelper Bls.toBytesSignature sigPtr

-- |A timeout certificate aggregates signatures on timeout messages for the same round.
-- Finalizers may have different QC rounds.
--
-- Invariant: If 'tcFinalizerQCRoundsSecondEpoch' is not empty, then so is
-- 'tcFinalizerQCRoundsFirstEpoch'.
data TimeoutCertificate = TimeoutCertificate
    { -- |The round that has timed-out.
      tcRound :: !Round,
      -- |The minimum epoch for which we include signatures.
      tcMinEpoch :: !Epoch,
      -- |The rounds for which finalizers have their best QCs in the epoch 'tcMinEpoch'.
      tcFinalizerQCRoundsFirstEpoch :: !FinalizerRounds,
      -- |The rounds for which finalizers have their best QCs in the epoch @tcMinEpoch + 1@.
      tcFinalizerQCRoundsSecondEpoch :: !FinalizerRounds,
      -- |Aggregate of the finalizers' 'TimeoutSignature's on the round and QC round.
      tcAggregateSignature :: !TimeoutSignature
    }
    deriving (Eq, Show)

instance Serialize TimeoutCertificate where
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
tcIsSingleEpoch :: TimeoutCertificate -> Bool
tcIsSingleEpoch = null . theFinalizerRounds . tcFinalizerQCRoundsSecondEpoch

-- |The maximum epoch for which a 'TimeoutCertificate' includes signatures.
-- (This will be 'tcMinEpoch' in the case that the certificate contains no signatures.)
tcMaxEpoch :: TimeoutCertificate -> Epoch
tcMaxEpoch tc
    | tcIsSingleEpoch tc = tcMinEpoch tc
    | otherwise = tcMinEpoch tc + 1

-- |The maximum round for which a 'TimeoutCertificate' includes signatures.
-- (This will be 0 if the certificate contains no signatures.)
tcMaxRound :: TimeoutCertificate -> Round
tcMaxRound tc =
    max
        (maxRound (tcFinalizerQCRoundsFirstEpoch tc))
        (maxRound (tcFinalizerQCRoundsSecondEpoch tc))
  where
    maxRound (FinalizerRounds r) = maybe 0 fst (Map.lookupMax r)
