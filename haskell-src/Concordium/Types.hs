{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TemplateHaskell #-}
{-# OPTIONS_GHC -Wall #-}
-- |Basic blockchain types.
module Concordium.Types (
  -- * Cost units
  module Concordium.Common.Amount,
  Energy(..),
  AmountDelta(..),
  amountToDelta,
  amountDiff,
  applyAmountDelta,
  -- ** Exchange rates
  ExchangeRate(..),
  EnergyRate,
  computeEnergyRate,

  -- * Time units
  Duration(..),
  durationToNominalDiffTime,
  getTransactionTime,
  Timestamp(..),
  timestampToUTCTime,
  utcTimeToTimestamp,
  timestampToSeconds,
  addDuration,
  TransactionTime(..),
  TransactionExpiryTime,
  utcTimeToTransactionTime,
  transactionTimeToTimestamp,
  transactionExpired,
  isTimestampBefore,

  -- * Accounts
  SchemeId,
  AccountAddress(..),
  AccountEncryptedAmount(..),
  initialAccountEncryptedAmount,
  incomingEncryptedAmounts,
  getIncomingAmountsList,
  aggregatedAmount,
  selfAmount,
  startIndex,
  Nonce(..),
  minNonce,
  AccountVerificationKey,

  -- * Smart contracts
  ModuleRef(..),
  ContractIndex(..),
  ContractSubindex(..),
  ContractAddress(..),
  -- ** Chain metadata
  ChainMetadata(..),
  encodeChainMeta,

  -- * Addresses
  Address(..),

  -- * Baking
  ElectionDifficulty(..),
  makeElectionDifficulty,
  isValidElectionDifficulty,
  LotteryPower,
  BakerAggregationProof,
  BakerAggregationPrivateKey,
  BakerAggregationVerifyKey,
  BakerElectionPrivateKey,
  BakerElectionVerifyKey,
  BakerSignPrivateKey,
  BakerSignVerifyKey,
  LeadershipElectionNonce,
  BakerId(..),
  -- ** Block elements
  BlockNonce,
  BlockSignature,
  BlockProof,
  TransactionOutcomesHashV0(..),
  TransactionOutcomesHash,
  StateHashV0(..),
  StateHash,
  BlockHashV0(..),
  BlockHash,
  BlockHeight(..),
  Slot(..),
  EpochLength,
  genesisSlot,
  -- ** Transactions
  EncodedPayload(..),
  PayloadSize(..),
  putEncodedPayload,
  getEncodedPayload,
  payloadSize,
  TransactionSignHashV0(..),
  TransactionSignHash,
  transactionSignHashToByteString,
  TransactionHashV0(..),
  TransactionHash,

  -- * Finalization
  VoterId,
  VoterPower(..),
  VoterSignKey,
  VoterVerificationKey,
  VoterVRFPublicKey,
  VoterAggregationPrivateKey,
  VoterAggregationVerifyKey,
  FinalizationCommitteeSize,

  -- * Hashing
  Hashed(..),
  unhashed,
  makeHashed) where

import GHC.Generics
import Data.Data (Typeable, Data)

import Concordium.Common.Amount
import qualified Concordium.Crypto.BlockSignature as Sig
import Concordium.Crypto.EncryptedTransfers
import qualified Concordium.Crypto.SHA256 as Hash
import qualified Concordium.Crypto.VRF as VRF
import qualified Concordium.Crypto.BlsSignature as Bls
import Concordium.ID.Types
import Concordium.Crypto.SignatureScheme (SchemeId)
import Concordium.Types.HashableTo

import Control.Exception (assert)
import Control.Monad

import Data.Hashable (Hashable)
import Data.Word
import qualified Data.Sequence as Seq
import Data.ByteString.Char8 (ByteString)
import qualified Data.ByteString.Short as BSS
import Data.Bits
import Data.Ratio
import Data.Foldable

import Data.Aeson as AE
import Data.Aeson.TH

import Data.Time
import Data.Time.Clock.POSIX

import qualified Data.Serialize as S
import qualified Data.Serialize.Put as P
import qualified Data.Serialize.Get as G
import Database.Persist.Class
import Database.Persist.Sql

import Lens.Micro.Platform

data Hashed a = Hashed {_unhashed :: a, _hashed :: Hash.Hash}

instance HashableTo Hash.Hash (Hashed a) where
    getHash = _hashed

-- |This lens allows for getting and setting the value inside a Hashed structure.
-- If a value is updated the new hash is recomputed automatically.
unhashed :: (HashableTo Hash.Hash a) => Lens' (Hashed a) a
unhashed f h = makeHashed <$> f (_unhashed h)

makeHashed :: HashableTo Hash.Hash a => a -> Hashed a
makeHashed v = Hashed v (getHash v)

instance Eq (Hashed a) where
    a == b = _hashed a == _hashed b

instance Ord a => Ord (Hashed a) where
    compare a b = compare (_unhashed a) (_unhashed b)

instance (Show a) => Show (Hashed a) where
    show = show . _hashed

-- * Types related to bakers.
newtype BakerId = BakerId Word64
    deriving (Eq, Ord, Num, Enum, Bounded, Real, Hashable, Read, Show, Integral, FromJSON, ToJSON, Bits) via Word64

instance S.Serialize BakerId where
    get = BakerId <$> G.getWord64be
    put (BakerId i) = P.putWord64be i

type LeadershipElectionNonce = Hash.Hash
type BakerSignVerifyKey = Sig.VerifyKey
type BakerSignPrivateKey = Sig.KeyPair
type BakerElectionVerifyKey = VRF.PublicKey
type BakerElectionPrivateKey = VRF.KeyPair
type BakerAggregationVerifyKey = Bls.PublicKey
type BakerAggregationPrivateKey = Bls.SecretKey
type BakerAggregationProof = Bls.Proof
type LotteryPower = Ratio Amount

-- | The type of the birk parameter "election difficulty".
-- The value must be in the range [0,1).
newtype ElectionDifficulty = ElectionDifficulty {electionDifficulty :: Double}
  deriving newtype (Eq, Ord, Show, ToJSON)

instance S.Serialize ElectionDifficulty where
    get = do
        d <- ElectionDifficulty <$> S.get
        if isValidElectionDifficulty d then
          return d
        else
          fail "Invalid election difficulty (must be in the range [0,1))."
    put = S.put . electionDifficulty

instance HashableTo Hash.Hash ElectionDifficulty where
    getHash e = Hash.hash $ S.encode e

instance Monad m => MHashableTo m Hash.Hash ElectionDifficulty

instance FromJSON ElectionDifficulty where
    parseJSON v = do
        d <- ElectionDifficulty <$> parseJSON v
        if isValidElectionDifficulty d then
          return d
        else
          fail "Invalid election difficulty (must be in the range [0,1))."

-- |Convert a 'Double' to an 'ElectionDifficulty'. This requires
-- the value to be in the range @[0,1)@.
makeElectionDifficulty :: Double -> ElectionDifficulty
makeElectionDifficulty d = assert (d >= 0 && d < 1) $ ElectionDifficulty d

-- |Verify that an 'ElectionDifficulty' is valid, that is, in the range
-- @[0,1)@. This is checked by 'makeElectionDifficulty' as well as the
-- 'Serialize' and 'FromJSON' instances of 'ElectionDifficulty'.
isValidElectionDifficulty :: ElectionDifficulty -> Bool
isValidElectionDifficulty (ElectionDifficulty d) = d >= 0 && d < 1

type FinalizationCommitteeSize = Word32
-- |An exchange rate (e.g. uGTU/Euro or Euro/Energy).
-- Infinity and zero are disallowed.
newtype ExchangeRate = ExchangeRate (Ratio Word64)
    deriving newtype (Eq, Ord, Num, Real, Show, Fractional, ToJSON)

-- |We require the serialization to be in reduced form to ensure
-- that an exchange rate has a unique serialized representation.
instance S.Serialize ExchangeRate where
    put (ExchangeRate r) = assert (numerator r /= 0 && denominator r /= 0) $
        S.put (numerator r) >> S.put (denominator r)
    get = do
        num <- S.get
        den <- S.get
        if num == 0 || den == 0 || gcd num den /= 1 then
            fail "Invalid exchange rate"
        else
            return $ ExchangeRate (num % den)

instance FromJSON ExchangeRate where
    parseJSON v = do
        r <- parseJSON v
        if numerator r == 0 || denominator r == 0 then
            fail "Invalid exchange rate"
        else
            return $ ExchangeRate r

instance HashableTo Hash.Hash ExchangeRate where
    getHash = Hash.hash . S.encode

instance Monad m => MHashableTo m Hash.Hash ExchangeRate

-- |Energy to GTU conversion rate in microGTU per Energy.
type EnergyRate = Rational

-- |Compute the exchange rate of microGTU per Energy from the
-- rate of microGTU per Euro and the rate of Euros per Energy.
computeEnergyRate
  :: ExchangeRate
  -- ^microGTU per Euro
  -> ExchangeRate
  -- ^Euros per Energy
  -> EnergyRate
computeEnergyRate microGTUPerEuro euroPerEnergy = toRational microGTUPerEuro * toRational euroPerEnergy

type VoterId = Word64
type VoterVerificationKey = Sig.VerifyKey
type VoterVRFPublicKey = VRF.PublicKey
type VoterAggregationVerifyKey = Bls.PublicKey
type VoterSignKey = Sig.SignKey
type VoterAggregationPrivateKey = Bls.SecretKey
newtype VoterPower = VoterPower AmountUnit
    deriving newtype (Eq, Ord, Num, Enum, Bounded, Real, Show, Integral, S.Serialize)

-- * Blockchain specific types.
-- Eventually these will be replaced by types given by the global store.
-- For now they are placeholders

newtype ContractIndex = ContractIndex { _contractIndex :: Word64 }
    deriving newtype (Eq, Ord, Num, Enum, Bounded, Real, Hashable, Show, Bits, Integral)
    deriving (Typeable, Data)

instance S.Serialize ContractIndex where
    get = ContractIndex <$> G.getWord64be
    put (ContractIndex i) = P.putWord64be i

newtype ContractSubindex = ContractSubindex { _contractSubindex :: Word64 }
    deriving newtype (Eq, Ord, Num, Enum, Bounded, Real, Hashable, Show, Integral)
    deriving (Typeable, Data)

instance S.Serialize ContractSubindex where
    get = ContractSubindex <$> G.getWord64be
    put (ContractSubindex i) = P.putWord64be i

data ContractAddress = ContractAddress { contractIndex :: !ContractIndex
                                       , contractSubindex :: !ContractSubindex}
    deriving(Eq, Ord, Generic, Typeable, Data)

instance FromJSON ContractAddress where
  parseJSON = withObject "ContractAddress" $ \v -> do
    i <- v .: "index"
    j <- v .: "subindex"
    return $ ContractAddress (fromIntegral (i :: Word64)) (fromIntegral (j :: Word64))

instance ToJSON ContractAddress where
  toJSON (ContractAddress i j) =
    object ["index" AE..= (fromIntegral i :: Word64), "subindex" AE..= (fromIntegral j :: Word64)]
  toEncoding (ContractAddress i j) =
    pairs ("index" AE..= (fromIntegral i :: Word64) <> "subindex" AE..= (fromIntegral j :: Word64))

instance Hashable ContractAddress

instance Show ContractAddress where
  show (ContractAddress i v) = "<" ++ show i ++ ", " ++ show v ++ ">"

instance S.Serialize ContractAddress where
  get = ContractAddress <$> S.get <*> S.get
  put (ContractAddress i v) = S.put i <> S.put v

-- |Unique module reference.
newtype ModuleRef = ModuleRef {moduleRef :: Hash.Hash}
    deriving(Eq, Ord, Hashable, Typeable, Data)
    deriving (FromJSON, ToJSON) via Hash.Hash

instance Show ModuleRef where
  show (ModuleRef m) = show m

instance S.Serialize ModuleRef where
  get = ModuleRef <$> S.get
  put (ModuleRef mref) = S.put mref

-- |An address is either a contract or account.
data Address = AddressAccount !AccountAddress
             | AddressContract !ContractAddress
             deriving (Eq)

instance S.Serialize Address where
  get = do
    h <- G.getWord8 -- FIXME: this is inefficient but ok for testing. The size
                    -- of the data should already tell what address it is.
    case h of
      0 -> AddressAccount <$> S.get
      1 -> AddressContract <$> S.get
      _ -> fail "Only two types of addresses are supported."

  put (AddressAccount acc) = P.putWord8 0 <> S.put acc
  put (AddressContract cnt) = P.putWord8 1 <> S.put cnt

instance Show Address where
  show (AddressAccount a) = show a
  show (AddressContract a) = show a

-- | Time in milliseconds since the epoch
newtype Timestamp = Timestamp { tsMillis :: Word64 }
  deriving (Show, Read, Eq, Num, Ord, Real, Enum, S.Serialize, FromJSON, PersistField) via Word64

-- | Time in seconds since the unix epoch
newtype TransactionTime = TransactionTime { ttsSeconds :: Word64 }
    deriving (Show, Read, Eq, Num, Ord, FromJSON, ToJSON, Real, Enum, Integral) via Word64

instance S.Serialize TransactionTime where
  put = P.putWord64be . ttsSeconds
  get = TransactionTime <$> G.getWord64be

-- |Get time in seconds since the unix epoch.
getTransactionTime :: IO TransactionTime
getTransactionTime = utcTimeToTransactionTime <$> getCurrentTime

utcTimeToTransactionTime :: UTCTime -> TransactionTime
utcTimeToTransactionTime = floor . utcTimeToPOSIXSeconds

instance PersistFieldSql Timestamp where
    sqlType _ = SqlInt64

-- | Time duration in milliseconds
newtype Duration = Duration { durationMillis :: Word64 }
  deriving (Show, Read, Eq, Num, Ord, Real, Enum, S.Serialize, FromJSON) via Word64

-- | Convert a 'Timestamp' to a 'UTCTime'
timestampToUTCTime :: Timestamp -> UTCTime
timestampToUTCTime ts = posixSecondsToUTCTime $ fromIntegral (tsMillis ts) / 1000

-- | Covert a 'UTCTime' to a 'Timestamp'.
-- This rounds down to the nearest millisecond.
utcTimeToTimestamp :: UTCTime -> Timestamp
utcTimeToTimestamp = Timestamp . truncate . (*1000) . utcTimeToPOSIXSeconds

-- | Convert a 'Timestamp' to seconds since the epoch, rounding down
timestampToSeconds :: Timestamp -> Word64
timestampToSeconds ts = tsMillis ts `div` 1000

durationToNominalDiffTime :: Duration -> NominalDiffTime
durationToNominalDiffTime dur = fromIntegral (durationMillis dur) / 1000

addDuration :: Timestamp -> Duration -> Timestamp
addDuration (Timestamp ts) (Duration d) = Timestamp (ts + d)

-- | Expiry time of a transaction in seconds since the epoch
type TransactionExpiryTime = TransactionTime

-- | Convert a 'TransactionTime' (seconds since epoch) to a
-- 'Timestamp' (milliseconds since epoch).
transactionTimeToTimestamp :: TransactionTime -> Timestamp
transactionTimeToTimestamp (TransactionTime x) = Timestamp (1000 * x)

-- |Check if a transaction expiry time precedes a given timestamp.
transactionExpired :: TransactionExpiryTime -> Timestamp -> Bool
transactionExpired (TransactionTime x) (Timestamp t) = 1000*x < t

-- |Check if whether the given timestamp is no greater than the end of the day
-- of the given year and month.
isTimestampBefore :: Timestamp -> YearMonth -> Bool
isTimestampBefore ts ym =
    utcTs < utcYearMonthExpiryTs
  where
    utcTs = timestampToUTCTime ts
    utcYearMonthExpiryTs = UTCTime expiryDay 0
      where
        year = toInteger (ymYear ym)
        month = fromIntegral (ymMonth ym)
        expiryYear = if month == 12 then year + 1 else year
        expiryMonth = if month == 12 then 1 else month + 1 -- (month % 12) + 1
        expiryDay = fromGregorian expiryYear expiryMonth 1 -- unchecked, always valid


-- |Type representing a difference between amounts.
newtype AmountDelta = AmountDelta { amountDelta :: Integer }
    deriving (Eq, Ord, Enum, Num, Integral, Real)

amountToDelta :: Amount -> AmountDelta
amountToDelta = fromIntegral

amountDiff :: Amount -> Amount -> AmountDelta
amountDiff amt1 amt2 = fromIntegral amt1 - fromIntegral amt2

applyAmountDelta ::  AmountDelta -> Amount -> Amount
applyAmountDelta del amt =
        assert (amt' >= fromIntegral (minBound :: Amount)) $
        assert (amt' <= fromIntegral (maxBound :: Amount)) $
            fromIntegral amt'
    where
        amt' = fromIntegral amt + del

-- |The type used to count exact execution cost. This cost is then converted to
-- amounts in some way.
newtype Energy = Energy { _energy :: Word64 }
    deriving (Show, Read, Eq, Enum, Ord, Num, Real, Integral, Hashable, Bounded, FromJSON, ToJSON) via Word64

instance S.Serialize Energy where
  get = Energy <$> G.getWord64be
  put (Energy v) = P.putWord64be v

newtype Nonce = Nonce Word64
    deriving (Show, Read, Eq, Ord, Num, Enum, FromJSON, ToJSON) via Word64

instance S.Serialize Nonce where
  put (Nonce w) = P.putWord64be w
  get = Nonce <$> G.getWord64be

minNonce :: Nonce
minNonce = 1

-- * Account encrypted amount.

-- | Encrypted amounts stored on an account.
data AccountEncryptedAmount = AccountEncryptedAmount {
  -- | Encrypted amount that is a result of this accounts' actions.
  -- In particular this list includes the aggregate of
  --
  -- - remaining amounts that result when transfering to public balance
  -- - remaining amounts when transfering to another account
  -- - encrypted amounts that are transfered from public balance
  --
  -- When a transfer is made all of these must always be used.
  _selfAmount :: !EncryptedAmount,
  -- | Starting index for incoming encrypted amounts. If there is an aggregated amount
  -- present, this index is the one for such amount. Otherwise it refers to the first
  -- amount in the list of incoming encrypted amounts.
  _startIndex :: !EncryptedAmountAggIndex,
  -- |If 'Just', the amount that has resulted from aggregating other amounts and the
  -- number of aggregated amounts (must be at least 2 if present).
  _aggregatedAmount :: !(Maybe (EncryptedAmount, Word32)),
  -- | Amounts starting at @startIndex@ (or at @startIndex + 1@ if an aggregated amount is present).
  -- They are assumed to be numbered sequentially.
  -- This list (plus the optionally present aggregated amount) will never contain more than
  -- 'maxNumIncoming' values.
  _incomingEncryptedAmounts :: !(Seq.Seq EncryptedAmount)
} deriving(Eq, Show)

-- | When serializing to a JSON, we will put the aggregated amount if present at the
-- beginning of the `"incomingAmounts"` field.
instance AE.ToJSON AccountEncryptedAmount where
  toJSON AccountEncryptedAmount{..} = AE.object $ [
    "selfAmount" AE..= _selfAmount,
    "startIndex" AE..= _startIndex,
    "incomingAmounts" AE..= case _aggregatedAmount of
                               Nothing -> _incomingEncryptedAmounts
                               Just (e, _) -> e Seq.:<| _incomingEncryptedAmounts
    ] ++ aggregated
    where aggregated = case _aggregatedAmount of
            Nothing -> []
            Just (_, n) -> ["numAggregated" AE..= n]

-- | When deserializing from JSON, if the field `"numAggregated"` is present, we will
-- interpret the first item in the `"incomingAmounts"` list as the aggregated amount.
instance AE.FromJSON AccountEncryptedAmount where
  parseJSON = AE.withObject "AccountEncryptedAmount" $ \obj -> do
    _selfAmount <- obj AE..: "selfAmount"
    _startIndex <- obj AE..: "startIndex"
    incomingEncryptedAmounts <- obj AE..: "incomingAmounts"
    numAggregated <- obj AE..:? "numAggregated"
    (_aggregatedAmount, _incomingEncryptedAmounts) <-
      case numAggregated of
        Nothing -> return (Nothing, incomingEncryptedAmounts)
        Just n | n > 1 -> case incomingEncryptedAmounts of
                           agg Seq.:<| rest ->
                             return (Just (agg, n), rest)
                           _ -> fail "The list of amounts doesn't contain any amounts but it claims some amounts have been aggregated"
               | otherwise -> fail "Cannot have less than 2 amounts aggregated"
    return AccountEncryptedAmount{..}

-- |Initial encrypted amount on a newly created account.
initialAccountEncryptedAmount :: AccountEncryptedAmount
initialAccountEncryptedAmount = AccountEncryptedAmount{
  _selfAmount = mempty,
  _startIndex = 0,
  _incomingEncryptedAmounts = Seq.empty,
  _aggregatedAmount = Nothing
}

instance S.Serialize AccountEncryptedAmount where
  put AccountEncryptedAmount{..} = do
    S.put _selfAmount
    S.put _startIndex
    S.putWord32be (fromIntegral (Seq.length _incomingEncryptedAmounts))
    mapM_ S.put _incomingEncryptedAmounts
    case _aggregatedAmount of
      Nothing -> S.putWord32be 0
      Just (e, n) -> do
        S.putWord32be n
        S.put e

  get = do
    _selfAmount <- S.get
    _startIndex <- S.get
    len <- S.getWord32be
    _incomingEncryptedAmounts <- Seq.fromList <$> replicateM (fromIntegral len) S.get
    mNumAggregated <- S.getWord32be
    case mNumAggregated of
      0 -> return AccountEncryptedAmount{_aggregatedAmount = Nothing,..}
      n | n >= 2 -> do
            e <- S.get
            return AccountEncryptedAmount{_aggregatedAmount = Just (e, n),..}
      _ -> fail "numAggregated must be at least 2, if non-zero."

makeLenses ''AccountEncryptedAmount

-- |Get the list of incoming amounts ordered by index, starting at `_startIndex`.
getIncomingAmountsList :: AccountEncryptedAmount -> [EncryptedAmount]
getIncomingAmountsList AccountEncryptedAmount{..} =
    toList $ case _aggregatedAmount of
               Nothing -> _incomingEncryptedAmounts
               Just (e, _) -> e Seq.:<| _incomingEncryptedAmounts

-- |Size of the transaction payload.
newtype PayloadSize = PayloadSize {thePayloadSize :: Word32}
    deriving (Eq, Show, Ord, Num, Real, Enum, Integral, FromJSON, ToJSON) via Word32

-- |Serialization format as specified
--
-- * @SPEC: <$DOCS/Transactions#transaction-header>
instance S.Serialize PayloadSize where
  put (PayloadSize n) = S.putWord32be n
  get = PayloadSize <$> S.getWord32be

-- |Serialized payload of the transaction
newtype EncodedPayload = EncodedPayload { _spayload :: BSS.ShortByteString }
    deriving(Eq, Show)

-- |There is no corresponding getter (to fit into the Serialize instance) since
-- encoded payload does not encode its own length. See 'getPayload' below.
putEncodedPayload :: P.Putter EncodedPayload
putEncodedPayload = P.putShortByteString . _spayload

-- |Get payload with given length.
getEncodedPayload :: PayloadSize -> G.Get EncodedPayload
getEncodedPayload (PayloadSize n) = EncodedPayload <$> G.getShortByteString (fromIntegral n)

payloadSize :: EncodedPayload -> PayloadSize
payloadSize = fromIntegral . BSS.length . _spayload

-- *Types that are morally part of the consensus, but need to be exposed in
-- other parts of the system as well, e.g., in smart contracts.

newtype Slot = Slot {theSlot :: Word64} deriving (Eq, Ord, Num, Real, Enum, Integral, Show, Read, S.Serialize) via Word64

-- |The slot number of the genesis block (0).
genesisSlot :: Slot
genesisSlot = 0

type EpochLength = Slot

newtype BlockHeight = BlockHeight {theBlockHeight :: Word64}
  deriving (Eq, Ord, Num, Real, Enum, Integral, Read, Show, Hashable, FromJSON, ToJSON, PersistField) via Word64

instance PersistFieldSql BlockHeight where
  sqlType _ = SqlInt64


instance S.Serialize BlockHeight where
  put = S.putWord64be . theBlockHeight
  get = BlockHeight <$> S.getWord64be


-- |Blockchain metadata as needed by contract execution.
data ChainMetadata =
  ChainMetadata { slotNumber :: Slot
                -- |Height of the current block (the block which the transaction is going to be a part of).
                , blockHeight :: BlockHeight
                -- |Height of the last finalized block. NB: Each block has a
                -- pointer to the last finalized block, and this field is the
                -- height of that block. This information is stable with respect
                -- to time. In the future a block between that block and the
                -- current block might become finalized, so the distance
                -- blockHeight - finalizedHeight is an upper bound only.
                , finalizedHeight :: BlockHeight
                -- |Time at the beginning of the slot.
                , slotTime :: Timestamp
                }

-- |Encode chain metadata for passing over FFI. Uses little-endian encoding
-- for integral values since that is what is expected on the other side of FFI.
-- This is deliberately not made into a serialize instance so that it is not accidentally
-- misused, since it differs in endianess from most other network-related serialization.
encodeChainMeta :: ChainMetadata -> ByteString
encodeChainMeta ChainMetadata{..} = S.runPut encoder
  where encoder =
          P.putWord64le (fromIntegral slotNumber) <>
          P.putWord64le (fromIntegral blockHeight) <>
          P.putWord64le (fromIntegral finalizedHeight) <>
          P.putWord64le (tsMillis slotTime)

-- |The hash of a transaction which is then signed.
-- (Naturally, this does not include the transaction signature.)
newtype TransactionSignHashV0 = TransactionSignHashV0 {v0TransactionSignHash :: Hash.Hash}
  deriving newtype (Eq, Ord, Show, S.Serialize, AE.ToJSON, AE.FromJSON, AE.FromJSONKey, AE.ToJSONKey, Read, Hashable)

type TransactionSignHash = TransactionSignHashV0

transactionSignHashToByteString :: TransactionSignHash -> ByteString
transactionSignHashToByteString = Hash.hashToByteString . v0TransactionSignHash

-- |Hash of a transaction including the signature.
-- (For credential deployments, there is no signature.)
newtype TransactionHashV0 = TransactionHashV0 {v0TransactionHash :: Hash.Hash}
  deriving newtype (Eq, Ord, Show, S.Serialize, AE.ToJSON, AE.FromJSON, AE.FromJSONKey, AE.ToJSONKey, Read, Hashable)

type TransactionHash = TransactionHashV0

-- * Types related to blocks
newtype BlockHashV0 = BlockHashV0 {v0BlockHash :: Hash.Hash}
  deriving newtype (Eq, Ord, Show, S.Serialize, AE.ToJSON, AE.FromJSON, AE.FromJSONKey, AE.ToJSONKey, Read, Hashable)

newtype TransactionOutcomesHashV0 = TransactionOutcomesHashV0 {v0TransactionOutcomesHash :: Hash.Hash}
  deriving newtype (Eq, Ord, Show, S.Serialize, AE.ToJSON, AE.FromJSON, AE.FromJSONKey, AE.ToJSONKey, Read, Hashable)

newtype StateHashV0 = StateHashV0 {v0StateHash :: Hash.Hash}
  deriving newtype (Eq, Ord, Show, S.Serialize, AE.ToJSON, AE.FromJSON, AE.FromJSONKey, AE.ToJSONKey, Read, Hashable)



type BlockHash = BlockHashV0
type StateHash = StateHashV0
type TransactionOutcomesHash = TransactionOutcomesHashV0
type BlockProof = VRF.Proof
type BlockSignature = Sig.Signature
type BlockNonce = VRF.Proof



-- Template haskell derivations. At the end to get around staging restrictions.
$(deriveJSON defaultOptions{sumEncoding = TaggedObject{tagFieldName = "type", contentsFieldName = "address"}} ''Address)
