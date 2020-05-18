{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE TemplateHaskell #-}
module Concordium.Types.Transactions where

import Data.Time.Clock
import Data.Time.Clock.POSIX
import Control.Exception
import Control.Monad
import Data.Aeson.TH
import Data.Aeson(FromJSON, ToJSON)
import qualified Data.ByteString as BS
import qualified Data.Serialize as S
import qualified Data.HashMap.Strict as HM
import qualified Data.HashSet as HS
import qualified Data.Set as Set
import qualified Data.Map.Strict as Map
import Lens.Micro.Platform
import Lens.Micro.Internal
import Concordium.Utils

import Data.List
import qualified Concordium.Crypto.SHA256 as H
import Concordium.Crypto.SignatureScheme as SigScheme

import qualified Data.Vector as Vec
import Data.Word

import Concordium.Types
import Concordium.Types.Utils
import Concordium.ID.Types
import Concordium.Types.HashableTo
import Concordium.Types.Execution

-- |A signature is an association list of index of the key, and the actual signature.
-- The index is relative to the account address, and the indices should be distinct.
-- The maximum length of the list is 255, and the minimum length is 1.
newtype TransactionSignature = TransactionSignature { tsSignature :: Map.Map KeyIndex Signature }
  deriving (Eq, Show)
  deriving (ToJSON, FromJSON) via (Map.Map KeyIndex Signature)
-- |Get the number of actual signatures contained in a 'TransactionSignature'.
getTransactionNumSigs :: TransactionSignature -> Int
getTransactionNumSigs = length . tsSignature


-- |NB: Relies on the scheme and signature serialization to be sensibly defined
-- as specified on the wiki!
instance S.Serialize TransactionSignature where
  put TransactionSignature{..} = do
    S.putWord8 (fromIntegral (length tsSignature))
    forM_ (Map.toList tsSignature) $ \(idx, sig) -> S.put idx <> S.put sig
  get = do
    len <- S.getWord8
    when (len == 0) $ fail "Need at least one signature."
    -- it is fine to redefine signatures during serialization (if there are multiple with the same key index).
    -- this cannot harm validity
    TransactionSignature . Map.fromList <$> replicateM (fromIntegral len) (S.getTwoOf S.get S.get)

-- |Size of the signature in bytes.
-- Should be kept up to date with the serialize instance.
signatureSize :: TransactionSignature -> Int
signatureSize TransactionSignature{..} =
    1 -- length
    + length tsSignature -- key indices
    + foldl' (\acc (_, sig) -> acc + signatureSerializedSize sig) 0 (Map.toList tsSignature) -- signatures

type TransactionTime = Word64

-- |Get time in seconds since the unix epoch.
getTransactionTime :: IO TransactionTime
getTransactionTime = utcTimeToTransactionTime <$> getCurrentTime

utcTimeToTransactionTime :: UTCTime -> TransactionTime
utcTimeToTransactionTime = floor . utcTimeToPOSIXSeconds

-- | Data common to all transaction types.
--
--  * @SPEC: <$DOCS/Transactions#transaction-header>
data TransactionHeader = TransactionHeader {
    -- |Sender account.
    thSender :: AccountAddress,
    -- |Account nonce.
    thNonce :: !Nonce,
    -- |Amount of energy dedicated for the execution of this transaction.
    thEnergyAmount :: !Energy,
    -- |Size of the payload in bytes.
    thPayloadSize :: PayloadSize,
    -- |Absolute expiration time after which transaction will not be executed
    -- TODO In the future, transaction will not be executed but added to a block and charged NRG
    thExpiry :: TransactionExpiryTime
    } deriving (Show)

-- | The size of a serialized transaction header in bytes.
transactionHeaderSize :: Word64
transactionHeaderSize =
  32 -- AccountAddress (FBS 32)
  + 8 -- Nonce (Word64)
  + 8 -- Energy (Word64)
  + 4 -- PayloadSize (Word32)
  + 8 -- TransactionExpiryTime (Word64)

-- | Get the size of serialized transactions header and payload in bytes.
getTransactionHeaderPayloadSize :: TransactionHeader -> Word64
getTransactionHeaderPayloadSize h = fromIntegral (thPayloadSize h) + transactionHeaderSize

$(deriveJSON defaultOptions{fieldLabelModifier = firstLower . drop 2} ''TransactionHeader)

-- |Eq instance ignores derived fields.
instance Eq TransactionHeader where
  th1 == th2 = thNonce th1 == thNonce th2 &&
               thEnergyAmount th1 == thEnergyAmount th2 &&
               thPayloadSize th1 == thPayloadSize th2 &&
               thExpiry th1 == thExpiry th2

-- * @SPEC: <$DOCS/Transactions#transaction-header-serialization>
instance S.Serialize TransactionHeader where
  put TransactionHeader{..} =
      S.put thSender <>
      S.put thNonce <>
      S.put thEnergyAmount <>
      S.put thPayloadSize <>
      S.put thExpiry

  get = do
    thSender <- S.get
    thNonce <- S.get
    thEnergyAmount <- S.get
    thPayloadSize <- S.get
    thExpiry <- S.get
    return $! TransactionHeader{..}

-- |Transaction without the metadata.
--
-- * @SPEC: <$DOCS/Transactions#serialization-format-transactions>
data BareTransaction = BareTransaction{
  btrSignature :: !TransactionSignature,
  btrHeader :: !TransactionHeader,
  btrPayload :: !EncodedPayload
  } deriving(Eq, Show)

-- |Serialization of transactions
--
-- * @SPEC: <$DOCS/Transactions#serialization-format-transactions>
instance S.Serialize BareTransaction where
  put BareTransaction{..} =
    S.put btrSignature <>
    S.put btrHeader <>
    putPayload btrPayload

  get = do
    btrSignature <- S.get
    btrHeader <- S.get
    btrPayload <- getPayload (thPayloadSize btrHeader)
    return $! BareTransaction{..}

fromBareTransaction :: TransactionTime -> BareTransaction -> Transaction
fromBareTransaction wmdArrivalTime wmdData@BareTransaction{..} =
  let txBodyBytes = S.runPut (S.put btrHeader <> putPayload btrPayload)
      wmdHash = H.hash txBodyBytes
      wmdSize = BS.length txBodyBytes + BS.length (S.encode btrSignature)
  in WithMetadata{..}

data WithMetadata value = WithMetadata {
  wmdData :: !value,
  -- |Size of the data in bytes, derived field.
  wmdSize :: !Int,
  -- |Hash of the transaction. Derived from the first field.
  wmdHash :: !TransactionHash,
  -- |Arrival time of the transaction.
  wmdArrivalTime :: !TransactionTime
  } deriving(Show, Functor)

-- Serialize instance which writes out everything including the metadata.
instance S.Serialize value => S.Serialize (WithMetadata value) where
  put WithMetadata{..} =
    S.put wmdData <>
    S.putWord64be (fromIntegral wmdSize) <>
    S.put wmdHash <>
    S.put wmdArrivalTime

  get = do
    wmdData <- S.get
    wmdSize <- fromIntegral <$> S.getWord64be
    wmdHash <- S.get
    wmdArrivalTime <- S.get
    return WithMetadata{..}

metaDataSize :: Int
metaDataSize = H.digestSize + 8 + 8

-- |Block item metadata.
class BIMetadata a where
  biSize :: a -> Int
  biHash :: a -> TransactionHash
  biArrivalTime :: a -> TransactionTime

instance BIMetadata (WithMetadata value) where
  {-# INLINE biSize #-}
  biSize = wmdSize
  {-# INLINE biHash #-}
  biHash = wmdHash
  {-# INLINE biArrivalTime #-}
  biArrivalTime = wmdArrivalTime

-- |Eq instance based on Hash comparison
-- FIXME: Possibly we want to be defensive and check true equality in case hashes are equal.
instance Eq (WithMetadata value) where
  {-# INLINE (==) #-}
  x == y = wmdHash x == wmdHash y

-- |The Ord instance does comparison only on hashes.
instance Ord (WithMetadata value) where
  compare t1 t2 = compare (wmdHash t1) (wmdHash t2)

instance HashableTo H.Hash (WithMetadata value) where
  {-# INLINE getHash #-}
  getHash x = wmdHash x

type Transaction = WithMetadata BareTransaction
type CredentialDeploymentWithMeta = WithMetadata CredentialDeploymentInformation

fromCDI :: TransactionTime -> CredentialDeploymentInformation -> CredentialDeploymentWithMeta
fromCDI wmdArrivalTime wmdData =
  let cdiBytes = S.encode wmdData
      wmdSize = BS.length cdiBytes
      wmdHash = H.hash cdiBytes
  in WithMetadata{..}

-- |Data that can go onto a block.
data BareBlockItem =
  NormalTransaction {
    biTransaction :: !BareTransaction
  }
  | CredentialDeployment {
      biCred :: !CredentialDeploymentInformation
  } deriving(Eq, Show)

instance HashableTo H.Hash BareBlockItem where
  getHash NormalTransaction{..} = transactionHash biTransaction
  getHash CredentialDeployment{..} = H.hash (S.encode biCred)

type BlockItem = WithMetadata BareBlockItem

instance S.Serialize BareBlockItem  where
  put NormalTransaction{..} = S.putWord8 0 <> S.put biTransaction
  put CredentialDeployment{..} = S.putWord8 1 <> S.put biCred

  get =
    S.getWord8 >>= \case
    0 -> NormalTransaction <$> S.get
    1 -> CredentialDeployment <$> S.get
    _ -> fail "Unknown bare block item."

instance ToPut BareBlockItem where
  {-# INLINE toPut #-}
  toPut = S.put

-- |Size of the block item when full serialized (including metadata).
blockItemSize :: BlockItem -> Int
blockItemSize bi = metaDataSize + biSize bi

getCDWM :: TransactionTime -> S.Get CredentialDeploymentWithMeta
getCDWM time = do
    start <- S.bytesRead
    (wmdData, end) <- S.lookAhead $ do
      cdi <- S.get
      end <- S.bytesRead
      return (cdi, end)
    let wmdSize = end - start
    bytes <- S.getByteString wmdSize
    let wmdHash = H.hash bytes
    return WithMetadata{wmdArrivalTime=time,..}

-- |Get reconstructing metadata.
getBlockItem :: Word64 -- ^Timestamp of when the item arrived.
             -> S.Get BlockItem
getBlockItem time =
    S.getWord8 >>= \case
      0 -> fmap NormalTransaction <$> getUnverifiedTransaction time
      1 -> fmap CredentialDeployment <$> getCDWM time
      _ -> fail "Block item must be either normal transaction or credential deployment."

-- |Class which is one part of serialize
class ToPut a where
  toPut :: a -> S.Put

-- |When writing to bytes ignore the metadata.
instance ToPut value => ToPut (WithMetadata value) where
  {-# INLINE toPut #-}
  toPut = toPut . wmdData

-- |Serialize without metadata.
instance ToPut BareTransaction where
  {-# INLINE toPut #-}
  toPut = S.put

-- |Deserialize a transaction, but don't check it's signature.
--
-- * @SPEC: <$DOCS/Transactions#serialization-format-transactions>
getUnverifiedTransaction :: TransactionTime -> S.Get Transaction
getUnverifiedTransaction wmdArrivalTime = do
  sigStart <- S.bytesRead
  btrSignature <- S.get
  sigEnd <- S.bytesRead
  -- we use lookahead to deserialize the transaction without consuming the input.
  -- after that we read the bytes we just deserialized for further processing.
  (btrHeader, btrPayload, bodySize) <- S.lookAhead $! do
    start <- S.bytesRead
    trHeader <- S.get
    trPayload <- getPayload (thPayloadSize trHeader)
    end <- S.bytesRead
    return (trHeader, trPayload, end - start)
  txBytes <- S.getBytes bodySize
  let wmdHash = H.hash txBytes
  let sigSize = sigEnd - sigStart
  let wmdSize = bodySize + sigSize
  return WithMetadata{wmdData=BareTransaction{..},..}

-- |Make a transaction out of minimal data needed.
-- This computes the derived fields, in particular the hash of the transaction.
makeTransaction :: TransactionTime -> TransactionSignature -> TransactionHeader -> EncodedPayload -> Transaction
makeTransaction wmdArrivalTime btrSignature btrHeader btrPayload =
    let txBodyBytes = S.runPut $ S.put btrHeader <> putPayload btrPayload
        -- transaction hash only refers to the body, not the signature of the transaction
        wmdHash = H.hash txBodyBytes
        wmdSize = BS.length txBodyBytes + BS.length (S.encode btrSignature)
        wmdData = BareTransaction{..}
    in WithMetadata{..}

-- |Sign a transaction with the given header and body, using the given keypair.
-- This assumes that there is only one key on the account, and that is with index 0.
--
-- * @SPEC: <$DOCS/Transactions#transaction-signature>
signTransactionSingle :: KeyPair -> TransactionHeader -> EncodedPayload -> BareTransaction
signTransactionSingle kp = signTransaction [(0, kp)]

-- |Sign a transaction with the given header and body, using the given keypairs.
-- The function does not sanity checking that the keys are valid, or that the
-- indices are distint.
--
-- * @SPEC: <$DOCS/Transactions#transaction-signature>
signTransaction :: [(KeyIndex, KeyPair)] -> TransactionHeader -> EncodedPayload -> BareTransaction
signTransaction keys btrHeader btrPayload =
  let body = S.runPut (S.put btrHeader <> putPayload btrPayload)
      -- only sign the hash of the transaction
      bodyHash = H.hashToByteString (H.hash body)
      tsSignature = Map.fromList $ map (\(idx, key) -> (idx, SigScheme.sign key bodyHash)) keys
      btrSignature = TransactionSignature{..}
  in BareTransaction{..}

-- |Verify that the given transaction was signed by the required number of keys.
--
-- * @SPEC: <$DOCS/Transactions#transaction-signature>
verifyTransaction :: TransactionData msg => AccountKeys -> msg -> Bool
verifyTransaction keys tx =
  let bodyHash = H.hashToByteString (transactionHash tx)
      TransactionSignature sigs = transactionSignature tx
      keysCheck = foldl' (\b (idx, sig) -> b && maybe False (\vfKey -> SigScheme.verify vfKey bodyHash sig) (getAccountKey idx keys)) True (Map.toList sigs)
      numSigs = length sigs
      threshold = akThreshold keys
  in numSigs <= 255 && fromIntegral numSigs >= threshold && keysCheck

-- |The 'TransactionData' class abstracts away from the particular data
-- structure. It makes it possible to unify operations on 'Transaction' as well
-- as other types providing the same data (such as partially serialized
-- transactions).
class TransactionData t where
    transactionHeader :: t -> TransactionHeader
    transactionSender :: t -> AccountAddress
    transactionNonce :: t -> Nonce
    transactionGasAmount :: t -> Energy
    transactionPayload :: t -> EncodedPayload
    transactionSignature :: t -> TransactionSignature
    transactionHash :: t -> H.Hash
    transactionSize :: t -> Int

instance TransactionData BareTransaction where
    transactionHeader = btrHeader
    transactionSender = thSender . btrHeader
    transactionNonce = thNonce . btrHeader
    transactionGasAmount = thEnergyAmount . btrHeader
    transactionPayload = btrPayload
    transactionSignature = btrSignature
    transactionHash t = H.hash (S.runPut $ S.put (btrHeader t) <> putPayload (btrPayload t))
    transactionSize t = BS.length serialized
      where serialized = S.encode t

instance TransactionData Transaction where
    transactionHeader = btrHeader . wmdData
    transactionSender = thSender . btrHeader . wmdData
    transactionNonce = thNonce . btrHeader . wmdData
    transactionGasAmount = thEnergyAmount . btrHeader . wmdData
    transactionPayload = btrPayload . wmdData
    transactionSignature = btrSignature . wmdData
    transactionHash = getHash
    transactionSize = wmdSize

data AccountNonFinalizedTransactions = AccountNonFinalizedTransactions {
    -- |Non-finalized transactions (for an account) indexed by nonce.
    _anftMap :: Map.Map Nonce (Set.Set Transaction),
    -- |The next available nonce at the last finalized block.
    -- 'anftMap' should only contain nonces that are at least 'anftNextNonce'.
    _anftNextNonce :: Nonce
} deriving (Eq)
makeLenses ''AccountNonFinalizedTransactions

-- |Empty (no pending transactions) account non-finalized table starting at the
-- minimal nonce.
emptyANFT :: AccountNonFinalizedTransactions
emptyANFT = emptyANFTWithNonce minNonce

-- |An account non-finalized table with no pending transactions and given
-- starting nonce.
emptyANFTWithNonce :: Nonce -> AccountNonFinalizedTransactions
emptyANFTWithNonce n = AccountNonFinalizedTransactions Map.empty n

-- |Result of a transaction is block dependent.
data TransactionStatus =
  -- |Transaction is received, but no outcomes from any blocks are known
  -- although the transaction might be known to be in some blocks. The Slot is the
  -- largest slot of a block the transaction is in.
  Received { _tsSlot :: !Slot }
  -- |Transaction is committed in a number of blocks. '_tsSlot' is the maximal slot.
  -- 'tsResults' is always a non-empty map and global state must maintain the invariant
  -- that if a block hash @bh@ is in the 'tsResults' map then
  --
  -- * @bh@ is a live block
  -- * we have blockState for the block available
  -- * if @tsResults(bh) = i@ then the transaction is the relevant transaction is the i-th transaction in the block
  --   (where we start counting from 0)
  | Committed {_tsSlot :: !Slot,
               tsResults :: !(HM.HashMap BlockHash TransactionIndex)
              }
  -- |Transaction is finalized in a given block with a specific outcome.
  -- NB: With the current implementation a transaction can appear in at most one finalized block.
  -- When that part is reworked so that branches are not pruned we will likely rework this.
  | Finalized {
      _tsSlot :: !Slot,
      tsBlockHash :: !BlockHash,
      tsFinResult :: !TransactionIndex
      }
  deriving(Eq, Show)
makeLenses ''TransactionStatus

instance S.Serialize TransactionStatus where
  put Received{..} = do
    S.putWord8 0
    S.put _tsSlot
  put Committed{..} = do
    S.putWord8 1
    S.put _tsSlot
    S.putWord32be $ (fromIntegral (HM.size tsResults))
    forM_ (HM.toList tsResults) $ \(h, i) -> S.put h <> S.put i
  put Finalized{..} = do
    S.putWord8 2
    S.put _tsSlot
    S.put tsBlockHash
    S.put tsFinResult

  get = do
    tag <- S.getWord8
    case tag of
      0 -> do
        _tsSlot <- S.get
        return Received{..}
      1 -> do
        _tsSlot <- S.get
        len <- S.getWord32be
        tsResults <- HM.fromList <$> replicateM (fromIntegral len) (do
                                           k <- S.get
                                           v <- S.get
                                           return (k, v))
        return $ Committed{..}
      2 -> do
        _tsSlot <- S.get
        tsBlockHash <- S.get
        tsFinResult <- S.get
        return $ Finalized{..}
      _ -> fail $ "Unknown transaction status variant: " ++ show tag

-- |Add a transaction result. This function assumes the transaction is not finalized yet.
-- If the transaction is already finalized the function will return the original status.
addResult :: BlockHash -> Slot -> TransactionIndex -> TransactionStatus -> TransactionStatus
addResult bh slot vr = \case
  Committed{_tsSlot=currentSlot, tsResults=currentResults} -> Committed{_tsSlot = max slot currentSlot, tsResults = HM.insert bh vr currentResults}
  Received{_tsSlot=currentSlot} -> Committed{_tsSlot = max slot currentSlot, tsResults = HM.singleton bh vr}
  s@Finalized{} -> s

-- |Remove a transaction result for a given block. This can happen when a block
-- is removed from the block tree because it is not a successor of the last
-- finalized block.
-- This function will only have effect if the transaction status is 'Committed' and
-- the given block hash is in the table of outcomes.
markDeadResult :: BlockHash -> TransactionStatus -> TransactionStatus
markDeadResult bh Committed{..} =
  let newResults = HM.delete bh tsResults
  in if HM.null newResults then Received{..} else Committed{tsResults=newResults,..}
markDeadResult _ ts = ts

updateSlot :: Slot -> TransactionStatus -> TransactionStatus
updateSlot _ ts@Finalized{} = ts
updateSlot s ts = ts { _tsSlot = s}

initialStatus :: Slot -> TransactionStatus
initialStatus = Received

{-# INLINE getTransactionIndex #-}
-- |Get the outcome of the transaction in a particular block, and whether it is finalized.
getTransactionIndex :: BlockHash -> TransactionStatus -> Maybe (Bool, TransactionIndex)
getTransactionIndex bh = \case
  Committed{..} -> (False, ) <$> HM.lookup bh tsResults
  Finalized{..} -> if bh == tsBlockHash then Just (True, tsFinResult) else Nothing
  _ -> Nothing

-- |A pending transaction table records whether transactions are pending after
-- execution of a particular block.  For each account address, if there are
-- pending transactions, then it should be in the map with value @(nextNonce, highNonce)@,
-- where @nextNonce@ is the next nonce for the account address (i.e. 1+nonce of last executed transaction),
-- and @highNonce@ is the highest nonce known for a transaction associated with that account.
-- @highNonce@ should always be at least @nextNonce@ (otherwise, what transaction is pending?).
-- If an account has no pending transactions, then it should not be in the map.
data PendingTransactionTable = PTT {
  _pttWithSender :: !(HM.HashMap AccountAddress (Nonce, Nonce)),
  -- |Pending credentials. We only store the hash because updating the
  -- pending table would otherwise be more costly with the current setup.
  _pttDeployCredential :: HS.HashSet TransactionHash
  } deriving(Eq, Show)

makeLenses ''PendingTransactionTable

emptyPendingTransactionTable :: PendingTransactionTable
emptyPendingTransactionTable = PTT HM.empty HS.empty

-- |Insert an additional element in the pending transaction table.
-- If the account does not yet exist create it.
-- NB: This only updates the pending table, and does not ensure that invariants elsewhere are maintained.
-- PRECONDITION: the next nonce should be less than or equal to the transaction nonce.
extendPendingTransactionTable :: TransactionData t => Nonce -> t -> PendingTransactionTable -> PendingTransactionTable
extendPendingTransactionTable nextNonce tx PTT{..} = assert (nextNonce <= nonce) $ let v = HM.alter f sender _pttWithSender in PTT{_pttWithSender = v, ..}
  where
        f Nothing = Just (nextNonce, nonce)
        f (Just (l, u)) = Just (l, max u nonce)
        nonce = transactionNonce tx
        sender = transactionSender tx

-- |Insert an additional element in the pending transaction table.
-- Does nothing if the next nonce is greater than the transaction nonce.
-- If the account does not yet exist create it.
-- NB: This only updates the pending table, and does not ensure that invariants elsewhere are maintained.
checkedExtendPendingTransactionTable :: TransactionData t => Nonce -> t -> PendingTransactionTable -> PendingTransactionTable
checkedExtendPendingTransactionTable nextNonce tx pt =
  if nextNonce > nonce then pt else
    pt & pttWithSender . at' (transactionSender tx) %~ \case Nothing -> Just (nextNonce, nonce)
                                                             Just (l, u) -> Just (l, max u nonce)
  where nonce = transactionNonce tx

-- |Extend the pending transaction table with a credential hash.
extendPendingTransactionTable' :: TransactionHash -> PendingTransactionTable -> PendingTransactionTable
extendPendingTransactionTable' hash pt =
  pt & pttDeployCredential %~ HS.insert hash

forwardPTT :: [BlockItem] -> PendingTransactionTable -> PendingTransactionTable
forwardPTT trs ptt0 = foldl forward1 ptt0 trs
    where
        forward1 :: PendingTransactionTable -> BlockItem -> PendingTransactionTable
        forward1 ptt WithMetadata{wmdData=NormalTransaction tr} = ptt & pttWithSender . at' (transactionSender tr) %~ upd
            where
                upd Nothing = error "forwardPTT : forwarding transaction that is not pending"
                upd (Just (low, high)) =
                    assert (low == transactionNonce tr) $ assert (low <= high) $
                        if low == high then Nothing else Just (low+1,high)
        forward1 ptt WithMetadata{wmdData=CredentialDeployment{..},..} = ptt & pttDeployCredential %~ upd
            where
              upd ps = case HS.member wmdHash ps of
                         False -> error "forwardPTT: forwarding a block item that is not pending."
                         True -> HS.delete wmdHash ps

reversePTT :: [BlockItem] -> PendingTransactionTable -> PendingTransactionTable
reversePTT trs ptt0 = foldr reverse1 ptt0 trs
    where
        reverse1 :: BlockItem -> PendingTransactionTable -> PendingTransactionTable
        reverse1 WithMetadata{wmdData=NormalTransaction tr} = pttWithSender . at' (transactionSender tr) %~ upd
            where
                upd Nothing = Just (transactionNonce tr, transactionNonce tr)
                upd (Just (low, high)) =
                        assert (low == transactionNonce tr + 1) $
                        Just (low-1,high)
        reverse1 WithMetadata{wmdData=CredentialDeployment{..},..} = pttDeployCredential %~ upd
            where
              upd ps = assert (not (HS.member wmdHash ps)) $ HS.insert wmdHash ps

-- |Record special transactions as well for logging purposes.
data SpecialTransactionOutcome =
  BakingReward {
    stoBakerId :: !BakerId,
    stoBakerAccount :: !AccountAddress,
    stoRewardAmount :: !Amount
    }
  deriving(Show, Eq)

$(deriveJSON defaultOptions{fieldLabelModifier = firstLower . drop 3} ''SpecialTransactionOutcome)

instance S.Serialize SpecialTransactionOutcome where
    put (BakingReward bid addr amt) = S.put bid <> S.put addr <> S.put amt
    get = BakingReward <$> S.get <*> S.get <*> S.get

-- |Outcomes of transactions. The vector of outcomes must have the same size as the
-- number of transactions in the block, and ordered in the same way.
data TransactionOutcomes = TransactionOutcomes {
    outcomeValues :: !(Vec.Vector TransactionSummary),
    _outcomeSpecial :: ![SpecialTransactionOutcome]
}

makeLenses ''TransactionOutcomes

instance Show TransactionOutcomes where
    show (TransactionOutcomes v s) = "Normal transactions: " ++ show (Vec.toList v) ++ ", special transactions: " ++ show s

-- FIXME: More consistent serialization.
instance S.Serialize TransactionOutcomes where
    put TransactionOutcomes{..} = do
        S.put (Vec.toList outcomeValues)
        S.put _outcomeSpecial
    get = TransactionOutcomes <$> (Vec.fromList <$> S.get) <*> S.get

emptyTransactionOutcomes :: TransactionOutcomes
emptyTransactionOutcomes = TransactionOutcomes Vec.empty []

transactionOutcomesFromList :: [TransactionSummary] -> TransactionOutcomes
transactionOutcomesFromList l =
  let outcomeValues = Vec.fromList l
      _outcomeSpecial = []
  in TransactionOutcomes{..}

type instance Index TransactionOutcomes = TransactionIndex
type instance IxValue TransactionOutcomes = TransactionSummary

instance Ixed TransactionOutcomes where
  ix idx f outcomes@TransactionOutcomes{..} =
    let x = fromIntegral idx
    in if x >= length outcomeValues then pure outcomes
       else ix x f outcomeValues <&> (\ov -> TransactionOutcomes{outcomeValues=ov,..})
