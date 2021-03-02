{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE TemplateHaskell #-}
module Concordium.Types.Transactions where

import Concordium.Common.Version
import Control.Monad
import Data.Aeson.TH
import qualified Data.Sequence as Seq
import Data.Aeson(FromJSON(..), ToJSON(..))
import qualified Data.Aeson as AE
import qualified Data.ByteString as BS
import qualified Data.Serialize as S
import qualified Data.Map.Strict as Map
import Lens.Micro.Platform
import Lens.Micro.Internal
import Concordium.Utils.Serialization

import Data.List (foldl')
import qualified Concordium.Crypto.SHA256 as H
import Concordium.Crypto.SignatureScheme as SigScheme

import qualified Data.Vector as Vec
import Data.Word

import Concordium.Utils
import Concordium.Types
import Concordium.ID.Types
import Concordium.Types.HashableTo
import Concordium.Types.Execution
import Concordium.Types.Updates

-- * Account transactions

-- |Construct a 'TransactionSignHash' from the serialized bytes of
-- an account transaction's header and payload.
transactionSignHashFromBytes :: BS.ByteString -> TransactionSignHashV0
transactionSignHashFromBytes = TransactionSignHashV0 . H.hash

-- |Construct a 'TransactionSignHash' from a 'TransactionHeader' and 'EncodedPayload'.
transactionSignHashFromHeaderPayload :: TransactionHeader -> EncodedPayload -> TransactionSignHashV0
transactionSignHashFromHeaderPayload atrHeader atrPayload = TransactionSignHashV0 $ H.hashLazy $ S.runPutLazy $ S.put atrHeader <> putEncodedPayload atrPayload

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
    forM_ (Map.toAscList tsSignature) $ \(idx, sig) -> S.put idx <> S.put sig
  get = do
    len <- S.getWord8
    when (len == 0) $ fail "Need at least one signature."
    let accumulateSigs accum mlast count
          | count == 0 = return accum
          | otherwise = do
              idx <- S.get
              forM_ mlast $ \lasti -> unless (idx > lasti) $ fail "Signatures are not in canonical order."
              sig <- S.get
              accumulateSigs (Map.insert idx sig accum) (Just idx) (count - 1)
    TransactionSignature <$> accumulateSigs Map.empty Nothing len

-- |Size of the signature in bytes.
-- Should be kept up to date with the serialize instance.
signatureSize :: TransactionSignature -> Int
signatureSize TransactionSignature{..} =
    1 -- length
    + length tsSignature -- key indices
    + foldl' (\acc (_, sig) -> acc + signatureSerializedSize sig) 0 (Map.toList tsSignature) -- signatures

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
    } deriving (Show, Eq)

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

-- |An 'AccountTransaction' is a transaction that originates from
-- a specific account (the sender), and is paid for by the sender.
-- 
-- The representation includes a 'TransactionSignHash' which is
-- the value that is signed. This is derived from the header and
-- payload, and so does not form part of the serialization.
--
-- The payload is stored in serialized form. Deserializing the
-- payload is considered part of the transaction execution.
data AccountTransaction = AccountTransaction {
  -- |Signature
  atrSignature :: !TransactionSignature,
  -- |Header
  atrHeader :: !TransactionHeader,
  -- |Serialized payload
  atrPayload :: !EncodedPayload,
  -- |Hash used for signing
  atrSignHash :: !TransactionSignHashV0
  } deriving(Eq, Show)

-- |Construct an 'AccountTransaction', computing the correct
-- 'TransactionSignHash'.
makeAccountTransaction :: TransactionSignature -> TransactionHeader -> EncodedPayload -> AccountTransaction
makeAccountTransaction atrSignature atrHeader atrPayload = AccountTransaction{..}
  where
    atrSignHash = transactionSignHashFromHeaderPayload atrHeader atrPayload

-- | @SPEC: <$DOCS/Transactions#serialization-format-transactions>
instance S.Serialize AccountTransaction where
  put AccountTransaction{..} =
    S.put atrSignature <>
    S.put atrHeader <>
    putEncodedPayload atrPayload

  get = S.label "account transaction" $ do
    atrSignature <- S.label "signature" S.get
    ((atrHeader, atrPayload), bodyBytes) <- getWithBytes $ do
      atrHeader <- S.label "header" S.get
      atrPayload <- S.label "payload" $ getEncodedPayload (thPayloadSize atrHeader)
      return (atrHeader, atrPayload)
    let atrSignHash = transactionSignHashFromBytes bodyBytes
    return $! AccountTransaction{..}

instance HashableTo TransactionHashV0 AccountTransaction where
  getHash = transactionHashFromBareBlockItem . NormalTransaction
  {-# INLINE getHash #-}

instance HashableTo TransactionSignHashV0 AccountTransaction where
  getHash = atrSignHash

--------------------------
-- * Transaction metadata
--------------------------

-- |Metadata for a block item.
data WithMetadata value = WithMetadata {
  wmdData :: !value,
  -- |Size of the block item in bytes; derived field.
  wmdSize :: !Int,
  -- |Hash of the transaction. Derived from the first field.
  wmdHash :: !TransactionHash,
  -- |Arrival time of the transaction.
  wmdArrivalTime :: !TransactionTime
  } deriving(Show)

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

instance HashableTo TransactionHash (WithMetadata value) where
  {-# INLINE getHash #-}
  getHash = wmdHash

type Transaction = WithMetadata AccountTransaction
type CredentialDeploymentWithMeta = WithMetadata AccountCredentialWithProofs

addMetadata :: (a -> BareBlockItem) -> TransactionTime -> a -> WithMetadata a
addMetadata f time a = WithMetadata {
    wmdData = a,
    wmdSize = BS.length bs,
    wmdHash = transactionHashFromBytes bs,
    wmdArrivalTime = time
  }
  where
    bs = S.encode (f a)

fromAccountTransaction :: TransactionTime -> AccountTransaction -> Transaction
fromAccountTransaction wmdArrivalTime wmdData =
  let wmdHash = getHash wmdData
      wmdSize = BS.length (S.encode wmdData) + 1
  in WithMetadata{..}

fromCDI :: TransactionTime -> CredentialDeploymentInformation -> CredentialDeploymentWithMeta
fromCDI wmdArrivalTime wmdData =
  let cdiBytes = S.encode wmdData
      wmdSize = BS.length cdiBytes + 2 -- + 2 for the two tags
      wmdHash = getHash (CredentialDeployment (NormalACWP wmdData))
  in WithMetadata{wmdData = NormalACWP wmdData,..}

fromICDI :: TransactionTime -> InitialCredentialDeploymentInfo -> CredentialDeploymentWithMeta
fromICDI wmdArrivalTime wmdData =
  let cdiBytes = S.encode wmdData
      wmdSize = BS.length cdiBytes + 2 -- + 2 for the two tags
      wmdHash = getHash (CredentialDeployment (InitialACWP wmdData))
  in WithMetadata{wmdData = InitialACWP wmdData,..}

-----------------
-- * Block items
-----------------

data BlockItemKind
  = AccountTransactionKind
  | CredentialDeploymentKind
  | UpdateInstructionKind
  deriving (Eq, Ord, Show)

instance S.Serialize BlockItemKind where
  put AccountTransactionKind = S.putWord8 0
  put CredentialDeploymentKind = S.putWord8 1
  put UpdateInstructionKind = S.putWord8 2
  {-# INLINE put #-}
  get = S.getWord8 >>= \case
    0 -> return AccountTransactionKind
    1 -> return CredentialDeploymentKind
    2 -> return UpdateInstructionKind
    _ -> fail "unknown block item kind"
  {-# INLINE get #-}

-- |Data that can go onto a block.
data BareBlockItem =
  NormalTransaction {
    biTransaction :: !AccountTransaction
  }
  | CredentialDeployment {
      biCred :: !AccountCredentialWithProofs
  }
  | ChainUpdate {
    biUpdate :: !UpdateInstruction
  }
  deriving(Eq, Show)

instance HashableTo TransactionHash BareBlockItem where
  getHash = transactionHashFromBareBlockItem

type BlockItem = WithMetadata BareBlockItem

instance S.Serialize BareBlockItem  where
  put NormalTransaction{..} = S.put AccountTransactionKind <> S.put biTransaction
  put CredentialDeployment{..} = S.put CredentialDeploymentKind <> S.put biCred
  put ChainUpdate{..} = S.put UpdateInstructionKind <> S.put biUpdate

  get = S.label "BareBlockItem" $
    S.get >>= \case
    AccountTransactionKind -> NormalTransaction <$> S.get
    CredentialDeploymentKind -> CredentialDeployment <$> S.get
    UpdateInstructionKind -> ChainUpdate <$> S.get

-- |Embed a transaction as a block item.
normalTransaction :: Transaction -> BlockItem
-- the +1 is for the additional tag.
normalTransaction WithMetadata{..} = WithMetadata{wmdData = NormalTransaction wmdData, wmdSize = wmdSize + 1,..}

credentialDeployment :: WithMetadata AccountCredentialWithProofs -> BlockItem
credentialDeployment WithMetadata{..} = WithMetadata{wmdData = CredentialDeployment wmdData, wmdSize = wmdSize + 1,..}

chainUpdate :: WithMetadata UpdateInstruction -> BlockItem
chainUpdate WithMetadata{..} = WithMetadata{wmdData = ChainUpdate wmdData, wmdSize = wmdSize + 1,..}

-- |Serialize a block item according to V0 format, without the metadata.
putBlockItemV0 :: BlockItem -> S.Put
putBlockItemV0 = putBareBlockItemV0 . wmdData

-- |Serialize a bare block item according to the V0 format, without the metadata.
putBareBlockItemV0 :: BareBlockItem -> S.Put
putBareBlockItemV0 = S.put

---------------------------------
-- * 'TransactionHash' functions
---------------------------------

-- |Construct a hash from a serialized block item.
transactionHashFromBytes :: BS.ByteString -> TransactionHashV0
transactionHashFromBytes = TransactionHashV0 . H.hash

transactionHashFromBareBlockItem :: BareBlockItem -> TransactionHashV0
transactionHashFromBareBlockItem = transactionHashFromBytes . S.encode

-------------------
-- * Serialization
-------------------

-- |Try to parse a versioned block item, stripping the version, and
-- reconstructing the block item metadata from the raw data.
-- The parsing format is determined by the version.
--
-- The only supported version at the moment is version 0.
--
-- * @SPEC: <$DOCS/Versioning#binary-format>
-- * @SPEC: <$DOCS/Versioning>
getExactVersionedBlockItem :: TransactionTime
                           -- ^Timestamp for when the item is received, used to
                           -- construct the metadata.
                           -> S.Get BlockItem
getExactVersionedBlockItem time = do
    version <- S.get :: S.Get Version
    case version of
      0 -> getBlockItemV0 time
      _ -> fail $ "Unsupported block item version " ++ show version ++ "."

-- |Get a block item according to V0 format, reconstructing metadata.
--
-- * @SPEC: <$DOCS/Transactions#v0-format>
-- * @SPEC: <$DOCS/Versioning>
getBlockItemV0 :: TransactionTime -- ^Timestamp of when the item arrived.
             -> S.Get BlockItem
getBlockItemV0 time = S.label "getBlockItemV0" $ do
    (bbi, bytes) <- getWithBytes S.get
    return WithMetadata{
        wmdData = bbi,
        wmdSize = BS.length bytes,
        wmdHash = transactionHashFromBytes bytes,
        wmdArrivalTime = time
      }

-- |Serialize a block item with version according to the V0 format, prepending the version.
putVersionedBlockItemV0 :: BlockItem -> S.Put
putVersionedBlockItemV0 bi = putVersion 0 <> putBlockItemV0 bi

-- |Serialize a bare block item with version according to the V0 format, prepending the version.
putVersionedBareBlockItemV0 :: BareBlockItem -> S.Put
putVersionedBareBlockItemV0 bi = putVersion 0 <> putBareBlockItemV0 bi

----------------
-- * Signatures
----------------

-- |Sign a transaction with the given header and body, using the given keypair.
-- This assumes that there is only one key on the account, and that is with index 0.
--
-- * @SPEC: <$DOCS/Transactions#transaction-signature>
signTransactionSingle :: KeyPair -> TransactionHeader -> EncodedPayload -> AccountTransaction
signTransactionSingle kp = signTransaction [(0, kp)]

-- |Sign a transaction with the given header and body, using the given keypairs.
-- The function does not sanity checking that the keys are valid, or that the
-- indices are distint.
--
-- * @SPEC: <$DOCS/Transactions#transaction-signature>
signTransaction :: [(KeyIndex, KeyPair)] -> TransactionHeader -> EncodedPayload -> AccountTransaction
signTransaction keys atrHeader atrPayload =
  let 
      atrSignHash = transactionSignHashFromHeaderPayload atrHeader atrPayload
      -- only sign the hash of the transaction
      bodyHash = transactionSignHashToByteString atrSignHash
      tsSignature = Map.fromList $ map (\(idx, key) -> (idx, SigScheme.sign key bodyHash)) keys
      atrSignature = TransactionSignature{..}
  in AccountTransaction{..}

-- |Verify that the given transaction was signed by the required number of keys.
--
-- * @SPEC: <$DOCS/Transactions#transaction-signature>
verifyTransaction :: TransactionData msg => AccountKeys -> msg -> Bool
verifyTransaction keys tx =
  let bodyHash = transactionSignHashToByteString (transactionSignHash tx)
      TransactionSignature sigs = transactionSignature tx
      keysCheck = foldl' (\b (idx, sig) -> b && maybe False (\vfKey -> SigScheme.verify vfKey bodyHash sig) (getAccountKey idx keys)) True (Map.toList sigs)
      numSigs = length sigs
      threshold = akThreshold keys
  in numSigs <= 255 && fromIntegral numSigs >= threshold && keysCheck

-----------------------------------
-- * 'TransactionData' abstraction
-----------------------------------

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
    transactionSignHash :: t -> TransactionSignHash
    transactionHash :: t -> TransactionHash

transactionSize :: Transaction -> Int
transactionSize = wmdSize

instance TransactionData AccountTransaction where
    transactionHeader = atrHeader
    transactionSender = thSender . atrHeader
    transactionNonce = thNonce . atrHeader
    transactionGasAmount = thEnergyAmount . atrHeader
    transactionPayload = atrPayload
    transactionSignature = atrSignature
    transactionSignHash = atrSignHash
    transactionHash = getHash

instance TransactionData Transaction where
    transactionHeader = atrHeader . wmdData
    transactionSender = thSender . atrHeader . wmdData
    transactionNonce = thNonce . atrHeader . wmdData
    transactionGasAmount = thEnergyAmount . atrHeader . wmdData
    transactionPayload = atrPayload . wmdData
    transactionSignature = atrSignature . wmdData
    transactionSignHash = atrSignHash . wmdData
    transactionHash = wmdHash

--------------------------
-- * Transaction outcomes
--------------------------
-- TODO: Move to Execution???

-- |A mapping from account addresses to amounts.
--
-- This is used in 'SpecialTransactionOutcome' to represent baking
-- and finalization rewards that pay multiple accounts.
-- Defining this as an explicit newtype is chiefly for convenience
-- in defining the serialization formats.
newtype AccountAmounts = AccountAmounts {accountAmounts :: Map.Map AccountAddress Amount}
  deriving newtype (Eq,Ord,Show)

instance S.Serialize AccountAmounts where
  put = putSafeMapOf S.put S.put . accountAmounts
  get = AccountAmounts <$> getSafeMapOf S.get S.get

instance ToJSON AccountAmounts where
  toJSON (AccountAmounts m) = AE.Array $ Vec.fromList $ mkObj <$> Map.toList m
    where
      mkObj (addr, amt) = AE.object ["address" AE..= addr, "amount" AE..= amt]

instance FromJSON AccountAmounts where
  parseJSON = AE.withArray "AccountAmounts" $ \v -> do
    v' <- forM v $ AE.withObject "AccountAmount" $ \o -> (,) <$> o AE..: "address" <*> o AE..: "amount"
    return $ AccountAmounts $ Map.fromList $ Vec.toList v'

-- |Record special transactions as well for logging purposes.
data SpecialTransactionOutcome =
  -- |Payment to each baker of a previous epoch,
  -- in proportion to the number of blocks they
  -- contributed.
  BakingRewards {
    -- |The amount awarded to each baker.
    stoBakerRewards :: !AccountAmounts,
    -- |The remaining balance of the baker reward account.
    stoRemainder :: !Amount
  }
  -- |Minting of new GTU.
  | Mint {
    -- |The amount allocated to the banking reward account.
    stoMintBakingReward :: !Amount,
    -- |The amount allocated to the finalization reward account.
    stoMintFinalizationReward :: !Amount,
    -- |The amount allocated as the platform development charge.
    stoMintPlatformDevelopmentCharge :: !Amount,
    -- |The account to which the platform development charge is paid.
    stoFoundationAccount :: !AccountAddress
  }
  -- |Payment to each finalizer on inclusion of a finalization
  -- record in a block.
  | FinalizationRewards {
    -- |The amount awarded to each finalizer.
    stoFinalizationRewards :: !AccountAmounts,
    -- |The remaining balance of the finalization reward account.
    stoRemainder :: !Amount
  }
  -- |Disbursement of fees from a block between the GAS account,
  -- the baker, and the foundation. It should always be that:
  --
  -- > stoTransactionFees + stOldGASAccount = stoNewGASAccount + stoBakerReward + stoFoundationCharge
  | BlockReward {
    -- |The total fees paid for transactions in the block.
    stoTransactionFees :: !Amount,
    -- |The old balance of the GAS account.
    stoOldGASAccount :: !Amount,
    -- |The new balance of the GAS account.
    stoNewGASAccount :: !Amount,
    -- |The amount awarded to the baker.
    stoBakerReward :: !Amount,
    -- |The amount awarded to the foundation.
    stoFoundationCharge :: !Amount,
    -- |The baker of the block, who receives the award.
    stoBaker :: !AccountAddress,
    -- |The foundation account.
    stoFoundationAccount :: !AccountAddress
  }
  deriving(Show, Eq)

$(deriveJSON defaultOptions{fieldLabelModifier = firstLower . drop 3} ''SpecialTransactionOutcome)

instance S.Serialize SpecialTransactionOutcome where
    put BakingRewards{..} = do
      S.putWord8 0
      S.put stoBakerRewards
      S.put stoRemainder
    put Mint{..} = do
      S.putWord8 1
      S.put stoMintBakingReward
      S.put stoMintFinalizationReward
      S.put stoMintPlatformDevelopmentCharge
      S.put stoFoundationAccount
    put FinalizationRewards{..} = do
      S.putWord8 2
      S.put stoFinalizationRewards
      S.put stoRemainder
    put BlockReward{..} = do
      S.putWord8 3
      S.put stoTransactionFees
      S.put stoOldGASAccount
      S.put stoNewGASAccount
      S.put stoBakerReward
      S.put stoFoundationCharge
      S.put stoBaker
      S.put stoFoundationAccount

    get = S.getWord8 >>= \case
      0 -> do
        stoBakerRewards <- S.get
        stoRemainder <- S.get
        return BakingRewards{..}
      1 -> do
        stoMintBakingReward <- S.get
        stoMintFinalizationReward <- S.get
        stoMintPlatformDevelopmentCharge <- S.get
        stoFoundationAccount <- S.get
        return Mint{..}
      2 -> do
        stoFinalizationRewards <- S.get
        stoRemainder <- S.get
        return FinalizationRewards{..}
      3 -> do
        stoTransactionFees <- S.get
        stoOldGASAccount <- S.get
        stoNewGASAccount <- S.get
        stoBakerReward <- S.get
        stoFoundationCharge <- S.get
        stoBaker <- S.get
        stoFoundationAccount <- S.get
        return BlockReward{..}
      _ -> fail "Invalid SpecialTransactionOutcome type"

-- |Outcomes of transactions. The vector of outcomes must have the same size as the
-- number of transactions in the block, and ordered in the same way.
data TransactionOutcomes = TransactionOutcomes {
    outcomeValues :: !(Vec.Vector TransactionSummary),
    _outcomeSpecial :: !(Seq.Seq SpecialTransactionOutcome)
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

-- TODO: fix this to use an lfmb tree. Potentially change storage type to the tree in blockstate too.
-- Does this need to be domain seperated? (Would require serialisation changes?)
instance HashableTo TransactionOutcomesHashV0 TransactionOutcomes where
    getHash transactionoutcomes = TransactionOutcomesHashV0 $ H.hash $ S.encode transactionoutcomes

emptyTransactionOutcomes :: TransactionOutcomes
emptyTransactionOutcomes = TransactionOutcomes Vec.empty Seq.empty

transactionOutcomesFromList :: [TransactionSummary] -> TransactionOutcomes
transactionOutcomesFromList l =
  let outcomeValues = Vec.fromList l
      _outcomeSpecial = Seq.empty
  in TransactionOutcomes{..}

type instance Index TransactionOutcomes = TransactionIndex
type instance IxValue TransactionOutcomes = TransactionSummary

instance Ixed TransactionOutcomes where
  ix idx f outcomes@TransactionOutcomes{..} =
    let x = fromIntegral idx
    in if x >= length outcomeValues then pure outcomes
       else ix x f outcomeValues <&> (\ov -> TransactionOutcomes{outcomeValues=ov,..})
