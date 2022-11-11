{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies #-}

module Concordium.Types.Transactions where

import Concordium.Common.Version
import Concordium.Utils.Serialization
import Control.Monad
import Data.Aeson (FromJSON (..), ToJSON (..))
import qualified Data.Aeson as AE
import Data.Aeson.TH
import qualified Data.ByteString as BS
import Data.Hashable
import qualified Data.Map.Strict as Map
import qualified Data.Sequence as Seq
import qualified Data.Serialize as S
import Lens.Micro.Internal
import Lens.Micro.Platform

import qualified Concordium.Crypto.SHA256 as H
import Concordium.Crypto.SignatureScheme as SigScheme
import Data.List (foldl')

import qualified Data.Vector as Vec
import Data.Word

import Concordium.ID.Types
import Concordium.Types
import Concordium.Types.Execution
import Concordium.Types.HashableTo
import Concordium.Types.Updates
import Concordium.Utils

-- * Account transactions

-- | Data common to all transaction types.
--
--  * @SPEC: <$DOCS/Transactions#transaction-header>
data TransactionHeader = TransactionHeader
    { -- | Sender account.
      thSender :: AccountAddress,
      -- | Account nonce.
      thNonce :: !Nonce,
      -- | Amount of energy dedicated for the execution of this transaction.
      thEnergyAmount :: !Energy,
      -- | Size of the payload in bytes.
      thPayloadSize :: PayloadSize,
      -- | Absolute expiration time after which transaction will not be executed
      thExpiry :: TransactionExpiryTime
    }
    deriving (Show, Eq)

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
        S.put thSender
            <> S.put thNonce
            <> S.put thEnergyAmount
            <> S.put thPayloadSize
            <> S.put thExpiry

    get = do
        thSender <- S.get
        thNonce <- S.get
        thEnergyAmount <- S.get
        thPayloadSize <- S.get
        thExpiry <- S.get
        return $! TransactionHeader{..}

-- |Construct a 'TransactionSignHash' from the serialized bytes of
-- an account transaction's header and payload.
transactionSignHashFromBytes :: BS.ByteString -> TransactionSignHashV0
transactionSignHashFromBytes = TransactionSignHashV0 . H.hash

-- |Construct a 'TransactionSignHash' from a 'TransactionHeader' and 'EncodedPayload'.
transactionSignHashFromHeaderPayload :: TransactionHeader -> EncodedPayload -> TransactionSignHashV0
transactionSignHashFromHeaderPayload atrHeader atrPayload = TransactionSignHashV0 $ H.hashLazy $ S.runPutLazy $ S.put atrHeader <> putEncodedPayload atrPayload

-- |A transaction signature is map from the index of the credential to another map from the key index to the actual signature.
-- The credential index is relative to the account address, and the indices should be distinct.
-- The key index is relative to the credential.
-- The maximum length of the list is 255, and the minimum length is 1.
newtype TransactionSignature = TransactionSignature {tsSignatures :: Map.Map CredentialIndex (Map.Map KeyIndex Signature)}
    deriving (Eq, Show)
    deriving (ToJSON, FromJSON) via (Map.Map CredentialIndex (Map.Map KeyIndex Signature))

-- |Get the number of actual signatures contained in a 'TransactionSignature'.
getTransactionNumSigs :: TransactionSignature -> Int
getTransactionNumSigs = foldl' (\l m -> l + length m) 0 . tsSignatures

-- |NB: Relies on the scheme and signature serialization to be sensibly defined
-- as specified on the wiki!
instance S.Serialize TransactionSignature where
    put TransactionSignature{..} = do
        S.putWord8 (fromIntegral (length tsSignatures))
        forM_ (Map.toAscList tsSignatures) $ \(credIndex, sigmap) ->
            S.put credIndex
                <> S.putWord8 (fromIntegral (length sigmap))
                <> forM_ (Map.toAscList sigmap) (\(idx, sig) -> S.put idx <> S.put sig)
    get = do
        len <- S.getWord8
        when (len == 0) $ fail "Need at least one signature."

        let accumulateCredSigs accum mlast count
                | count == 0 = return accum
                | otherwise = do
                    idx <- S.get
                    forM_ mlast $ \lasti -> unless (idx > lasti) $ fail "Signatures are not in canonical order."
                    sig <- S.get
                    accumulateCredSigs (Map.insert idx sig accum) (Just idx) (count - 1)
        let accumulateSigs accum mlast count
                | count == 0 = return accum
                | otherwise = do
                    idx <- S.get
                    forM_ mlast $ \lasti -> unless (idx > lasti) $ fail "Signatures are not in canonical order."
                    -- sig <- S.get
                    sigmaplen <- S.getWord8
                    when (sigmaplen == 0) $ fail "There must be at least one signature for each listed credential."
                    sigmap <- accumulateCredSigs Map.empty Nothing sigmaplen
                    accumulateSigs (Map.insert idx sigmap accum) (Just idx) (count - 1)
        TransactionSignature <$> accumulateSigs Map.empty Nothing len

-- |An 'AccountTransaction' is a transaction that originates from
-- a specific account (the sender), and is paid for by the sender.
--
-- The representation includes a 'TransactionSignHash' which is
-- the value that is signed. This is derived from the header and
-- payload, and so does not form part of the serialization.
--
-- The payload is stored in serialized form. Deserializing the
-- payload is considered part of the transaction execution.
data AccountTransaction = AccountTransaction
    { -- |Signature
      atrSignature :: !TransactionSignature,
      -- |Header
      atrHeader :: !TransactionHeader,
      -- |Serialized payload
      atrPayload :: !EncodedPayload,
      -- |Hash used for signing
      atrSignHash :: !TransactionSignHashV0
    }
    deriving (Eq, Show)

-- |Construct an 'AccountTransaction', computing the correct
-- 'TransactionSignHash'.
makeAccountTransaction :: TransactionSignature -> TransactionHeader -> EncodedPayload -> AccountTransaction
makeAccountTransaction atrSignature atrHeader atrPayload = AccountTransaction{..}
  where
    atrSignHash = transactionSignHashFromHeaderPayload atrHeader atrPayload

-- | @SPEC: <$DOCS/Transactions#serialization-format-transactions>
instance S.Serialize AccountTransaction where
    put AccountTransaction{..} =
        S.put atrSignature
            <> S.put atrHeader
            <> putEncodedPayload atrPayload

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

-- |An 'AccountCreation' is a credential together with an expiry. It is a
-- message that is included in a block, if valid, but it is not paid for
-- directly by the sender.
data AccountCreation = AccountCreation
    { messageExpiry :: !TransactionExpiryTime,
      credential :: !AccountCredentialWithProofs
    }
    deriving (Eq, Show)

instance S.Serialize AccountCreation where
    put AccountCreation{..} = S.put messageExpiry <> S.put credential
    get = AccountCreation <$> S.get <*> S.get

instance FromJSON AccountCreation where
    parseJSON = AE.withObject "AccountCreation" $ \obj -> do
        messageExpiry <- obj AE..: "messageExpiry"
        credential <- obj AE..: "credential"
        return AccountCreation{..}

--------------------------

-- * Transaction metadata

--------------------------

-- |Metadata for a block item.
data WithMetadata value = WithMetadata
    { wmdData :: !value,
      -- |Size of the block item in bytes; derived field.
      wmdSize :: !Int,
      -- |Hash of the transaction. Derived from the first field.
      wmdHash :: !TransactionHash,
      -- |Arrival time of the transaction.
      wmdArrivalTime :: !TransactionTime
    }
    deriving (Show)

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
type CredentialDeploymentWithMeta = WithMetadata AccountCreation

addMetadata :: (a -> BareBlockItem) -> TransactionTime -> a -> WithMetadata a
addMetadata f time a =
    WithMetadata
        { wmdData = a,
          wmdSize = BS.length bs,
          wmdHash = transactionHashFromBytes bs,
          wmdArrivalTime = time
        }
  where
    bs = S.runPut $ putBareBlockItem (f a)

fromAccountTransaction :: TransactionTime -> AccountTransaction -> Transaction
fromAccountTransaction wmdArrivalTime wmdData =
    let wmdHash = getHash wmdData
        wmdSize = BS.length (S.encode wmdData) + 1
    in  WithMetadata{..}

fromCDI ::
    -- |Arrival time
    TransactionTime ->
    -- |Expiry time of the message
    TransactionExpiryTime ->
    CredentialDeploymentInformation ->
    CredentialDeploymentWithMeta
fromCDI wmdArrivalTime messageExpiry cdi =
    let cdiBytes = S.encode wmdData
        wmdSize = BS.length cdiBytes + 1 -- + 1 for the tag
        wmdData = AccountCreation{credential = NormalACWP cdi, ..}
        wmdHash = getHash (CredentialDeployment wmdData)
    in  WithMetadata{..}

fromICDI ::
    -- |Arrival time
    TransactionTime ->
    -- |Expiry time of the message
    TransactionExpiryTime ->
    InitialCredentialDeploymentInfo ->
    CredentialDeploymentWithMeta
fromICDI wmdArrivalTime messageExpiry icdi =
    let cdiBytes = S.encode wmdData
        wmdSize = BS.length cdiBytes + 1 -- + 1 for the tag
        wmdData = AccountCreation{credential = InitialACWP icdi, ..}
        wmdHash = getHash (CredentialDeployment wmdData)
    in  WithMetadata{..}

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
    get =
        S.getWord8 >>= \case
            0 -> return AccountTransactionKind
            1 -> return CredentialDeploymentKind
            2 -> return UpdateInstructionKind
            _ -> fail "unknown block item kind"
    {-# INLINE get #-}

-- |Data that can go onto a block.
data BareBlockItem
    = NormalTransaction
        { biTransaction :: !AccountTransaction
        }
    | CredentialDeployment
        { biCred :: !AccountCreation
        }
    | ChainUpdate
        { biUpdate :: !UpdateInstruction
        }
    deriving (Eq, Show)

instance HashableTo TransactionHash BareBlockItem where
    getHash = transactionHashFromBareBlockItem

type BlockItem = WithMetadata BareBlockItem

putBareBlockItem :: S.Putter BareBlockItem
putBareBlockItem NormalTransaction{..} = S.put AccountTransactionKind <> S.put biTransaction
putBareBlockItem CredentialDeployment{..} = S.put CredentialDeploymentKind <> S.put biCred
putBareBlockItem ChainUpdate{..} = S.put UpdateInstructionKind <> putUpdateInstruction biUpdate

getBareBlockItem :: SProtocolVersion pv -> S.Get BareBlockItem
getBareBlockItem spv =
    S.label "BareBlockItem" $
        S.get >>= \case
            AccountTransactionKind -> NormalTransaction <$> S.get
            CredentialDeploymentKind -> CredentialDeployment <$> S.get
            UpdateInstructionKind -> ChainUpdate <$> getUpdateInstruction spv

-- |Datatypes which have an expiry, which here we set to mean the latest time
-- the item can be included in a block.
class HasMessageExpiry a where
    msgExpiry :: a -> TransactionExpiryTime

instance HasMessageExpiry AccountTransaction where
    {-# INLINE msgExpiry #-}
    msgExpiry = thExpiry . transactionHeader

instance HasMessageExpiry AccountCreation where
    {-# INLINE msgExpiry #-}
    msgExpiry = messageExpiry

instance HasMessageExpiry UpdateInstruction where
    {-# INLINE msgExpiry #-}
    msgExpiry = updateTimeout . uiHeader

instance HasMessageExpiry BareBlockItem where
    msgExpiry (NormalTransaction t) = msgExpiry t
    msgExpiry (CredentialDeployment t) = msgExpiry t
    msgExpiry (ChainUpdate t) = msgExpiry t

instance HasMessageExpiry a => HasMessageExpiry (WithMetadata a) where
    {-# INLINE msgExpiry #-}
    msgExpiry = msgExpiry . wmdData

instance HasMessageExpiry a => HasMessageExpiry (Versioned a) where
    {-# INLINE msgExpiry #-}
    msgExpiry = msgExpiry . vValue

instance HasCredentialType AccountCreation where
    {-# INLINE credentialType #-}
    credentialType = credentialType . credential

instance CredentialValuesFields CredentialRegistrationID AccountCreation where
    {-# INLINE credId #-}
    credId = credId . credential
    {-# INLINE ipId #-}
    ipId = ipId . credential
    {-# INLINE policy #-}
    policy = policy . credential
    {-# INLINE credPubKeys #-}
    credPubKeys = credPubKeys . credential

instance HasCredentialType a => HasCredentialType (WithMetadata a) where
    {-# INLINE credentialType #-}
    credentialType = credentialType . wmdData

instance CredentialValuesFields CredentialRegistrationID a => CredentialValuesFields CredentialRegistrationID (WithMetadata a) where
    {-# INLINE credId #-}
    credId = credId . wmdData
    {-# INLINE ipId #-}
    ipId = ipId . wmdData
    {-# INLINE policy #-}
    policy = policy . wmdData
    {-# INLINE credPubKeys #-}
    credPubKeys = credPubKeys . wmdData

-- |Embed a transaction as a block item.
normalTransaction :: Transaction -> BlockItem
-- the +1 is for the additional tag.
normalTransaction WithMetadata{..} = WithMetadata{wmdData = NormalTransaction wmdData, wmdSize = wmdSize + 1, ..}

credentialDeployment :: CredentialDeploymentWithMeta -> BlockItem
credentialDeployment WithMetadata{..} = WithMetadata{wmdData = CredentialDeployment wmdData, wmdSize = wmdSize + 1, ..}

chainUpdate :: WithMetadata UpdateInstruction -> BlockItem
chainUpdate WithMetadata{..} = WithMetadata{wmdData = ChainUpdate wmdData, wmdSize = wmdSize + 1, ..}

-- |Serialize a block item according to V0 format, without the metadata.
putBlockItemV0 :: BlockItem -> S.Put
putBlockItemV0 = putBareBlockItemV0 . wmdData

-- |Serialize a bare block item according to the V0 format, without the metadata.
putBareBlockItemV0 :: BareBlockItem -> S.Put
putBareBlockItemV0 = putBareBlockItem

---------------------------------

-- * 'TransactionHash' functions

---------------------------------

-- |Construct a hash from a serialized block item.
transactionHashFromBytes :: BS.ByteString -> TransactionHashV0
transactionHashFromBytes = TransactionHashV0 . H.hash

transactionHashFromBareBlockItem :: BareBlockItem -> TransactionHashV0
transactionHashFromBareBlockItem = transactionHashFromBytes . S.runPut . putBareBlockItem

-------------------

-- * Serialization

-------------------

-- |Try to parse a versioned block item, stripping the version, and
-- reconstructing the block item metadata from the raw data.
-- The parsing format is determined by the version tag.
--
-- The only supported version at the moment is version 0.
--
-- Note, the deserialization is parametrised by the protocol version.
-- For version 0 serialization, the protocol version will only determine __whether__ the block item
-- can be deserialized, and not __how__ it is deserialized.
--
-- * @SPEC: <$DOCS/Versioning#binary-format>
-- * @SPEC: <$DOCS/Versioning>
getExactVersionedBlockItem ::
    SProtocolVersion spv ->
    -- |Timestamp for when the item is received, used to
    -- construct the metadata.
    TransactionTime ->
    S.Get BlockItem
getExactVersionedBlockItem spv time = do
    version <- S.get :: S.Get Version
    case version of
        0 -> getBlockItemV0 spv time
        _ -> fail $ "Unsupported block item version " ++ show version ++ "."

-- |Get a block item according to V0 format, reconstructing metadata.
--
-- * @SPEC: <$DOCS/Transactions#v0-format>
-- * @SPEC: <$DOCS/Versioning>
getBlockItemV0 ::
    SProtocolVersion spv ->
    -- |Timestamp of when the item arrived.
    TransactionTime ->
    S.Get BlockItem
getBlockItemV0 spv time = S.label "getBlockItemV0" $ do
    (bbi, bytes) <- getWithBytes $ getBareBlockItem spv
    return
        WithMetadata
            { wmdData = bbi,
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
signTransactionSingle kp = signTransaction [(0, [(0, kp)])]

-- |Sign a transaction with the given header and body, using the given keypairs.
-- The function does not sanity checking that the keys are valid, or that the
-- indices are distint.
--
-- * @SPEC: <$DOCS/Transactions#transaction-signature>
signTransaction :: [(CredentialIndex, [(KeyIndex, KeyPair)])] -> TransactionHeader -> EncodedPayload -> AccountTransaction
signTransaction keys atrHeader atrPayload =
    let
        atrSignHash = transactionSignHashFromHeaderPayload atrHeader atrPayload
        -- only sign the hash of the transaction
        bodyHash = transactionSignHashToByteString atrSignHash
        credSignature cKeys = Map.fromList $ map (\(idx, key) -> (idx, SigScheme.sign key bodyHash)) cKeys
        tsSignatures = Map.fromList $ map (\(idx, cKeys) -> (idx, credSignature cKeys)) keys
        atrSignature = TransactionSignature{..}
    in
        AccountTransaction{..}

-- |Verify credential signatures. This checks
--
-- - the number of signatures is less than 255
-- - __all__ signatures are valid
-- - there are at least threshold number of signatures.
verifyCredentialSignatures :: BS.ByteString -> Map.Map KeyIndex Signature -> CredentialPublicKeys -> Bool
verifyCredentialSignatures bodyHash sigs keys =
    let numSigs = length sigs
        -- foldr is the right function to use here because the body is lazy in the second argument.
        -- This does rely on the specific order of arguments since && is strict in the first argument, but not the second.
        check = foldr (\(idx, sig) b -> maybe False (\vfKey -> SigScheme.verify vfKey bodyHash sig) (getCredentialPublicKey idx keys) && b) True (Map.toList sigs)
    in  numSigs <= 255 && (fromIntegral numSigs >= credThreshold keys) && check

-- |Verify that the given transaction was signed by the required number of keys.
-- Concretely this means
--
-- - enough credential holders signed the transaction
-- - each of the credential signres has the required number of signatures, see 'verifyCredentialSignatures'
-- - all of the signatures are valid, that is, it is not sufficient that a threshold number are valid, and some extra ones are invalid.
verifyTransaction :: TransactionData msg => AccountInformation -> msg -> Bool
verifyTransaction ai tx =
    let bodyHash = transactionSignHashToByteString (transactionSignHash tx)
        TransactionSignature maps = transactionSignature tx
        -- foldr is the right function to use here because the body is lazy in the second argument.
        -- This does rely on the specific order of arguments since && is strict in the first argument, but not the second.
        keysCheck = foldr (\(idx, sigmap) b -> maybe False (verifyCredentialSignatures bodyHash sigmap) (getCredentialKeys idx ai) && b) True (Map.toList maps)
        numSigs = length maps
        threshold = aiThreshold ai
    in  numSigs <= 255 && fromIntegral numSigs >= threshold && keysCheck

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
    deriving newtype (Eq, Ord, Show)

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
data SpecialTransactionOutcome
    = -- |Payment to each baker of a previous epoch,
      -- in proportion to the number of blocks they
      -- contributed.
      BakingRewards
        { -- |The amount awarded to each baker.
          stoBakerRewards :: !AccountAmounts,
          -- |The remaining balance of the baker reward account.
          stoRemainder :: !Amount
        }
    | -- |Minting of new GTU.
      Mint
        { -- |The amount allocated to the banking reward account.
          stoMintBakingReward :: !Amount,
          -- |The amount allocated to the finalization reward account.
          stoMintFinalizationReward :: !Amount,
          -- |The amount allocated as the platform development charge.
          stoMintPlatformDevelopmentCharge :: !Amount,
          -- |The account to which the platform development charge is paid.
          stoFoundationAccount :: !AccountAddress
        }
    | -- |Payment to each finalizer on inclusion of a finalization
      -- record in a block.
      FinalizationRewards
        { -- |The amount awarded to each finalizer.
          stoFinalizationRewards :: !AccountAmounts,
          -- |The remaining balance of the finalization reward account.
          stoRemainder :: !Amount
        }
    | -- |Disbursement of fees from a block between the GAS account,
      -- the baker, and the foundation. It should always be that:
      --
      -- > stoTransactionFees + stOldGASAccount = stoNewGASAccount + stoBakerReward + stoFoundationCharge
      BlockReward
        { -- |The total fees paid for transactions in the block.
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
    | -- |Payment for a particular account.
      PaydayFoundationReward
        { -- |The account that got rewarded.
          stoFoundationAccount :: !AccountAddress,
          -- |The transaction fee reward at payday to the account.
          stoDevelopmentCharge :: !Amount
        }
    | -- |Payment for a particular account.
      PaydayAccountReward
        { -- |The account that got rewarded.
          stoAccount :: !AccountAddress,
          -- |The transaction fee reward at payday to the account.
          stoTransactionFees :: !Amount,
          -- |The baking reward at payday to the account.
          stoBakerReward :: !Amount,
          -- |The finalization reward at payday to the account.
          stoFinalizationReward :: !Amount
        }
    | -- |Amounts accrued to accounts for each baked block.
      BlockAccrueReward
        { -- |The total fees paid for transactions in the block.
          stoTransactionFees :: !Amount,
          -- |The old balance of the GAS account.
          stoOldGASAccount :: !Amount,
          -- |The new balance of the GAS account.
          stoNewGASAccount :: !Amount,
          -- |The amount awarded to the baker.
          stoBakerReward :: !Amount,
          -- |The amount awarded to the passive delegators.
          stoPassiveReward :: !Amount,
          -- |The amount awarded to the foundation.
          stoFoundationCharge :: !Amount,
          -- |The baker of the block, who will receive the award.
          stoBakerId :: !BakerId
        }
    | -- |Payment distributed to a pool or passive delegators.
      PaydayPoolReward
        { -- |The pool owner (passive delegators when 'Nothing').
          stoPoolOwner :: !(Maybe BakerId),
          -- |Accrued transaction fees for pool.
          stoTransactionFees :: !Amount,
          -- |Accrued baking rewards for pool.
          stoBakerReward :: !Amount,
          -- |Accrued finalization rewards for pool.
          stoFinalizationReward :: !Amount
        }
    deriving (Show, Eq)

$(deriveJSON defaultOptions{fieldLabelModifier = firstLower . drop 3} ''SpecialTransactionOutcome)

instance HashableTo H.Hash SpecialTransactionOutcome where
    getHash = H.hash . S.encode

-- Generic instance based on the HashableTo instance
instance Monad m => MHashableTo m H.Hash SpecialTransactionOutcome

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
    put PaydayFoundationReward{..} = do
        S.putWord8 4
        S.put stoFoundationAccount
        S.put stoDevelopmentCharge
    put PaydayAccountReward{..} = do
        S.putWord8 5
        S.put stoAccount
        S.put stoTransactionFees
        S.put stoBakerReward
        S.put stoFinalizationReward
    put BlockAccrueReward{..} = do
        S.putWord8 6
        S.put stoTransactionFees
        S.put stoOldGASAccount
        S.put stoNewGASAccount
        S.put stoBakerReward
        S.put stoPassiveReward
        S.put stoFoundationCharge
        S.put stoBakerId
    put PaydayPoolReward{..} = do
        S.putWord8 7
        S.put stoPoolOwner
        S.put stoTransactionFees
        S.put stoBakerReward
        S.put stoFinalizationReward

    get =
        S.getWord8 >>= \case
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
            4 -> do
                stoFoundationAccount <- S.get
                stoDevelopmentCharge <- S.get
                return PaydayFoundationReward{..}
            5 -> do
                stoAccount <- S.get
                stoTransactionFees <- S.get
                stoBakerReward <- S.get
                stoFinalizationReward <- S.get
                return PaydayAccountReward{..}
            6 -> do
                stoTransactionFees <- S.get
                stoOldGASAccount <- S.get
                stoNewGASAccount <- S.get
                stoBakerReward <- S.get
                stoPassiveReward <- S.get
                stoFoundationCharge <- S.get
                stoBakerId <- S.get
                return BlockAccrueReward{..}
            7 -> do
                stoPoolOwner <- S.get
                stoTransactionFees <- S.get
                stoBakerReward <- S.get
                stoFinalizationReward <- S.get
                return PaydayPoolReward{..}
            _ -> fail "Invalid SpecialTransactionOutcome type"

-- |Outcomes of transactions. The vector of outcomes must have the same size as the
-- number of transactions in the block, and ordered in the same way.
data TransactionOutcomes = TransactionOutcomes
    { outcomeValues :: !(Vec.Vector TransactionSummary),
      _outcomeSpecial :: !(Seq.Seq SpecialTransactionOutcome)
    }

makeLenses ''TransactionOutcomes

instance Show TransactionOutcomes where
    show (TransactionOutcomes v s) = "Normal transactions: " ++ show (Vec.toList v) ++ ", special transactions: " ++ show s

putTransactionOutcomes :: S.Putter TransactionOutcomes
putTransactionOutcomes TransactionOutcomes{..} = do
    putListOf putTransactionSummary (Vec.toList outcomeValues)
    S.put _outcomeSpecial

getTransactionOutcomes :: SProtocolVersion pv -> S.Get TransactionOutcomes
getTransactionOutcomes spv = TransactionOutcomes <$> (Vec.fromList <$> getListOf (getTransactionSummary spv)) <*> S.get

instance HashableTo TransactionOutcomesHash TransactionOutcomes where
    getHash transactionoutcomes = TransactionOutcomesHash $ H.hash $ S.runPut $ putTransactionOutcomes transactionoutcomes

-- |A simple wrapper around a `Hash`.
-- No matter the strategy for deriving the 'TrasactionOutcomeHash' we will
-- always end up with a value of this type.
newtype TransactionOutcomesHash = TransactionOutcomesHash {tohGet :: H.Hash}
    deriving newtype (Eq, Ord, Show, S.Serialize, ToJSON, FromJSON, AE.FromJSONKey, AE.ToJSONKey, Read, Hashable)

emptyTransactionOutcomesV0 :: TransactionOutcomes
emptyTransactionOutcomesV0 = TransactionOutcomes Vec.empty Seq.empty

{-# NOINLINE emptyTransactionOutcomesHashV1 #-}

-- |Hash of the empty V1 transaction outcomes structure. This transaction outcomes
-- structure is used starting in protocol version 5.
--
-- This is not the ideal location here, since the merkle structures that define
-- it are defined in the global state modules, however any other place leads to
-- problematic module dependencies. We should ideally restructure those so that
-- we do not have this duplication here.
emptyTransactionOutcomesHashV1 :: TransactionOutcomesHash
emptyTransactionOutcomesHashV1 =
    TransactionOutcomesHash $
        H.hashShort
            ( "TransactionOutcomesV1"
                <> H.hashToShortByteString (H.hash "EmptyLFMBTree")
                <> H.hashToShortByteString (H.hash "EmptyLFMBTree")
            )

transactionOutcomesV0FromList :: [TransactionSummary] -> TransactionOutcomes
transactionOutcomesV0FromList l =
    let outcomeValues = Vec.fromList l
        _outcomeSpecial = Seq.empty
    in  TransactionOutcomes{..}

type instance Index TransactionOutcomes = TransactionIndex
type instance IxValue TransactionOutcomes = TransactionSummary

instance Ixed TransactionOutcomes where
    ix idx f outcomes@TransactionOutcomes{..} =
        let x = fromIntegral idx
        in  if x >= length outcomeValues
                then pure outcomes
                else ix x f outcomeValues <&> (\ov -> TransactionOutcomes{outcomeValues = ov, ..})
