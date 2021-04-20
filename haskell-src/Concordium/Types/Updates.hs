{-# LANGUAGE BangPatterns, DerivingStrategies, OverloadedStrings, ScopedTypeVariables, TemplateHaskell, StandaloneDeriving, DeriveTraversable, RankNTypes #-}
-- |Types for chain update instructions, together with basic validation functions.
-- For specification, see: https://concordium.gitlab.io/whitepapers/update-mechanism/main.pdf
--
-- The specification defines the following update types:
--
--   - authorization updates
--   - parameter updates
--   - protocol updates
--   - emergency updates
--
-- Authorization updates alter the set of keys used to authorize chain updates.
-- (Practically, they are a type of parameter update.)
--
-- Parameter updates update a chain parameter.
-- Currently provided parameters are:
--
--   - election difficulty
--   - Energy to Euro exchange rate
--   - GTU to Euro exchange rate
--   - address of the foundation account
--   - parameters for distribution of newly minted tokens
--   - parameters controlling the transaction fee distribution
--   - parameters controlling the GAS account
--
-- Each parameter has an independent update queue.
-- Sequence numbers for each different parameter are thus independent.
-- (Note, where two parameters are tightly coupled, such that one should
-- not be changed independently of the other, then they should be combined
-- as a single parameter.)
--
-- Protocol updates specify a new protocol version.
-- The implementation should stop the current chain when a protocol update takes effect.
-- If it supports the new protocol version, it should begin a new chain according to that protocol,
-- and based on the state when the update took effect.
-- (Currently, this is not implemented.)
--
-- Emergency updates are inherently outside the scope of the chain implementation itself.
-- The chain only records the keys authorized for emergency updates, but does
-- not support any kind of emergency update messages.
module Concordium.Types.Updates where

import qualified Data.Aeson as AE
import Data.Aeson.TH
import Data.Aeson.Types (FromJSON(..), ToJSON(..), (.:), withObject, object)
import Data.Maybe
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as BS16
import Data.Hashable (Hashable)
import Data.Ix
import qualified Data.Map as Map
import Data.Serialize
import qualified Data.Set as Set
import Data.Text (Text, unpack)
import Data.Text.Encoding (encodeUtf8, decodeUtf8)
import qualified Data.Vector as Vec
import Data.Word
import Control.Monad
import Lens.Micro.Platform

import Concordium.Crypto.SignatureScheme
import qualified Concordium.Crypto.SHA256 as SHA256

import Concordium.Utils
import Concordium.Utils.Serialization
import Concordium.Types
import Concordium.Types.HashableTo

----------------
-- * Parameter updates
----------------

-- |The minting rate and the distribution of newly-minted GTU
-- among bakers, finalizers, and the foundation account.
-- It must be the case that
-- @_mdBakingReward + _mdFinalizationReward <= 1@.
-- The remaining amount is the platform development charge.
data MintDistribution = MintDistribution {
    -- |Mint rate per slot
    _mdMintPerSlot :: !MintRate,
    -- |BakingRewMintFrac: the fraction allocated to baker rewards
    _mdBakingReward :: !RewardFraction,
    -- |FinRewMintFrac: the fraction allocated to finalization rewards
    _mdFinalizationReward :: !RewardFraction
} deriving (Eq, Show)
makeClassy ''MintDistribution

instance ToJSON MintDistribution where
  toJSON MintDistribution{..} = object [
      "mintPerSlot" AE..= _mdMintPerSlot,
      "bakingReward" AE..= _mdBakingReward,
      "finalizationReward" AE..= _mdFinalizationReward
    ]
instance FromJSON MintDistribution where
  parseJSON = withObject "MintDistribution" $ \v -> do
    _mdMintPerSlot <- v .: "mintPerSlot"
    _mdBakingReward <- v .: "bakingReward"
    _mdFinalizationReward <- v .: "finalizationReward"
    unless (isJust (_mdBakingReward `addRewardFraction` _mdFinalizationReward)) $ fail "Reward fractions exceed 100%"
    return MintDistribution{..}

instance Serialize MintDistribution where
  put MintDistribution{..} = put _mdMintPerSlot >> put _mdBakingReward >> put _mdFinalizationReward
  get = do
    _mdMintPerSlot <- get
    _mdBakingReward <- get
    _mdFinalizationReward <- get
    unless (isJust (_mdBakingReward `addRewardFraction` _mdFinalizationReward)) $ fail "Reward fractions exceed 100%"
    return MintDistribution{..}

instance HashableTo SHA256.Hash MintDistribution where
  getHash = SHA256.hash . encode

instance Monad m => MHashableTo m SHA256.Hash MintDistribution

-- |The distribution of block transaction fees among the block
-- baker, the GAS account, and the foundation account.  It
-- must be the case that @_tfdBaker + _tfdGASAccount <= 1@.
-- The remaining amount is the TransChargeFrac (paid to the
-- foundation account).
data TransactionFeeDistribution = TransactionFeeDistribution {
    -- |BakerTransFrac: the fraction allocated to the baker
    _tfdBaker :: !RewardFraction,
    -- |The fraction allocated to the GAS account
    _tfdGASAccount :: !RewardFraction
} deriving (Eq, Show)
makeClassy ''TransactionFeeDistribution

instance ToJSON TransactionFeeDistribution where
  toJSON TransactionFeeDistribution{..} = object [
      "baker" AE..= _tfdBaker,
      "gasAccount" AE..= _tfdGASAccount
    ]
instance FromJSON TransactionFeeDistribution where
  parseJSON = withObject "TransactionFeeDistribution" $ \v -> do
    _tfdBaker <- v .: "baker"
    _tfdGASAccount <- v .: "gasAccount"
    unless (isJust (_tfdBaker `addRewardFraction` _tfdGASAccount)) $ fail "Transaction fee fractions exceed 100%"
    return TransactionFeeDistribution{..}

instance Serialize TransactionFeeDistribution where
  put TransactionFeeDistribution{..} = put _tfdBaker >> put _tfdGASAccount
  get = do
    _tfdBaker <- get
    _tfdGASAccount <- get
    unless (isJust (_tfdBaker `addRewardFraction` _tfdGASAccount)) $ fail "Transaction fee fractions exceed 100%"
    return TransactionFeeDistribution{..}

instance HashableTo SHA256.Hash TransactionFeeDistribution where
  getHash = SHA256.hash . encode

instance Monad m => MHashableTo m SHA256.Hash TransactionFeeDistribution

data GASRewards = GASRewards {
  -- |BakerPrevTransFrac: fraction paid to baker
  _gasBaker :: !RewardFraction,
  -- |FeeAddFinalisationProof: fraction paid for including a
  -- finalization proof in a block.
  _gasFinalizationProof :: !RewardFraction,
  -- |FeeAccountCreation: fraction paid for including each
  -- account creation transaction in a block.
  _gasAccountCreation :: !RewardFraction,
  -- |FeeUpdate: fraction paid for including an update
  -- transaction in a block.
  _gasChainUpdate :: !RewardFraction
} deriving (Eq, Show)
makeClassy ''GASRewards

$(deriveJSON AE.defaultOptions{AE.fieldLabelModifier = firstLower . drop 4} ''GASRewards)

instance Serialize GASRewards where
  put GASRewards{..} = do
    put _gasBaker
    put _gasFinalizationProof
    put _gasAccountCreation
    put _gasChainUpdate
  get = do
    _gasBaker <- get
    _gasFinalizationProof <- get
    _gasAccountCreation <- get
    _gasChainUpdate <- get
    return GASRewards{..}

instance HashableTo SHA256.Hash GASRewards where
  getHash = SHA256.hash . encode

instance Monad m => MHashableTo m SHA256.Hash GASRewards

-- |Parameters affecting rewards.
-- It must be that @rpBakingRewMintFrac + rpFinRewMintFrac < 1@
data RewardParameters = RewardParameters {
    -- |Distribution of newly-minted GTUs.
    _rpMintDistribution :: !MintDistribution,
    -- |Distribution of transaction fees.
    _rpTransactionFeeDistribution :: !TransactionFeeDistribution,
    -- |Rewards paid from the GAS account.
    _rpGASRewards :: !GASRewards
} deriving (Eq, Show)
makeClassy ''RewardParameters

instance HasMintDistribution RewardParameters where
  mintDistribution = rpMintDistribution

instance HasTransactionFeeDistribution RewardParameters where
  transactionFeeDistribution = rpTransactionFeeDistribution

instance HasGASRewards RewardParameters where
  gASRewards = rpGASRewards

$(deriveJSON AE.defaultOptions{AE.fieldLabelModifier = firstLower . drop 3} ''RewardParameters)

instance Serialize RewardParameters where
  put RewardParameters{..} = do
    put _rpMintDistribution
    put _rpTransactionFeeDistribution
    put _rpGASRewards
  get = do
    _rpMintDistribution <- get
    _rpTransactionFeeDistribution <- get
    _rpGASRewards <- get
    return RewardParameters{..}

--------------------
-- * Update Keys Types
--------------------

-- |Key type for update authorization.
type UpdatePublicKey = VerifyKey

-- |Index of a key in an 'Authorizations'.
type UpdateKeyIndex = Word16

-- |A wrapper over Word16 to ensure on Serialize.get and Aeson.parseJSON that it
-- is not zero and it doesn't exceed the max value.
newtype UpdateKeysThreshold = UpdateKeysThreshold { uktTheThreshold :: Word16 }
 deriving (Show, Eq, Enum, Num, Real, Ord, Integral, AE.ToJSON, AE.FromJSON)

instance Serialize UpdateKeysThreshold where
  put = putWord16be . uktTheThreshold
  get = do
    r <- getWord16be
    when (r == 0) $ fail "UpdateKeysThreshold cannot be 0."
    return (UpdateKeysThreshold r)


--------------------
-- * Authorizations updates (Level 2 keys)
--------------------

-- |Access structure for level 2 update authorization.
data AccessStructure = AccessStructure {
        -- |Public keys
        accessPublicKeys :: !(Set.Set UpdateKeyIndex),
        -- |Number of keys required to authorize an update
        accessThreshold :: !UpdateKeysThreshold
    }
    deriving (Eq, Show)

instance Serialize AccessStructure where
    put AccessStructure{..} = do
        putWord16be (fromIntegral (Set.size accessPublicKeys))
        mapM_ putWord16be (Set.toAscList accessPublicKeys)
        put accessThreshold
    get = do
        keyCount <- getWord16be
        accessPublicKeys <- getSafeSizedSetOf keyCount getWord16be
        accessThreshold <- get
        when (accessThreshold > fromIntegral keyCount || accessThreshold < 1) $ fail "Invalid threshold"
        return AccessStructure{..}

-- |The set of keys authorized for chain updates, together with
-- access structures determining which keys are authorized for
-- which update types. This is the payload of an update to authorization.
data Authorizations = Authorizations {
        asKeys :: !(Vec.Vector UpdatePublicKey),
        -- |New emergency keys
        asEmergency :: !AccessStructure,
        -- |New protocol update keys
        asProtocol :: !AccessStructure,
        -- |Parameter keys: election difficulty
        asParamElectionDifficulty :: !AccessStructure,
        -- |Parameter keys: Euro:NRG
        asParamEuroPerEnergy :: !AccessStructure,
        -- |Parameter keys: microGTU:Euro
        asParamMicroGTUPerEuro :: !AccessStructure,
        -- |Parameter keys: foundation account
        asParamFoundationAccount :: !AccessStructure,
        -- |Parameter keys: mint distribution
        asParamMintDistribution :: !AccessStructure,
        -- |Parameter keys: transaction fee distribution
        asParamTransactionFeeDistribution :: !AccessStructure,
        -- |Parameter keys: GAS rewards
        asParamGASRewards :: !AccessStructure,
        -- |Parameter keys: Baker Minimum Threshold
        asBakerStakeThreshold :: !AccessStructure
    }
    deriving (Eq, Show)

instance Serialize Authorizations where
    put Authorizations{..} = do
        putWord16be (fromIntegral (Vec.length asKeys))
        mapM_ put asKeys
        put asEmergency
        put asProtocol
        put asParamElectionDifficulty
        put asParamEuroPerEnergy
        put asParamMicroGTUPerEuro
        put asParamFoundationAccount
        put asParamMintDistribution
        put asParamTransactionFeeDistribution
        put asParamGASRewards
        put asBakerStakeThreshold
    get = label "deserialization update authorizations" $ do
        keyCount <- getWord16be
        asKeys <- Vec.replicateM (fromIntegral keyCount) get
        let getChecked = do
                r <- get
                case Set.lookupMax (accessPublicKeys r) of
                    Just v
                        | v < keyCount -> return r
                        | otherwise -> fail "invalid key index"
                    Nothing -> return r
        asEmergency <- getChecked
        asProtocol <- getChecked
        asParamElectionDifficulty <- getChecked
        asParamEuroPerEnergy <- getChecked
        asParamMicroGTUPerEuro <- getChecked
        asParamFoundationAccount <- getChecked
        asParamMintDistribution <- getChecked
        asParamTransactionFeeDistribution <- getChecked
        asParamGASRewards <- getChecked
        asBakerStakeThreshold <- getChecked
        return Authorizations{..}

instance HashableTo SHA256.Hash Authorizations where
    getHash a = SHA256.hash $ "Authorizations" <> encode a

instance Monad m => MHashableTo m SHA256.Hash Authorizations

instance AE.FromJSON Authorizations where
    parseJSON = AE.withObject "Authorizations" $ \v -> do
        asKeys <- Vec.fromList <$> v .: "keys"
        let
            parseAS x = v .: x >>= AE.withObject (unpack x) (\o -> do
                accessPublicKeys :: Set.Set UpdateKeyIndex <- o .: "authorizedKeys"
                accessThreshold <- o .: "threshold"
                when (accessThreshold > fromIntegral (Set.size accessPublicKeys) || accessThreshold < 1) $ fail "Invalid threshold"
                case Set.lookupMax accessPublicKeys of
                    Just maxKeyIndex
                        | fromIntegral maxKeyIndex >= Vec.length asKeys -> fail "invalid key index"
                    _ -> return AccessStructure{..}
                )
        asEmergency <- parseAS "emergency"
        asProtocol <- parseAS "protocol"
        asParamElectionDifficulty <- parseAS "electionDifficulty"
        asParamEuroPerEnergy <- parseAS "euroPerEnergy"
        asParamMicroGTUPerEuro <- parseAS "microGTUPerEuro"
        asParamFoundationAccount <- parseAS "foundationAccount"
        asParamMintDistribution <- parseAS "mintDistribution"
        asParamTransactionFeeDistribution <- parseAS "transactionFeeDistribution"
        asParamGASRewards <- parseAS "paramGASRewards"
        asBakerStakeThreshold <- parseAS "bakerStakeThreshold"
        return Authorizations{..}

instance AE.ToJSON Authorizations where
    toJSON Authorizations{..} = AE.object [
                "keys" AE..= Vec.toList asKeys,
                "emergency" AE..= t asEmergency,
                "protocol" AE..= t asProtocol,
                "electionDifficulty" AE..= t asParamElectionDifficulty,
                "euroPerEnergy" AE..= t asParamEuroPerEnergy,
                "microGTUPerEuro" AE..= t asParamMicroGTUPerEuro,
                "foundationAccount" AE..= t asParamFoundationAccount,
                "mintDistribution" AE..= t asParamMintDistribution,
                "transactionFeeDistribution" AE..= t asParamTransactionFeeDistribution,
                "paramGASRewards" AE..= t asParamGASRewards,
                "bakerStakeThreshold" AE..= t asBakerStakeThreshold
            ]
        where
            t AccessStructure{..} = AE.object [
                    "authorizedKeys" AE..= accessPublicKeys,
                    "threshold" AE..= accessThreshold
                ]

-----------------
-- * Higher Level keys (Root and Level 1 keys)
-----------------

data RootKeysKind
data Level1KeysKind

-- |This data structure will be used for all the updates that update Root or
-- level 1 keys, and to store the authorized keys for those operations. The phantom
-- type has to be either RootKeysKind or Level1KeysKind.
data HigherLevelKeys keyKind = HigherLevelKeys {
  hlkKeys :: !(Vec.Vector UpdatePublicKey),
  hlkThreshold :: !UpdateKeysThreshold
  } deriving (Eq, Show)

instance Serialize (HigherLevelKeys a) where
  put HigherLevelKeys{..} = do
    putWord16be (fromIntegral (Vec.length hlkKeys))
    mapM_ put hlkKeys
    put hlkThreshold
  get = do
    keyCount <- getWord16be
    hlkKeys <- Vec.replicateM (fromIntegral keyCount) get
    hlkThreshold <- get
    when (hlkThreshold > fromIntegral keyCount || hlkThreshold < 1) $ fail "Invalid threshold"
    return HigherLevelKeys{..}

instance AE.FromJSON (HigherLevelKeys a) where
  parseJSON = AE.withObject "HigherLevelKeys" $ \v -> do
    hlkKeys <- Vec.fromList <$> v .: "keys"
    hlkThreshold <- (v .: "threshold")
    when (hlkThreshold > fromIntegral (Vec.length hlkKeys) || hlkThreshold < 1) $ fail "Invalid threshold"
    return HigherLevelKeys{..}

instance AE.ToJSON (HigherLevelKeys a) where
  toJSON HigherLevelKeys{..} = AE.object [
    "keys" AE..= Vec.toList hlkKeys,
    "threshold" AE..= hlkThreshold
    ]

instance HashableTo SHA256.Hash (HigherLevelKeys a) where
  getHash = SHA256.hash . encode

instance Monad m => MHashableTo m SHA256.Hash (HigherLevelKeys a) where

--------------------
-- * Root update
--------------------

-- |Root updates are the highest kind of updates. They can update every other
-- set of keys, even themselves. They can only be performed by Root level keys.
data RootUpdate =
  RootKeysRootUpdate {
    rkruKeys :: !(HigherLevelKeys RootKeysKind)
  }
  -- ^Update the root keys
  | Level1KeysRootUpdate {
    l1kruKeys :: !(HigherLevelKeys Level1KeysKind)
  }
  -- ^Update the Level 1 keys
  | Level2KeysRootUpdate {
    l2kruAuthorizations :: !Authorizations
  }
  -- ^Update the level 2 keys
  deriving (Eq, Show)

instance Serialize RootUpdate where
  put RootKeysRootUpdate{..} = do
    putWord8 0
    put rkruKeys
  put Level1KeysRootUpdate{..} = do
    putWord8 1
    put l1kruKeys
  put Level2KeysRootUpdate{..} = do
    putWord8 2
    put l2kruAuthorizations
  get = label "RootUpdate" $ do
    variant <- getWord8
    case variant of
      0 -> RootKeysRootUpdate <$> get
      1 -> Level1KeysRootUpdate <$> get
      2 -> Level2KeysRootUpdate <$> get
      _ -> fail $ "Unknown variant: " ++ show variant

instance AE.FromJSON RootUpdate where
  parseJSON = AE.withObject "RootUpdate" $ \o -> do
    variant :: Text <- o .: "typeOfUpdate"
    case variant of
         "rootKeysUpdate" -> RootKeysRootUpdate <$> o .: "updatePayload"
         "level1KeysUpdate" -> Level1KeysRootUpdate <$> o .: "updatePayload"
         "level2KeysUpdate" -> Level2KeysRootUpdate <$> o .: "updatePayload"
         _ -> fail $ "Unknown variant: " ++ show variant

instance AE.ToJSON RootUpdate where
  toJSON RootKeysRootUpdate{..} =
    AE.object [ "typeOfUpdate" AE..= ("rootKeysUpdate" :: Text),
                "updatePayload" AE..= rkruKeys
              ]
  toJSON Level1KeysRootUpdate{..} =
    AE.object [ "typeOfUpdate" AE..= ("level1KeysUpdate" :: Text),
                "updatePayload" AE..= l1kruKeys
              ]
  toJSON Level2KeysRootUpdate{..} =
    AE.object [ "typeOfUpdate" AE..= ("level2KeysUpdate" :: Text),
                "updatePayload" AE..= l2kruAuthorizations
              ]

--------------------
-- * Level 1 updates
--------------------

-- |Level 1 updates are the intermediate update kind. They can update themselves
-- or level 2 keys. They can only be performed by Level 1 keys.
data Level1Update =
  Level1KeysLevel1Update {
    l1kl1uKeys :: !(HigherLevelKeys Level1KeysKind)
  }
  | Level2KeysLevel1Update {
    l2kl1uAuthorizations :: !Authorizations
  }
  deriving (Eq, Show)

instance Serialize Level1Update where
  put Level1KeysLevel1Update{..} = do
    putWord8 0
    put l1kl1uKeys
  put Level2KeysLevel1Update{..} = do
    putWord8 1
    put l2kl1uAuthorizations
  get = label "Level1Update" $ do
    variant <- getWord8
    case variant of
      0 -> Level1KeysLevel1Update <$> get
      1 -> Level2KeysLevel1Update <$> get
      _ -> fail $ "Unknown variant: " ++ show variant

instance AE.FromJSON Level1Update where
  parseJSON = AE.withObject "Level1Update" $ \o -> do
    variant :: Text <- o .: "typeOfUpdate"
    case variant of
      "level1KeysUpdate" -> Level1KeysLevel1Update <$> o .: "updatePayload"
      "level2KeysUpdate" -> Level2KeysLevel1Update <$> o .: "updatePayload"
      _ -> fail $ "Unknown variant: " ++ show variant

instance AE.ToJSON Level1Update where
  toJSON Level1KeysLevel1Update{..} =
    AE.object [ "typeOfUpdate" AE..= ("level1KeysUpdate" :: Text),
                "updatePayload" AE..= l1kl1uKeys
              ]
  toJSON Level2KeysLevel1Update{..} =
    AE.object [ "typeOfUpdate" AE..= ("level2KeysUpdate" :: Text),
                "updatePayload" AE..= l2kl1uAuthorizations
              ]

----------------------
-- * Protocol updates
----------------------

-- |Payload of a protocol update.
data ProtocolUpdate = ProtocolUpdate {
        -- |A brief message about the update
        puMessage :: !Text,
        -- |A URL of a document describing the update
        puSpecificationURL :: !Text,
        -- |SHA256 hash of the specification document
        puSpecificationHash :: !SHA256.Hash,
        -- |Auxiliary data whose interpretation is defined by the new specification
        puSpecificationAuxiliaryData :: !ByteString
    }
    deriving (Eq, Show)

-- |The serialization of a protocol update payload is as follows:
--
--      1. Length of the rest of the payload (Word64)
--      2. UTF-8 encoded textual description: length (Word64) + text (Bytes(length))
--      3. UTF-8 encoded URL of description document: length (Word64) + text (Bytes(length))
--      4. SHA-256 hash of description document
--      5. Uninterpreted bytes for the rest of the payload
instance Serialize ProtocolUpdate where
    put ProtocolUpdate{..} = putNested putLength $ do
            putUtf8 puMessage
            putUtf8 puSpecificationURL
            put puSpecificationHash
            putByteString puSpecificationAuxiliaryData
    get = label "deserializing a protocol update payload" $ do
        len <- getLength
        isolate len $ do
            puMessage <- getUtf8
            puSpecificationURL <- getUtf8
            puSpecificationHash <- get
            puSpecificationAuxiliaryData <- getByteString =<< remaining
            return ProtocolUpdate{..}

instance HashableTo SHA256.Hash ProtocolUpdate where
    getHash pu = SHA256.hash $ "ProtocolUpdate" <> encode pu

instance Monad m => MHashableTo m SHA256.Hash ProtocolUpdate

instance AE.ToJSON ProtocolUpdate where
    toJSON ProtocolUpdate{..} = AE.object [
            "message" AE..= puMessage,
            "specificationURL" AE..= puSpecificationURL,
            "specificationHash" AE..= puSpecificationHash,
            "specificationAuxiliaryData" AE..= decodeUtf8 (BS16.encode puSpecificationAuxiliaryData)
        ]

instance AE.FromJSON ProtocolUpdate where
    parseJSON = AE.withObject "ProtocolUpdate" $ \v -> do
            puMessage <- v AE..: "message"
            puSpecificationURL <- v AE..: "specificationURL"
            puSpecificationHash <- v AE..: "specificationHash"
            (puSpecificationAuxiliaryData, garbage) <- BS16.decode . encodeUtf8 <$> v AE..: "specificationAuxiliaryData"
            unless (BS.null garbage) $ fail "Unable to parse \"specificationAuxiliaryData\" as Base-16"
            return ProtocolUpdate{..}

-------------------------
-- * Keys collection
-------------------------

-- |A data structure that holds a complete set of update keys. It will be stored
-- in the BlockState.
data UpdateKeysCollection = UpdateKeysCollection {
  rootKeys :: !(HigherLevelKeys RootKeysKind),
  level1Keys :: !(HigherLevelKeys Level1KeysKind),
  level2Keys :: !Authorizations
  } deriving (Eq, Show)

instance Serialize UpdateKeysCollection where
  put UpdateKeysCollection{..} = do
    put rootKeys
    put level1Keys
    put level2Keys
  get = UpdateKeysCollection <$> get <*> get <*> get

instance HashableTo SHA256.Hash UpdateKeysCollection where
  getHash = SHA256.hash . encode

instance Monad m => MHashableTo m SHA256.Hash UpdateKeysCollection where

instance AE.FromJSON UpdateKeysCollection where
  parseJSON = AE.withObject "UpdateKeysCollection" $ \v -> do
    rootKeys <- v .: "rootKeys"
    level1Keys <- v .: "level1Keys"
    level2Keys <- v .: "level2Keys"
    return UpdateKeysCollection{..}

instance AE.ToJSON UpdateKeysCollection where
  toJSON UpdateKeysCollection{..} = AE.object [
    "rootKeys" AE..= rootKeys,
    "level1Keys" AE..= level1Keys,
    "level2Keys" AE..= level2Keys
    ]

-------------------------
-- * Update Instructions
-------------------------

-- |Types of updates to the chain. Used to disambiguate to which queue of updates should the value be pushed.
-- NB: This does not match exactly the update payload. Some update payloads can enqueue in different update queues.
data UpdateType
    = UpdateProtocol
    -- ^Update the chain protocol
    | UpdateElectionDifficulty
    -- ^Update the election difficulty
    | UpdateEuroPerEnergy
    -- ^Update the euro per energy exchange rate
    | UpdateMicroGTUPerEuro
    -- ^Update the microGTU per euro exchange rate
    | UpdateFoundationAccount
    -- ^Update the address of the foundation account
    | UpdateMintDistribution
    -- ^Update the distribution of newly minted GTU
    | UpdateTransactionFeeDistribution
    -- ^Update the distribution of transaction fees
    | UpdateGASRewards
    -- ^Update the GAS rewards
    | UpdateBakerStakeThreshold
    -- ^Minimum amount to register as a baker
    | UpdateRootKeys
    -- ^Update the root keys with the root keys
    | UpdateLevel1Keys
    -- ^Update the level 1 keys
    | UpdateLevel2Keys
    deriving (Eq, Ord, Show, Ix, Bounded, Enum)

-- The JSON instance will encode all values as strings, lower-casing the first
-- character, so, e.g., `toJSON UpdateProtocol = String "updateProtocol"`.
$(deriveJSON defaultOptions{
    constructorTagModifier = firstLower,
    allNullaryToStringTag = True
    }
    ''UpdateType)

instance Serialize UpdateType where
    put UpdateProtocol = putWord8 1
    put UpdateElectionDifficulty = putWord8 2
    put UpdateEuroPerEnergy = putWord8 3
    put UpdateMicroGTUPerEuro = putWord8 4
    put UpdateFoundationAccount = putWord8 5
    put UpdateMintDistribution = putWord8 6
    put UpdateTransactionFeeDistribution = putWord8 7
    put UpdateGASRewards = putWord8 8
    put UpdateBakerStakeThreshold = putWord8 9
    put UpdateRootKeys = putWord8 10
    put UpdateLevel1Keys = putWord8 11
    put UpdateLevel2Keys = putWord8 12
    get = getWord8 >>= \case
        1 -> return UpdateProtocol
        2 -> return UpdateElectionDifficulty
        3 -> return UpdateEuroPerEnergy
        4 -> return UpdateMicroGTUPerEuro
        5 -> return UpdateFoundationAccount
        6 -> return UpdateMintDistribution
        7 -> return UpdateTransactionFeeDistribution
        8 -> return UpdateGASRewards
        9 -> return UpdateBakerStakeThreshold
        10 -> return UpdateRootKeys
        11 -> return UpdateLevel1Keys
        12 -> return UpdateLevel2Keys
        n -> fail $ "invalid update type: " ++ show n

-- |Sequence number for updates of a given type.
type UpdateSequenceNumber = Nonce

-- |Lowest 'UpdateSequenceNumber'.
minUpdateSequenceNumber :: UpdateSequenceNumber
minUpdateSequenceNumber = minNonce

--------------------
-- * Update Header
--------------------

-- |The header for an update instruction, consisting of the
-- sequence number, effective time, expiry time (timeout),
-- and payload size. This structure is the same for all
-- update payload types.
data UpdateHeader = UpdateHeader {
        updateSeqNumber :: !UpdateSequenceNumber,
        updateEffectiveTime :: !TransactionTime,
        updateTimeout :: !TransactionExpiryTime,
        updatePayloadSize :: !PayloadSize
    }
    deriving (Eq, Show)

instance Serialize UpdateHeader where
    put UpdateHeader{..} = do
        put updateSeqNumber
        put updateEffectiveTime
        put updateTimeout
        put updatePayloadSize
    get = do
        updateSeqNumber <- get
        updateEffectiveTime <- get
        updateTimeout <- get
        updatePayloadSize <- get
        return UpdateHeader{..}

--------------------
-- * Update Payload
--------------------

-- |The payload of an update instruction.
data UpdatePayload
    = ProtocolUpdatePayload !ProtocolUpdate
    -- ^Update the protocol
    | ElectionDifficultyUpdatePayload !ElectionDifficulty
    -- ^Update the election difficulty parameter
    | EuroPerEnergyUpdatePayload !ExchangeRate
    -- ^Update the euro-per-energy parameter
    | MicroGTUPerEuroUpdatePayload !ExchangeRate
    -- ^Update the microGTU-per-euro parameter
    | FoundationAccountUpdatePayload !AccountAddress
    -- ^Update the address of the foundation account
    | MintDistributionUpdatePayload !MintDistribution
    -- ^Update the distribution of newly minted GTU
    | TransactionFeeDistributionUpdatePayload !TransactionFeeDistribution
    -- ^Update the distribution of transaction fees
    | GASRewardsUpdatePayload !GASRewards
    -- ^Update the GAS rewards
    | BakerStakeThresholdUpdatePayload !Amount
    -- ^Update the minimum amount to register as a baker
    | RootUpdatePayload !RootUpdate
    -- ^Root level updates
    | Level1UpdatePayload !Level1Update
    -- ^Level 1 update
    deriving (Eq, Show)

instance Serialize UpdatePayload where
    put (ProtocolUpdatePayload u) = putWord8 1 >> put u
    put (ElectionDifficultyUpdatePayload u) = putWord8 2 >> put u
    put (EuroPerEnergyUpdatePayload u) = putWord8 3 >> put u
    put (MicroGTUPerEuroUpdatePayload u) = putWord8 4 >> put u
    put (FoundationAccountUpdatePayload u) = putWord8 5 >> put u
    put (MintDistributionUpdatePayload u) = putWord8 6 >> put u
    put (TransactionFeeDistributionUpdatePayload u) = putWord8 7 >> put u
    put (GASRewardsUpdatePayload u) = putWord8 8 >> put u
    put (BakerStakeThresholdUpdatePayload u) = putWord8 9 >> put u
    put (RootUpdatePayload u) = putWord8 10 >> put u
    put (Level1UpdatePayload u) = putWord8 11 >> put u
    get = getWord8 >>= \case
            1 -> ProtocolUpdatePayload <$> get
            2 -> ElectionDifficultyUpdatePayload <$> get
            3 -> EuroPerEnergyUpdatePayload <$> get
            4 -> MicroGTUPerEuroUpdatePayload <$> get
            5 -> FoundationAccountUpdatePayload <$> get
            6 -> MintDistributionUpdatePayload <$> get
            7 -> TransactionFeeDistributionUpdatePayload <$> get
            8 -> GASRewardsUpdatePayload <$> get
            9 -> BakerStakeThresholdUpdatePayload <$> get
            10 -> RootUpdatePayload <$> get
            11 -> Level1UpdatePayload <$> get
            x -> fail $ "Unknown update payload kind: " ++ show x

$(deriveJSON defaultOptions{
    constructorTagModifier = firstLower . reverse . drop (length ("UpdatePayload" :: String)) . reverse,
    sumEncoding = TaggedObject {tagFieldName = "updateType", contentsFieldName = "update"}
    }
    ''UpdatePayload)

-- |Determine the 'UpdateType' associated with an 'UpdatePayload'.
updateType :: UpdatePayload -> UpdateType
updateType ProtocolUpdatePayload{} = UpdateProtocol
updateType ElectionDifficultyUpdatePayload{} = UpdateElectionDifficulty
updateType EuroPerEnergyUpdatePayload{} = UpdateEuroPerEnergy
updateType MicroGTUPerEuroUpdatePayload{} = UpdateMicroGTUPerEuro
updateType FoundationAccountUpdatePayload{} = UpdateFoundationAccount
updateType MintDistributionUpdatePayload{} = UpdateMintDistribution
updateType TransactionFeeDistributionUpdatePayload{} = UpdateTransactionFeeDistribution
updateType GASRewardsUpdatePayload{} = UpdateGASRewards
updateType BakerStakeThresholdUpdatePayload{} = UpdateBakerStakeThreshold
updateType (RootUpdatePayload RootKeysRootUpdate{}) = UpdateRootKeys
updateType (RootUpdatePayload Level1KeysRootUpdate{}) = UpdateLevel1Keys
updateType (RootUpdatePayload Level2KeysRootUpdate{}) = UpdateLevel2Keys
updateType (Level1UpdatePayload Level1KeysLevel1Update{}) = UpdateLevel1Keys
updateType (Level1UpdatePayload Level2KeysLevel1Update{}) = UpdateLevel2Keys

-- |Extract the relevant set of key indices and threshold authorized for the given update instruction.
extractKeysIndices :: UpdatePayload -> UpdateKeysCollection -> (Set.Set UpdateKeyIndex, UpdateKeysThreshold)
extractKeysIndices p =
  case p of
    ProtocolUpdatePayload{} -> f asProtocol
    ElectionDifficultyUpdatePayload{} -> f asParamElectionDifficulty
    EuroPerEnergyUpdatePayload{} -> f asParamEuroPerEnergy
    MicroGTUPerEuroUpdatePayload{} -> f asParamMicroGTUPerEuro
    FoundationAccountUpdatePayload{} -> f asParamFoundationAccount
    MintDistributionUpdatePayload{} -> f asParamMintDistribution
    TransactionFeeDistributionUpdatePayload{} -> f asParamTransactionFeeDistribution
    GASRewardsUpdatePayload{} -> f asParamGASRewards
    BakerStakeThresholdUpdatePayload{} -> f asBakerStakeThreshold
    RootUpdatePayload{} -> g rootKeys
    Level1UpdatePayload{} -> g level1Keys
  where f v = (\AccessStructure{..} -> (accessPublicKeys, accessThreshold)) . v . level2Keys
        g v = (\HigherLevelKeys{..} -> (Set.fromList $ [0..(fromIntegral $ Vec.length hlkKeys) - 1], hlkThreshold)) . v

-- |Extract the vector of public keys that are authorized for this kind of update. Note
-- that for a level 2 update it will return the whole set of level 2 keys.
extractPubKeys :: UpdatePayload -> UpdateKeysCollection -> Vec.Vector UpdatePublicKey
extractPubKeys p =
  case p of
    RootUpdatePayload{} -> hlkKeys . rootKeys
    Level1UpdatePayload{} -> hlkKeys . level1Keys
    _ -> asKeys . level2Keys

-- |Check that an access structure authorizes the given key set, this means particularly
-- that all the keys are authorized and the number of keys is above the threshold.
checkEnoughKeys ::
  -- |Set of known key indices.
  (Set.Set UpdateKeyIndex, UpdateKeysThreshold) ->
  -- |Set of key indices that signed the update.
  Set.Set UpdateKeyIndex ->
  Bool
checkEnoughKeys (knownIndices, thr) ks =
  let numOfAuthorizedKeysReceived = Set.size (ks `Set.intersection` knownIndices) in
    numOfAuthorizedKeysReceived >= fromIntegral thr
    && numOfAuthorizedKeysReceived == Set.size ks

--------------------
-- * Signatures
--------------------

-- |Hash of an update instruction, as used for signing.
newtype UpdateInstructionSignHashV0 = UpdateInstructionSignHashV0 {v0UpdateInstructionSignHash :: SHA256.Hash}
  deriving newtype (Eq, Ord, Show, Serialize, AE.ToJSON, AE.FromJSON, AE.FromJSONKey, AE.ToJSONKey, Read, Hashable)

-- |Alias for 'UpdateInstructionSignHashV0'.
type UpdateInstructionSignHash = UpdateInstructionSignHashV0

-- |Construct an 'UpdateInstructionSignHash' from the serialized header and payload of
-- an update instruction.
makeUpdateInstructionSignHash ::
    ByteString
    -- ^Serialized update instruction header and payload
    -> UpdateInstructionSignHash
makeUpdateInstructionSignHash body = UpdateInstructionSignHashV0 (SHA256.hash body)

-- |Signatures on an update instruction.
-- The serialization of 'UpdateInstructionSignatures' is uniquely determined.
-- It can't be empty and in that case will be rejected when parsing.
newtype UpdateInstructionSignatures = UpdateInstructionSignatures {
  signatures :: Map.Map UpdateKeyIndex Signature
  } deriving newtype (Eq, Show)

instance Serialize UpdateInstructionSignatures where
    put (UpdateInstructionSignatures m) = do
        putWord16be (fromIntegral (Map.size m))
        putSafeSizedMapOf put put m
    get = do
        sz <- getWord16be
        when (sz == 0) $ fail "signatures must not be empty"
        UpdateInstructionSignatures <$> getSafeSizedMapOf sz get get

-- |Check that a hash is correctly signed by the keys specified by the map indices.
checkCorrectSignatures ::
  UpdateInstructionSignHash ->
  Vec.Vector UpdatePublicKey ->
  UpdateInstructionSignatures ->
  Bool
checkCorrectSignatures signHash keyVec UpdateInstructionSignatures{..} =
  all checkSig $ Map.toList signatures
  where checkSig (i, sig) = case keyVec Vec.!? fromIntegral i of
                              Nothing -> False
                              Just verKey -> verify verKey (encode signHash) sig

--------------------
-- * Update instruction
--------------------

-- |An update instruction.
-- The header must have the correct length of the payload, and the
-- sign hash must be correctly computed (in the appropriate context).
data UpdateInstruction = UpdateInstruction {
        uiHeader :: !UpdateHeader,
        uiPayload :: !UpdatePayload,
        uiSignHash :: !UpdateInstructionSignHashV0,
        uiSignatures :: !UpdateInstructionSignatures
    }
    deriving (Eq, Show)

instance Serialize UpdateInstruction where
    get = do
        ((uiHeader, uiPayload), body) <- getWithBytes $ do
            uiHeader <- get
            uiPayload <- isolate (fromIntegral (updatePayloadSize uiHeader)) get
            return (uiHeader, uiPayload)
        let uiSignHash = makeUpdateInstructionSignHash body
        uiSignatures <- get
        return UpdateInstruction{..}
    put UpdateInstruction{..} = do
        put uiHeader
        put uiPayload
        put uiSignatures

--------------------------------------
-- * Constructing Update Instructions
--------------------------------------

-- |An update instruction without signatures and payload length.
-- This is used for constructing an update instruction.
data RawUpdateInstruction = RawUpdateInstruction {
        ruiSeqNumber :: UpdateSequenceNumber,
        ruiEffectiveTime :: TransactionTime,
        ruiTimeout :: TransactionTime,
        ruiPayload :: UpdatePayload
    } deriving (Eq, Show)

$(deriveJSON defaultOptions{fieldLabelModifier = firstLower . drop 3} ''RawUpdateInstruction)

-- |Serialize a 'RawUpdateInstruction'; used for signing.
putRawUpdateInstruction :: Putter RawUpdateInstruction
putRawUpdateInstruction RawUpdateInstruction{..} = do
        put ruiSeqNumber
        put ruiEffectiveTime
        put ruiTimeout
        putNested putPayloadSize (put ruiPayload)
    where
        putPayloadSize l = put (fromIntegral l :: PayloadSize)

-- |Produce a signature for an update instruction with the given 'UpdateInstructionSignHash'
-- using the supplied keys.
signUpdateInstruction ::
  -- |The hash to sign.
  UpdateInstructionSignHash ->
  -- |The map of keys to use for signing.
  Map.Map UpdateKeyIndex KeyPair ->
  UpdateInstructionSignatures
signUpdateInstruction sh =
  UpdateInstructionSignatures . fmap (\kp -> sign kp (encode sh))

-- |Make an 'UpdateInstruction' by signing a 'RawUpdateInstruction' with the given keys.
makeUpdateInstruction ::
  -- |The raw update instruction
  RawUpdateInstruction ->
  -- |The keys to be used to sign this instruction.
  Map.Map UpdateKeyIndex KeyPair ->
  UpdateInstruction
makeUpdateInstruction rui@RawUpdateInstruction{..} keys = UpdateInstruction {
            uiHeader = UpdateHeader {
                    updateSeqNumber = ruiSeqNumber,
                    updateEffectiveTime = ruiEffectiveTime,
                    updateTimeout = ruiTimeout,
                    updatePayloadSize = fromIntegral (BS.length (encode ruiPayload))
                },
            uiPayload = ruiPayload,
            ..
        }
    where
      uiSignHash = makeUpdateInstructionSignHash (runPut $ putRawUpdateInstruction rui)
      uiSignatures = signUpdateInstruction uiSignHash keys

----------------
-- * Validation
----------------

-- |Check if an update is authorized by the given 'UpdateKeysCollection'.
-- That is, it must have signatures from at least the required threshold of
-- those authorized to perform the given update, and all signatures must be
-- valid and authorized.
checkAuthorizedUpdate
    :: UpdateKeysCollection
    -- ^Current authorizations
    -> UpdateInstruction
    -- ^Instruction to verify
    -> Bool
checkAuthorizedUpdate ukc UpdateInstruction{uiSignatures=u@UpdateInstructionSignatures{..},..} =
      -- check number of authorized keys is above threshold
      checkEnoughKeys (extractKeysIndices uiPayload ukc) (Map.keysSet signatures)
      -- check signatures validate
      && checkCorrectSignatures uiSignHash (extractPubKeys uiPayload ukc) u
