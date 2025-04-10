{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveTraversable #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

-- | Types for chain update instructions, together with basic validation functions.
--  For specification, see: https://concordium.gitlab.io/whitepapers/update-mechanism/main.pdf
--
--  The specification defines the following update types:
--
--    - authorization updates
--    - parameter updates
--    - protocol updates
--    - emergency updates
--
--  Authorization updates alter the set of keys used to authorize chain updates.
--  (Practically, they are a type of parameter update.)
--
--  Parameter updates update a chain parameter.
--  Currently provided parameters are:
--
--    - consensus parameters [these have a common access structure, but separate queues]
--      - for P1-P5: election difficulty
--      - for P6 onwards:
--        - timeout parameters
--        - minimum block time
--        - block energy limit
--    - Energy to Euro exchange rate
--    - GTU to Euro exchange rate
--    - address of the foundation account
--    - parameters for distribution of newly minted tokens
--    - parameters controlling the transaction fee distribution
--    - parameters controlling the GAS account
--    - parameters pertaining to bakers (P1-P3) and baker pools (P4 onwards)
--    - anonymity revokers (append only)
--    - identity providers (append only)
--    - parameters determining cooldown times (P4 onwards)
--    - parameters determining reward period length and mint rate (P4 onwards)
--
--  Each parameter (or parameter group) has an independent update queue.
--  Sequence numbers for each different parameter are thus independent.
--  (Note, where two parameters are tightly coupled, such that one should
--  not be changed independently of the other, then they should be combined
--  as a single parameter.)
--
--  Protocol updates specify a new protocol version.
--  The implementation should stop the current chain when a protocol update takes effect.
--  If it supports the new protocol version, it should begin a new chain according to that protocol,
--  and based on the state when the update took effect.
--
--  Emergency updates are inherently outside the scope of the chain implementation itself.
--  The chain only records the keys authorized for emergency updates, but does
--  not support any kind of emergency update messages.
module Concordium.Types.Updates where

import Control.Monad
import qualified Data.Aeson as AE
import qualified Data.Aeson.Key as AE
import Data.Aeson.TH
import Data.Aeson.Types (
    FromJSON (..),
    ToJSON (..),
    (.:),
 )
import qualified Data.Aeson.Types as AE
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as BS16
import Data.Hashable (Hashable)
import Data.Ix
import qualified Data.Map as Map
import Data.Serialize
import qualified Data.Set as Set
import Data.Singletons
import Data.Text (Text)
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import qualified Data.Vector as Vec
import Data.Word

import qualified Concordium.Crypto.SHA256 as SHA256
import Concordium.Crypto.SignatureScheme

import Concordium.ID.AnonymityRevoker (ArInfo)
import Concordium.ID.IdentityProvider (IpInfo)
import Concordium.Types
import Concordium.Types.HashableTo
import Concordium.Types.Parameters
import Concordium.Utils
import Concordium.Utils.Serialization

----------------

-- * Parameter updates

----------------

--------------------

-- * Update Keys Types

--------------------

-- | Key type for update authorization.
type UpdatePublicKey = VerifyKey

-- | Index of a key in an 'Authorizations'.
type UpdateKeyIndex = Word16

-- | A wrapper over Word16 to ensure on Serialize.get and Aeson.parseJSON that it
--  is not zero and it doesn't exceed the max value.
newtype UpdateKeysThreshold = UpdateKeysThreshold {uktTheThreshold :: Word16}
    deriving newtype (Show, Eq, Enum, Num, Real, Ord, Integral, AE.ToJSON, AE.FromJSON)

instance Serialize UpdateKeysThreshold where
    put = putWord16be . uktTheThreshold
    get = do
        r <- getWord16be
        when (r == 0) $ fail "UpdateKeysThreshold cannot be 0."
        return (UpdateKeysThreshold r)

--------------------

-- * Authorizations updates (Level 2 keys)

--------------------

-- | Access structure for level 2 update authorization.
data AccessStructure = AccessStructure
    { -- | Public keys
      accessPublicKeys :: !(Set.Set UpdateKeyIndex),
      -- | Number of keys required to authorize an update
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

-- | The set of keys authorized for chain updates, together with
--  access structures determining which keys are authorized for
--  which update types. This is the payload of an update to authorization.
data Authorizations (auv :: AuthorizationsVersion) = Authorizations
    { asKeys :: !(Vec.Vector UpdatePublicKey),
      -- | New emergency keys
      asEmergency :: !AccessStructure,
      -- | New protocol update keys
      asProtocol :: !AccessStructure,
      -- | Parameter keys: Consensus parameters
      --  Either 'ConsensusParametersV0' or 'ConsensusParametersV1' depending
      --  on the chain parameter version.
      asParamConsensusParameters :: !AccessStructure,
      -- | Parameter keys: Euro:NRG
      asParamEuroPerEnergy :: !AccessStructure,
      -- | Parameter keys: microGTU:Euro
      asParamMicroGTUPerEuro :: !AccessStructure,
      -- | Parameter keys: foundation account
      asParamFoundationAccount :: !AccessStructure,
      -- | Parameter keys: mint distribution
      asParamMintDistribution :: !AccessStructure,
      -- | Parameter keys: transaction fee distribution
      asParamTransactionFeeDistribution :: !AccessStructure,
      -- | Parameter keys: GAS rewards
      asParamGASRewards :: !AccessStructure,
      -- | Parameter keys: Baker Minimum Threshold/Pool parameters
      asPoolParameters :: !AccessStructure,
      -- | Parameter keys: ArIdentity and ArInfo
      asAddAnonymityRevoker :: !AccessStructure,
      -- | Parameter keys: IdentityProviderIdentity and IpInfo
      asAddIdentityProvider :: !AccessStructure,
      -- | Parameter keys: Cooldown periods for pool owners and delegators
      asCooldownParameters :: !(Conditionally (SupportsCooldownParametersAccessStructure auv) AccessStructure),
      -- | Parameter keys: Length of reward period / payday
      asTimeParameters :: !(Conditionally (SupportsTimeParameters auv) AccessStructure)
    }

deriving instance Eq (Authorizations auv)
deriving instance Show (Authorizations auv)

putAuthorizations :: Putter (Authorizations auv)
putAuthorizations Authorizations{..} = do
    putWord16be (fromIntegral (Vec.length asKeys))
    mapM_ put asKeys
    put asEmergency
    put asProtocol
    put asParamConsensusParameters
    put asParamEuroPerEnergy
    put asParamMicroGTUPerEuro
    put asParamFoundationAccount
    put asParamMintDistribution
    put asParamTransactionFeeDistribution
    put asParamGASRewards
    put asPoolParameters
    put asAddAnonymityRevoker
    put asAddIdentityProvider
    mapM_ put asCooldownParameters
    mapM_ put asTimeParameters

getAuthorizations :: forall auv. (IsAuthorizationsVersion auv) => Get (Authorizations auv)
getAuthorizations = label "deserialization update authorizations" $ do
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
    asParamConsensusParameters <- getChecked
    asParamEuroPerEnergy <- getChecked
    asParamMicroGTUPerEuro <- getChecked
    asParamFoundationAccount <- getChecked
    asParamMintDistribution <- getChecked
    asParamTransactionFeeDistribution <- getChecked
    asParamGASRewards <- getChecked
    asPoolParameters <- getChecked
    asAddAnonymityRevoker <- getChecked
    asAddIdentityProvider <- getChecked
    asCooldownParameters <- conditionallyA (sSupportsCooldownParametersAccessStructure (sing @auv)) getChecked
    asTimeParameters <- conditionallyA (sSupportsTimeParameters (sing @auv)) getChecked
    return Authorizations{..}

instance (IsAuthorizationsVersion auv) => Serialize (Authorizations auv) where
    put = putAuthorizations
    get = getAuthorizations

instance HashableTo SHA256.Hash (Authorizations auv) where
    getHash a = SHA256.hash $ "Authorizations" <> runPut (putAuthorizations a)

instance (Monad m) => MHashableTo m SHA256.Hash (Authorizations auv)

parseAuthorizationsJSON :: forall auv. (IsAuthorizationsVersion auv) => AE.Value -> AE.Parser (Authorizations auv)
parseAuthorizationsJSON = AE.withObject "Authorizations" $ \v -> do
    asKeys <- Vec.fromList <$> v .: "keys"
    let parseAS x =
            v
                .: x
                >>= AE.withObject
                    (AE.toString x)
                    ( \o -> do
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
    asParamEuroPerEnergy <- parseAS "euroPerEnergy"
    asParamMicroGTUPerEuro <- parseAS "microGTUPerEuro"
    -- Note: the consensus parameters is encoded as "electionDifficulty" for backwards compatibility
    asParamConsensusParameters <- parseAS "electionDifficulty"
    asParamFoundationAccount <- parseAS "foundationAccount"
    asParamMintDistribution <- parseAS "mintDistribution"
    asParamTransactionFeeDistribution <- parseAS "transactionFeeDistribution"
    asParamGASRewards <- parseAS "paramGASRewards"
    asPoolParameters <- parseAS "poolParameters"
    asAddAnonymityRevoker <- parseAS "addAnonymityRevoker"
    asAddIdentityProvider <- parseAS "addIdentityProvider"
    let auv = sing @auv
    asCooldownParameters <- conditionallyA (sSupportsCooldownParametersAccessStructure auv) $ parseAS "cooldownParameters"
    asTimeParameters <- conditionallyA (sSupportsTimeParameters auv) $ parseAS "timeParameters"
    return Authorizations{..}

instance (IsAuthorizationsVersion auv) => AE.FromJSON (Authorizations auv) where
    parseJSON = parseAuthorizationsJSON

instance (IsAuthorizationsVersion auv) => AE.ToJSON (Authorizations auv) where
    toJSON Authorizations{..} =
        AE.object
            ( [ "keys" AE..= Vec.toList asKeys,
                "emergency" AE..= t asEmergency,
                "protocol" AE..= t asProtocol,
                -- Note: "electionDifficulty" is used for backwards compatibility
                "electionDifficulty" AE..= t asParamConsensusParameters,
                "euroPerEnergy" AE..= t asParamEuroPerEnergy,
                "microGTUPerEuro" AE..= t asParamMicroGTUPerEuro,
                "foundationAccount" AE..= t asParamFoundationAccount,
                "mintDistribution" AE..= t asParamMintDistribution,
                "transactionFeeDistribution" AE..= t asParamTransactionFeeDistribution,
                "paramGASRewards" AE..= t asParamGASRewards,
                "poolParameters" AE..= t asPoolParameters,
                "addAnonymityRevoker" AE..= t asAddAnonymityRevoker,
                "addIdentityProvider" AE..= t asAddIdentityProvider
              ]
                ++ cooldownParameters
                ++ timeParameters'
            )
      where
        t AccessStructure{..} =
            AE.object
                [ "authorizedKeys" AE..= accessPublicKeys,
                  "threshold" AE..= accessThreshold
                ]
        cooldownParameters = foldMap (\as -> ["cooldownParameters" AE..= t as]) asCooldownParameters
        timeParameters' = foldMap (\as -> ["timeParameters" AE..= t as]) asTimeParameters

-----------------

-- * Higher Level keys (Root and Level 1 keys)

-----------------

data RootKeysKind
data Level1KeysKind

-- | This data structure will be used for all the updates that update Root or
--  level 1 keys, and to store the authorized keys for those operations. The phantom
--  type has to be either RootKeysKind or Level1KeysKind.
data HigherLevelKeys keyKind = HigherLevelKeys
    { hlkKeys :: !(Vec.Vector UpdatePublicKey),
      hlkThreshold :: !UpdateKeysThreshold
    }
    deriving (Eq, Show)

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
    toJSON HigherLevelKeys{..} =
        AE.object
            [ "keys" AE..= Vec.toList hlkKeys,
              "threshold" AE..= hlkThreshold
            ]

instance HashableTo SHA256.Hash (HigherLevelKeys a) where
    getHash = SHA256.hash . encode

instance (Monad m) => MHashableTo m SHA256.Hash (HigherLevelKeys a)

--------------------

-- * Root update

--------------------

-- | Root updates are the highest kind of updates. They can update every other
--  set of keys, even themselves. They can only be performed by Root level keys.
data RootUpdate
    = -- | Update the root keys
      RootKeysRootUpdate
        { rkruKeys :: !(HigherLevelKeys RootKeysKind)
        }
    | -- | Update the Level 1 keys
      Level1KeysRootUpdate
        { l1kruKeys :: !(HigherLevelKeys Level1KeysKind)
        }
    | -- | Update the Level 2 keys in chain parameters version 0
      Level2KeysRootUpdate
        { l2kruAuthorizations :: !(Authorizations 'AuthorizationsVersion0)
        }
    | -- | Update the level 2 keys in chain parameters version 1 and 2
      Level2KeysRootUpdateV1
        { l2kruAuthorizationsV1 :: !(Authorizations 'AuthorizationsVersion1)
        }
    deriving (Eq, Show)

putRootUpdate :: Putter RootUpdate
putRootUpdate RootKeysRootUpdate{..} = do
    putWord8 0
    put rkruKeys
putRootUpdate Level1KeysRootUpdate{..} = do
    putWord8 1
    put l1kruKeys
putRootUpdate Level2KeysRootUpdate{..} = do
    putWord8 2
    putAuthorizations l2kruAuthorizations
putRootUpdate Level2KeysRootUpdateV1{..} = do
    putWord8 3
    putAuthorizations l2kruAuthorizationsV1

getRootUpdate :: SAuthorizationsVersion auv -> Get RootUpdate
getRootUpdate sauv = label "RootUpdate" $ do
    variant <- getWord8
    case variant of
        0 -> RootKeysRootUpdate <$> get
        1 -> Level1KeysRootUpdate <$> get
        2 | SAuthorizationsVersion0 <- sauv -> Level2KeysRootUpdate <$> getAuthorizations
        3 | SAuthorizationsVersion1 <- sauv -> Level2KeysRootUpdateV1 <$> getAuthorizations
        _ -> fail $ "Unknown variant: " ++ show variant

instance AE.FromJSON RootUpdate where
    parseJSON = AE.withObject "RootUpdate" $ \o -> do
        variant :: Text <- o .: "typeOfUpdate"
        case variant of
            "rootKeysUpdate" -> RootKeysRootUpdate <$> o .: "updatePayload"
            "level1KeysUpdate" -> Level1KeysRootUpdate <$> o .: "updatePayload"
            "level2KeysUpdate" -> Level2KeysRootUpdate <$> o .: "updatePayload"
            "level2KeysUpdateV1" -> Level2KeysRootUpdateV1 <$> o .: "updatePayload"
            _ -> fail $ "Unknown variant: " ++ show variant

instance AE.ToJSON RootUpdate where
    toJSON RootKeysRootUpdate{..} =
        AE.object
            [ "typeOfUpdate" AE..= ("rootKeysUpdate" :: Text),
              "updatePayload" AE..= rkruKeys
            ]
    toJSON Level1KeysRootUpdate{..} =
        AE.object
            [ "typeOfUpdate" AE..= ("level1KeysUpdate" :: Text),
              "updatePayload" AE..= l1kruKeys
            ]
    toJSON Level2KeysRootUpdate{..} =
        AE.object
            [ "typeOfUpdate" AE..= ("level2KeysUpdate" :: Text),
              "updatePayload" AE..= l2kruAuthorizations
            ]
    toJSON Level2KeysRootUpdateV1{..} =
        AE.object
            [ "typeOfUpdate" AE..= ("level2KeysUpdateV1" :: Text),
              "updatePayload" AE..= l2kruAuthorizationsV1
            ]

--------------------

-- * Level 1 updates

--------------------

-- | Level 1 updates are the intermediate update kind. They can update themselves
--  or level 2 keys. They can only be performed by Level 1 keys.
data Level1Update
    = Level1KeysLevel1Update
        { l1kl1uKeys :: !(HigherLevelKeys Level1KeysKind)
        }
    | Level2KeysLevel1Update
        { l2kl1uAuthorizations :: !(Authorizations 'AuthorizationsVersion0)
        }
    | Level2KeysLevel1UpdateV1
        { l2kl1uAuthorizationsV1 :: !(Authorizations 'AuthorizationsVersion1)
        }

deriving instance Eq Level1Update
deriving instance Show Level1Update

putLevel1Update :: Putter Level1Update
putLevel1Update Level1KeysLevel1Update{..} = do
    putWord8 0
    put l1kl1uKeys
putLevel1Update Level2KeysLevel1Update{..} = do
    putWord8 1
    putAuthorizations l2kl1uAuthorizations
putLevel1Update Level2KeysLevel1UpdateV1{..} = do
    putWord8 2
    putAuthorizations l2kl1uAuthorizationsV1

getLevel1Update :: SAuthorizationsVersion auv -> Get Level1Update
getLevel1Update sauv = label "Level1Update" $ do
    variant <- getWord8
    case variant of
        0 -> Level1KeysLevel1Update <$> get
        1 | SAuthorizationsVersion0 <- sauv -> Level2KeysLevel1Update <$> getAuthorizations
        2 | SAuthorizationsVersion1 <- sauv -> Level2KeysLevel1UpdateV1 <$> getAuthorizations
        _ -> fail $ "Unknown variant: " ++ show variant

instance AE.FromJSON Level1Update where
    parseJSON = AE.withObject "Level1Update" $ \o -> do
        variant :: Text <- o .: "typeOfUpdate"
        case variant of
            "level1KeysUpdate" -> Level1KeysLevel1Update <$> o .: "updatePayload"
            "level2KeysUpdate" -> Level2KeysLevel1Update <$> o .: "updatePayload"
            "level2KeysUpdateV1" -> Level2KeysLevel1UpdateV1 <$> o .: "updatePayload"
            _ -> fail $ "Unknown variant: " ++ show variant

instance AE.ToJSON Level1Update where
    toJSON Level1KeysLevel1Update{..} =
        AE.object
            [ "typeOfUpdate" AE..= ("level1KeysUpdate" :: Text),
              "updatePayload" AE..= l1kl1uKeys
            ]
    toJSON Level2KeysLevel1Update{..} =
        AE.object
            [ "typeOfUpdate" AE..= ("level2KeysUpdate" :: Text),
              "updatePayload" AE..= l2kl1uAuthorizations
            ]
    toJSON Level2KeysLevel1UpdateV1{..} =
        AE.object
            [ "typeOfUpdate" AE..= ("level2KeysUpdateV1" :: Text),
              "updatePayload" AE..= l2kl1uAuthorizationsV1
            ]

----------------------

-- * Protocol updates

----------------------

-- | Payload of a protocol update.
data ProtocolUpdate = ProtocolUpdate
    { -- | A brief message about the update
      puMessage :: !Text,
      -- | A URL of a document describing the update
      puSpecificationURL :: !Text,
      -- | SHA256 hash of the specification document
      puSpecificationHash :: !SHA256.Hash,
      -- | Auxiliary data whose interpretation is defined by the new specification
      puSpecificationAuxiliaryData :: !ByteString
    }
    deriving (Eq, Show)

-- | The serialization of a protocol update payload is as follows:
--
--       1. Length of the rest of the payload (Word64)
--       2. UTF-8 encoded textual description: length (Word64) + text (Bytes(length))
--       3. UTF-8 encoded URL of description document: length (Word64) + text (Bytes(length))
--       4. SHA-256 hash of description document
--       5. Uninterpreted bytes for the rest of the payload
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

instance (Monad m) => MHashableTo m SHA256.Hash ProtocolUpdate

instance AE.ToJSON ProtocolUpdate where
    toJSON ProtocolUpdate{..} =
        AE.object
            [ "message" AE..= puMessage,
              "specificationURL" AE..= puSpecificationURL,
              "specificationHash" AE..= puSpecificationHash,
              "specificationAuxiliaryData" AE..= decodeUtf8 (BS16.encode puSpecificationAuxiliaryData)
            ]

instance AE.FromJSON ProtocolUpdate where
    parseJSON = AE.withObject "ProtocolUpdate" $ \v -> do
        puMessage <- v AE..: "message"
        puSpecificationURL <- v AE..: "specificationURL"
        puSpecificationHash <- v AE..: "specificationHash"
        res <- BS16.decode . encodeUtf8 <$> v AE..: "specificationAuxiliaryData"
        case res of
            Right puSpecificationAuxiliaryData -> return ProtocolUpdate{..}
            Left _ -> fail "Unable to parse \"specificationAuxiliaryData\" as Base-16"

-------------------------

-- * Keys collection

-------------------------

-- | A data structure that holds a complete set of update keys. It will be stored
--  in the BlockState.
data UpdateKeysCollection (auv :: AuthorizationsVersion) = UpdateKeysCollection
    { rootKeys :: !(HigherLevelKeys RootKeysKind),
      level1Keys :: !(HigherLevelKeys Level1KeysKind),
      level2Keys :: !(Authorizations auv)
    }
    deriving (Eq, Show)

putUpdateKeysCollection :: Putter (UpdateKeysCollection auv)
putUpdateKeysCollection UpdateKeysCollection{..} = do
    put rootKeys
    put level1Keys
    putAuthorizations level2Keys

getUpdateKeysCollection :: (IsAuthorizationsVersion auv) => Get (UpdateKeysCollection auv)
getUpdateKeysCollection = UpdateKeysCollection <$> get <*> get <*> getAuthorizations

instance (IsAuthorizationsVersion auv) => Serialize (UpdateKeysCollection auv) where
    put = putUpdateKeysCollection
    get = getUpdateKeysCollection

-- | SHA256 hashing instance for `UpdateKeysCollection`
--  Security considerations: It is crucial to use a cryptographic secure hash instance for `UpdateKeysCollection`.
--  The caller must be able to use the resulting hash in security critical application code.
--  Currently the computed hash is used to short circuit the signature verification check of transactions.
instance HashableTo SHA256.Hash (UpdateKeysCollection auv) where
    getHash = SHA256.hash . runPut . putUpdateKeysCollection

-- | Check that the update keys collection matches the given SHA256 hash.
--  Note. See above for more information.
matchesUpdateKeysCollection :: UpdateKeysCollection auv -> SHA256.Hash -> Bool
matchesUpdateKeysCollection ukc h = getHash ukc == h

instance (Monad m) => MHashableTo m SHA256.Hash (UpdateKeysCollection auv)

instance (IsAuthorizationsVersion auv) => AE.FromJSON (UpdateKeysCollection auv) where
    parseJSON = AE.withObject "UpdateKeysCollection" $ \v -> do
        rootKeys <- v .: "rootKeys"
        level1Keys <- v .: "level1Keys"
        level2Keys <- v .: "level2Keys"
        return UpdateKeysCollection{..}

instance (IsAuthorizationsVersion auv) => AE.ToJSON (UpdateKeysCollection auv) where
    toJSON UpdateKeysCollection{..} =
        AE.object
            [ "rootKeys" AE..= rootKeys,
              "level1Keys" AE..= level1Keys,
              "level2Keys" AE..= level2Keys
            ]

-------------------------

-- * Update Instructions

-------------------------

-- | Types of updates to the chain. Used to disambiguate to which queue of updates should the value be pushed.
--  NB: This does not match exactly the update payload. Some update payloads can enqueue in different update queues.
data UpdateType
    = -- | Update the chain protocol
      UpdateProtocol
    | -- | Update the election difficulty
      UpdateElectionDifficulty
    | -- | Update the euro per energy exchange rate
      UpdateEuroPerEnergy
    | -- | Update the microGTU per euro exchange rate
      UpdateMicroGTUPerEuro
    | -- | Update the address of the foundation account
      UpdateFoundationAccount
    | -- | Update the distribution of newly minted GTU
      UpdateMintDistribution
    | -- | Update the distribution of transaction fees
      UpdateTransactionFeeDistribution
    | -- | Update the GAS rewards
      UpdateGASRewards
    | -- | Update for pool parameters (previously baker stake threshold).
      UpdatePoolParameters
    | -- | Add new anonymity revoker
      UpdateAddAnonymityRevoker
    | -- | Add new identity provider
      UpdateAddIdentityProvider
    | -- | Update the root keys with the root keys
      UpdateRootKeys
    | -- | Update the level 1 keys
      UpdateLevel1Keys
    | -- | Update the level 2 keys
      UpdateLevel2Keys
    | -- | Update for cooldown parameters, but not used by chain parameter version 0
      UpdateCooldownParameters
    | -- | Update for time parameters, but not used by chain parameter version 0
      UpdateTimeParameters
    | -- | Update timeout parameters for consensus version 2
      UpdateTimeoutParameters
    | -- | Update minimum block time for consensus version 2
      UpdateMinBlockTime
    | -- | Update block energy limit for consensus version 2
      UpdateBlockEnergyLimit
    | -- | Update the finalization committee parameters for consensus version 2
      UpdateFinalizationCommitteeParameters
    | -- | Update the validator score parameters for consensus version 2
      UpdateValidatorScoreParameters
    | -- | Update creating a protocol level token
      UpdateCreatePLT
    deriving (Eq, Ord, Show, Ix, Bounded, Enum)

-- The JSON instance will encode all values as strings, lower-casing the first
-- character, so, e.g., `toJSON UpdateProtocol = String "updateProtocol"`.
$( deriveJSON
    defaultOptions
        { constructorTagModifier = firstLower,
          allNullaryToStringTag = True
        }
    ''UpdateType
 )

instance Serialize UpdateType where
    put UpdateProtocol = putWord8 1
    put UpdateElectionDifficulty = putWord8 2
    put UpdateEuroPerEnergy = putWord8 3
    put UpdateMicroGTUPerEuro = putWord8 4
    put UpdateFoundationAccount = putWord8 5
    put UpdateMintDistribution = putWord8 6
    put UpdateTransactionFeeDistribution = putWord8 7
    put UpdateGASRewards = putWord8 8
    put UpdatePoolParameters = putWord8 9
    put UpdateRootKeys = putWord8 10
    put UpdateLevel1Keys = putWord8 11
    put UpdateLevel2Keys = putWord8 12
    put UpdateAddAnonymityRevoker = putWord8 13
    put UpdateAddIdentityProvider = putWord8 14
    put UpdateCooldownParameters = putWord8 15
    put UpdateTimeParameters = putWord8 16
    put UpdateTimeoutParameters = putWord8 17
    put UpdateMinBlockTime = putWord8 18
    put UpdateBlockEnergyLimit = putWord8 19
    put UpdateFinalizationCommitteeParameters = putWord8 20
    put UpdateValidatorScoreParameters = putWord8 21
    put UpdateCreatePLT = putWord8 22
    get =
        getWord8 >>= \case
            1 -> return UpdateProtocol
            2 -> return UpdateElectionDifficulty
            3 -> return UpdateEuroPerEnergy
            4 -> return UpdateMicroGTUPerEuro
            5 -> return UpdateFoundationAccount
            6 -> return UpdateMintDistribution
            7 -> return UpdateTransactionFeeDistribution
            8 -> return UpdateGASRewards
            9 -> return UpdatePoolParameters
            10 -> return UpdateRootKeys
            11 -> return UpdateLevel1Keys
            12 -> return UpdateLevel2Keys
            13 -> return UpdateAddAnonymityRevoker
            14 -> return UpdateAddIdentityProvider
            15 -> return UpdateCooldownParameters
            16 -> return UpdateTimeParameters
            17 -> return UpdateTimeoutParameters
            18 -> return UpdateMinBlockTime
            19 -> return UpdateBlockEnergyLimit
            20 -> return UpdateFinalizationCommitteeParameters
            21 -> return UpdateValidatorScoreParameters
            22 -> return UpdateCreatePLT
            n -> fail $ "invalid update type: " ++ show n

-- | Sequence number for updates of a given type.
type UpdateSequenceNumber = Nonce

-- | Lowest 'UpdateSequenceNumber'.
minUpdateSequenceNumber :: UpdateSequenceNumber
minUpdateSequenceNumber = minNonce

--------------------

-- * Update Header

--------------------

-- | The header for an update instruction, consisting of the
--  sequence number, effective time, expiry time (timeout),
--  and payload size. This structure is the same for all
--  update payload types.
data UpdateHeader = UpdateHeader
    { updateSeqNumber :: !UpdateSequenceNumber,
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

-- | The payload of an update instruction.
data UpdatePayload
    = -- | Update the protocol
      ProtocolUpdatePayload !ProtocolUpdate
    | -- | Update the election difficulty parameter
      ElectionDifficultyUpdatePayload !ElectionDifficulty
    | -- | Update the euro-per-energy parameter
      EuroPerEnergyUpdatePayload !ExchangeRate
    | -- | Update the microGTU-per-euro parameter
      MicroGTUPerEuroUpdatePayload !ExchangeRate
    | -- | Update the address of the foundation account
      FoundationAccountUpdatePayload !AccountAddress
    | -- | Update the distribution of newly minted GTU in chain parameters version 0
      MintDistributionUpdatePayload !(MintDistribution 'MintDistributionVersion0)
    | -- | Update the distribution of transaction fees
      TransactionFeeDistributionUpdatePayload !TransactionFeeDistribution
    | -- | Update the GAS rewards (chain parameters versions 0 and 1)
      GASRewardsUpdatePayload !(GASRewards 'GASRewardsVersion0)
    | -- | Update the minimum amount to register as a baker with chain parameter version 0
      BakerStakeThresholdUpdatePayload !(PoolParameters 'ChainParametersV0)
    | -- | Root level update
      RootUpdatePayload !RootUpdate
    | -- | Level 1 update
      Level1UpdatePayload !Level1Update
    | -- | Add an anonymity revoker
      AddAnonymityRevokerUpdatePayload !ArInfo
    | -- | Add an identity provider
      AddIdentityProviderUpdatePayload !IpInfo
    | -- | Cooldown parameters with chain parameter version 1 onwards
      CooldownParametersCPV1UpdatePayload !(CooldownParameters' 'CooldownParametersVersion1)
    | -- | Pool parameters with chain parameter version 1 onwards
      PoolParametersCPV1UpdatePayload !(PoolParameters 'ChainParametersV1)
    | -- | Time parameters with chain parameter version 1 onwards
      TimeParametersCPV1UpdatePayload !TimeParameters
    | -- | Update the distribution of newly minted GTU in chain parameters version 1 onwards
      MintDistributionCPV1UpdatePayload !(MintDistribution 'MintDistributionVersion1)
    | -- | Update the timeout parameters (chain parameters version 2)
      TimeoutParametersUpdatePayload !TimeoutParameters
    | -- | Update the minimum block time (chain parameters version 2)
      MinBlockTimeUpdatePayload !Duration
    | -- | Update block energy limit (chain parameters version 2)
      BlockEnergyLimitUpdatePayload !Energy
    | -- | Update the GAS rewards (chain parameters version 2)
      GASRewardsCPV2UpdatePayload !(GASRewards 'GASRewardsVersion1)
    | -- | Update the finalization committee parameters (chain parameters version 2)
      FinalizationCommitteeParametersUpdatePayload !FinalizationCommitteeParameters
    | -- | Update the validator score parameters (chain parameters version 3)
      ValidatorScoreParametersUpdatePayload !ValidatorScoreParameters
    | -- | Issue a new Protocol Level Token (PLT) (Support starting from protocol version 9)
      CreatePLTUpdatePayload !CreatePLT
    deriving (Eq, Show)

putUpdatePayload :: Putter UpdatePayload
putUpdatePayload (ProtocolUpdatePayload u) = putWord8 1 >> put u
putUpdatePayload (ElectionDifficultyUpdatePayload u) = putWord8 2 >> put u
putUpdatePayload (EuroPerEnergyUpdatePayload u) = putWord8 3 >> put u
putUpdatePayload (MicroGTUPerEuroUpdatePayload u) = putWord8 4 >> put u
putUpdatePayload (FoundationAccountUpdatePayload u) = putWord8 5 >> put u
putUpdatePayload (MintDistributionUpdatePayload u) = putWord8 6 >> put u
putUpdatePayload (TransactionFeeDistributionUpdatePayload u) = putWord8 7 >> put u
putUpdatePayload (GASRewardsUpdatePayload u) = putWord8 8 >> put u
putUpdatePayload (BakerStakeThresholdUpdatePayload u) = putWord8 9 >> putPoolParameters u
putUpdatePayload (RootUpdatePayload u) = putWord8 10 >> putRootUpdate u
putUpdatePayload (Level1UpdatePayload u) = putWord8 11 >> putLevel1Update u
putUpdatePayload (AddAnonymityRevokerUpdatePayload u) = putWord8 12 >> put u
putUpdatePayload (AddIdentityProviderUpdatePayload u) = putWord8 13 >> put u
putUpdatePayload (CooldownParametersCPV1UpdatePayload u) = putWord8 14 >> putCooldownParameters u
putUpdatePayload (PoolParametersCPV1UpdatePayload u) = putWord8 15 >> putPoolParameters u
putUpdatePayload (TimeParametersCPV1UpdatePayload u) = putWord8 16 >> putTimeParameters u
putUpdatePayload (MintDistributionCPV1UpdatePayload u) = putWord8 17 >> put u
putUpdatePayload (TimeoutParametersUpdatePayload u) = putWord8 18 >> put u
putUpdatePayload (MinBlockTimeUpdatePayload u) = putWord8 19 >> put u
putUpdatePayload (BlockEnergyLimitUpdatePayload u) = putWord8 20 >> put u
putUpdatePayload (GASRewardsCPV2UpdatePayload u) = putWord8 21 >> put u
putUpdatePayload (FinalizationCommitteeParametersUpdatePayload u) = putWord8 22 >> put u
putUpdatePayload (ValidatorScoreParametersUpdatePayload u) = putWord8 23 >> put u
putUpdatePayload (CreatePLTUpdatePayload u) = putWord8 24 >> put u

getUpdatePayload :: SProtocolVersion pv -> Get UpdatePayload
getUpdatePayload spv =
    getWord8 >>= \case
        1 -> ProtocolUpdatePayload <$> get
        2
            | isSupported PTElectionDifficulty cpv ->
                ElectionDifficultyUpdatePayload <$> get
        3 -> EuroPerEnergyUpdatePayload <$> get
        4 -> MicroGTUPerEuroUpdatePayload <$> get
        5 -> FoundationAccountUpdatePayload <$> get
        6
            | MintDistributionVersion0 <- mintDistributionVersionFor cpv ->
                MintDistributionUpdatePayload <$> get
        7 -> TransactionFeeDistributionUpdatePayload <$> get
        8 | GASRewardsVersion0 <- gasRewardsVersionFor cpv -> GASRewardsUpdatePayload <$> get
        9
            | PoolParametersVersion0 <- poolParametersVersionFor cpv ->
                BakerStakeThresholdUpdatePayload <$> getPoolParameters SPoolParametersVersion0
        10 -> RootUpdatePayload <$> getRootUpdate (sAuthorizationsVersionFor scpv)
        11 -> Level1UpdatePayload <$> getLevel1Update (sAuthorizationsVersionFor scpv)
        12 -> AddAnonymityRevokerUpdatePayload <$> get
        13 -> AddIdentityProviderUpdatePayload <$> get
        14
            | CooldownParametersVersion1 <- cooldownParametersVersionFor cpv ->
                CooldownParametersCPV1UpdatePayload <$> getCooldownParameters SCooldownParametersVersion1
        15
            | PoolParametersVersion1 <- poolParametersVersionFor cpv ->
                PoolParametersCPV1UpdatePayload <$> getPoolParameters SPoolParametersVersion1
        16
            | isSupported PTTimeParameters cpv ->
                TimeParametersCPV1UpdatePayload <$> getTimeParameters
        17
            | MintDistributionVersion1 <- mintDistributionVersionFor cpv ->
                MintDistributionCPV1UpdatePayload <$> get
        18 | isSupported PTTimeoutParameters cpv -> TimeoutParametersUpdatePayload <$> get
        19 | isSupported PTMinBlockTime cpv -> MinBlockTimeUpdatePayload <$> get
        20 | isSupported PTBlockEnergyLimit cpv -> BlockEnergyLimitUpdatePayload <$> get
        21 | GASRewardsVersion1 <- gasRewardsVersionFor cpv -> GASRewardsCPV2UpdatePayload <$> get
        22 | isSupported PTFinalizationCommitteeParameters cpv -> FinalizationCommitteeParametersUpdatePayload <$> get
        23 | isSupported PTValidatorScoreParameters cpv -> ValidatorScoreParametersUpdatePayload <$> get
        24 | isSupported PTProtocolLevelTokensParameters cpv -> CreatePLTUpdatePayload <$> get
        x -> fail $ "Unknown update payload kind: " ++ show x
  where
    scpv = sChainParametersVersionFor spv
    cpv = demoteChainParameterVersion scpv

$( deriveJSON
    defaultOptions
        { constructorTagModifier = firstLower . reverse . drop (length ("UpdatePayload" :: String)) . reverse,
          sumEncoding = TaggedObject{tagFieldName = "updateType", contentsFieldName = "update"}
        }
    ''UpdatePayload
 )

-- | Determine the 'UpdateType' associated with an 'UpdatePayload'.
updateType :: UpdatePayload -> UpdateType
updateType ProtocolUpdatePayload{} = UpdateProtocol
updateType ElectionDifficultyUpdatePayload{} = UpdateElectionDifficulty
updateType EuroPerEnergyUpdatePayload{} = UpdateEuroPerEnergy
updateType MicroGTUPerEuroUpdatePayload{} = UpdateMicroGTUPerEuro
updateType FoundationAccountUpdatePayload{} = UpdateFoundationAccount
updateType MintDistributionUpdatePayload{} = UpdateMintDistribution
updateType TransactionFeeDistributionUpdatePayload{} = UpdateTransactionFeeDistribution
updateType GASRewardsUpdatePayload{} = UpdateGASRewards
updateType GASRewardsCPV2UpdatePayload{} = UpdateGASRewards
updateType BakerStakeThresholdUpdatePayload{} = UpdatePoolParameters
updateType AddAnonymityRevokerUpdatePayload{} = UpdateAddAnonymityRevoker
updateType AddIdentityProviderUpdatePayload{} = UpdateAddIdentityProvider
updateType CooldownParametersCPV1UpdatePayload{} = UpdateCooldownParameters
updateType PoolParametersCPV1UpdatePayload{} = UpdatePoolParameters
updateType TimeParametersCPV1UpdatePayload{} = UpdateTimeParameters
updateType MintDistributionCPV1UpdatePayload{} = UpdateMintDistribution
updateType (RootUpdatePayload RootKeysRootUpdate{}) = UpdateRootKeys
updateType (RootUpdatePayload Level1KeysRootUpdate{}) = UpdateLevel1Keys
updateType (RootUpdatePayload Level2KeysRootUpdate{}) = UpdateLevel2Keys
updateType (RootUpdatePayload Level2KeysRootUpdateV1{}) = UpdateLevel2Keys
updateType (Level1UpdatePayload Level1KeysLevel1Update{}) = UpdateLevel1Keys
updateType (Level1UpdatePayload Level2KeysLevel1Update{}) = UpdateLevel2Keys
updateType (Level1UpdatePayload Level2KeysLevel1UpdateV1{}) = UpdateLevel2Keys
updateType TimeoutParametersUpdatePayload{} = UpdateTimeoutParameters
updateType MinBlockTimeUpdatePayload{} = UpdateMinBlockTime
updateType BlockEnergyLimitUpdatePayload{} = UpdateBlockEnergyLimit
updateType FinalizationCommitteeParametersUpdatePayload{} = UpdateFinalizationCommitteeParameters
updateType ValidatorScoreParametersUpdatePayload{} = UpdateValidatorScoreParameters
updateType CreatePLTUpdatePayload{} = UpdateCreatePLT

-- | Extract the relevant set of key indices and threshold authorized for the given update instruction.
extractKeysIndices :: UpdatePayload -> UpdateKeysCollection cpv -> (Set.Set UpdateKeyIndex, UpdateKeysThreshold)
extractKeysIndices p =
    case p of
        ProtocolUpdatePayload{} -> getLevel2KeysAndThreshold asProtocol
        ElectionDifficultyUpdatePayload{} -> getLevel2KeysAndThreshold asParamConsensusParameters
        EuroPerEnergyUpdatePayload{} -> getLevel2KeysAndThreshold asParamEuroPerEnergy
        MicroGTUPerEuroUpdatePayload{} -> getLevel2KeysAndThreshold asParamMicroGTUPerEuro
        FoundationAccountUpdatePayload{} -> getLevel2KeysAndThreshold asParamFoundationAccount
        MintDistributionUpdatePayload{} -> getLevel2KeysAndThreshold asParamMintDistribution
        MintDistributionCPV1UpdatePayload{} -> getLevel2KeysAndThreshold asParamMintDistribution
        TransactionFeeDistributionUpdatePayload{} -> getLevel2KeysAndThreshold asParamTransactionFeeDistribution
        GASRewardsUpdatePayload{} -> getLevel2KeysAndThreshold asParamGASRewards
        GASRewardsCPV2UpdatePayload{} -> getLevel2KeysAndThreshold asParamGASRewards
        BakerStakeThresholdUpdatePayload{} -> getLevel2KeysAndThreshold asPoolParameters
        RootUpdatePayload{} -> getHiglerLevelKeysAndThreshold rootKeys
        Level1UpdatePayload{} -> getHiglerLevelKeysAndThreshold level1Keys
        AddAnonymityRevokerUpdatePayload{} -> getLevel2KeysAndThreshold asAddAnonymityRevoker
        AddIdentityProviderUpdatePayload{} -> getLevel2KeysAndThreshold asAddIdentityProvider
        CooldownParametersCPV1UpdatePayload{} -> getOptionalLevel2KeysAndThreshold asCooldownParameters
        PoolParametersCPV1UpdatePayload{} -> getLevel2KeysAndThreshold asPoolParameters
        TimeParametersCPV1UpdatePayload{} -> getOptionalLevel2KeysAndThreshold asTimeParameters
        TimeoutParametersUpdatePayload{} -> getLevel2KeysAndThreshold asParamConsensusParameters
        MinBlockTimeUpdatePayload{} -> getLevel2KeysAndThreshold asParamConsensusParameters
        BlockEnergyLimitUpdatePayload{} -> getLevel2KeysAndThreshold asParamConsensusParameters
        FinalizationCommitteeParametersUpdatePayload{} -> getLevel2KeysAndThreshold asPoolParameters
        ValidatorScoreParametersUpdatePayload{} -> getLevel2KeysAndThreshold asPoolParameters
        -- TODO Not implemented yet, authorization of this update type is planned for a later iteration".
        -- Tracked by issue NOD-701.
        CreatePLTUpdatePayload{} -> const (Set.fromAscList [1, 2], 2)
  where
    getLevel2KeysAndThreshold accessStructure = (\AccessStructure{..} -> (accessPublicKeys, accessThreshold)) . accessStructure . level2Keys
    getOptionalLevel2KeysAndThreshold accessStructure = keysForOParam . accessStructure . level2Keys
    getHiglerLevelKeysAndThreshold v = (\HigherLevelKeys{..} -> (Set.fromList [0 .. fromIntegral (Vec.length hlkKeys) - 1], hlkThreshold)) . v
    -- If the 'AccessStructure' is not supported at the chain parameter version @cpv@, then there are no keys to return.
    keysForOParam :: Conditionally c AccessStructure -> (Set.Set UpdateKeyIndex, UpdateKeysThreshold)
    keysForOParam (CTrue AccessStructure{..}) = (accessPublicKeys, accessThreshold)
    keysForOParam CFalse = (Set.empty, 1)

-- The latter case happens if the UpdateKeysCollection is used with chain parameter version 0 but the update payload is
-- is a cooldown parameter update or a time parameter update, which only exists in chain parameter version 1.
-- Therefore, the empty set with threshold 1 is returned so that checkEnoughKeys will return false in this case.

-- | Extract the vector of public keys that are authorized for this kind of update. Note
--  that for a level 2 update it will return the whole set of level 2 keys.
extractPubKeys :: UpdatePayload -> UpdateKeysCollection cpv -> Vec.Vector UpdatePublicKey
extractPubKeys p =
    case p of
        RootUpdatePayload{} -> hlkKeys . rootKeys
        Level1UpdatePayload{} -> hlkKeys . level1Keys
        _ -> asKeys . level2Keys

-- | Check that an access structure authorizes the given key set, this means particularly
--  that all the keys are authorized and the number of keys is above the threshold.
checkEnoughKeys ::
    -- | Set of known key indices.
    (Set.Set UpdateKeyIndex, UpdateKeysThreshold) ->
    -- | Set of key indices that signed the update.
    Set.Set UpdateKeyIndex ->
    Bool
checkEnoughKeys (knownIndices, thr) ks =
    let numOfAuthorizedKeysReceived = Set.size (ks `Set.intersection` knownIndices)
    in  numOfAuthorizedKeysReceived >= fromIntegral thr
            && numOfAuthorizedKeysReceived == Set.size ks

--------------------

-- * Signatures

--------------------

-- | Hash of an update instruction, as used for signing.
newtype UpdateInstructionSignHashV0 = UpdateInstructionSignHashV0 {v0UpdateInstructionSignHash :: SHA256.Hash}
    deriving newtype (Eq, Ord, Show, Serialize, AE.ToJSON, AE.FromJSON, AE.FromJSONKey, AE.ToJSONKey, Read, Hashable)

-- | Alias for 'UpdateInstructionSignHashV0'.
type UpdateInstructionSignHash = UpdateInstructionSignHashV0

-- | Construct an 'UpdateInstructionSignHash' from the serialized header and payload of
--  an update instruction.
makeUpdateInstructionSignHash ::
    -- | Serialized update instruction header and payload
    ByteString ->
    UpdateInstructionSignHash
makeUpdateInstructionSignHash body = UpdateInstructionSignHashV0 (SHA256.hash body)

-- | Signatures on an update instruction.
--  The serialization of 'UpdateInstructionSignatures' is uniquely determined.
--  It can't be empty and in that case will be rejected when parsing.
newtype UpdateInstructionSignatures = UpdateInstructionSignatures
    { signatures :: Map.Map UpdateKeyIndex Signature
    }
    deriving newtype (Eq, Show)

instance Serialize UpdateInstructionSignatures where
    put (UpdateInstructionSignatures m) = do
        putWord16be (fromIntegral (Map.size m))
        putSafeSizedMapOf put put m
    get = do
        sz <- getWord16be
        when (sz == 0) $ fail "signatures must not be empty"
        UpdateInstructionSignatures <$> getSafeSizedMapOf sz get get

-- | Check that a hash is correctly signed by the keys specified by the map indices.
checkCorrectSignatures ::
    UpdateInstructionSignHash ->
    Vec.Vector UpdatePublicKey ->
    UpdateInstructionSignatures ->
    Bool
checkCorrectSignatures signHash keyVec UpdateInstructionSignatures{..} =
    all checkSig $ Map.toList signatures
  where
    checkSig (i, sig) = case keyVec Vec.!? fromIntegral i of
        Nothing -> False
        Just verKey -> verify verKey (encode signHash) sig

--------------------

-- * Update instruction

--------------------

-- | An update instruction.
--  The header must have the correct length of the payload, and the
--  sign hash must be correctly computed (in the appropriate context).
data UpdateInstruction = UpdateInstruction
    { uiHeader :: !UpdateHeader,
      uiPayload :: !UpdatePayload,
      uiSignHash :: !UpdateInstructionSignHashV0,
      uiSignatures :: !UpdateInstructionSignatures
    }
    deriving (Eq, Show)

getUpdateInstruction :: SProtocolVersion pv -> Get UpdateInstruction
getUpdateInstruction spv = do
    ((uiHeader, uiPayload), body) <- getWithBytes $ do
        uiHeader <- get
        uiPayload <- isolate (fromIntegral (updatePayloadSize uiHeader)) $ getUpdatePayload spv
        return (uiHeader, uiPayload)
    let uiSignHash = makeUpdateInstructionSignHash body
    uiSignatures <- get
    return UpdateInstruction{..}

putUpdateInstruction :: Putter UpdateInstruction
putUpdateInstruction UpdateInstruction{..} = do
    put uiHeader
    putUpdatePayload uiPayload
    put uiSignatures

--------------------------------------

-- * Constructing Update Instructions

--------------------------------------

-- | An update instruction without signatures and payload length.
--  This is used for constructing an update instruction.
data RawUpdateInstruction = RawUpdateInstruction
    { ruiSeqNumber :: UpdateSequenceNumber,
      ruiEffectiveTime :: TransactionTime,
      ruiTimeout :: TransactionTime,
      ruiPayload :: UpdatePayload
    }
    deriving (Eq, Show)

$(deriveJSON defaultOptions{fieldLabelModifier = firstLower . drop 3} ''RawUpdateInstruction)

-- | Serialize a 'RawUpdateInstruction'; used for signing.
putRawUpdateInstruction :: Putter RawUpdateInstruction
putRawUpdateInstruction RawUpdateInstruction{..} = do
    put ruiSeqNumber
    put ruiEffectiveTime
    put ruiTimeout
    putNested putPayloadSize (putUpdatePayload ruiPayload)
  where
    putPayloadSize l = put (fromIntegral l :: PayloadSize)

-- | Produce a signature for an update instruction with the given 'UpdateInstructionSignHash'
--  using the supplied keys.
signUpdateInstruction ::
    -- | The hash to sign.
    UpdateInstructionSignHash ->
    -- | The map of keys to use for signing.
    Map.Map UpdateKeyIndex KeyPair ->
    UpdateInstructionSignatures
signUpdateInstruction sh =
    UpdateInstructionSignatures . fmap (\kp -> sign kp (encode sh))

-- | Make an 'UpdateInstruction' by signing a 'RawUpdateInstruction' with the given keys.
makeUpdateInstruction ::
    -- | The raw update instruction
    RawUpdateInstruction ->
    -- | The keys to be used to sign this instruction.
    Map.Map UpdateKeyIndex KeyPair ->
    UpdateInstruction
makeUpdateInstruction rui@RawUpdateInstruction{..} keys =
    UpdateInstruction
        { uiHeader =
            UpdateHeader
                { updateSeqNumber = ruiSeqNumber,
                  updateEffectiveTime = ruiEffectiveTime,
                  updateTimeout = ruiTimeout,
                  updatePayloadSize = fromIntegral (BS.length (runPut $ putUpdatePayload ruiPayload))
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

-- | Check if an update is authorized by the given 'UpdateKeysCollection'.
--  That is, it must have signatures from at least the required threshold of
--  those authorized to perform the given update, and all signatures must be
--  valid and authorized.
checkAuthorizedUpdate ::
    -- | Current authorizations
    UpdateKeysCollection cpv ->
    -- | Instruction to verify
    UpdateInstruction ->
    Bool
checkAuthorizedUpdate ukc UpdateInstruction{uiSignatures = u@UpdateInstructionSignatures{..}, ..} =
    -- check number of authorized keys is above threshold
    checkEnoughKeys (extractKeysIndices uiPayload ukc) (Map.keysSet signatures)
        -- check signatures validate
        && checkCorrectSignatures uiSignHash (extractPubKeys uiPayload ukc) u
