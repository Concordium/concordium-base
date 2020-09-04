{-# LANGUAGE BangPatterns, DerivingStrategies, OverloadedStrings, ScopedTypeVariables, TemplateHaskell, StandaloneDeriving, DeriveTraversable, RankNTypes #-}
-- |Types for chain update instructions.
module Concordium.Types.Updates where

import qualified Data.Aeson as AE
import Data.Aeson.TH
import Data.Aeson ((.:))
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

import Concordium.Crypto.SignatureScheme
import qualified Concordium.Crypto.SHA256 as SHA256

import Concordium.Utils
import Concordium.Utils.Serialization
import Concordium.Types
import Concordium.Types.HashableTo

-- |Types of updates to the chain.
data UpdateType
    = UpdateAuthorization
    -- ^Update the access structures that authorize updates
    | UpdateProtocol
    -- ^Update the chain protocol
    | UpdateElectionDifficulty
    -- ^Update the election difficulty
    | UpdateEuroPerEnergy
    -- ^Update the euro per energy exchange rate
    | UpdateMicroGTUPerEuro
    -- ^Update the microGTU per euro exchange rate
    deriving (Eq, Ord, Show, Ix, Bounded, Enum)

instance Serialize UpdateType where
    put UpdateAuthorization = putWord8 0
    put UpdateProtocol = putWord8 1
    put UpdateElectionDifficulty = putWord8 2
    put UpdateEuroPerEnergy = putWord8 3
    put UpdateMicroGTUPerEuro = putWord8 4
    get = getWord8 >>= \case
        0 -> return UpdateAuthorization
        1 -> return UpdateProtocol
        2 -> return UpdateElectionDifficulty
        3 -> return UpdateEuroPerEnergy
        4 -> return UpdateMicroGTUPerEuro
        n -> fail $ "invalid update type: " ++ show n

-- |Key type for update authorization.
type UpdatePublicKey = VerifyKey

type UpdateKeyIndex = Word16

-- |Access structure for update authorization.
data AccessStructure = AccessStructure {
        -- |Public keys
        accessPublicKeys :: !(Set.Set UpdateKeyIndex),
        -- |Number of keys required to authorize an update
        accessThreshold :: !Word16
    }
    deriving (Eq, Show)

instance Serialize AccessStructure where
    put AccessStructure{..} = do
        putWord16be (fromIntegral (Set.size accessPublicKeys))
        mapM_ putWord16be (Set.toAscList accessPublicKeys)
        putWord16be accessThreshold
    get = do
        keyCount <- getWord16be
        accessPublicKeys <- getSafeSizedSetOf keyCount getWord16be
        accessThreshold <- getWord16be
        when (accessThreshold > keyCount) $ fail "invalid threshold"
        return AccessStructure{..}

-- |Check that an access structure authorizes the given key set.
checkKeySet :: AccessStructure -> Set.Set UpdateKeyIndex -> Bool
checkKeySet AccessStructure{..} ks = Set.size (ks `Set.intersection` accessPublicKeys) >= fromIntegral accessThreshold

-- |Sequence number for updates of a given type.
type UpdateSequenceNumber = Nonce

minUpdateSequenceNumber :: UpdateSequenceNumber
minUpdateSequenceNumber = minNonce

-- |Payload of an update to authorization.
data Authorizations = Authorizations {
        asKeys :: !(Vec.Vector UpdatePublicKey),
        -- |New emergency keys
        asEmergency :: !AccessStructure,
        -- |New authorization update keys
        asAuthorization :: !AccessStructure,
        -- |New protocol update keys
        asProtocol :: !AccessStructure,
        -- |Parameter keys: election difficulty
        asParamElectionDifficulty :: !AccessStructure,
        -- |Parameter keys: Euro:NRG
        asParamEuroPerEnergy :: !AccessStructure,
        -- |Parameter keys: microGTU:Euro
        asParamMicroGTUPerEuro :: !AccessStructure
    }
    deriving (Eq, Show)

instance Serialize Authorizations where
    put Authorizations{..} = do
        putWord16be (fromIntegral (Vec.length asKeys))
        mapM_ put asKeys
        put asEmergency
        put asAuthorization
        put asProtocol
        put asParamElectionDifficulty
        put asParamEuroPerEnergy
        put asParamMicroGTUPerEuro
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
        asAuthorization <- getChecked
        asProtocol <- getChecked
        asParamElectionDifficulty <- getChecked
        asParamEuroPerEnergy <- getChecked
        asParamMicroGTUPerEuro <- getChecked
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
                accessThreshold :: Word16 <- o .: "threshold"
                when (fromIntegral accessThreshold > Set.size accessPublicKeys) $
                    fail "invalid threshold"
                case Set.lookupMax accessPublicKeys of
                    Just maxKeyIndex
                        | fromIntegral maxKeyIndex >= Vec.length asKeys -> fail "invalid key index"
                    _ -> return AccessStructure{..}
                )
        asEmergency <- parseAS "emergency"
        asAuthorization <- parseAS "authorization"
        asProtocol <- parseAS "protocol"
        asParamElectionDifficulty <- parseAS "electionDifficulty"
        asParamEuroPerEnergy <- parseAS "euroPerEnergy"
        asParamMicroGTUPerEuro <- parseAS "microGTUPerEuro"
        return Authorizations{..}

instance AE.ToJSON Authorizations where
    toJSON Authorizations{..} = AE.object [
                "keys" AE..= Vec.toList asKeys,
                "emergency" AE..= t asEmergency,
                "authorization" AE..= t asAuthorization,
                "protocol" AE..= t asProtocol,
                "electionDifficulty" AE..= t asParamElectionDifficulty,
                "euroPerEnergy" AE..= t asParamEuroPerEnergy,
                "microGTUPerEuro" AE..= t asParamMicroGTUPerEuro
            ]
        where
            t AccessStructure{..} = AE.object [
                    "authorizedKeys" AE..= accessPublicKeys,
                    "threshold" AE..= accessThreshold
                ]

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

data UpdateHeader = UpdateHeader {
        updateSeqNumber :: UpdateSequenceNumber,
        updateEffectiveTime :: TransactionTime,
        updateTimeout :: TransactionExpiryTime,
        updatePayloadSize :: PayloadSize
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

data UpdatePayload
    = AuthorizationUpdatePayload !Authorizations
    | ProtocolUpdatePayload !ProtocolUpdate
    | ElectionDifficultyUpdatePayload !ElectionDifficulty
    | EuroPerEnergyUpdatePayload !ExchangeRate
    | MicroGTUPerEuroUpdatePayload !ExchangeRate
    deriving (Eq, Show)

instance Serialize UpdatePayload where
    put (AuthorizationUpdatePayload u) = put UpdateAuthorization >> put u
    put (ProtocolUpdatePayload u) = put UpdateProtocol >> put u
    put (ElectionDifficultyUpdatePayload u) = put UpdateElectionDifficulty >> put u
    put (EuroPerEnergyUpdatePayload u) = put UpdateEuroPerEnergy >> put u
    put (MicroGTUPerEuroUpdatePayload u) = put UpdateMicroGTUPerEuro >> put u
    get = get >>= \case
            UpdateAuthorization -> AuthorizationUpdatePayload <$> get
            UpdateProtocol -> ProtocolUpdatePayload <$> get
            UpdateElectionDifficulty -> ElectionDifficultyUpdatePayload <$> get
            UpdateEuroPerEnergy -> EuroPerEnergyUpdatePayload <$> get
            UpdateMicroGTUPerEuro -> MicroGTUPerEuroUpdatePayload <$> get

$(deriveJSON defaultOptions{
    constructorTagModifier = firstLower . reverse . drop (length ("UpdatePayload" :: String)) . reverse,
    sumEncoding = TaggedObject {tagFieldName = "updateType", contentsFieldName = "update"}
    }
    ''UpdatePayload)

updateType :: UpdatePayload -> UpdateType
updateType AuthorizationUpdatePayload{} = UpdateAuthorization
updateType ProtocolUpdatePayload{} = UpdateProtocol
updateType ElectionDifficultyUpdatePayload{} = UpdateElectionDifficulty
updateType EuroPerEnergyUpdatePayload{} = UpdateEuroPerEnergy
updateType MicroGTUPerEuroUpdatePayload{} = UpdateMicroGTUPerEuro

-- |Determine if signatures from the given set of keys would be
-- sufficient to authorize the given update.
checkUpdateAuthorizationKeys :: Authorizations -> UpdatePayload -> Set.Set UpdateKeyIndex -> Bool
checkUpdateAuthorizationKeys Authorizations{..} (AuthorizationUpdatePayload _) ks = checkKeySet asAuthorization ks
checkUpdateAuthorizationKeys Authorizations{..} (ProtocolUpdatePayload _) ks = checkKeySet asProtocol ks
checkUpdateAuthorizationKeys Authorizations{..} (ElectionDifficultyUpdatePayload _) ks = checkKeySet asParamElectionDifficulty ks
checkUpdateAuthorizationKeys Authorizations{..} (EuroPerEnergyUpdatePayload _) ks = checkKeySet asParamEuroPerEnergy ks
checkUpdateAuthorizationKeys Authorizations{..} (MicroGTUPerEuroUpdatePayload _) ks = checkKeySet asParamMicroGTUPerEuro ks

newtype UpdateInstructionSignatures = UpdateInstructionSignatures {updateInstructionSignatures :: Map.Map UpdateKeyIndex Signature}
    deriving newtype (Eq, Show)

instance Serialize UpdateInstructionSignatures where
    put (UpdateInstructionSignatures m) =
        putSafeMapOf (putWord16be . fromIntegral) put put m
    get = do
        sz <- getWord16be
        when (sz == 0) $ fail "signatures must not be empty"
        UpdateInstructionSignatures <$> getSafeSizedMapOf sz get get

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

-- |An update instruction without signatures and payload length.
-- This is used for constructing an update instruction.
data RawUpdateInstruction = RawUpdateInstruction {
        ruiSeqNumber :: UpdateSequenceNumber,
        ruiEffectiveTime :: TransactionTime,
        ruiTimeout :: TransactionTime,
        ruiPayload :: UpdatePayload
    }

putRawUpdateInstruction :: Putter RawUpdateInstruction
putRawUpdateInstruction RawUpdateInstruction{..} = do
        put ruiSeqNumber
        put ruiEffectiveTime
        put ruiTimeout
        putNested putPayloadSize (put ruiPayload)
    where
        putPayloadSize l = put (fromIntegral l :: PayloadSize)

newtype UpdateInstructionSignHashV0 = UpdateInstructionSignHashV0 {v0UpdateInstructionSignHash :: SHA256.Hash}
  deriving newtype (Eq, Ord, Show, Serialize, AE.ToJSON, AE.FromJSON, AE.FromJSONKey, AE.ToJSONKey, Read, Hashable)

type UpdateInstructionSignHash = UpdateInstructionSignHashV0

makeUpdateInstructionSignHash ::
    ByteString
    -- ^Serialized update instruction header and payload
    -> UpdateInstructionSignHash
makeUpdateInstructionSignHash body = UpdateInstructionSignHashV0 (SHA256.hash body)


signUpdateInstruction :: UpdateInstructionSignHash -> Map.Map UpdateKeyIndex KeyPair -> UpdateInstructionSignatures
signUpdateInstruction sh = UpdateInstructionSignatures . fmap (\kp -> sign kp (encode sh))

-- |Make an 'UpdateInstruction' by signing a 'RawUpdateInstruction' with the given keys.
makeUpdateInstruction :: RawUpdateInstruction -> Map.Map UpdateKeyIndex KeyPair -> UpdateInstruction
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

-- |Check if the signatures on an 'UpdateInstruction' are valid with respect
-- to the given 'Authorizations'.
checkUpdateInstructionSignatures
    :: Authorizations
    -- ^Current authorizations
    -> UpdateInstruction
    -- ^Instruction to verify
    -> Bool
checkUpdateInstructionSignatures auth UpdateInstruction{..} = all checkSig sigs
    where
        sigs = Map.toList (updateInstructionSignatures uiSignatures)
        checkSig (i, sig) = case asKeys auth Vec.!? fromIntegral i of
            Nothing -> False
            Just verKey -> verify verKey (encode uiSignHash) sig