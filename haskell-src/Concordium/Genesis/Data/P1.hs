-- |This module defines the genesis data fromat for the 'P1' protocol version.
module Concordium.Genesis.Data.P1 where

import Data.ByteString (ByteString)
import Data.Serialize
import qualified Data.Vector as Vec

import Concordium.Common.Version
import qualified Concordium.Crypto.SHA256 as Hash
import Concordium.Genesis.Account
import Concordium.Genesis.Data.Base
import Concordium.Genesis.Parameters
import Concordium.Types
import Concordium.Types.AnonymityRevokers
import Concordium.Types.IdentityProviders
import Concordium.Types.Parameters
import Concordium.Types.Updates
import Concordium.Utils.Serialization

-- |Core parameters that are set at genesis.
data CoreGenesisParameters = CoreGenesisParameters
    { genesisTime :: !Timestamp,
      genesisSlotDuration :: !Duration,
      genesisEpochLength :: !EpochLength,
      genesisMaxBlockEnergy :: !Energy,
      genesisFinalizationParameters :: !FinalizationParameters
    }
    deriving (Eq, Show)

instance Serialize CoreGenesisParameters where
    put CoreGenesisParameters{..} = do
        put genesisTime
        put genesisSlotDuration
        put genesisEpochLength
        put genesisMaxBlockEnergy
        putFinalizationParametersGD3 genesisFinalizationParameters
    get = do
        genesisTime <- get
        genesisSlotDuration <- get
        genesisEpochLength <- get
        genesisMaxBlockEnergy <- get
        genesisFinalizationParameters <- getFinalizationParametersGD3
        return CoreGenesisParameters{..}

-- |Initial state configuration for genesis.
data GenesisState = GenesisState
    { genesisCryptographicParameters :: !CryptographicParameters,
      genesisIdentityProviders :: !IdentityProviders,
      genesisAnonymityRevokers :: !AnonymityRevokers,
      genesisAuthorizations :: !Authorizations,
      genesisChainParameters :: !ChainParameters,
      genesisLeadershipElectionNonce :: !LeadershipElectionNonce,
      genesisAccounts :: !(Vec.Vector GenesisAccount)
    }
    deriving (Eq, Show)

instance Serialize GenesisState where
    put GenesisState{..} = do
        put genesisCryptographicParameters
        put genesisIdentityProviders
        put genesisAnonymityRevokers
        put genesisAuthorizations
        put genesisChainParameters
        put genesisLeadershipElectionNonce
        putLength (length genesisAccounts)
        mapM_ putGenesisAccountGD3 genesisAccounts
    get = do
        genesisCryptographicParameters <- get
        genesisIdentityProviders <- get
        genesisAnonymityRevokers <- get
        genesisAuthorizations <- get
        genesisChainParameters <- get
        genesisLeadershipElectionNonce <- get
        nGenesisAccounts <- getLength
        genesisAccounts <- Vec.replicateM nGenesisAccounts getGenesisAccountGD3
        return GenesisState{..}

-- |Genesis data for the P1 protocol version.
data GenesisDataP1
    = GDP1Initial
        { genesisCore :: !CoreGenesisParameters,
          genesisInitialState :: !GenesisState
        }
    | GDP1Regenesis
        { genesisCore :: !CoreGenesisParameters,
          genesisFirstGenesis :: !BlockHash,
          genesisPreviousGenesis :: !BlockHash,
          genesisTerminalBlock :: !BlockHash,
          genesisStateHash :: !StateHash,
          genesisNewState :: !ByteString
        }
    deriving (Eq, Show)

instance BasicGenesisData GenesisDataP1 where
    gdGenesisTime = genesisTime . genesisCore
    {-# INLINE gdGenesisTime #-}
    gdSlotDuration = genesisSlotDuration . genesisCore
    {-# INLINE gdSlotDuration #-}
    gdMaxBlockEnergy = genesisMaxBlockEnergy . genesisCore
    {-# INLINE gdMaxBlockEnergy #-}
    gdFinalizationParameters = genesisFinalizationParameters . genesisCore
    {-# INLINE gdFinalizationParameters #-}
    gdEpochLength = genesisEpochLength . genesisCore
    {-# INLINE gdEpochLength #-}

-- |Deserialize genesis data in the V3 format.
getGenesisDataV3 :: Get GenesisDataP1
getGenesisDataV3 =
    getWord8 >>= \case
        0 -> do
            genesisCore <- get
            genesisInitialState <- get
            return GDP1Initial{..}
        1 -> do
            genesisCore <- get
            genesisFirstGenesis <- get
            genesisPreviousGenesis <- get
            genesisTerminalBlock <- get
            genesisStateHash <- get
            genesisNewState <- getByteStringLen
            return GDP1Regenesis{..}
        _ -> fail "Unrecognised genesis data type"

-- |Serialize genesis data in the V3 format.
putGenesisDataV3 :: Putter GenesisDataP1
putGenesisDataV3 GDP1Initial{..} = do
    putWord8 0
    put genesisCore
    put genesisInitialState
putGenesisDataV3 GDP1Regenesis{..} = do
    putWord8 1
    put genesisCore
    put genesisFirstGenesis
    put genesisPreviousGenesis
    put genesisTerminalBlock
    put genesisStateHash
    putByteStringLen genesisNewState

-- |Deserialize genesis data with a version tag.
getVersionedGenesisData :: Get GenesisDataP1
getVersionedGenesisData =
    getVersion >>= \case
        3 -> getGenesisDataV3
        n -> fail $ "Unsupported genesis data version: " ++ show n

-- |Serialize genesis data with a version tag.
-- This will use the V3 format.
putVersionedGenesisData :: Putter GenesisDataP1
putVersionedGenesisData gd = do
    putVersion 3
    putGenesisDataV3 gd

-- |Convert 'GenesisParameters' to 'GenesisDataP1'.
-- If some of the parameters are not valid, or inconsistent, this function will
-- raise an exception.
parametersToGenesisData :: GenesisParameters -> GenesisDataP1
parametersToGenesisData GenesisParametersV2{gpChainParameters = GenesisChainParameters{..}, ..} =
    GDP1Initial
        { genesisCore = CoreGenesisParameters{..},
          genesisInitialState = GenesisState{..}
        }
  where
    genesisTime = gpGenesisTime
    genesisSlotDuration = gpSlotDuration
    genesisEpochLength = gpEpochLength
    genesisLeadershipElectionNonce = gpLeadershipElectionNonce
    genesisAccounts = Vec.fromList gpInitialAccounts
    genesisFinalizationParameters = gpFinalizationParameters
    genesisCryptographicParameters = gpCryptographicParameters
    genesisIdentityProviders = gpIdentityProviders
    genesisAnonymityRevokers = gpAnonymityRevokers
    genesisMaxBlockEnergy = gpMaxBlockEnergy
    genesisAuthorizations = gpAuthorizations
    genesisChainParameters =
        makeChainParameters
            gcpElectionDifficulty
            gcpEuroPerEnergy
            gcpMicroGTUPerEuro
            gcpBakerExtraCooldownEpochs
            gcpAccountCreationLimit
            gcpRewardParameters
            foundationAccountIndex
    foundationAccountIndex = case Vec.findIndex ((gcpFoundationAccount ==) . gaAddress) genesisAccounts of
        Nothing -> error "Foundation account is missing"
        Just i -> fromIntegral i

genesisBlockHash :: GenesisDataP1 -> BlockHash
genesisBlockHash GDP1Initial{..} = BlockHash . Hash.hashLazy . runPutLazy $ do
    put genesisSlot
    put P1
    putWord8 0 -- Initial
    put genesisCore
    put genesisInitialState
genesisBlockHash GDP1Regenesis{..} = BlockHash . Hash.hashLazy . runPutLazy $ do
    put genesisSlot
    put P1
    putWord8 1 -- Regenesis
    put genesisCore
    put genesisFirstGenesis
    put genesisPreviousGenesis
    put genesisTerminalBlock
    put genesisStateHash
