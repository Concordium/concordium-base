{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}

-- |This module defines the genesis data format for the 'P4' protocol version.
module Concordium.Genesis.Data.P4 where

import Data.Serialize
import Data.Word

import Concordium.Common.Version
import qualified Concordium.Crypto.SHA256 as Hash
import Concordium.Genesis.Data.Base
import Concordium.Genesis.Parameters
import Concordium.Types
import Concordium.Types.Accounts
import Concordium.Types.Execution
import Concordium.Types.Parameters
import Concordium.Types.Updates

-- |Parameter data type for the 'P3' to 'P4' protocol update.
-- This is provided as a parameter to the protocol update chain update instruction.
data ProtocolUpdateData = ProtocolUpdateData
    { -- |The commission rate to apply to bakers on migration.
      updateDefaultCommissionRate :: !CommissionRates,
      -- |The state of a baking pool on migration.
      updateDefaultPoolState :: !OpenStatus,
      -- |Access structure defining the keys and threshold for cooldown parameter updates.
      updateCooldownParametersAccessStructure :: !AccessStructure,
      -- |Access structure defining the keys and threshold for time parameter updates.
      updateTimeParametersAccessStructure :: !AccessStructure,
      -- |New cooldown parameters.
      updateCooldownParameters :: !(CooldownParameters 'ChainParametersV1),
      -- |New time parameters.
      updateTimeParameters :: !(TimeParameters 'ChainParametersV1),
      -- |New pool parameters
      updatePoolParameters :: !(PoolParameters 'ChainParametersV1)
    }
    deriving (Eq, Show)

instance Serialize ProtocolUpdateData where
    put ProtocolUpdateData{..} = do
        put updateDefaultCommissionRate
        put updateDefaultPoolState
        put updateCooldownParametersAccessStructure
        put updateTimeParametersAccessStructure
        put updateCooldownParameters
        put updateTimeParameters
        put updatePoolParameters
    get = do
        updateDefaultCommissionRate <- get
        updateDefaultPoolState <- get
        updateCooldownParametersAccessStructure <- get
        updateTimeParametersAccessStructure <- get
        updateCooldownParameters <- get
        updateTimeParameters <- get
        updatePoolParameters <- get
        return ProtocolUpdateData{..}

-- |Parameters used to migrate state from protocol version 'P3' to 'P4'.
data StateMigrationData = StateMigrationData
    { -- |Parameters provided by the protocol update instruction.
      migrationProtocolUpdateData :: !ProtocolUpdateData,
      -- |The genesis time of the previous genesis block.
      migrationPreviousGenesisTime :: !Timestamp,
      -- |The duration of an epoch in the previous chain.
      migrationPreviousEpochDuration :: !Duration
    }
    deriving (Eq, Show)

instance Serialize StateMigrationData where
    put StateMigrationData{..} = do
        put migrationProtocolUpdateData
        put migrationPreviousGenesisTime
        put migrationPreviousEpochDuration
    get = do
        migrationProtocolUpdateData <- get
        migrationPreviousGenesisTime <- get
        migrationPreviousEpochDuration <- get
        return StateMigrationData{..}

-- |Construct a 'StateMigrationParametersP3toP4' from a 'ProtocolUpdateData' together with the
-- previous genesis time and previous epoch duration.
makeStateMigrationParametersP3toP4 ::
    ProtocolUpdateData -> Timestamp -> Duration -> StateMigrationData
makeStateMigrationParametersP3toP4
    migrationProtocolUpdateData
    migrationPreviousGenesisTime
    migrationPreviousEpochDuration =
        StateMigrationData{..}

-- |The baker pool information to assign to existing bakers on migrating from 'P3' to 'P4'.
defaultBakerPoolInfo :: StateMigrationData -> BakerPoolInfo
defaultBakerPoolInfo StateMigrationData{migrationProtocolUpdateData=ProtocolUpdateData{..}} =
    BakerPoolInfo
        { _poolOpenStatus = updateDefaultPoolState,
          _poolMetadataUrl = emptyUrlText,
          _poolCommissionRates = updateDefaultCommissionRate
        }

-- |Genesis data for the P4 protocol version. The initial variant is here
-- because it might be used in the future, at present it is not used.
data GenesisDataP4
    = GDP4Initial
        { -- |The immutable genesis parameters.
          genesisCore :: !CoreGenesisParameters,
          -- |Serialized initial block state.
          -- NB: This block state contains some of the same values as 'genesisCore', and they should match.
          genesisInitialState :: !(GenesisState 'P4)
        }
    | GDP4MigrateFromP3
        { genesisRegenesis :: !RegenesisData,
          genesisMigration :: !StateMigrationData
        }
    | GDP4Regenesis {genesisRegenesis :: !RegenesisData}
    deriving (Eq, Show)

_core :: GenesisDataP4 -> CoreGenesisParameters
_core GDP4Initial{..} = genesisCore
_core GDP4MigrateFromP3{genesisRegenesis = RegenesisData{..}} = genesisCore
_core GDP4Regenesis{genesisRegenesis = RegenesisData{..}} = genesisCore

instance BasicGenesisData GenesisDataP4 where
    gdGenesisTime = genesisTime . _core
    {-# INLINE gdGenesisTime #-}
    gdSlotDuration = genesisSlotDuration . _core
    {-# INLINE gdSlotDuration #-}
    gdMaxBlockEnergy = genesisMaxBlockEnergy . _core
    {-# INLINE gdMaxBlockEnergy #-}
    gdFinalizationParameters = genesisFinalizationParameters . _core
    {-# INLINE gdFinalizationParameters #-}
    gdEpochLength = genesisEpochLength . _core
    {-# INLINE gdEpochLength #-}

-- |Deserialize genesis data in the V6 format.
getGenesisDataV6 :: Get GenesisDataP4
getGenesisDataV6 =
    getWord8 >>= \case
        0 -> do
            genesisCore <- get
            genesisInitialState <- get
            return GDP4Initial{..}
        1 -> do
            genesisRegenesis <- getRegenesisData
            return GDP4Regenesis{..}
        2 -> do
            genesisRegenesis <- getRegenesisData
            genesisMigration <- get
            return GDP4MigrateFromP3{..}
        _ -> fail "Unrecognized P4 genesis data type."

-- |Serialize genesis data in the V6 format.
putGenesisDataV6 :: Putter GenesisDataP4
putGenesisDataV6 GDP4Initial{..} = do
    putWord8 0
    put genesisCore
    put genesisInitialState
putGenesisDataV6 GDP4Regenesis{..} = do
    putWord8 1
    putRegenesisData genesisRegenesis
putGenesisDataV6 GDP4MigrateFromP3{..} = do
    putWord8 2
    putRegenesisData genesisRegenesis
    put genesisMigration

-- |Deserialize genesis configuration from the serialized genesis data.
--
-- Note that this will not consume the entire genesis data, only the initial
-- prefix. In particular, in case of initial genesis data it will not read the
-- genesis state.
--
-- The argument is the hash of the genesis data from which the configuration is
-- to be read.
getGenesisConfigurationV6 :: BlockHash -> Get GenesisConfiguration
getGenesisConfigurationV6 genHash = do
    getWord8 >>= \case
        0 -> do
            _gcCore <- get
            return GenesisConfiguration{
                _gcTag = 0,
                _gcCurrentHash = genHash,
                _gcFirstGenesis = genHash,
                ..
                }
        1 -> do
          _gcCore <- get
          _gcFirstGenesis <- get
          return GenesisConfiguration{
            _gcTag = 1,
            _gcCurrentHash = genHash,
            ..
            }
        2 -> do
          _gcCore <- get
          _gcFirstGenesis <- get
          return GenesisConfiguration{
            _gcTag = 2,
            _gcCurrentHash = genHash,
            ..
            }
        _ -> fail "Unrecognised genesis data type"

-- |Deserialize genesis data with a version tag. The expected version tag is 6
-- and this must be distinct from version tags of other genesis data formats.
getVersionedGenesisData :: Get GenesisDataP4
getVersionedGenesisData =
    getVersion >>= \case
        6 -> getGenesisDataV6
        n -> fail $ "Unsupported genesis data version for P4 genesis: " ++ show n

-- |Serialize genesis data with a version tag.
-- This will use the V6 format.
putVersionedGenesisData :: Putter GenesisDataP4
putVersionedGenesisData gd = do
    putVersion 6
    putGenesisDataV6 gd

parametersToGenesisData :: GenesisParameters 'P4 -> GenesisDataP4
parametersToGenesisData = uncurry GDP4Initial . parametersToState

-- |Compute the block hash of the genesis block with the given genesis data.
-- Every block hash is derived from a message that begins with the block slot,
-- which is 0 for genesis blocks.
--
-- NB: For the regenesis variant the serialized state is not included in the
-- block hash, only the state hash is. This makes it possible to optimize the
-- format in the future since it does not have protocol defined meaning. In
-- contrast, for the initial P4 genesis the initial state is hashed as is.
genesisBlockHash :: GenesisDataP4 -> BlockHash
genesisBlockHash GDP4Initial{..} = BlockHash . Hash.hashLazy . runPutLazy $ do
    put genesisSlot
    put P4
    putWord8 0 -- initial variant
    put genesisCore
    put genesisInitialState
genesisBlockHash GDP4Regenesis{genesisRegenesis = RegenesisData{..}} = BlockHash . Hash.hashLazy . runPutLazy $ do
    put genesisSlot
    put P4
    putWord8 1 -- regenesis variant
    -- NB: 'putRegenesisData' is not used since the state serialization does not go into computing the hash.
    -- Only the state hash is used.
    put genesisCore
    put genesisFirstGenesis
    put genesisPreviousGenesis
    put genesisTerminalBlock
    put genesisStateHash
genesisBlockHash GDP4MigrateFromP3{genesisRegenesis = RegenesisData{..}, ..} = BlockHash . Hash.hashLazy . runPutLazy $ do
    put genesisSlot
    put P4
    putWord8 2 -- migration from P3 variant
    -- NB: 'putRegenesisData' is not used since the state serialization does not go into computing the hash.
    -- Only the state hash is used.
    put genesisCore
    put genesisFirstGenesis
    put genesisPreviousGenesis
    put genesisTerminalBlock
    put genesisStateHash
    put genesisMigration

-- |The hash of the first genesis block in the chain.
firstGenesisBlockHash :: GenesisDataP4 -> BlockHash
firstGenesisBlockHash GDP4Regenesis{genesisRegenesis=RegenesisData{..}} = genesisFirstGenesis
firstGenesisBlockHash GDP4MigrateFromP3{genesisRegenesis=RegenesisData{..}} = genesisFirstGenesis
firstGenesisBlockHash other@GDP4Initial{} = genesisBlockHash other

-- |Tag of the genesis data used for serialization.
genesisVariantTag :: GenesisDataP4 -> Word8
genesisVariantTag GDP4Initial{} = 0
genesisVariantTag GDP4Regenesis{} = 1
genesisVariantTag GDP4MigrateFromP3{} = 2
