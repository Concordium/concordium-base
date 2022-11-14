{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}

-- |This module defines the genesis data format for the 'P4' protocol version.
module Concordium.Genesis.Data.P4 where

import Data.Serialize
import Data.Word

import Concordium.Common.Version
import qualified Concordium.Crypto.SHA256 as Hash
import qualified Concordium.Genesis.Data.Base as Base
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
defaultBakerPoolInfo StateMigrationData{migrationProtocolUpdateData = ProtocolUpdateData{..}} =
    BakerPoolInfo
        { _poolOpenStatus = updateDefaultPoolState,
          _poolMetadataUrl = emptyUrlText,
          _poolCommissionRates = updateDefaultCommissionRate
        }

-- |Initial genesis data for the P4 protocol version.
data GenesisDataP4 = GDP4Initial
    { -- |The immutable genesis parameters.
      genesisCore :: !Base.CoreGenesisParameters,
      -- |Serialized initial block state.
      -- NB: This block state contains some of the same values as 'genesisCore', and they should match.
      genesisInitialState :: !(Base.GenesisState 'P4)
    }
    deriving (Eq, Show)

-- |The regenesis represents a reset of the protocol with a new genesis block.
--  This does not include the full new state, but only its hash.
--
-- The relationship between the new state and the state of the
-- terminal block of the old chain should be defined by the
-- chain update mechanism used.
--
-- There are two variants, one when migrating from P3, and another one for an
-- update from P4 to P4.
data RegenesisP4
    = GDP4MigrateFromP3
        { genesisRegenesis :: !Base.RegenesisData,
          genesisMigration :: !StateMigrationData
        }
    | GDP4Regenesis {genesisRegenesis :: !Base.RegenesisData}
    deriving (Eq, Show)

instance Base.BasicGenesisData GenesisDataP4 where
    gdGenesisTime = Base.genesisTime . genesisCore
    {-# INLINE gdGenesisTime #-}
    gdSlotDuration = Base.genesisSlotDuration . genesisCore
    {-# INLINE gdSlotDuration #-}
    gdMaxBlockEnergy = Base.genesisMaxBlockEnergy . genesisCore
    {-# INLINE gdMaxBlockEnergy #-}
    gdFinalizationParameters = Base.genesisFinalizationParameters . genesisCore
    {-# INLINE gdFinalizationParameters #-}
    gdEpochLength = Base.genesisEpochLength . genesisCore
    {-# INLINE gdEpochLength #-}

instance Base.BasicGenesisData RegenesisP4 where
    gdGenesisTime = Base.genesisTime . Base.genesisCore . genesisRegenesis
    {-# INLINE gdGenesisTime #-}
    gdSlotDuration = Base.genesisSlotDuration . Base.genesisCore . genesisRegenesis
    {-# INLINE gdSlotDuration #-}
    gdMaxBlockEnergy = Base.genesisMaxBlockEnergy . Base.genesisCore . genesisRegenesis
    {-# INLINE gdMaxBlockEnergy #-}
    gdFinalizationParameters = Base.genesisFinalizationParameters . Base.genesisCore . genesisRegenesis
    {-# INLINE gdFinalizationParameters #-}
    gdEpochLength = Base.genesisEpochLength . Base.genesisCore . genesisRegenesis
    {-# INLINE gdEpochLength #-}

-- |Deserialize genesis data in the V6 format.
getGenesisDataV6 :: Get GenesisDataP4
getGenesisDataV6 =
    getWord8 >>= \case
        0 -> do
            genesisCore <- get
            genesisInitialState <- get
            return GDP4Initial{..}
        _ -> fail "Unrecognized P4 genesis data type."

getRegenesisData :: Get RegenesisP4
getRegenesisData =
    getWord8 >>= \case
        1 -> do
            genesisRegenesis <- Base.getRegenesisData
            return GDP4Regenesis{..}
        2 -> do
            genesisRegenesis <- Base.getRegenesisData
            genesisMigration <- get
            return GDP4MigrateFromP3{..}
        _ -> fail "Unrecognized P4 regenesis data type."

-- |Serialize genesis data in the V6 format.
putGenesisDataV6 :: Putter GenesisDataP4
putGenesisDataV6 GDP4Initial{..} = do
    putWord8 0
    put genesisCore
    put genesisInitialState

-- |Deserialize genesis configuration from the serialized genesis **or** regenesis data.
--
-- Note that this will not consume the entire genesis data, only the initial
-- prefix. In particular, in case of initial genesis data it will not read the
-- genesis state.
--
-- The argument is the hash of the genesis data from which the configuration is
-- to be read.
getGenesisConfigurationV6 :: BlockHash -> Get Base.GenesisConfiguration
getGenesisConfigurationV6 genHash = do
    getWord8 >>= \case
        0 -> do
            _gcCore <- get
            return
                Base.GenesisConfiguration
                    { _gcTag = 0,
                      _gcCurrentHash = genHash,
                      _gcFirstGenesis = genHash,
                      ..
                    }
        1 -> do
            _gcCore <- get
            _gcFirstGenesis <- get
            return
                Base.GenesisConfiguration
                    { _gcTag = 1,
                      _gcCurrentHash = genHash,
                      ..
                    }
        2 -> do
            _gcCore <- get
            _gcFirstGenesis <- get
            return
                Base.GenesisConfiguration
                    { _gcTag = 2,
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
parametersToGenesisData = uncurry GDP4Initial . Base.parametersToState

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

-- |Compute the block hash of the regenesis data as defined by the specified
-- protocol. This becomes the block hash of the genesis block of the new chain
-- after the protocol update.
regenesisBlockHash :: RegenesisP4 -> BlockHash
regenesisBlockHash GDP4Regenesis{genesisRegenesis = Base.RegenesisData{..}} = BlockHash . Hash.hashLazy . runPutLazy $ do
    put genesisSlot
    put P4
    putWord8 1 -- regenesis variant
    put genesisCore
    put genesisFirstGenesis
    put genesisPreviousGenesis
    put genesisTerminalBlock
    put genesisStateHash
regenesisBlockHash GDP4MigrateFromP3{genesisRegenesis = Base.RegenesisData{..}, ..} = BlockHash . Hash.hashLazy . runPutLazy $ do
    put genesisSlot
    put P4
    putWord8 2 -- migration from P3 variant
    put genesisCore
    put genesisFirstGenesis
    put genesisPreviousGenesis
    put genesisTerminalBlock
    put genesisStateHash
    put genesisMigration

-- |The hash of the first genesis block in the chain.
firstGenesisBlockHash :: RegenesisP4 -> BlockHash
firstGenesisBlockHash GDP4MigrateFromP3{genesisRegenesis = Base.RegenesisData{..}} = genesisFirstGenesis
firstGenesisBlockHash GDP4Regenesis{genesisRegenesis = Base.RegenesisData{..}} = genesisFirstGenesis

-- |Tag of the genesis data used for serialization.
genesisVariantTag :: GenesisDataP4 -> Word8
genesisVariantTag GDP4Initial{} = 0

-- |Tag of the regenesis variant used for serialization. This tag determines
-- whether the genesis data is, e.g., initial genesis, or regenesis and allows
-- us to deserialize one or the other from the data without knowing apriori what
-- the data is.
regenesisVariantTag :: RegenesisP4 -> Word8
regenesisVariantTag GDP4Regenesis{} = 1
regenesisVariantTag GDP4MigrateFromP3{} = 2
