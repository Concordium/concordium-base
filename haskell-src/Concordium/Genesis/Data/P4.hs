{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}

-- |This module defines the genesis data fromat for the 'P4' protocol version.
module Concordium.Genesis.Data.P4 where

import Data.Serialize

import Concordium.Common.Version
import qualified Concordium.Crypto.SHA256 as Hash
import Concordium.Genesis.Data.Base
import Concordium.Genesis.Parameters
import Concordium.Types
import Concordium.Types.Accounts
import Concordium.Types.Execution

-- |Parameters used to migrate state from protocol version 'P3' to 'P4'.
data StateMigrationParametersP3toP4 = StateMigrationParametersP3toP4
    { -- |The commission rate to apply to bakers on migration.
      migrationDefaultCommissionRate :: !CommissionRates,
      -- |The genesis time of the previous genesis block.
      migrationPreviousGenesisTime :: !Timestamp,
      -- |The duration of an epoch in the previous chain.
      migrationPreviousEpochDuration :: !Duration
    }
    deriving (Eq, Show)

instance Serialize StateMigrationParametersP3toP4 where
    put StateMigrationParametersP3toP4{..} = do
        put migrationDefaultCommissionRate
        put migrationPreviousGenesisTime
        put migrationPreviousEpochDuration
    get = do
        migrationDefaultCommissionRate <- get
        migrationPreviousGenesisTime <- get
        migrationPreviousEpochDuration <- get
        return StateMigrationParametersP3toP4{..}

-- |The baker pool information to assign to existing bakers on migrating from 'P3' to 'P4'.
defaultBakerPoolInfo :: StateMigrationParametersP3toP4 -> BakerPoolInfo
defaultBakerPoolInfo StateMigrationParametersP3toP4{..} =
    BakerPoolInfo
        { _poolOpenStatus = ClosedForAll,
          _poolMetadataUrl = UrlText "",
          _poolCommissionRates = migrationDefaultCommissionRate
        }

-- |Migrate an 'AccountStake' from 'AccountV0' to 'AccountV1', given the 'BakerPoolInfo' to attach
-- to any baker.
migrateAccountStakeV0toV1 ::
    StateMigrationParametersP3toP4 ->
    AccountStake 'AccountV0 ->
    AccountStake 'AccountV1
migrateAccountStakeV0toV1 _ AccountStakeNone = AccountStakeNone
migrateAccountStakeV0toV1
    migration@StateMigrationParametersP3toP4{..}
    (AccountStakeBaker AccountBaker{_accountBakerInfo = BakerInfoExV0 bi, ..}) =
        AccountStakeBaker
            AccountBaker
                { _accountBakerInfo = BakerInfoExV1 bi (defaultBakerPoolInfo migration),
                  _bakerPendingChange = migratePCE <$> _bakerPendingChange,
                  ..
                }
      where
        migratePCE (PendingChangeEffectiveV0 eff) =
            PendingChangeEffectiveV1 $
                addDuration
                    migrationPreviousGenesisTime
                    (migrationPreviousEpochDuration * fromIntegral eff)

-- |Genesis data for the P4 protocol version. The initial variant is here
-- because it might be used in the future, at present it is not used.
data GenesisDataP4
    = GDP4Initial
        { -- |The immutable genesis parameters.
          genesisCore :: !CoreGenesisParameters,
          -- |Serialized initial block state.
          -- NB: This block state contains some of the same values as 'genesisCore', and they should match.
          genesisInitialState :: !GenesisState
        }
    | GDP4MigrateFromP3
        { genesisRegenesis :: !RegenesisData,
          genesisMigration :: StateMigrationParametersP3toP4
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

parametersToGenesisData :: GenesisParameters -> GenesisDataP4
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
