-- |Common types for genesis data for consensus version 1.
module Concordium.Genesis.Data.BaseV1 where

import Data.Serialize

import Concordium.Types

-- |Core parameters that are set at genesis.
-- These parameters are not updatable (except via protocol update).
-- These apply to consensus version 1.
data CoreGenesisParametersV1 = CoreGenesisParametersV1
    { -- |The nominal time of the genesis block.
      genesisTime :: !Timestamp,
      -- |Duration of an epoch.
      genesisEpochDuration :: !Duration
    }
    deriving (Eq, Show)

instance Serialize CoreGenesisParametersV1 where
    put CoreGenesisParametersV1{..} = do
        put genesisTime
        put genesisEpochDuration
    get = do
        genesisTime <- get
        genesisEpochDuration <- get
        return CoreGenesisParametersV1{..}

-- |Common data in the "regenesis" block, which is the first block of the chain after
-- the protocol update takes effect.
data RegenesisDataV1 = RegenesisDataV1
    { -- |Non-updatable genesis parameters,
      genesisCore :: CoreGenesisParametersV1,
      -- |The hash of the first genesis block in the chain.
      genesisFirstGenesis :: !BlockHash,
      -- |The hash of the preceding (re)genesis block.
      genesisPreviousGenesis :: !BlockHash,
      -- |The hash of the last finalized block that terminated the chain before the
      -- new genesis.
      genesisTerminalBlock :: !BlockHash,
      -- |The hash of the block state for the regenesis.
      -- This is taken from the old protocol version, and should be the state hash of the terminal
      -- block. [Note, in consensus version 0, modifications were applied to the state before
      -- migration. From consensus version 1, we will apply such modifications during migration.]
      genesisStateHash :: !StateHash
    }
    deriving (Eq, Show)

instance Serialize RegenesisDataV1 where
    put RegenesisDataV1{..} = do
        put genesisCore
        put genesisFirstGenesis
        put genesisPreviousGenesis
        put genesisTerminalBlock
        put genesisStateHash
    get = do
        genesisCore <- get
        genesisFirstGenesis <- get
        genesisPreviousGenesis <- get
        genesisTerminalBlock <- get
        genesisStateHash <- get
        return RegenesisDataV1{..}
