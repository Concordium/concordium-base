module Concordium.Genesis.Data.Base where

import qualified Data.ByteString as BS
import Data.Serialize

import Concordium.Types
import Concordium.Types.Parameters
import Concordium.Utils.Serialization

-- |A class that provides access to fields of genesis data that
-- are expected to be stable across versions.
class BasicGenesisData gd where
    -- |The genesis time.
    gdGenesisTime :: gd -> Timestamp

    -- |The duration of a slot.
    gdSlotDuration :: gd -> Duration

    -- |The maximum energy per block.
    gdMaxBlockEnergy :: gd -> Energy

    -- |The finalization parameters.
    gdFinalizationParameters :: gd -> FinalizationParameters

    -- |The epoch length in slots
    gdEpochLength :: gd -> EpochLength


-- |Core parameters that are set at genesis.
-- These parameters are not updatable (except via protocol update) and
-- so are specified anew in any regenesis block.
data CoreGenesisParameters = CoreGenesisParameters
    { -- |The nominal time of the genesis block.
      genesisTime :: !Timestamp,
      -- |The duration of each slot.
      genesisSlotDuration :: !Duration,
      -- |Length of a baking epoch.
      genesisEpochLength :: !EpochLength,
      -- |The maximum total energy that may be expended by transactions in a block.
      genesisMaxBlockEnergy :: !Energy,
      -- |The parameters of the finalization protocol.
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

-- | Data in the "regenesis" block, which is the first block of the chain after
-- the protocol update takes effect.
-- It is likely that the data in here will change for future protocol versions, but
-- P1 and P2 updates share it.
data RegenesisData = RegenesisData {
    -- |The immutable genesis parameters.
    -- (These need not be invariant across re-genesis.)
    genesisCore :: !CoreGenesisParameters,
    -- |The hash of the first genesis block in the chain.
    genesisFirstGenesis :: !BlockHash,
    -- |The hash of the preceding (re)genesis block.
    genesisPreviousGenesis :: !BlockHash,
    -- |The hash of the last finalized block that terminated the chain before the
    -- new genesis.
    genesisTerminalBlock :: !BlockHash,
    -- |The hash of the block state for the regenesis.
    genesisStateHash :: !StateHash,
    -- |The serialized block state. This should match the specified hash.
    genesisNewState :: !BS.ByteString
  } deriving(Eq, Show)


getRegenesisData :: Get RegenesisData
getRegenesisData = do
    genesisCore <- get
    genesisFirstGenesis <- get
    genesisPreviousGenesis <- get
    genesisTerminalBlock <- get
    genesisStateHash <- get
    genesisNewState <- getByteStringLen
    return RegenesisData{..}

putRegenesisData :: Putter RegenesisData
putRegenesisData RegenesisData{..} = do
    put genesisCore
    put genesisFirstGenesis
    put genesisPreviousGenesis
    put genesisTerminalBlock
    put genesisStateHash
    putByteStringLen genesisNewState
