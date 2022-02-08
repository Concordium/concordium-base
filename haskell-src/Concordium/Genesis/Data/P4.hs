-- |This module defines the genesis data format for the 'P4' protocol version.
module Concordium.Genesis.Data.P4 where

import Data.Serialize

import Concordium.Common.Version
import qualified Concordium.Crypto.SHA256 as Hash
import Concordium.Genesis.Data.Base
import Concordium.Genesis.Parameters
import Concordium.Types

-- |Genesis data for the P4 protocol version. The initial variant is here
-- because it might be used in the future, at present it is not used.
data GenesisDataP4
    = GDP4Initial {
      -- |The immutable genesis parameters.
      genesisCore :: !CoreGenesisParameters,
      -- |Serialized initial block state.
      -- NB: This block state contains some of the same values as 'genesisCore', and they should match.
      genesisInitialState :: !GenesisState
    }
    | GDP4Regenesis { genesisRegenesis :: !RegenesisData }
    deriving (Eq, Show)

_core :: GenesisDataP4 -> CoreGenesisParameters
_core GDP4Initial{..} = genesisCore
_core GDP4Regenesis{genesisRegenesis=RegenesisData{..}} = genesisCore

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
genesisBlockHash GDP4Regenesis{genesisRegenesis=RegenesisData{..}} = BlockHash . Hash.hashLazy . runPutLazy $ do
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
