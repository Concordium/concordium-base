{-# LANGUAGE DataKinds #-}

-- |This module defines the genesis data format for the 'P3' protocol version.
module Concordium.Genesis.Data.P3 where

import Data.Serialize

import Concordium.Common.Version
import qualified Concordium.Crypto.SHA256 as Hash
import Concordium.Genesis.Data.Base
import Concordium.Genesis.Parameters
import Concordium.Types

-- |Genesis data for the P3 protocol version. The initial variant is here
-- because it might be used in the future, at present it is not used.
data GenesisDataP3
    = GDP3Initial {
      -- |The immutable genesis parameters.
      genesisCore :: !CoreGenesisParameters,
      -- |Serialized initial block state.
      -- NB: This block state contains some of the same values as 'genesisCore', and they should match.
      genesisInitialState :: !(GenesisState 'P3)
    }
    | GDP3Regenesis { genesisRegenesis :: !RegenesisData }
    deriving (Eq, Show)

_core :: GenesisDataP3 -> CoreGenesisParameters
_core GDP3Initial{..} = genesisCore
_core GDP3Regenesis{genesisRegenesis=RegenesisData{..}} = genesisCore

instance BasicGenesisData GenesisDataP3 where
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

-- |Deserialize genesis data in the V5 format.
getGenesisDataV5 :: Get GenesisDataP3
getGenesisDataV5 =
    getWord8 >>= \case
        0 -> do
            genesisCore <- get
            genesisInitialState <- get
            return GDP3Initial{..}
        1 -> do
            genesisRegenesis <- getRegenesisData
            return GDP3Regenesis{..}
        _ -> fail "Unrecognized P3 genesis data type."

-- |Serialize genesis data in the V5 format.
putGenesisDataV5 :: Putter GenesisDataP3
putGenesisDataV5 GDP3Initial{..} = do
  putWord8 0
  put genesisCore
  put genesisInitialState
putGenesisDataV5 GDP3Regenesis{..} = do
  putWord8 1
  putRegenesisData genesisRegenesis

-- |Deserialize genesis data with a version tag. The expected version tag is 5
-- and this must be distinct from version tags of other genesis data formats.
getVersionedGenesisData :: Get GenesisDataP3
getVersionedGenesisData =
    getVersion >>= \case
        5 -> getGenesisDataV5
        n -> fail $ "Unsupported genesis data version for P3 genesis: " ++ show n

-- |Serialize genesis data with a version tag.
-- This will use the V5 format.
putVersionedGenesisData :: Putter GenesisDataP3
putVersionedGenesisData gd = do
    putVersion 5
    putGenesisDataV5 gd

parametersToGenesisData :: GenesisParameters 'P3 -> GenesisDataP3
parametersToGenesisData = uncurry GDP3Initial . parametersToState

-- |Compute the block hash of the genesis block with the given genesis data.
-- Every block hash is derived from a message that begins with the block slot,
-- which is 0 for genesis blocks.
--
-- NB: For the regenesis variant the serialized state is not included in the
-- block hash, only the state hash is. This makes it possible to optimize the
-- format in the future since it does not have protocol defined meaning. In
-- contrast, for the initial P3 genesis the initial state is hashed as is.
genesisBlockHash :: GenesisDataP3 -> BlockHash
genesisBlockHash GDP3Initial{..} = BlockHash . Hash.hashLazy . runPutLazy $ do
  put genesisSlot
  put P3
  putWord8 0 -- initial variant
  put genesisCore
  put genesisInitialState
genesisBlockHash GDP3Regenesis{genesisRegenesis=RegenesisData{..}} = BlockHash . Hash.hashLazy . runPutLazy $ do
    put genesisSlot
    put P3
    putWord8 1 -- regenesis variant
    -- NB: 'putRegenesisData' is not used since the state serialization does not go into computing the hash.
    -- Only the state hash is used.
    put genesisCore
    put genesisFirstGenesis
    put genesisPreviousGenesis
    put genesisTerminalBlock
    put genesisStateHash

-- |The hash of the first genesis block in the chain.
firstGenesisBlockHash :: GenesisDataP3 -> BlockHash
firstGenesisBlockHash GDP3Regenesis{genesisRegenesis=RegenesisData{..}} = genesisFirstGenesis
firstGenesisBlockHash other@GDP3Initial{} = genesisBlockHash other
