{-# LANGUAGE DataKinds #-}

-- |This module defines the genesis data format for the 'P2' protocol version.
module Concordium.Genesis.Data.P2 where

import Data.Serialize
import Data.Word

import Concordium.Common.Version
import qualified Concordium.Crypto.SHA256 as Hash
import Concordium.Genesis.Data.Base
import Concordium.Genesis.Parameters
import Concordium.Types

-- |Genesis data for the P2 protocol version. The initial variant is here
-- because it might be used in the future, at present it is not used.
data GenesisDataP2
    = GDP2Initial {
      -- |The immutable genesis parameters.
      genesisCore :: !CoreGenesisParameters,
      -- |Serialized initial block state.
      -- NB: This block state contains some of the same values as 'genesisCore', and they should match.
      genesisInitialState :: !(GenesisState 'P2)
    }
    | GDP2Regenesis { genesisRegenesis :: !RegenesisData }
    deriving (Eq, Show)

_core :: GenesisDataP2 -> CoreGenesisParameters
_core GDP2Initial{..} = genesisCore
_core GDP2Regenesis{genesisRegenesis=RegenesisData{..}} = genesisCore

instance BasicGenesisData GenesisDataP2 where
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

-- |Deserialize genesis data in the V4 format.
getGenesisDataV4 :: Get GenesisDataP2
getGenesisDataV4 =
    getWord8 >>= \case
        0 -> do
            genesisCore <- get
            genesisInitialState <- get
            return GDP2Initial{..}
        1 -> do
            genesisRegenesis <- getRegenesisData
            return GDP2Regenesis{..}
        _ -> fail "Unrecognized P2 genesis data type."

-- |Serialize genesis data in the V4 format.
putGenesisDataV4 :: Putter GenesisDataP2
putGenesisDataV4 GDP2Initial{..} = do
  putWord8 0
  put genesisCore
  put genesisInitialState
putGenesisDataV4 GDP2Regenesis{..} = do
  putWord8 1
  putRegenesisData genesisRegenesis

-- |Deserialize genesis configuration from the serialized genesis data.
--
-- Note that this will not consume the entire genesis data, only the initial
-- prefix. In particular, in case of initial genesis data it will not read the
-- genesis state.
--
-- The argument is the hash of the genesis data from which the configuration is
-- to be read.
getGenesisConfigurationV4 :: BlockHash -> Get GenesisConfiguration
getGenesisConfigurationV4 genHash = do
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
        _ -> fail "Unrecognised genesis data type"

-- |Deserialize genesis data with a version tag. The expected version tag is 4
-- and this must be distinct from version tags of other genesis data formats.
getVersionedGenesisData :: Get GenesisDataP2
getVersionedGenesisData =
    getVersion >>= \case
        4 -> getGenesisDataV4
        n -> fail $ "Unsupported genesis data version for P2 genesis: " ++ show n

-- |Serialize genesis data with a version tag.
-- This will use the V4 format.
putVersionedGenesisData :: Putter GenesisDataP2
putVersionedGenesisData gd = do
    putVersion 4
    putGenesisDataV4 gd

parametersToGenesisData :: GenesisParameters 'P2 -> GenesisDataP2
parametersToGenesisData = uncurry GDP2Initial . parametersToState

-- |Compute the block hash of the genesis block with the given genesis data.
-- Every block hash is derived from a message that begins with the block slot,
-- which is 0 for genesis blocks.
--
-- NB: For the regenesis variant the serialized state is not included in the
-- block hash, only the state hash is. This makes it possible to optimize the
-- format in the future since it does not have protocol defined meaning. In
-- contrast, for the initial P2 genesis the initial state is hashed as is.
genesisBlockHash :: GenesisDataP2 -> BlockHash
genesisBlockHash GDP2Initial{..} = BlockHash . Hash.hashLazy . runPutLazy $ do
  put genesisSlot
  put P2
  putWord8 0 -- initial variant
  put genesisCore
  put genesisInitialState
genesisBlockHash GDP2Regenesis{genesisRegenesis=RegenesisData{..}} = BlockHash . Hash.hashLazy . runPutLazy $ do
    put genesisSlot
    put P2
    putWord8 1 -- regenesis variant
    -- NB: 'putRegenesisData' is not used since the state serialization does not go into computing the hash.
    -- Only the state hash is used.
    put genesisCore
    put genesisFirstGenesis
    put genesisPreviousGenesis
    put genesisTerminalBlock
    put genesisStateHash

-- |The hash of the first genesis block in the chain.
firstGenesisBlockHash :: GenesisDataP2 -> BlockHash
firstGenesisBlockHash GDP2Regenesis{genesisRegenesis=RegenesisData{..}} = genesisFirstGenesis
firstGenesisBlockHash other@GDP2Initial{} = genesisBlockHash other

-- |Tag of the genesis data used for serialization.
genesisVariantTag :: GenesisDataP2 -> Word8
genesisVariantTag GDP2Initial{} = 0
genesisVariantTag GDP2Regenesis{} = 1
