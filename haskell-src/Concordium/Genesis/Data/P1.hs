{-# LANGUAGE DataKinds #-}

-- |This module defines the genesis data format for the 'P1' protocol version.
module Concordium.Genesis.Data.P1 where

import Data.Serialize
import Data.Word

import Concordium.Common.Version
import qualified Concordium.Crypto.SHA256 as Hash
import qualified Concordium.Genesis.Data.Base as Base
import Concordium.Genesis.Parameters
import Concordium.Types

-- |The initial genesis data for the P1 protocol version.
--  It specifies how the initial state should be configured.
--
-- To the extent that the 'CoreGenesisParameters' are represented
-- in the block state, they should agree. (This is probably only
-- the epoch length.)
data GenesisDataP1
    = -- |An initial genesis block.
      GDP1Initial
      { -- |The immutable genesis parameters.
        genesisCore :: !Base.CoreGenesisParameters,
        -- |The blueprint for the initial state at genesis.
        genesisInitialState :: !(Base.GenesisState 'P1)
      }
    deriving (Eq, Show)

-- |The regenesis represents a reset of the protocol with a new genesis block.
--  This does not include the full new state, but only its hash.
--
-- The relationship between the new state and the state of the
-- terminal block of the old chain should be defined by the
-- chain update mechanism used.
newtype RegenesisP1 = GDP1Regenesis {genesisRegenesis :: Base.RegenesisData}

instance Base.BasicGenesisData GenesisDataP1 where
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

instance Base.BasicGenesisData RegenesisP1 where
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

-- |Deserialize genesis data in the V3 format.
getGenesisDataV3 :: Get GenesisDataP1
getGenesisDataV3 =
    getWord8 >>= \case
        0 -> do
            genesisCore <- get
            genesisInitialState <- get
            return GDP1Initial{..}
        _ -> fail "Unrecognised genesis data type"

getRegenesisDataV3 :: Get RegenesisP1
getRegenesisDataV3 =
    getWord8 >>= \case
        1 -> GDP1Regenesis <$> Base.getRegenesisData
        _ -> fail "Unrecognised regenesis data type"

-- |Deserialize genesis configuration from the serialized genesis or regenesis data.
--
-- Note that this will not consume the entire genesis data, only the initial
-- prefix. In particular, in case of initial genesis data it will not read the
-- genesis state.
--
-- The argument is the hash of the genesis data from which the configuration is
-- to be read.
getGenesisConfigurationV3 :: BlockHash -> Get Base.GenesisConfiguration
getGenesisConfigurationV3 genHash = do
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
        _ -> fail "Unrecognised genesis data type"

-- |Serialize genesis data in the V3 format.
putGenesisDataV3 :: Putter GenesisDataP1
putGenesisDataV3 GDP1Initial{..} = do
    putWord8 0
    put genesisCore
    put genesisInitialState

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

parametersToGenesisData :: GenesisParameters 'P1 -> GenesisDataP1
parametersToGenesisData = uncurry GDP1Initial . Base.parametersToState

-- |Compute the block hash of the genesis block with the given genesis data.
-- Every block hash is derived from a message that begins with the block slot,
-- which is 0 for genesis blocks.  For the genesis block, as of 'P1', we include
-- a signifier of the protocol version next.
--
-- Note, for regenesis blocks, the state is only represented by its hash.
genesisBlockHash :: GenesisDataP1 -> BlockHash
genesisBlockHash GDP1Initial{..} = BlockHash . Hash.hashLazy . runPutLazy $ do
    put genesisSlot
    put P1
    putWord8 0 -- Initial
    put genesisCore
    put genesisInitialState

-- |Compute the block hash of the regenesis data as defined by the specified
-- protocol. This becomes the block hash of the genesis block of the new chain
-- after the protocol update.
regenesisBlockHash :: RegenesisP1 -> BlockHash
regenesisBlockHash GDP1Regenesis{genesisRegenesis = Base.RegenesisData{..}} = BlockHash . Hash.hashLazy . runPutLazy $ do
    put genesisSlot
    put P1
    putWord8 1 -- Regenesis
    put genesisCore
    put genesisFirstGenesis
    put genesisPreviousGenesis
    put genesisTerminalBlock
    put genesisStateHash

-- |The hash of the first genesis block in the chain.
firstGenesisBlockHash :: RegenesisP1 -> BlockHash
firstGenesisBlockHash GDP1Regenesis{genesisRegenesis = Base.RegenesisData{..}} = genesisFirstGenesis

-- |Tag of the genesis data used for serialization.
genesisVariantTag :: GenesisDataP1 -> Word8
genesisVariantTag GDP1Initial{} = 0

-- |Tag of the regenesis variant used for serialization. This tag determines
-- whether the genesis data is, e.g., initial genesis, or regenesis and allows
-- us to deserialize one or the other from the data without knowing apriori what
-- the data is.
regenesisVariantTag :: RegenesisP1 -> Word8
regenesisVariantTag GDP1Regenesis{} = 1
