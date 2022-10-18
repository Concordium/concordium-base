{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}

-- |This module defines the genesis data format for the 'P5' protocol version.
module Concordium.Genesis.Data.P5 where

import Data.Serialize
import Data.Word

import Concordium.Common.Version
import qualified Concordium.Crypto.SHA256 as Hash
import qualified Concordium.Genesis.Data.Base as Base
import Concordium.Genesis.Parameters
import Concordium.Types

-- |Initial genesis data for the P5 protocol version.
data GenesisDataP5 = GDP5Initial
    { -- |The immutable genesis parameters.
      genesisCore :: !Base.CoreGenesisParameters,
      -- |Serialized initial block state.
      -- NB: This block state contains some of the same values as 'genesisCore', and they should match.
      genesisInitialState :: !(Base.GenesisState 'P5)
    }
    deriving (Eq, Show)

-- |The regenesis represents a reset of the protocol with a new genesis block.
--  This does not include the full new state, but only its hash.
--
-- The relationship between the new state and the state of the
-- terminal block of the old chain should be defined by the
-- chain update mechanism used.
newtype RegenesisP5 = GDP5Regenesis {genesisRegenesis :: Base.RegenesisData}
    deriving (Eq, Show)

instance Base.BasicGenesisData GenesisDataP5 where
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

instance Base.BasicGenesisData RegenesisP5 where
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

-- |Deserialize genesis data in the V7 format.
getGenesisDataV7 :: Get GenesisDataP5
getGenesisDataV7 =
    getWord8 >>= \case
        0 -> do
            genesisCore <- get
            genesisInitialState <- get
            return GDP5Initial{..}
        _ -> fail "Unrecognized P5 genesis data type."

getRegenesisData :: Get RegenesisP5
getRegenesisData =
    getWord8 >>= \case
        1 -> do
            genesisRegenesis <- Base.getRegenesisData
            return GDP5Regenesis{..}
        _ -> fail "Unrecognized P5 regenesis data type."

-- |Serialize genesis data in the V7 format.
putGenesisDataV7 :: Putter GenesisDataP5
putGenesisDataV7 GDP5Initial{..} = do
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
getGenesisConfigurationV7 :: BlockHash -> Get Base.GenesisConfiguration
getGenesisConfigurationV7 genHash = do
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

-- |Deserialize genesis data with a version tag. The expected version tag is 7
-- and this must be distinct from version tags of other genesis data formats.
getVersionedGenesisData :: Get GenesisDataP5
getVersionedGenesisData =
    getVersion >>= \case
        7 -> getGenesisDataV7
        n -> fail $ "Unsupported genesis data version for P5 genesis: " ++ show n

-- |Serialize genesis data with a version tag.
-- This will use the V7 format.
putVersionedGenesisData :: Putter GenesisDataP5
putVersionedGenesisData gd = do
    putVersion 7
    putGenesisDataV7 gd

parametersToGenesisData :: GenesisParameters 'P5 -> GenesisDataP5
parametersToGenesisData = uncurry GDP5Initial . Base.parametersToState

-- |Compute the block hash of the genesis block with the given genesis data.
-- Every block hash is derived from a message that begins with the block slot,
-- which is 0 for genesis blocks.
--
-- NB: For the regenesis variant the serialized state is not included in the
-- block hash, only the state hash is. This makes it possible to optimize the
-- format in the future since it does not have protocol defined meaning. In
-- contrast, for the initial P5 genesis the initial state is hashed as is.
genesisBlockHash :: GenesisDataP5 -> BlockHash
genesisBlockHash GDP5Initial{..} = BlockHash . Hash.hashLazy . runPutLazy $ do
    put genesisSlot
    put P5
    putWord8 0 -- initial variant
    put genesisCore
    put genesisInitialState

-- |Compute the block hash of the regenesis data as defined by the specified
-- protocol. This becomes the block hash of the genesis block of the new chain
-- after the protocol update.
regenesisBlockHash :: RegenesisP5 -> BlockHash
regenesisBlockHash GDP5Regenesis{genesisRegenesis = Base.RegenesisData{..}} = BlockHash . Hash.hashLazy . runPutLazy $ do
    put genesisSlot
    put P5
    putWord8 1 -- regenesis variant
    put genesisCore
    put genesisFirstGenesis
    put genesisPreviousGenesis
    put genesisTerminalBlock
    put genesisStateHash

-- |The hash of the first genesis block in the chain.
firstGenesisBlockHash :: RegenesisP5 -> BlockHash
firstGenesisBlockHash GDP5Regenesis{genesisRegenesis = Base.RegenesisData{..}} = genesisFirstGenesis

-- |Tag of the genesis data used for serialization.
genesisVariantTag :: GenesisDataP5 -> Word8
genesisVariantTag GDP5Initial{} = 0

-- |Tag of the regenesis variant used for serialization. This tag determines
-- whether the genesis data is, e.g., initial genesis, or regenesis and allows
-- us to deserialize one or the other from the data without knowing a priori what
-- the data is.
regenesisVariantTag :: RegenesisP5 -> Word8
regenesisVariantTag GDP5Regenesis{} = 1
