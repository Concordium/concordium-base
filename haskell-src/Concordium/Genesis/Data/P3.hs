{-# LANGUAGE DataKinds #-}

-- |This module defines the genesis data format for the 'P3' protocol version.
module Concordium.Genesis.Data.P3 where

import Data.Serialize
import Data.Word

import Concordium.Common.Version
import qualified Concordium.Crypto.SHA256 as Hash
import qualified Concordium.Genesis.Data.Base as Base
import Concordium.Genesis.Parameters
import Concordium.Types

-- |Genesis data for the P3 protocol version. The initial variant is here
-- because it might be used in the future, at present it is not used.
data GenesisDataP3 = GDP3Initial
    { -- |The immutable genesis parameters.
      genesisCore :: !Base.CoreGenesisParameters,
      -- |Serialized initial block state.
      -- NB: This block state contains some of the same values as 'genesisCore', and they should match.
      genesisInitialState :: !(Base.GenesisState 'P3)
    }
    deriving (Eq, Show)

-- |The regenesis represents a reset of the protocol with a new genesis block.
--  This does not include the full new state, but only its hash.
--
-- The relationship between the new state and the state of the
-- terminal block of the old chain should be defined by the
-- chain update mechanism used.
newtype RegenesisP3 = GDP3Regenesis {genesisRegenesis :: Base.RegenesisData}
    deriving (Eq, Show)

instance Base.BasicGenesisData GenesisDataP3 where
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

instance Base.BasicGenesisData RegenesisP3 where
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

-- |Deserialize genesis data in the V5 format.
getGenesisDataV5 :: Get GenesisDataP3
getGenesisDataV5 =
    getWord8 >>= \case
        0 -> do
            genesisCore <- get
            genesisInitialState <- get
            return GDP3Initial{..}
        _ -> fail "Unrecognized P3 genesis data type."

getRegenesisDataV5 :: Get RegenesisP3
getRegenesisDataV5 =
    getWord8 >>= \case
        1 -> do
            genesisRegenesis <- Base.getRegenesisData
            return GDP3Regenesis{..}
        _ -> fail "Unrecognized P3 regenesis data type."

-- |Serialize genesis data in the V5 format.
putGenesisDataV5 :: Putter GenesisDataP3
putGenesisDataV5 GDP3Initial{..} = do
    putWord8 0
    put genesisCore
    put genesisInitialState

-- |Deserialize genesis configuration from the serialized genesis data.
--
-- Note that this will not consume the entire genesis data, only the initial
-- prefix. In particular, in case of initial genesis data it will not read the
-- genesis state.
--
-- The argument is the hash of the genesis data from which the configuration is
-- to be read.
getGenesisConfigurationV5 :: BlockHash -> Get Base.GenesisConfiguration
getGenesisConfigurationV5 genHash = do
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
parametersToGenesisData = uncurry GDP3Initial . Base.parametersToState

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

-- |Compute the block hash of the regenesis data as defined by the specified
-- protocol. This becomes the block hash of the genesis block of the new chain
-- after the protocol update.
regenesisBlockHash :: RegenesisP3 -> BlockHash
regenesisBlockHash GDP3Regenesis{genesisRegenesis = Base.RegenesisData{..}} = BlockHash . Hash.hashLazy . runPutLazy $ do
    put genesisSlot
    put P3
    putWord8 1 -- regenesis variant
    put genesisCore
    put genesisFirstGenesis
    put genesisPreviousGenesis
    put genesisTerminalBlock
    put genesisStateHash

-- |The hash of the first genesis block in the chain.
firstGenesisBlockHash :: RegenesisP3 -> BlockHash
firstGenesisBlockHash GDP3Regenesis{genesisRegenesis = Base.RegenesisData{..}} = genesisFirstGenesis

-- |Tag of the genesis data used for serialization.
genesisVariantTag :: GenesisDataP3 -> Word8
genesisVariantTag GDP3Initial{} = 0

-- |Tag of the regenesis variant used for serialization. This tag determines
-- whether the genesis data is, e.g., initial genesis, or regenesis and allows
-- us to deserialize one or the other from the data without knowing apriori what
-- the data is.
regenesisVariantTag :: RegenesisP3 -> Word8
regenesisVariantTag GDP3Regenesis{} = 1
