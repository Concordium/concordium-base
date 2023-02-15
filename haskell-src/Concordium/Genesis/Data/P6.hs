{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}

-- |This module defines the genesis data format for the 'P6' protocol version.
module Concordium.Genesis.Data.P6 where

import Data.Serialize
import Data.Word

import Concordium.Common.Version
import qualified Concordium.Crypto.SHA256 as Hash
import qualified Concordium.Genesis.Data.Base as Base
import qualified Concordium.Genesis.Data.BaseV1 as BaseV1
import Concordium.Types

-- |Initial genesis data for the P6 protocol version.
data GenesisDataP6 = GDP6Initial
    { -- |The immutable genesis parameters.
      genesisCore :: !BaseV1.CoreGenesisParametersV1,
      -- |Serialized initial block state.
      -- NB: This block state contains some of the same values as 'genesisCore', and they should match.
      genesisInitialState :: !(Base.GenesisState 'P6)
    }
    deriving (Eq, Show)

-- |The regenesis represents a reset of the protocol with a new genesis block.
--  This does not include the full new state, but only its hash.
--
-- The relationship between the new state and the state of the
-- terminal block of the old chain should be defined by the
-- chain update mechanism used.
newtype RegenesisP6 = GDP6Regenesis {genesisRegenesis :: BaseV1.RegenesisDataV1}
    deriving (Eq, Show)

-- |Deserialize genesis data in the V8 format.
getGenesisDataV8 :: Get GenesisDataP6
getGenesisDataV8 =
    getWord8 >>= \case
        0 -> do
            genesisCore <- get
            genesisInitialState <- get
            return GDP6Initial{..}
        _ -> fail "Unrecognized P6 genesis data type."

getRegenesisData :: Get RegenesisP6
getRegenesisData =
    getWord8 >>= \case
        1 -> do
            genesisRegenesis <- get
            return GDP6Regenesis{..}
        _ -> fail "Unrecognized P6 regenesis data type."

-- |Serialize genesis data in the V8 format.
putGenesisDataV8 :: Putter GenesisDataP6
putGenesisDataV8 GDP6Initial{..} = do
    putWord8 0
    put genesisCore
    put genesisInitialState

-- |Deserialize genesis data with a version tag. The expected version tag is 8
-- and this must be distinct from version tags of other genesis data formats.
getVersionedGenesisData :: Get GenesisDataP6
getVersionedGenesisData =
    getVersion >>= \case
        8 -> getGenesisDataV8
        n -> fail $ "Unsupported genesis data version for P6 genesis: " ++ show n

-- |Serialize genesis data with a version tag.
-- This will use the V8 format.
putVersionedGenesisData :: Putter GenesisDataP6
putVersionedGenesisData gd = do
    putVersion 8
    putGenesisDataV8 gd

-- |Compute the block hash of the genesis block with the given genesis data.
-- Every block hash is derived from a message that begins with the block slot,
-- which is 0 for genesis blocks.
--
-- NB: For the regenesis variant the serialized state is not included in the
-- block hash, only the state hash is. This makes it possible to optimize the
-- format in the future since it does not have protocol defined meaning. In
-- contrast, for the initial P6 genesis the initial state is hashed as is.
genesisBlockHash :: GenesisDataP6 -> BlockHash
genesisBlockHash GDP6Initial{..} = BlockHash . Hash.hashLazy . runPutLazy $ do
    put genesisSlot
    put P6
    putWord8 0 -- initial variant
    put genesisCore
    put genesisInitialState

-- |Compute the block hash of the regenesis data as defined by the specified
-- protocol. This becomes the block hash of the genesis block of the new chain
-- after the protocol update.
regenesisBlockHash :: RegenesisP6 -> BlockHash
regenesisBlockHash GDP6Regenesis{genesisRegenesis = BaseV1.RegenesisDataV1{..}} = BlockHash . Hash.hashLazy . runPutLazy $ do
    put genesisSlot
    put P6
    putWord8 1 -- regenesis variant
    put genesisCore
    put genesisFirstGenesis
    put genesisPreviousGenesis
    put genesisTerminalBlock
    put genesisStateHash

-- |The hash of the first genesis block in the chain.
firstGenesisBlockHash :: RegenesisP6 -> BlockHash
firstGenesisBlockHash GDP6Regenesis{genesisRegenesis = BaseV1.RegenesisDataV1{..}} = genesisFirstGenesis

-- |Tag of the genesis data used for serialization.
genesisVariantTag :: GenesisDataP6 -> Word8
genesisVariantTag GDP6Initial{} = 0

-- |Tag of the regenesis variant used for serialization. This tag determines
-- whether the genesis data is, e.g., initial genesis, or regenesis and allows
-- us to deserialize one or the other from the data without knowing a priori what
-- the data is.
regenesisVariantTag :: RegenesisP6 -> Word8
regenesisVariantTag GDP6Regenesis{} = 1
