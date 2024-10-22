{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}

-- | This module defines the genesis data format for the 'P8' protocol version.
module Concordium.Genesis.Data.P8 where

import Data.Serialize
import Data.Word

import Concordium.Common.Version
import qualified Concordium.Crypto.SHA256 as Hash
import qualified Concordium.Genesis.Data.Base as Base
import qualified Concordium.Genesis.Data.BaseV1 as BaseV1
import Concordium.Types

-- | Initial genesis data for the P8 protocol version.
data GenesisDataP8 = GDP8Initial
    { -- | The immutable genesis parameters.
      genesisCore :: !BaseV1.CoreGenesisParametersV1,
      -- | Serialized initial block state.
      genesisInitialState :: !(Base.GenesisState 'P8)
    }
    deriving (Eq, Show)

-- | The regenesis represents a reset of the protocol with a new genesis block.
--   This does not include the full new state, but only its hash.
--
--  The relationship between the new state and the state of the
--  terminal block of the old chain should be defined by the
--  chain update mechanism used.
--
--  There are two variants, one when migrating from 'P7' to 'P8' and
--  one from 'P8' to 'P8'.
data RegenesisP8
    = GDP8Regenesis {genesisRegenesis :: !BaseV1.RegenesisDataV1}
    | GDP8RegenesisFromP7
        { genesisRegenesis :: !BaseV1.RegenesisDataV1,
          genesisMigration :: ()
        }
    deriving (Eq, Show)

-- | Deserialize genesis data in the V10 format.
getGenesisDataV10 :: Get GenesisDataP8
getGenesisDataV10 =
    getWord8 >>= \case
        0 -> do
            genesisCore <- get
            genesisInitialState <- get
            return GDP8Initial{..}
        _ -> fail "Unrecognized P8 genesis data type."

getRegenesisData :: Get RegenesisP8
getRegenesisData =
    getWord8 >>= \case
        1 -> do
            genesisRegenesis <- get
            return GDP8Regenesis{..}
        2 -> do
            genesisRegenesis <- get
            genesisMigration <- get
            return GDP8RegenesisFromP7{..}
        _ -> fail "Unrecognized P8 regenesis data type."

-- | Serialize genesis data in the V10 format.
putGenesisDataV10 :: Putter GenesisDataP8
putGenesisDataV10 GDP8Initial{..} = do
    putWord8 0
    put genesisCore
    put genesisInitialState

-- | Deserialize genesis data with a version tag. The expected version tag is 10
--  and this must be distinct from version tags of other genesis data formats.
getVersionedGenesisData :: Get GenesisDataP8
getVersionedGenesisData =
    getVersion >>= \case
        10 -> getGenesisDataV10
        n -> fail $ "Unsupported genesis data version for P8 genesis: " ++ show n

-- | Serialize genesis data with a version tag.
--  This will use the V10 format.
putVersionedGenesisData :: Putter GenesisDataP8
putVersionedGenesisData gd = do
    putVersion 10
    putGenesisDataV10 gd

-- | Compute the block hash of the genesis block with the given genesis data.
--  Every block hash is derived from a message that begins with the block slot,
--  which is 0 for genesis blocks.
--
--  NB: For the regenesis variant the serialized state is not included in the
--  block hash, only the state hash is. This makes it possible to optimize the
--  format in the future since it does not have protocol defined meaning. In
--  contrast, for the initial P8 genesis the initial state is hashed as is.
genesisBlockHash :: GenesisDataP8 -> BlockHash
genesisBlockHash GDP8Initial{..} = BlockHash . Hash.hashLazy . runPutLazy $ do
    put genesisSlot
    put P8
    putWord8 0 -- initial variant
    put genesisCore
    put genesisInitialState

-- | Compute the block hash of the regenesis data as defined by the specified
--  protocol. This becomes the block hash of the genesis block of the new chain
--  after the protocol update.
regenesisBlockHash :: RegenesisP8 -> BlockHash
regenesisBlockHash GDP8Regenesis{genesisRegenesis = BaseV1.RegenesisDataV1{..}} = BlockHash . Hash.hashLazy . runPutLazy $ do
    put genesisSlot
    put P8
    putWord8 1 -- regenesis variant
    put genesisCore
    put genesisFirstGenesis
    put genesisPreviousGenesis
    put genesisTerminalBlock
    put genesisStateHash
regenesisBlockHash GDP8RegenesisFromP7{genesisRegenesis = BaseV1.RegenesisDataV1{..}, ..} = BlockHash . Hash.hashLazy . runPutLazy $ do
    put genesisSlot
    put P8
    putWord8 2 -- migration from P6 variant
    put genesisCore
    put genesisFirstGenesis
    put genesisPreviousGenesis
    put genesisTerminalBlock
    put genesisStateHash
    put genesisMigration

-- | The hash of the first genesis block in the chain.
firstGenesisBlockHash :: RegenesisP8 -> BlockHash
firstGenesisBlockHash GDP8Regenesis{genesisRegenesis = BaseV1.RegenesisDataV1{..}} = genesisFirstGenesis
firstGenesisBlockHash GDP8RegenesisFromP7{genesisRegenesis = BaseV1.RegenesisDataV1{..}} = genesisFirstGenesis

-- | Tag of the genesis data used for serialization.
genesisVariantTag :: GenesisDataP8 -> Word8
genesisVariantTag GDP8Initial{} = 0

-- | Tag of the regenesis variant used for serialization. This tag determines
--  whether the genesis data is, e.g., initial genesis, or regenesis and allows
--  us to deserialize one or the other from the data without knowing a priori what
--  the data is.
regenesisVariantTag :: RegenesisP8 -> Word8
regenesisVariantTag GDP8Regenesis{} = 1
regenesisVariantTag GDP8RegenesisFromP7{} = 2
