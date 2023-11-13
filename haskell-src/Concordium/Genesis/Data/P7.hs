{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}

-- | This module defines the genesis data format for the 'P7' protocol version.
module Concordium.Genesis.Data.P7 where

import Data.Serialize
import Data.Word

import Concordium.Common.Version
import qualified Concordium.Crypto.SHA256 as Hash
import qualified Concordium.Genesis.Data.Base as Base
import qualified Concordium.Genesis.Data.BaseV1 as BaseV1
import Concordium.Types

-- | Initial genesis data for the P7 protocol version.
data GenesisDataP7 = GDP7Initial
    { -- | The immutable genesis parameters.
      genesisCore :: !BaseV1.CoreGenesisParametersV1,
      -- | Serialized initial block state.
      --  NB: This block state contains some of the same values as 'genesisCore', and they should match.
      genesisInitialState :: !(Base.GenesisState 'P7)
    }
    deriving (Eq, Show)

-- | The regenesis represents a reset of the protocol with a new genesis block.
--   This does not include the full new state, but only its hash.
--
--  The relationship between the new state and the state of the
--  terminal block of the old chain should be defined by the
--  chain update mechanism used.
--
--  There are two variants, one when migrating from 'P6' to 'P7' and
--  one from 'P7' to 'P7'.
data RegenesisP7
    = GDP7Regenesis {genesisRegenesis :: !BaseV1.RegenesisDataV1}
    | GDP7RegenesisFromP6
        { genesisRegenesis :: !BaseV1.RegenesisDataV1,
          genesisMigration :: ()
        }
    deriving (Eq, Show)

-- | Deserialize genesis data in the V9 format.
getGenesisDataV9 :: Get GenesisDataP7
getGenesisDataV9 =
    getWord8 >>= \case
        0 -> do
            genesisCore <- get
            genesisInitialState <- get
            return GDP7Initial{..}
        _ -> fail "Unrecognized P7 genesis data type."

getRegenesisData :: Get RegenesisP7
getRegenesisData =
    getWord8 >>= \case
        1 -> do
            genesisRegenesis <- get
            return GDP7Regenesis{..}
        2 -> do
            genesisRegenesis <- get
            genesisMigration <- get
            return GDP7RegenesisFromP6{..}
        _ -> fail "Unrecognized P7 regenesis data type."

-- | Serialize genesis data in the V9 format.
putGenesisDataV9 :: Putter GenesisDataP7
putGenesisDataV9 GDP7Initial{..} = do
    putWord8 0
    put genesisCore
    put genesisInitialState

-- | Deserialize genesis data with a version tag. The expected version tag is 9
--  and this must be distinct from version tags of other genesis data formats.
getVersionedGenesisData :: Get GenesisDataP7
getVersionedGenesisData =
    getVersion >>= \case
        9 -> getGenesisDataV9
        n -> fail $ "Unsupported genesis data version for P7 genesis: " ++ show n

-- | Serialize genesis data with a version tag.
--  This will use the V9 format.
putVersionedGenesisData :: Putter GenesisDataP7
putVersionedGenesisData gd = do
    putVersion 9
    putGenesisDataV9 gd

-- | Compute the block hash of the genesis block with the given genesis data.
--  Every block hash is derived from a message that begins with the block slot,
--  which is 0 for genesis blocks.
--
--  NB: For the regenesis variant the serialized state is not included in the
--  block hash, only the state hash is. This makes it possible to optimize the
--  format in the future since it does not have protocol defined meaning. In
--  contrast, for the initial P7 genesis the initial state is hashed as is.
genesisBlockHash :: GenesisDataP7 -> BlockHash
genesisBlockHash GDP7Initial{..} = BlockHash . Hash.hashLazy . runPutLazy $ do
    put genesisSlot
    put P7
    putWord8 0 -- initial variant
    put genesisCore
    put genesisInitialState

-- | Compute the block hash of the regenesis data as defined by the specified
--  protocol. This becomes the block hash of the genesis block of the new chain
--  after the protocol update.
regenesisBlockHash :: RegenesisP7 -> BlockHash
regenesisBlockHash GDP7Regenesis{genesisRegenesis = BaseV1.RegenesisDataV1{..}} = BlockHash . Hash.hashLazy . runPutLazy $ do
    put genesisSlot
    put P7
    putWord8 1 -- regenesis variant
    put genesisCore
    put genesisFirstGenesis
    put genesisPreviousGenesis
    put genesisTerminalBlock
    put genesisStateHash
regenesisBlockHash GDP7RegenesisFromP6{genesisRegenesis = BaseV1.RegenesisDataV1{..}, ..} = BlockHash . Hash.hashLazy . runPutLazy $ do
    put genesisSlot
    put P7
    putWord8 2 -- migration from P6 variant
    put genesisCore
    put genesisFirstGenesis
    put genesisPreviousGenesis
    put genesisTerminalBlock
    put genesisStateHash
    put genesisMigration

-- | The hash of the first genesis block in the chain.
firstGenesisBlockHash :: RegenesisP7 -> BlockHash
firstGenesisBlockHash GDP7Regenesis{genesisRegenesis = BaseV1.RegenesisDataV1{..}} = genesisFirstGenesis
firstGenesisBlockHash GDP7RegenesisFromP6{genesisRegenesis = BaseV1.RegenesisDataV1{..}} = genesisFirstGenesis

-- | Tag of the genesis data used for serialization.
genesisVariantTag :: GenesisDataP7 -> Word8
genesisVariantTag GDP7Initial{} = 0

-- | Tag of the regenesis variant used for serialization. This tag determines
--  whether the genesis data is, e.g., initial genesis, or regenesis and allows
--  us to deserialize one or the other from the data without knowing a priori what
--  the data is.
regenesisVariantTag :: RegenesisP7 -> Word8
regenesisVariantTag GDP7Regenesis{} = 1
regenesisVariantTag GDP7RegenesisFromP6{} = 2
