{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}

-- | This module defines the genesis data format for the 'P10' protocol version.
module Concordium.Genesis.Data.P10 where

import Data.Serialize
import Data.Word

import Concordium.Common.Version
import qualified Concordium.Crypto.SHA256 as Hash
import qualified Concordium.Genesis.Data.Base as Base
import qualified Concordium.Genesis.Data.BaseV1 as BaseV1
import Concordium.Types
import Concordium.Types.Updates

-- | Parameters used to migrate state from 'P9' to 'P10'.
data StateMigrationData = StateMigrationData
    deriving (Eq, Show)

instance Serialize StateMigrationData where
    put StateMigrationData = return ()
    get = return StateMigrationData

-- | Initial genesis data for the P10 protocol version.
data GenesisDataP10 = GDP10Initial
    { -- | The immutable genesis parameters.
      genesisCore :: !BaseV1.CoreGenesisParametersV1,
      -- | Serialized initial block state.
      genesisInitialState :: !(Base.GenesisState 'P10)
    }
    deriving (Eq, Show)

-- | The regenesis represents a reset of the protocol with a new genesis block.
--   This does not include the full new state, but only its hash.
--
--  The relationship between the new state and the state of the
--  terminal block of the old chain should be defined by the
--  chain update mechanism used.
--
--  There are two variants, one when migrating from 'P9' to 'P10' and
--  one from 'P10' to 'P10'.
data RegenesisP10
    = GDP10Regenesis {genesisRegenesis :: !BaseV1.RegenesisDataV1}
    | GDP10RegenesisFromP9
        { genesisRegenesis :: !BaseV1.RegenesisDataV1,
          genesisMigration :: !StateMigrationData
        }
    deriving (Eq, Show)

-- | Deserialize genesis data in the V12 format.
getGenesisDataV12 :: Get GenesisDataP10
getGenesisDataV12 =
    getWord8 >>= \case
        0 -> do
            genesisCore <- get
            genesisInitialState <- get
            return GDP10Initial{..}
        _ -> fail "Unrecognized P10 genesis data type."

getRegenesisData :: Get RegenesisP10
getRegenesisData =
    getWord8 >>= \case
        1 -> do
            genesisRegenesis <- get
            return GDP10Regenesis{..}
        2 -> do
            genesisRegenesis <- get
            genesisMigration <- get
            return GDP10RegenesisFromP9{..}
        _ -> fail "Unrecognized P10 regenesis data type."

-- | Serialize genesis data in the V12 format.
putGenesisDataV12 :: Putter GenesisDataP10
putGenesisDataV12 GDP10Initial{..} = do
    putWord8 0
    put genesisCore
    put genesisInitialState

-- | Deserialize genesis data with a version tag. The expected version tag is 12
--  and this must be distinct from version tags of other genesis data formats.
getVersionedGenesisData :: Get GenesisDataP10
getVersionedGenesisData =
    getVersion >>= \case
        12 -> getGenesisDataV12
        n -> fail $ "Unsupported genesis data version for P10 genesis: " ++ show n

-- | Serialize genesis data with a version tag.
--  This will use the V12 format.
putVersionedGenesisData :: Putter GenesisDataP10
putVersionedGenesisData gd = do
    putVersion 12
    putGenesisDataV12 gd

-- | Compute the block hash of the genesis block with the given genesis data.
--  Every block hash is derived from a message that begins with the block slot,
--  which is 0 for genesis blocks.
--
--  NB: For the regenesis variant the serialized state is not included in the
--  block hash, only the state hash is. This makes it possible to optimize the
--  format in the future since it does not have protocol defined meaning. In
--  contrast, for the initial P10 genesis the initial state is hashed as is.
genesisBlockHash :: GenesisDataP10 -> BlockHash
genesisBlockHash GDP10Initial{..} = BlockHash . Hash.hashLazy . runPutLazy $ do
    put genesisSlot
    put P10
    putWord8 0 -- initial variant
    put genesisCore
    put genesisInitialState

-- | Compute the block hash of the regenesis data as defined by the specified
--  protocol. This becomes the block hash of the genesis block of the new chain
--  after the protocol update.
regenesisBlockHash :: RegenesisP10 -> BlockHash
regenesisBlockHash GDP10Regenesis{genesisRegenesis = BaseV1.RegenesisDataV1{..}} = BlockHash . Hash.hashLazy . runPutLazy $ do
    put genesisSlot
    put P10
    putWord8 1 -- regenesis variant
    put genesisCore
    put genesisFirstGenesis
    put genesisPreviousGenesis
    put genesisTerminalBlock
    put genesisStateHash
regenesisBlockHash GDP10RegenesisFromP9{genesisRegenesis = BaseV1.RegenesisDataV1{..}, ..} = BlockHash . Hash.hashLazy . runPutLazy $ do
    put genesisSlot
    put P10
    putWord8 2 -- migration from P9 variant
    put genesisCore
    put genesisFirstGenesis
    put genesisPreviousGenesis
    put genesisTerminalBlock
    put genesisStateHash
    put genesisMigration

-- | The hash of the first genesis block in the chain.
firstGenesisBlockHash :: RegenesisP10 -> BlockHash
firstGenesisBlockHash GDP10Regenesis{genesisRegenesis = BaseV1.RegenesisDataV1{..}} = genesisFirstGenesis
firstGenesisBlockHash GDP10RegenesisFromP9{genesisRegenesis = BaseV1.RegenesisDataV1{..}} = genesisFirstGenesis

-- | Tag of the genesis data used for serialization.
genesisVariantTag :: GenesisDataP10 -> Word8
genesisVariantTag GDP10Initial{} = 0

-- | Tag of the regenesis variant used for serialization. This tag determines
--  whether the genesis data is, e.g., initial genesis, or regenesis and allows
--  us to deserialize one or the other from the data without knowing a priori what
--  the data is.
regenesisVariantTag :: RegenesisP10 -> Word8
regenesisVariantTag GDP10Regenesis{} = 1
regenesisVariantTag GDP10RegenesisFromP9{} = 2
