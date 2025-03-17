{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}

-- | This module defines the genesis data format for the 'P9' protocol version.
module Concordium.Genesis.Data.P9 where

import Data.Serialize
import Data.Word

import Concordium.Common.Version
import qualified Concordium.Crypto.SHA256 as Hash
import qualified Concordium.Genesis.Data.Base as Base
import qualified Concordium.Genesis.Data.BaseV1 as BaseV1
import Concordium.Types

-- import Concordium.Types.Parameters

-- | Parameters data type for the 'P8' to 'P9' protocol update.
--  This is provided as a parameter to the protocol update chain update instruction.
data ProtocolUpdateData = ProtocolUpdateData
    deriving (Eq, Show)

instance Serialize ProtocolUpdateData where
    put ProtocolUpdateData{} = put ()
    get = return ProtocolUpdateData

-- | Parameters used to migrate state from 'P8' to 'P9'.
newtype StateMigrationData = StateMigrationData
    { -- | Data provided by the protocol update to be used
      --  in the migration.
      migrationProtocolUpdateData :: ProtocolUpdateData
    }
    deriving (Eq, Show)

instance Serialize StateMigrationData where
    put StateMigrationData{..} = do
        put migrationProtocolUpdateData
    get = do
        migrationProtocolUpdateData <- get
        return StateMigrationData{..}

-- | Initial genesis data for the P9 protocol version.
data GenesisDataP9 = GDP9Initial
    { -- | The immutable genesis parameters.
      genesisCore :: !BaseV1.CoreGenesisParametersV1,
      -- | Serialized initial block state.
      genesisInitialState :: !(Base.GenesisState 'P9)
    }
    deriving (Eq, Show)

-- | The regenesis represents a reset of the protocol with a new genesis block.
--   This does not include the full new state, but only its hash.
--
--  The relationship between the new state and the state of the
--  terminal block of the old chain should be defined by the
--  chain update mechanism used.
--
--  There are two variants, one when migrating from 'P8' to 'P9' and
--  one from 'P9' to 'P9'.
data RegenesisP9
    = GDP9Regenesis {genesisRegenesis :: !BaseV1.RegenesisDataV1}
    | GDP9RegenesisFromP8
        { genesisRegenesis :: !BaseV1.RegenesisDataV1,
          genesisMigration :: !StateMigrationData
        }
    deriving (Eq, Show)

-- | Deserialize genesis data in the V11 format.
getGenesisDataV11 :: Get GenesisDataP9
getGenesisDataV11 =
    getWord8 >>= \case
        0 -> do
            genesisCore <- get
            genesisInitialState <- get
            return GDP9Initial{..}
        _ -> fail "Unrecognized P9 genesis data type."

getRegenesisData :: Get RegenesisP9
getRegenesisData =
    getWord8 >>= \case
        1 -> do
            genesisRegenesis <- get
            return GDP9Regenesis{..}
        2 -> do
            genesisRegenesis <- get
            genesisMigration <- get
            return GDP9RegenesisFromP8{..}
        _ -> fail "Unrecognized P9 regenesis data type."

-- | Serialize genesis data in the V11 format.
putGenesisDataV11 :: Putter GenesisDataP9
putGenesisDataV11 GDP9Initial{..} = do
    putWord8 0
    put genesisCore
    put genesisInitialState

-- | Deserialize genesis data with a version tag. The expected version tag is 10
--  and this must be distinct from version tags of other genesis data formats.
getVersionedGenesisData :: Get GenesisDataP9
getVersionedGenesisData =
    getVersion >>= \case
        11 -> getGenesisDataV11
        n -> fail $ "Unsupported genesis data version for P9 genesis: " ++ show n

-- | Serialize genesis data with a version tag.
--  This will use the V11 format.
putVersionedGenesisData :: Putter GenesisDataP9
putVersionedGenesisData gd = do
    putVersion 11
    putGenesisDataV11 gd

-- | Compute the block hash of the genesis block with the given genesis data.
--  Every block hash is derived from a message that begins with the block slot,
--  which is 0 for genesis blocks.
--
--  NB: For the regenesis variant the serialized state is not included in the
--  block hash, only the state hash is. This makes it possible to optimize the
--  format in the future since it does not have protocol defined meaning. In
--  contrast, for the initial P9 genesis the initial state is hashed as is.
genesisBlockHash :: GenesisDataP9 -> BlockHash
genesisBlockHash GDP9Initial{..} = BlockHash . Hash.hashLazy . runPutLazy $ do
    put genesisSlot
    put P9
    putWord8 0 -- initial variant
    put genesisCore
    put genesisInitialState

-- | Compute the block hash of the regenesis data as defined by the specified
--  protocol. This becomes the block hash of the genesis block of the new chain
--  after the protocol update.
regenesisBlockHash :: RegenesisP9 -> BlockHash
regenesisBlockHash GDP9Regenesis{genesisRegenesis = BaseV1.RegenesisDataV1{..}} = BlockHash . Hash.hashLazy . runPutLazy $ do
    put genesisSlot
    put P9
    putWord8 1 -- regenesis variant
    put genesisCore
    put genesisFirstGenesis
    put genesisPreviousGenesis
    put genesisTerminalBlock
    put genesisStateHash
regenesisBlockHash GDP9RegenesisFromP8{genesisRegenesis = BaseV1.RegenesisDataV1{..}, ..} = BlockHash . Hash.hashLazy . runPutLazy $ do
    put genesisSlot
    put P9
    putWord8 2 -- migration from P8 variant
    put genesisCore
    put genesisFirstGenesis
    put genesisPreviousGenesis
    put genesisTerminalBlock
    put genesisStateHash
    put genesisMigration

-- | The hash of the first genesis block in the chain.
firstGenesisBlockHash :: RegenesisP9 -> BlockHash
firstGenesisBlockHash GDP9Regenesis{genesisRegenesis = BaseV1.RegenesisDataV1{..}} = genesisFirstGenesis
firstGenesisBlockHash GDP9RegenesisFromP8{genesisRegenesis = BaseV1.RegenesisDataV1{..}} = genesisFirstGenesis

-- | Tag of the genesis data used for serialization.
genesisVariantTag :: GenesisDataP9 -> Word8
genesisVariantTag GDP9Initial{} = 0

-- | Tag of the regenesis variant used for serialization. This tag determines
--  whether the genesis data is, e.g., initial genesis, or regenesis and allows
--  us to deserialize one or the other from the data without knowing a priori what
--  the data is.
regenesisVariantTag :: RegenesisP9 -> Word8
regenesisVariantTag GDP9Regenesis{} = 1
regenesisVariantTag GDP9RegenesisFromP8{} = 2
