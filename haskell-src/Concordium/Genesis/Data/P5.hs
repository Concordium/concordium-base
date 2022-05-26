{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}

-- |This module defines the genesis data format for the 'P4' protocol version.
module Concordium.Genesis.Data.P5 where

import Data.Serialize

import Concordium.Common.Version
import qualified Concordium.Crypto.SHA256 as Hash
import Concordium.Genesis.Data.Base
import Concordium.Genesis.Parameters
import Concordium.Types
import qualified Concordium.Genesis.Data.P4  as P4

-- |Genesis data for the P5 protocol version. The initial variant is here
-- because it might be used in the future, at present it is not used.
newtype GenesisDataP5 = GenesisDataP5 {gdUnwrap :: P4.GenesisDataP4}
    deriving (Eq, BasicGenesisData)

-- |Deserialize genesis data in the V7 format.
getGenesisDataV7 :: Get GenesisDataP5
getGenesisDataV7 = GenesisDataP5 <$> P4.getGenesisDataV6

-- |Serialize genesis data in the V6 format.
putGenesisDataV7 :: Putter GenesisDataP5
putGenesisDataV7 = P4.putGenesisDataV6 . gdUnwrap

-- |Deserialize genesis data with a version tag. The expected version tag is 6
-- and this must be distinct from version tags of other genesis data formats.
getVersionedGenesisData :: Get GenesisDataP5
getVersionedGenesisData =
    getVersion >>= \case
        7 -> getGenesisDataV7
        n -> fail $ "Unsupported genesis data version for P5 genesis: " ++ show n

-- |Serialize genesis data with a version tag.
-- This will use the V6 format.
putVersionedGenesisData :: Putter GenesisDataP5
putVersionedGenesisData gd = do
    putVersion 7
    putGenesisDataV7 gd

parametersToGenesisData :: GenesisParameters 'P5 -> GenesisDataP5
parametersToGenesisData GenesisParameters{..} = GenesisDataP5 (uncurry P4.GDP4Initial (parametersToState GenesisParameters{..}))

-- |Compute the block hash of the genesis block with the given genesis data.
-- Every block hash is derived from a message that begins with the block slot,
-- which is 0 for genesis blocks.
--
-- NB: For the regenesis variant the serialized state is not included in the
-- block hash, only the state hash is. This makes it possible to optimize the
-- format in the future since it does not have protocol defined meaning. In
-- contrast, for the initial P5 genesis the initial state is hashed as is.
genesisBlockHash :: GenesisDataP5 -> BlockHash
genesisBlockHash (GenesisDataP5 P4.GDP4Initial{..}) = BlockHash . Hash.hashLazy . runPutLazy $ do
    put genesisSlot
    put P5
    putWord8 0 -- initial variant
    put genesisCore
    put genesisInitialState
genesisBlockHash (GenesisDataP5 P4.GDP4Regenesis{genesisRegenesis = RegenesisData{..}}) = BlockHash . Hash.hashLazy . runPutLazy $ do
    put genesisSlot
    put P5
    putWord8 1 -- regenesis variant
    -- NB: 'putRegenesisData' is not used since the state serialization does not go into computing the hash.
    -- Only the state hash is used.
    put genesisCore
    put genesisFirstGenesis
    put genesisPreviousGenesis
    put genesisTerminalBlock
    put genesisStateHash
genesisBlockHash (GenesisDataP5 P4.GDP4MigrateFromP3{genesisRegenesis = RegenesisData{..}, ..}) = BlockHash . Hash.hashLazy . runPutLazy $ do
    put genesisSlot
    put P5
    putWord8 2 -- migration from P3 variant
    -- NB: 'putRegenesisData' is not used since the state serialization does not go into computing the hash.
    -- Only the state hash is used.
    put genesisCore
    put genesisFirstGenesis
    put genesisPreviousGenesis
    put genesisTerminalBlock
    put genesisStateHash
    put genesisMigration
