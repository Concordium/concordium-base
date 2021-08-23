-- |This module defines the genesis data fromat for the 'P1' protocol version.
module Concordium.Genesis.Data.P2 where

import Data.Serialize

import Concordium.Common.Version
import qualified Concordium.Crypto.SHA256 as Hash
import Concordium.Genesis.Data.Base
import Concordium.Types

-- |Genesis data for the P2 protocol version.
newtype GenesisDataP2
    = GenesisDataP2 { unGenesisDataP2 :: RegenesisData }
    deriving (Eq, Show)

instance BasicGenesisData GenesisDataP2 where
    gdGenesisTime = genesisTime . genesisCore . unGenesisDataP2
    {-# INLINE gdGenesisTime #-}
    gdSlotDuration = genesisSlotDuration . genesisCore . unGenesisDataP2
    {-# INLINE gdSlotDuration #-}
    gdMaxBlockEnergy = genesisMaxBlockEnergy . genesisCore . unGenesisDataP2
    {-# INLINE gdMaxBlockEnergy #-}
    gdFinalizationParameters = genesisFinalizationParameters . genesisCore . unGenesisDataP2
    {-# INLINE gdFinalizationParameters #-}
    gdEpochLength = genesisEpochLength . genesisCore . unGenesisDataP2
    {-# INLINE gdEpochLength #-}

-- |Deserialize genesis data in the V4 format.
getGenesisDataV4 :: Get GenesisDataP2
getGenesisDataV4 = GenesisDataP2 <$> getRegenesisData

-- |Serialize genesis data in the V4 format.
putGenesisDataV4 :: Putter GenesisDataP2
putGenesisDataV4 = putRegenesisData . unGenesisDataP2

-- |Deserialize genesis data with a version tag. The expected version tag is 4
-- and this must be distinct from version tags of other genesis data formats.
getVersionedGenesisData :: Get GenesisDataP2
getVersionedGenesisData =
    getVersion >>= \case
        4 -> getGenesisDataV4
        n -> fail $ "Unsupported genesis data version for P2 genssis: " ++ show n

-- |Serialize genesis data with a version tag.
-- This will use the V4 format.
putVersionedGenesisData :: Putter GenesisDataP2
putVersionedGenesisData gd = do
    putVersion 4
    putGenesisDataV4 gd

-- |Compute the block hash of the genesis block with the given genesis data.
-- Every block hash is derived from a message that begins with the block slot,
-- which is 0 for genesis blocks.
--
-- NB: The serialized state is not included in the block hash, only the state
-- hash is.
genesisBlockHash :: GenesisDataP2 -> BlockHash
genesisBlockHash GenesisDataP2{unGenesisDataP2=RegenesisData{..}} = BlockHash . Hash.hashLazy . runPutLazy $ do
    put genesisSlot
    put P2
    -- NB: The following are unfolded since the state serialization does not go into computing the hash.
    -- Only the state hash is used.
    put genesisCore
    put genesisFirstGenesis
    put genesisPreviousGenesis
    put genesisTerminalBlock
    put genesisStateHash
