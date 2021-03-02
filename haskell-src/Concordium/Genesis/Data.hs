{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

module Concordium.Genesis.Data (
    GenesisBaker (..),
    GenesisAccount (..),
    module Concordium.Genesis.Data.Base,
    module Concordium.Genesis.Data,
) where

import Data.Function (on)
import Data.Serialize

import Concordium.Genesis.Account
import Concordium.Genesis.Data.Base
import qualified Concordium.Genesis.Data.P0 as P0
import qualified Concordium.Genesis.Data.P1 as P1
import Concordium.Types

-- |Data family for genesis data.
-- This has been chosen to be a data family so that the genesis data
-- will uniquely determine the protocol version.
data family GenesisData (pv :: ProtocolVersion)

newtype instance GenesisData 'P0 = GDP0 {unGDP0 :: P0.GenesisDataP0}
newtype instance GenesisData 'P1 = GDP1 {unGDP1 :: P1.GenesisDataP1}

instance (IsProtocolVersion pv) => BasicGenesisData (GenesisData pv) where
    gdGenesisTime = case protocolVersion @pv of
        SP0 -> gdGenesisTime . unGDP0
        SP1 -> gdGenesisTime . unGDP1
    {-# INLINE gdGenesisTime #-}
    gdSlotDuration = case protocolVersion @pv of
        SP0 -> gdSlotDuration . unGDP0
        SP1 -> gdSlotDuration . unGDP1
    {-# INLINE gdSlotDuration #-}
    gdMaxBlockEnergy = case protocolVersion @pv of
        SP0 -> gdMaxBlockEnergy . unGDP0
        SP1 -> gdMaxBlockEnergy . unGDP1
    {-# INLINE gdMaxBlockEnergy #-}
    gdFinalizationParameters = case protocolVersion @pv of
        SP0 -> gdFinalizationParameters . unGDP0
        SP1 -> gdFinalizationParameters . unGDP1
    {-# INLINE gdFinalizationParameters #-}
    gdEpochLength = case protocolVersion @pv of
        SP0 -> gdEpochLength . unGDP0
        SP1 -> gdEpochLength . unGDP1
    {-# INLINE gdEpochLength #-}

instance (IsProtocolVersion pv) => Eq (GenesisData pv) where
    (==) = case protocolVersion @pv of
        SP0 -> (==) `on` unGDP0
        SP1 -> (==) `on` unGDP1

instance (IsProtocolVersion pv) => Serialize (GenesisData pv) where
    get = case protocolVersion @pv of
        SP0 -> GDP0 <$> P0.getGenesisDataV2
        SP1 -> GDP1 <$> P1.getGenesisDataV3
    put = case protocolVersion @pv of
        SP0 -> P0.putGenesisDataV2 . unGDP0
        SP1 -> P1.putGenesisDataV3 . unGDP1

-- |Deserialize genesis data with a version tag.
getVersionedGenesisData :: forall pv. IsProtocolVersion pv => Get (GenesisData pv)
getVersionedGenesisData = case protocolVersion @pv of
    SP0 -> GDP0 <$> P0.getVersionedGenesisData
    SP1 -> GDP1 <$> P1.getVersionedGenesisData

-- |Serialize genesis data with a version tag.
putVersionedGenesisData :: forall pv. IsProtocolVersion pv => Putter (GenesisData pv)
putVersionedGenesisData = case protocolVersion @pv of
    SP0 -> P0.putVersionedGenesisData . unGDP0
    SP1 -> P1.putVersionedGenesisData . unGDP1

-- |Generate the block hash of a genesis block with the given genesis data.
-- This is based on the presumption that a block hash is computed from a byte string
-- beginning with the serialization of the block slot.
genesisBlockHash :: forall pv. IsProtocolVersion pv => GenesisData pv -> BlockHash
genesisBlockHash = case protocolVersion @pv of
    SP0 -> P0.genesisBlockHash . unGDP0
    SP1 -> P1.genesisBlockHash . unGDP1
