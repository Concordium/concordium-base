{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

module Concordium.Genesis.Data (
    GenesisBaker (..),
    GenesisAccount (..),
    module Concordium.Genesis.Data.Base,
    module Concordium.Genesis.Data,
) where

import Data.ByteString (ByteString)
import Data.Function (on)
import Data.Serialize

import Concordium.Common.Version
import Concordium.Genesis.Account
import Concordium.Genesis.Data.Base
import qualified Concordium.Genesis.Data.P1 as P1
import qualified Concordium.Genesis.Data.P2 as P2
import qualified Concordium.Genesis.Data.P3 as P3
import qualified Concordium.Genesis.Data.P4 as P4
import Concordium.Types
import Concordium.Types.ProtocolVersion (SomeProtocolVersion)

-- |Data family for genesis data.
-- This has been chosen to be a data family so that the genesis data
-- will uniquely determine the protocol version.
data family GenesisData (pv :: ProtocolVersion)

newtype instance GenesisData 'P1 = GDP1 {unGDP1 :: P1.GenesisDataP1}
newtype instance GenesisData 'P2 = GDP2 {unGDP2 :: P2.GenesisDataP2}
newtype instance GenesisData 'P3 = GDP3 {unGDP3 :: P3.GenesisDataP3}
newtype instance GenesisData 'P4 = GDP4 {unGDP4 :: P4.GenesisDataP4}

instance (IsProtocolVersion pv) => BasicGenesisData (GenesisData pv) where
    gdGenesisTime = case protocolVersion @pv of
        SP1 -> gdGenesisTime . unGDP1
        SP2 -> gdGenesisTime . unGDP2
        SP3 -> gdGenesisTime . unGDP3
        SP4 -> gdGenesisTime . unGDP4
    {-# INLINE gdGenesisTime #-}
    gdSlotDuration = case protocolVersion @pv of
        SP1 -> gdSlotDuration . unGDP1
        SP2 -> gdSlotDuration . unGDP2
        SP3 -> gdSlotDuration . unGDP3
        SP4 -> gdSlotDuration . unGDP4
    {-# INLINE gdSlotDuration #-}
    gdMaxBlockEnergy = case protocolVersion @pv of
        SP1 -> gdMaxBlockEnergy . unGDP1
        SP2 -> gdMaxBlockEnergy . unGDP2
        SP3 -> gdMaxBlockEnergy . unGDP3
        SP4 -> gdMaxBlockEnergy . unGDP4
    {-# INLINE gdMaxBlockEnergy #-}
    gdFinalizationParameters = case protocolVersion @pv of
        SP1 -> gdFinalizationParameters . unGDP1
        SP2 -> gdFinalizationParameters . unGDP2
        SP3 -> gdFinalizationParameters . unGDP3
        SP4 -> gdFinalizationParameters . unGDP4
    {-# INLINE gdFinalizationParameters #-}
    gdEpochLength = case protocolVersion @pv of
        SP1 -> gdEpochLength . unGDP1
        SP2 -> gdEpochLength . unGDP2
        SP3 -> gdEpochLength . unGDP3
        SP4 -> gdEpochLength . unGDP4
    {-# INLINE gdEpochLength #-}

instance (IsProtocolVersion pv) => Eq (GenesisData pv) where
    (==) = case protocolVersion @pv of
        SP1 -> (==) `on` unGDP1
        SP2 -> (==) `on` unGDP2
        SP3 -> (==) `on` unGDP3
        SP4 -> (==) `on` unGDP4

instance (IsProtocolVersion pv) => Serialize (GenesisData pv) where
    get = case protocolVersion @pv of
        SP1 -> GDP1 <$> P1.getGenesisDataV3
        SP2 -> GDP2 <$> P2.getGenesisDataV4
        SP3 -> GDP3 <$> P3.getGenesisDataV5
        SP4 -> GDP4 <$> P4.getGenesisDataV6

    put = case protocolVersion @pv of
        SP1 -> P1.putGenesisDataV3 . unGDP1
        SP2 -> P2.putGenesisDataV4 . unGDP2
        SP3 -> P3.putGenesisDataV5 . unGDP3
        SP4 -> P4.putGenesisDataV6 . unGDP4

-- |Deserialize genesis data with a version tag.
-- See `putVersionedGenesisData` for details of the version tag.
getVersionedGenesisData :: forall pv. IsProtocolVersion pv => Get (GenesisData pv)
getVersionedGenesisData = case protocolVersion @pv of
    SP1 -> GDP1 <$> P1.getVersionedGenesisData
    SP2 -> GDP2 <$> P2.getVersionedGenesisData
    SP3 -> GDP3 <$> P3.getVersionedGenesisData
    SP4 -> GDP4 <$> P4.getVersionedGenesisData

-- |Serialize genesis data with a version tag.
-- Each version tag must be specific to a protocol version, though more than one version tag can
-- be used for the same protocol version.
-- The currently supported versions are:
--
-- +-------------+------------------+
-- | Version tag | Protocol version |
-- +=============+==================+
-- | 3           | P1               |
-- | 4           | P2               |
-- | 5           | P3               |
-- | 6           | P4               |
-- +-------------+------------------+
putVersionedGenesisData :: forall pv. IsProtocolVersion pv => Putter (GenesisData pv)
putVersionedGenesisData = case protocolVersion @pv of
    SP1 -> P1.putVersionedGenesisData . unGDP1
    SP2 -> P2.putVersionedGenesisData . unGDP2
    SP3 -> P3.putVersionedGenesisData . unGDP3
    SP4 -> P4.putVersionedGenesisData . unGDP4

-- |Generate the block hash of a genesis block with the given genesis data.
-- This is based on the presumption that a block hash is computed from a byte string
-- beginning with the serialization of the block slot.
genesisBlockHash :: forall pv. IsProtocolVersion pv => GenesisData pv -> BlockHash
genesisBlockHash = case protocolVersion @pv of
    SP1 -> P1.genesisBlockHash . unGDP1
    SP2 -> P2.genesisBlockHash . unGDP2
    SP3 -> P3.genesisBlockHash . unGDP3
    SP4 -> P4.genesisBlockHash . unGDP4

-- Original genesis hash
firstGenesisBlockHash :: forall pv. IsProtocolVersion pv => GenesisData pv -> BlockHash
firstGenesisBlockHash = case protocolVersion @pv of
    SP1 -> P1.firstGenesisBlockHash . unGDP1
    SP2 -> P2.firstGenesisBlockHash . unGDP2
    SP3 -> P3.firstGenesisBlockHash . unGDP3
    SP4 -> P4.firstGenesisBlockHash . unGDP4

-- |A dependent pair of a protocol version and genesis data.
data PVGenesisData = forall pv. IsProtocolVersion pv => PVGenesisData (GenesisData pv)

-- |Deserialize genesis data with a version tag to a 'PVGenesisData'.
-- This should attempt to parse with all supported protocol versions.
-- The version tag will uniquely determine the protocol version.
-- For details, see `putVersionedGenesisData`.
getPVGenesisData :: Get PVGenesisData
getPVGenesisData = do
  getVersion >>= \case
    3 -> PVGenesisData . GDP1 <$> P1.getGenesisDataV3
    4 -> PVGenesisData . GDP2 <$> P2.getGenesisDataV4
    5 -> PVGenesisData . GDP3 <$> P3.getGenesisDataV5
    6 -> PVGenesisData . GDP4 <$> P4.getGenesisDataV6
    n -> fail $ "Unsupported genesis version: " ++ show n

-- |Serialize genesis data with a version tag. This is a helper function that
-- modulo types does exactly the same as 'putVersionedGenesisData' defined
-- above.
putPVGenesisData :: Putter PVGenesisData
putPVGenesisData (PVGenesisData gd) = putVersionedGenesisData gd

-- |Helper function that modulo types, does exactly the same as
-- 'genesisBlockHash' defined above.
pvGenesisBlockHash :: PVGenesisData -> BlockHash
pvGenesisBlockHash (PVGenesisData gd) = genesisBlockHash gd

-- |Helper function to project the protocol version out of 'PVGenesisData'.
pvProtocolVersion :: PVGenesisData -> ProtocolVersion
pvProtocolVersion (PVGenesisData (_ :: GenesisData pv)) = demoteProtocolVersion (protocolVersion @pv)

-- |The 'StateMigrationParameters' type encapsulates additional data that is required when migrating
-- state from one protocol version to another.  As the state for an older protocol version may not
-- include state information that is required in a newer protocol version, these parameters
-- determine how to fill the gaps.  Principally, these parameters are derived from the data
-- supplied with the protocol update, though some may also derive from other data about the chain.
data StateMigrationParameters (p1 :: ProtocolVersion) (p2 :: ProtocolVersion) where
    -- |No state migration is performed.
    StateMigrationParametersTrivial :: StateMigrationParameters p p
    -- |The state is migrated from protocol version 'P3' to 'P4'.
    StateMigrationParametersP3ToP4 :: P4.StateMigrationData -> StateMigrationParameters 'P3 'P4
