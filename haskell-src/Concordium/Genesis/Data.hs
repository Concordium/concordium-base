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

import Data.Function (on)
import Data.Serialize
import Data.Word

import Concordium.Common.Version
import Concordium.Genesis.Account
import Concordium.Genesis.Data.Base
import qualified Concordium.Genesis.Data.P1 as P1
import qualified Concordium.Genesis.Data.P2 as P2
import qualified Concordium.Genesis.Data.P3 as P3
import qualified Concordium.Genesis.Data.P4 as P4
import Concordium.Types

-- |Data family for genesis data.
-- This has been chosen to be a data family so that the genesis data
-- will uniquely determine the protocol version.
--
-- The genesis data should always be serialized in such a way that a
-- 'GenesisConfiguration' can be deserialized from the byte array without
-- loading extra data.
data family GenesisData (pv :: ProtocolVersion)

newtype instance GenesisData 'P1 = GDP1 {unGDP1 :: P1.GenesisDataP1}
newtype instance GenesisData 'P2 = GDP2 {unGDP2 :: P2.GenesisDataP2}
newtype instance GenesisData 'P3 = GDP3 {unGDP3 :: P3.GenesisDataP3}
newtype instance GenesisData 'P4 = GDP4 {unGDP4 :: P4.GenesisDataP4}

-- |Data family for regenesis data. This has been chosen to be a data family, as
-- opposed to a type family principally so that it is injective, i.e., so that
-- the @Regenesis pv@ determines @pv@.
--
-- The regenesis data should always be serialized in such a way that a
-- 'GenesisConfiguration' can be deserialized from the byte array without
-- loading extra data.
data family Regenesis (pv :: ProtocolVersion)

newtype instance Regenesis 'P1 = RGDP1 {unRGP1 :: P1.RegenesisP1}
newtype instance Regenesis 'P2 = RGDP2 {unRGP2 :: P2.RegenesisP2}
newtype instance Regenesis 'P3 = RGDP3 {unRGP3 :: P3.RegenesisP3}
newtype instance Regenesis 'P4 = RGDP4 {unRGP4 :: P4.RegenesisP4}

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

instance (IsProtocolVersion pv) => BasicGenesisData (Regenesis pv) where
    gdGenesisTime = case protocolVersion @pv of
        SP1 -> gdGenesisTime . unRGP1
        SP2 -> gdGenesisTime . unRGP2
        SP3 -> gdGenesisTime . unRGP3
        SP4 -> gdGenesisTime . unRGP4
    {-# INLINE gdGenesisTime #-}
    gdSlotDuration = case protocolVersion @pv of
        SP1 -> gdSlotDuration . unRGP1
        SP2 -> gdSlotDuration . unRGP2
        SP3 -> gdSlotDuration . unRGP3
        SP4 -> gdSlotDuration . unRGP4
    {-# INLINE gdSlotDuration #-}
    gdMaxBlockEnergy = case protocolVersion @pv of
        SP1 -> gdMaxBlockEnergy . unRGP1
        SP2 -> gdMaxBlockEnergy . unRGP2
        SP3 -> gdMaxBlockEnergy . unRGP3
        SP4 -> gdMaxBlockEnergy . unRGP4
    {-# INLINE gdMaxBlockEnergy #-}
    gdFinalizationParameters = case protocolVersion @pv of
        SP1 -> gdFinalizationParameters . unRGP1
        SP2 -> gdFinalizationParameters . unRGP2
        SP3 -> gdFinalizationParameters . unRGP3
        SP4 -> gdFinalizationParameters . unRGP4
    {-# INLINE gdFinalizationParameters #-}
    gdEpochLength = case protocolVersion @pv of
        SP1 -> gdEpochLength . unRGP1
        SP2 -> gdEpochLength . unRGP2
        SP3 -> gdEpochLength . unRGP3
        SP4 -> gdEpochLength . unRGP4
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

-- |Deserialize 'GenesisConfiguration' given the hash of the genesis. If
-- 'GenesisData' or 'Regenesis' is decodable (using its Serialize instance) from a given
-- bytestring then 'getGenesisConfiguration' will also succeed parsing.
--
-- Note that this will not consume the entire genesis data, only the initial
-- prefix. In particular, in case of initial genesis data it will not read the
-- genesis state.
getGenesisConfiguration :: SProtocolVersion pv -> BlockHash -> Get GenesisConfiguration
getGenesisConfiguration spv genHash = case spv of
        SP1 -> P1.getGenesisConfigurationV3 genHash
        SP2 -> P2.getGenesisConfigurationV4 genHash
        SP3 -> P3.getGenesisConfigurationV5 genHash
        SP4 -> P4.getGenesisConfigurationV6 genHash

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

-- |Generate the block hash of a regenesis block with the given regenesis data.
regenesisBlockHash :: forall pv. IsProtocolVersion pv => Regenesis pv -> BlockHash
regenesisBlockHash = case protocolVersion @pv of
    SP1 -> P1.regenesisBlockHash . unRGP1
    SP2 -> P2.regenesisBlockHash . unRGP2
    SP3 -> P3.regenesisBlockHash . unRGP3
    SP4 -> P4.regenesisBlockHash . unRGP4

-- |Hash of the initial genesis of the chain to which the given genesis data belongs.
-- Genesis created as part of a protocol update records the genesis
-- hash of the initial genesis block.
firstGenesisBlockHash :: forall pv. IsProtocolVersion pv => Regenesis pv -> BlockHash
firstGenesisBlockHash = case protocolVersion @pv of
    SP1 -> P1.firstGenesisBlockHash . unRGP1
    SP2 -> P2.firstGenesisBlockHash . unRGP2
    SP3 -> P3.firstGenesisBlockHash . unRGP3
    SP4 -> P4.firstGenesisBlockHash . unRGP4

-- |Tag of the genesis variant used for serialization. This tag determines
-- whether the genesis data is, e.g., initial genesis, or regenesis.
genesisVariantTag :: forall pv. IsProtocolVersion pv => GenesisData pv -> Word8
genesisVariantTag = case protocolVersion @pv of
    SP1 -> P1.genesisVariantTag . unGDP1
    SP2 -> P2.genesisVariantTag . unGDP2
    SP3 -> P3.genesisVariantTag . unGDP3
    SP4 -> P4.genesisVariantTag . unGDP4

-- |Tag of the regenesis variant used for serialization. This tag determines
-- whether the genesis data is, e.g., initial genesis, or regenesis and allows
-- us to deserialize one or the other from the data without knowing apriori what
-- the data is.
regenesisVariantTag :: forall pv. IsProtocolVersion pv => Regenesis pv -> Word8
regenesisVariantTag = case protocolVersion @pv of
    SP1 -> P1.regenesisVariantTag . unRGP1
    SP2 -> P2.regenesisVariantTag . unRGP2
    SP3 -> P3.regenesisVariantTag . unRGP3
    SP4 -> P4.regenesisVariantTag . unRGP4

-- |A dependent pair of a protocol version and genesis data.
data PVGenesisData = forall pv. IsProtocolVersion pv => PVGenesisData (GenesisData pv)

-- |A dependent pair of a protocol version and regenesis.
data PVRegenesis = forall pv. IsProtocolVersion pv => PVRegenesis (Regenesis pv)

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

-- |Deserialize a genesis data version tag and return the associated protocol
-- version. When applied to a byte array (e.g., using 'runGet'), this consumes
-- only the version prefix of the array so it may be applied to the same input
-- as 'getPVGenesisData' to efficiently only parse the protocol version.
getPVGenesisDataPV :: Get SomeProtocolVersion
getPVGenesisDataPV = do
  getVersion >>= \case
    3 -> return $ SomeProtocolVersion SP1
    4 -> return $ SomeProtocolVersion SP2
    5 -> return $ SomeProtocolVersion SP3
    6 -> return $ SomeProtocolVersion SP4
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
    -- |No state migration is performed.
    StateMigrationParametersTrivialP1P2 :: StateMigrationParameters 'P1 'P2
    -- |No state migration is performed.
    StateMigrationParametersTrivialP2P3 :: StateMigrationParameters 'P2 'P3
    -- |The state is migrated from protocol version 'P3' to 'P4'.
    StateMigrationParametersP3ToP4 :: P4.StateMigrationData -> StateMigrationParameters 'P3 'P4

-- |Extract the genesis configuration from the genesis data.
genesisConfiguration :: IsProtocolVersion pv => GenesisData pv -> GenesisConfiguration
genesisConfiguration genData = GenesisConfiguration {
    _gcTag = genesisVariantTag genData,
    _gcCore = coreGenesisParameters genData,
    _gcFirstGenesis = genesisBlockHash genData,
    _gcCurrentHash = genesisBlockHash genData
    }

-- |Extract the genesis configuration from the regenesis data.
regenesisConfiguration :: IsProtocolVersion pv => Regenesis pv -> GenesisConfiguration
regenesisConfiguration regenData = GenesisConfiguration {
    _gcTag = regenesisVariantTag regenData,
    _gcCore = coreGenesisParameters regenData,
    _gcFirstGenesis = firstGenesisBlockHash regenData,
    _gcCurrentHash = regenesisBlockHash regenData
    }
