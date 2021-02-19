{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}

module Concordium.Genesis.Data (
    GenesisBaker (..),
    GenesisAccount (..),
    module Concordium.Genesis.Data,
) where

import Control.Monad
import Data.Function (on)
import qualified Data.List as List
import qualified Data.List.NonEmpty as NE
import Data.Serialize
import GHC.Generics (Generic)
import Lens.Micro.Platform

import Concordium.Common.Version
import Concordium.Genesis.Account
import Concordium.Genesis.Parameters
import qualified Concordium.ID.Types as ID
import Concordium.Types
import Concordium.Types.AnonymityRevokers
import Concordium.Types.IdentityProviders
import Concordium.Types.Parameters
import qualified Concordium.Types.SeedState as SeedState
import Concordium.Types.Updates
import Concordium.Utils.Serialization

-- |A class that provides access to fields of genesis data that
-- are expected to be stable across versions.
class BasicGenesisData gd where
    -- |The genesis time.
    gdGenesisTime :: gd -> Timestamp
    -- |The duration of a slot.
    gdSlotDuration :: gd -> Duration
    -- |The maximum energy per block.
    gdMaxBlockEnergy :: gd -> Energy
    -- |The finalization parameters.
    gdFinalizationParameters :: gd -> FinalizationParameters
    -- |The epoch length in slots
    gdEpochLength :: gd -> EpochLength


data GenesisDataV2 = GenesisDataV2
    { genesisTime :: !Timestamp,
      genesisSlotDuration :: !Duration,
      genesisSeedState :: !SeedState.SeedState,
      genesisAccounts :: ![GenesisAccount],
      genesisFinalizationParameters :: !FinalizationParameters,
      genesisCryptographicParameters :: !CryptographicParameters,
      genesisIdentityProviders :: !IdentityProviders,
      genesisAnonymityRevokers :: !AnonymityRevokers,
      genesisMaxBlockEnergy :: !Energy,
      genesisAuthorizations :: !Authorizations,
      genesisChainParameters :: !ChainParameters
    }
    deriving (Generic, Show, Eq)

instance BasicGenesisData GenesisDataV2 where
    gdGenesisTime = genesisTime
    {-# INLINE gdGenesisTime #-}
    gdSlotDuration = genesisSlotDuration
    {-# INLINE gdSlotDuration #-}
    gdMaxBlockEnergy = genesisMaxBlockEnergy
    {-# INLINE gdMaxBlockEnergy #-}
    gdFinalizationParameters = genesisFinalizationParameters
    {-# INLINE gdFinalizationParameters #-}
    gdEpochLength = SeedState.epochLength . genesisSeedState
    {-# INLINE gdEpochLength #-}

getGenesisDataV2 :: Get GenesisDataV2
getGenesisDataV2 = do
    genesisTime <- get
    genesisSlotDuration <- get
    genesisSeedState <- get
    nAccounts <- getLength
    accountsAndEncryptionKeys <- replicateM nAccounts getGenesisAccountGD2
    let genesisAccounts = fst <$> accountsAndEncryptionKeys
    genesisFinalizationParameters <- get
    genesisCryptographicParameters <- get
    -- Verify that each baker account records the correct baker id
    -- and that the serialized encryption key is correct
    forM_ (zip [0 ..] accountsAndEncryptionKeys) $ \(i, (acct, ek)) -> case gaBaker acct of
        Just ab
            | gbBakerId ab /= i ->
                fail "BakerId does not match account index"
        _
            | let acctRegId = ID.regId (NE.head (gaCredentials acct)),
              let acctEK = ID.makeEncryptionKey genesisCryptographicParameters acctRegId,
              ek /= acctEK ->
                fail "Incorrect account encryption key"
        _ -> return ()
    genesisIdentityProviders <- get
    genesisAnonymityRevokers <- get
    genesisMaxBlockEnergy <- get
    genesisAuthorizations <- get
    genesisChainParameters <- get
    unless (toInteger (genesisChainParameters ^. cpFoundationAccount) < toInteger (length genesisAccounts)) $
        fail "Foundation account is not a valid account index."
    return GenesisDataV2{..}

putGenesisDataV2 :: Putter GenesisDataV2
putGenesisDataV2 GenesisDataV2{..} = do
    put genesisTime
    put genesisSlotDuration
    put genesisSeedState
    putLength (length genesisAccounts)
    mapM_ (putGenesisAccountGD2 genesisCryptographicParameters) genesisAccounts
    put genesisFinalizationParameters
    put genesisCryptographicParameters
    put genesisIdentityProviders
    put genesisAnonymityRevokers
    put genesisMaxBlockEnergy
    put genesisAuthorizations
    put genesisChainParameters

instance Serialize GenesisDataV2 where
    get = getGenesisDataV2
    put = putGenesisDataV2

-- type GenesisData = GenesisDataV2

-- |Data family for genesis data.
-- This has been chosen to be a data family so that the genesis data
-- will uniquely determine the protocol version.
data family GenesisData (pv :: ProtocolVersion)

newtype instance GenesisData 'P0 = GDP0 {unGDP0 :: GenesisDataV2}

instance (IsProtocolVersion pv) => BasicGenesisData (GenesisData pv) where
    gdGenesisTime = case protocolVersion :: SProtocolVersion pv of
        SP0 -> genesisTime . unGDP0
    {-# INLINE gdGenesisTime #-}
    gdSlotDuration = case protocolVersion :: SProtocolVersion pv of
        SP0 -> gdSlotDuration . unGDP0
    {-# INLINE gdSlotDuration #-}
    gdMaxBlockEnergy = case protocolVersion :: SProtocolVersion pv of
        SP0 -> gdMaxBlockEnergy . unGDP0
    {-# INLINE gdMaxBlockEnergy #-}
    gdFinalizationParameters = case protocolVersion :: SProtocolVersion pv of
        SP0 -> gdFinalizationParameters . unGDP0
    {-# INLINE gdFinalizationParameters #-}
    gdEpochLength = case protocolVersion :: SProtocolVersion pv of
        SP0 -> gdEpochLength . unGDP0
    {-# INLINE gdEpochLength #-}

instance (IsProtocolVersion pv) => Eq (GenesisData pv) where
    (==) = case protocolVersion :: SProtocolVersion pv of
        SP0 -> (==) `on` unGDP0

getExactVersionedGenesisData :: forall pv. IsProtocolVersion pv => Get (GenesisData pv)
getExactVersionedGenesisData = case protocolVersion :: SProtocolVersion pv of
    SP0 ->
        getVersion >>= \case
            2 -> GDP0 <$> getGenesisDataV2
            n -> fail $ "Unsupported Genesis version: " ++ show n

putVersionedGenesisData :: forall pv. IsProtocolVersion pv => Putter (GenesisData pv)
putVersionedGenesisData = case protocolVersion :: SProtocolVersion pv of
    SP0 -> putVersionedGenesisDataV2 . unGDP0

-- |Serialize the genesis data with a version according to the V2 format.
-- In contrast to 'putGenesisDataV2' this function also prepends the version.
putVersionedGenesisDataV2 :: GenesisDataV2 -> Put
putVersionedGenesisDataV2 fpm = putVersion 2 <> putGenesisDataV2 fpm

-- |Get the total amount of GTU in genesis data.
genesisTotalGTU :: GenesisDataV2 -> Amount
genesisTotalGTU GenesisDataV2{..} =
    sum (gaBalance <$> genesisAccounts)

-- |Convert 'GenesisParameters' to 'GenesisData'.
-- If some of the parameters are not valid, or inconsistent, this function will
-- raise an exception.
parametersToGenesisData :: GenesisParameters -> GenesisDataV2
parametersToGenesisData GenesisParametersV2{gpChainParameters = GenesisChainParameters{..}, ..} = GenesisDataV2{..}
  where
    genesisTime = gpGenesisTime
    genesisSlotDuration = gpSlotDuration
    genesisSeedState = SeedState.initialSeedState gpLeadershipElectionNonce gpEpochLength
    genesisAccounts = gpInitialAccounts
    genesisFinalizationParameters = gpFinalizationParameters
    genesisCryptographicParameters = gpCryptographicParameters
    genesisIdentityProviders = gpIdentityProviders
    genesisAnonymityRevokers = gpAnonymityRevokers
    genesisMaxBlockEnergy = gpMaxBlockEnergy
    genesisAuthorizations = gpAuthorizations
    genesisChainParameters =
        makeChainParameters
            gcpElectionDifficulty
            gcpEuroPerEnergy
            gcpMicroGTUPerEuro
            gcpBakerExtraCooldownEpochs
            gcpAccountCreationLimit
            gcpRewardParameters
            foundationAccountIndex
    foundationAccountIndex = case List.findIndex ((gcpFoundationAccount ==) . gaAddress) gpInitialAccounts of
        Nothing -> error "Foundation account is missing"
        Just i -> fromIntegral i
