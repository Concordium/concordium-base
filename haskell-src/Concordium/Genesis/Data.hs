{-# LANGUAGE DeriveGeneric #-}

module Concordium.Genesis.Data(
    GenesisBaker(..),
    GenesisAccount(..),
    module Concordium.Genesis.Data
) where

import Control.Monad
import qualified Data.List as List
import qualified Data.Map.Strict as Map
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
import qualified Concordium.Crypto.SHA256 as Hash

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

getGenesisDataV2 :: Get GenesisDataV2
getGenesisDataV2 = do
    genesisTime <- get
    genesisSlotDuration <- get
    genesisSeedState <- get
    nAccounts <- getLength
    accountsAndEncryptionKeys <- replicateM nAccounts getGenesisAccountGD2
    let genesisAccounts = fst <$> accountsAndEncryptionKeys
    genesisFinalizationParameters <- getFinalizationParametersGD2
    genesisCryptographicParameters <- get
    -- Verify that each baker account records the correct baker id
    -- and that the serialized encryption key is correct
    forM_ (zip [0 ..] accountsAndEncryptionKeys) $ \(i, (acct, ek)) -> case gaBaker acct of
        Just ab
            | gbBakerId ab /= i ->
                fail "BakerId does not match account index"
        _
            | let acctRegId = ID.credId (gaCredentials acct Map.! 0)
            , let acctEK = ID.makeEncryptionKey genesisCryptographicParameters acctRegId
            , ek /= acctEK ->
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
    putFinalizationParametersGD2 genesisFinalizationParameters
    put genesisCryptographicParameters
    put genesisIdentityProviders
    put genesisAnonymityRevokers
    put genesisMaxBlockEnergy
    put genesisAuthorizations
    put genesisChainParameters

instance Serialize GenesisDataV2 where
    get = getGenesisDataV2
    put = putGenesisDataV2

type GenesisData = GenesisDataV2

genesisDataVersion :: Version
genesisDataVersion = 2

-- |Deserialize genesis data.
-- Read the version and decide how to parse the remaining data based on the
-- version.
--
-- Currently only supports version 2
getExactVersionedGenesisData :: Get GenesisData
getExactVersionedGenesisData =
    getVersion >>= \case
        2 -> getGenesisDataV2
        n -> fail $ "Unsupported Genesis version: " ++ show n

-- |Serialize the genesis data with a version according to the V2 format.
-- In contrast to 'putGenesisDataV2' this function also prepends the version.
putVersionedGenesisDataV2 :: GenesisData -> Put
putVersionedGenesisDataV2 fpm = putVersion 2 <> putGenesisDataV2 fpm

-- |Get the total amount of GTU in genesis data.
genesisTotalGTU :: GenesisData -> Amount
genesisTotalGTU GenesisDataV2{..} =
    sum (gaBalance <$> genesisAccounts)

-- |Convert 'GenesisParameters' to 'GenesisData'.
-- If some of the parameters are not valid, or inconsistent, this function will
-- raise an exception.
parametersToGenesisData :: GenesisParameters -> GenesisData
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
            gcpBakerStakeThreshold
    foundationAccountIndex = case List.findIndex ((gcpFoundationAccount ==) . gaAddress) gpInitialAccounts of
        Nothing -> error "Foundation account is missing"
        Just i -> fromIntegral i

hashGenesisData :: GenesisData -> Hash.Hash
hashGenesisData genData = Hash.hashLazy . runPutLazy $ put genesisSlot >> put genData
