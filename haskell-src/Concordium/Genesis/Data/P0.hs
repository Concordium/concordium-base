-- |This module defines the genesis data format for the 'P0' protocol version.
module Concordium.Genesis.Data.P0 where

import Control.Monad
import qualified Data.List as List
import qualified Data.List.NonEmpty as NE
import Data.Serialize
import Lens.Micro.Platform

import Concordium.Common.Version
import qualified Concordium.Crypto.SHA256 as Hash
import Concordium.Genesis.Account
import Concordium.Genesis.Data.Base
import Concordium.Genesis.Parameters
import qualified Concordium.ID.Types as ID
import Concordium.Types
import Concordium.Types.AnonymityRevokers
import Concordium.Types.IdentityProviders
import Concordium.Types.Parameters
import qualified Concordium.Types.SeedState as SeedState
import Concordium.Types.Updates
import Concordium.Utils.Serialization

data GenesisDataP0 = GenesisDataP0
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
    deriving (Show, Eq)

instance BasicGenesisData GenesisDataP0 where
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

getGenesisDataV2 :: Get GenesisDataP0
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
    return GenesisDataP0{..}

putGenesisDataV2 :: Putter GenesisDataP0
putGenesisDataV2 GenesisDataP0{..} = do
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

instance Serialize GenesisDataP0 where
    get = getGenesisDataV2
    put = putGenesisDataV2

-- |Serialize the genesis data with a version according to the V2 format.
-- In contrast to 'putGenesisDataV2' this function also prepends the version.
putVersionedGenesisData :: Putter GenesisDataP0
putVersionedGenesisData fpm = putVersion 2 <> putGenesisDataV2 fpm

-- |Deserialize genesis data with a version tag. This only supports the V2
-- format.
getVersionedGenesisData :: Get GenesisDataP0
getVersionedGenesisData =
    getVersion >>= \case
        2 -> getGenesisDataV2
        n -> fail $ "Unsupported genesis data version: " ++ show n

-- |Get the total amount of GTU in genesis data.
genesisTotalGTU :: GenesisDataP0 -> Amount
genesisTotalGTU GenesisDataP0{..} =
    sum (gaBalance <$> genesisAccounts)

-- |Convert 'GenesisParameters' to 'GenesisDataP0'.
-- If some of the parameters are not valid, or inconsistent, this function will
-- raise an exception.
parametersToGenesisData :: GenesisParameters -> GenesisDataP0
parametersToGenesisData GenesisParametersV2{gpChainParameters = GenesisChainParameters{..}, ..} =
    GenesisDataP0{..}
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

-- |Determine the genesis block hash from genesis data.
genesisBlockHash :: GenesisDataP0 -> BlockHash
genesisBlockHash genData = BlockHash . Hash.hashLazy . runPutLazy $ put genesisSlot >> put genData