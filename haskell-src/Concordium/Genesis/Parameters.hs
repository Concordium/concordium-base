{-# LANGUAGE OverloadedStrings #-}

module Concordium.Genesis.Parameters where

import Control.Monad
import qualified Data.Aeson as AE
import Data.Aeson.Types

import Concordium.Common.Version
import Concordium.Genesis.Account
import Concordium.Types
import Concordium.Types.AnonymityRevokers
import Concordium.Types.IdentityProviders
import Concordium.Types.Parameters
import Concordium.Types.Updates

data GenesisChainParameters = GenesisChainParameters
    { -- |Election difficulty parameter.
      gcpElectionDifficulty :: !ElectionDifficulty
    , -- |Euro:Energy rate.
      gcpEuroPerEnergy :: !ExchangeRate
    , -- |uGTU:Euro rate.
      gcpMicroGTUPerEuro :: !ExchangeRate
    , -- |Number of additional epochs that bakers must cool down when
      -- removing stake. The cool-down will effectively be 2 epochs
      -- longer than this value, since at any given time, the bakers
      -- (and stakes) for the current and next epochs have already
      -- been determined.
      gcpBakerExtraCooldownEpochs :: !Epoch
    , -- |LimitAccountCreation: the maximum number of accounts
      -- that may be created in one block.
      gcpAccountCreationLimit :: !CredentialsPerBlockLimit
    , -- |Reward parameters.
      gcpRewardParameters :: !RewardParameters
    , -- |Foundation account address.
      gcpFoundationAccount :: !AccountAddress
    , -- |Minimum threshold required for registering as a baker.
      gcpBakerStakeThreshold :: !Amount
    }

instance FromJSON GenesisChainParameters where
    parseJSON = withObject "GenesisChainParameters" $ \v ->
        GenesisChainParameters
            <$> v .: "electionDifficulty"
            <*> v .: "euroPerEnergy"
            <*> v .: "microGTUPerEuro"
            <*> v .: "bakerCooldownEpochs"
            <*> v .: "accountCreationLimit"
            <*> v .: "rewardParameters"
            <*> v .: "foundationAccount"
            <*> v .: "minimumThresholdForBaking"

instance ToJSON GenesisChainParameters where
    toJSON GenesisChainParameters{..} =
        object
            [ "electionDifficulty" AE..= gcpElectionDifficulty
            , "euroPerEnergy" AE..= gcpEuroPerEnergy
            , "microGTUPerEuro" AE..= gcpMicroGTUPerEuro
            , "bakerCooldownEpochs" AE..= gcpBakerExtraCooldownEpochs
            , "accountCreationLimit" AE..= gcpAccountCreationLimit
            , "rewardParameters" AE..= gcpRewardParameters
            , "foundationAccount" AE..= gcpFoundationAccount
            , "minimumThresholdForBaking" AE..= gcpBakerStakeThreshold
            ]

-- 'GenesisParameters' provides a convenient abstraction for
-- constructing 'GenesisData'.
data GenesisParametersV2 = GenesisParametersV2
    { -- |Time at which genesis occurs.
      gpGenesisTime :: Timestamp
    , -- |Duration of each slot.
      gpSlotDuration :: Duration
    , -- |Initial nonce for seeding the leadership election.
      gpLeadershipElectionNonce :: LeadershipElectionNonce
    , -- |Number of slots that constitute an epoch.
      gpEpochLength :: EpochLength
    , -- |Parameters affecting finalization.
      gpFinalizationParameters :: FinalizationParameters
    , -- |Cryptographic parameters.
      gpCryptographicParameters :: CryptographicParameters
    , -- |The identity providers present at genesis.
      gpIdentityProviders :: IdentityProviders
    , -- |The anonymity revokers present at genesis.
      gpAnonymityRevokers :: AnonymityRevokers
    , -- |Initial accounts. Since an account can be a baker, it is important that the
      -- order of the accounts matches the assigned baker ids.
      gpInitialAccounts :: [GenesisAccount]
    , -- |Maximum total energy that can be consumed by the transactions in a block
      gpMaxBlockEnergy :: Energy
    , -- |The initial update authorizations
      gpAuthorizations :: Authorizations
    , -- |The initial (updatable) chain parameters
      gpChainParameters :: GenesisChainParameters
    }

instance FromJSON GenesisParametersV2 where
    parseJSON = withObject "GenesisParameters" $ \v -> do
        gpGenesisTime <- v .: "genesisTime"
        gpSlotDuration <- v .: "slotDuration"
        gpLeadershipElectionNonce <- v .: "leadershipElectionNonce"
        gpEpochLength <- Slot <$> v .: "epochLength"
        when (gpEpochLength == 0) $ fail "Epoch length should be non-zero"
        gpFinalizationParameters <- v .: "finalizationParameters"
        gpCryptographicParameters <- v .: "cryptographicParameters"
        gpIdentityProviders <- v .:? "identityProviders" .!= emptyIdentityProviders
        gpAnonymityRevokers <- v .:? "anonymityRevokers" .!= emptyAnonymityRevokers
        gpInitialAccounts <- v .:? "initialAccounts" .!= []
        let hasBaker GenesisAccount{gaBaker = Nothing} = False
            hasBaker _ = True
        unless (any hasBaker gpInitialAccounts) $ fail "Must have at least one baker at genesis"
        gpMaxBlockEnergy <- v .: "maxBlockEnergy"
        gpAuthorizations <- v .: "updateAuthorizations"
        gpChainParameters <- v .: "chainParameters"
        let facct = gcpFoundationAccount gpChainParameters
        unless (any ((facct ==) . gaAddress) gpInitialAccounts) $
            fail $ "Foundation account (" ++ show facct ++ ") is not in initialAccounts"
        return GenesisParametersV2{..}

-- |Alias for the current version of the genesis parameter format.
type GenesisParameters = GenesisParametersV2

-- |Version number identifying the current version of the genesis parameter format.
genesisParametersVersion :: Version
genesisParametersVersion = 2
