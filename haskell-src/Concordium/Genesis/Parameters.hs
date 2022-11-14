{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

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

-- |Representation format for the chain parameters at genesis.  This is used in the construction of
-- genesis data from JSON files.
data GenesisChainParameters' (cpv :: ChainParametersVersion) = GenesisChainParameters
    { -- |Election difficulty parameter.
      gcpElectionDifficulty :: !ElectionDifficulty,
      -- |Exchange rates.
      gcpExchangeRates :: !ExchangeRates,
      -- |Cooldown parameters.
      gcpCooldownParameters :: !(CooldownParameters cpv),
      -- |Time parameters.
      gcpTimeParameters :: !(TimeParameters cpv),
      -- |LimitAccountCreation: the maximum number of accounts
      -- that may be created in one block.
      gcpAccountCreationLimit :: !CredentialsPerBlockLimit,
      -- |Reward parameters.
      gcpRewardParameters :: !(RewardParameters cpv),
      -- |Foundation account address.
      gcpFoundationAccount :: !AccountAddress,
      -- |Minimum threshold required for registering as a baker.
      gcpPoolParameters :: !(PoolParameters cpv)
    }
    deriving (Eq, Show)

type GenesisChainParameters pv = GenesisChainParameters' (ChainParametersVersionFor pv)

instance IsChainParametersVersion cpv => FromJSON (GenesisChainParameters' cpv) where
    parseJSON = case chainParametersVersion @cpv of
        SCPV0 -> parseJSONForGCPV0
        SCPV1 -> parseJSONForGCPV1

-- |Parse 'GenesisChainParameters' from JSON for 'ChainParametersV0'.
parseJSONForGCPV0 :: Value -> Parser (GenesisChainParameters' 'ChainParametersV0)
parseJSONForGCPV0 =
    withObject "GenesisChainParameters" $ \v -> do
        gcpElectionDifficulty <- v .: "electionDifficulty"
        _erEuroPerEnergy <- v .: "euroPerEnergy"
        _erMicroGTUPerEuro <- v .: "microGTUPerEuro"
        _cpBakerExtraCooldownEpochs <- v .: "bakerCooldownEpochs"
        gcpAccountCreationLimit <- v .: "accountCreationLimit"
        gcpRewardParameters <- v .: "rewardParameters"
        gcpFoundationAccount <- v .: "foundationAccount"
        _ppBakerStakeThreshold <- v .: "minimumThresholdForBaking"
        let gcpCooldownParameters = CooldownParametersV0{..}
            gcpTimeParameters = TimeParametersV0
            gcpPoolParameters = PoolParametersV0{..}
            gcpExchangeRates = makeExchangeRates _erEuroPerEnergy _erMicroGTUPerEuro
        return GenesisChainParameters{..}

-- |Parse 'GenesisChainParameters' from JSON for 'ChainParametersV1'.
parseJSONForGCPV1 :: Value -> Parser (GenesisChainParameters' 'ChainParametersV1)
parseJSONForGCPV1 =
    withObject "GenesisChainParametersV1" $ \v -> do
        gcpElectionDifficulty <- v .: "electionDifficulty"
        _erEuroPerEnergy <- v .: "euroPerEnergy"
        _erMicroGTUPerEuro <- v .: "microGTUPerEuro"
        _cpPoolOwnerCooldown <- v .: "poolOwnerCooldown"
        _cpDelegatorCooldown <- v .: "delegatorCooldown"
        gcpAccountCreationLimit <- v .: "accountCreationLimit"
        gcpRewardParameters <- v .: "rewardParameters"
        gcpFoundationAccount <- v .: "foundationAccount"
        _finalizationCommission <- v .: "passiveFinalizationCommission"
        _bakingCommission <- v .: "passiveBakingCommission"
        _transactionCommission <- v .: "passiveTransactionCommission"
        _finalizationCommissionRange <- v .: "finalizationCommissionRange"
        _bakingCommissionRange <- v .: "bakingCommissionRange"
        _transactionCommissionRange <- v .: "transactionCommissionRange"
        _ppMinimumEquityCapital <- v .: "minimumEquityCapital"
        _ppCapitalBound <- v .: "capitalBound"
        _ppLeverageBound <- v .: "leverageBound"
        _tpRewardPeriodLength <- v .: "rewardPeriodLength"
        _tpMintPerPayday <- v .: "mintPerPayday"
        let gcpCooldownParameters = CooldownParametersV1{..}
            gcpTimeParameters = TimeParametersV1{..}
            gcpPoolParameters = PoolParametersV1{..}
            gcpExchangeRates = makeExchangeRates _erEuroPerEnergy _erMicroGTUPerEuro
            _ppPassiveCommissions = CommissionRates{..}
            _ppCommissionBounds = CommissionRanges{..}
        return GenesisChainParameters{..}

instance ToJSON (GenesisChainParameters' 'ChainParametersV0) where
    toJSON GenesisChainParameters{..} =
        object
            [ "electionDifficulty" AE..= gcpElectionDifficulty,
              "euroPerEnergy" AE..= _erEuroPerEnergy gcpExchangeRates,
              "microGTUPerEuro" AE..= _erMicroGTUPerEuro gcpExchangeRates,
              "bakerCooldownEpochs" AE..= _cpBakerExtraCooldownEpochs gcpCooldownParameters,
              "accountCreationLimit" AE..= gcpAccountCreationLimit,
              "rewardParameters" AE..= gcpRewardParameters,
              "foundationAccount" AE..= gcpFoundationAccount,
              "minimumThresholdForBaking" AE..= _ppBakerStakeThreshold gcpPoolParameters
            ]

instance ToJSON (GenesisChainParameters' 'ChainParametersV1) where
    toJSON GenesisChainParameters{..} =
        object
            [ "electionDifficulty" AE..= gcpElectionDifficulty,
              "euroPerEnergy" AE..= _erEuroPerEnergy gcpExchangeRates,
              "microGTUPerEuro" AE..= _erMicroGTUPerEuro gcpExchangeRates,
              "poolOwnerCooldown" AE..= _cpPoolOwnerCooldown gcpCooldownParameters,
              "delegatorCooldown" AE..= _cpDelegatorCooldown gcpCooldownParameters,
              "accountCreationLimit" AE..= gcpAccountCreationLimit,
              "rewardParameters" AE..= gcpRewardParameters,
              "foundationAccount" AE..= gcpFoundationAccount,
              "passiveFinalizationCommission" AE..= _finalizationCommission (_ppPassiveCommissions gcpPoolParameters),
              "passiveBakingCommission" AE..= _bakingCommission (_ppPassiveCommissions gcpPoolParameters),
              "passiveTransactionCommission" AE..= _transactionCommission (_ppPassiveCommissions gcpPoolParameters),
              "finalizationCommissionRange" AE..= _finalizationCommissionRange (_ppCommissionBounds gcpPoolParameters),
              "bakingCommissionRange" AE..= _bakingCommissionRange (_ppCommissionBounds gcpPoolParameters),
              "transactionCommissionRange" AE..= _transactionCommissionRange (_ppCommissionBounds gcpPoolParameters),
              "minimumEquityCapital" AE..= _ppMinimumEquityCapital gcpPoolParameters,
              "capitalBound" AE..= _ppCapitalBound gcpPoolParameters,
              "leverageBound" AE..= _ppLeverageBound gcpPoolParameters,
              "rewardPeriodLength" AE..= _tpRewardPeriodLength gcpTimeParameters,
              "mintPerPayday" AE..= _tpMintPerPayday gcpTimeParameters
            ]

-- | 'GenesisParameters' provides a convenient abstraction for
-- constructing 'GenesisData'. The following invariants are
-- required to hold:
--
-- * There must be at least one baker account in 'gpInitialAccounts'.
-- * Each baker in 'gpInitialAccounts' must have the correct baker id,
--   corresponding to its index in the list.
-- * The foundation account specified in 'gpChainParameters' must
--   correspond to an account in 'gpInitialAccounts'.
data GenesisParameters pv = GenesisParameters
    { -- |Time at which genesis occurs.
      gpGenesisTime :: Timestamp,
      -- |Duration of each slot.
      gpSlotDuration :: Duration,
      -- |Initial nonce for seeding the leadership election.
      gpLeadershipElectionNonce :: LeadershipElectionNonce,
      -- |Number of slots that constitute an epoch.
      gpEpochLength :: EpochLength,
      -- |Parameters affecting finalization.
      gpFinalizationParameters :: FinalizationParameters,
      -- |Cryptographic parameters.
      gpCryptographicParameters :: CryptographicParameters,
      -- |The identity providers present at genesis.
      gpIdentityProviders :: IdentityProviders,
      -- |The anonymity revokers present at genesis.
      gpAnonymityRevokers :: AnonymityRevokers,
      -- |Initial accounts. Since an account can be a baker, it is important that the
      -- order of the accounts matches the assigned baker ids.
      gpInitialAccounts :: [GenesisAccount],
      -- |Maximum total energy that can be consumed by the transactions in a block
      gpMaxBlockEnergy :: Energy,
      -- |The collection of update keys for performing updates
      gpUpdateKeys :: UpdateKeysCollection (ChainParametersVersionFor pv),
      -- |The initial (updatable) chain parameters
      gpChainParameters :: GenesisChainParameters pv
    }

instance forall pv. IsProtocolVersion pv => FromJSON (GenesisParameters pv) where
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
        let
            validateBaker (bid, GenesisAccount{gaBaker = Just bkr}) =
                unless (gbBakerId bkr == bid) $ fail $ "Expected baker id " ++ show bid ++ " but was " ++ show (gbBakerId bkr)
            validateBaker _ = return ()
        mapM_ validateBaker (zip [0 ..] gpInitialAccounts)
        gpMaxBlockEnergy <- v .: "maxBlockEnergy"
        gpUpdateKeys <- v .: "updateKeys"
        gpChainParameters <- v .: "chainParameters"
        let facct = gcpFoundationAccount gpChainParameters
        unless (any ((facct ==) . gaAddress) gpInitialAccounts) $
            fail $
                "Foundation account (" ++ show facct ++ ") is not in initialAccounts"
        return GenesisParameters{..}

-- |Version number identifying the current version of the genesis parameter format.
genesisParametersVersion :: Version
genesisParametersVersion = 2
