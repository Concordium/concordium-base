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

import Concordium.Genesis.Account
import Concordium.Types
import Concordium.Types.AnonymityRevokers
import Concordium.Types.IdentityProviders
import Concordium.Types.Parameters
import Concordium.Types.Updates

-- |Representation format for the chain parameters at genesis.  This is used in the construction of
-- genesis data from JSON files.
data GenesisChainParameters' (cpv :: ChainParametersVersion) = GenesisChainParameters
    { -- |Consensus parameters.
      gcpConsensusParameters :: !(ConsensusParameters cpv),
      -- |Exchange rates.
      gcpExchangeRates :: !ExchangeRates,
      -- |Cooldown parameters.
      gcpCooldownParameters :: !(CooldownParameters cpv),
      -- |Time parameters.
      gcpTimeParameters :: !(OParam 'PTTimeParameters cpv TimeParameters),
      -- |LimitAccountCreation: the maximum number of accounts
      -- that may be created in one block.
      gcpAccountCreationLimit :: !CredentialsPerBlockLimit,
      -- |Reward parameters.
      gcpRewardParameters :: !(RewardParameters cpv),
      -- |Foundation account address.
      gcpFoundationAccount :: !AccountAddress,
      -- |Minimum threshold required for registering as a baker.
      gcpPoolParameters :: !(PoolParameters cpv),
      -- |The Finalization committee parameters
      gcpFinalizationCommitteeParameters :: !(OParam 'PTFinalizationCommitteeParameters cpv FinalizationCommitteeParameters)
    }
    deriving (Eq, Show)

type GenesisChainParameters pv = GenesisChainParameters' (ChainParametersVersionFor pv)

instance IsChainParametersVersion cpv => FromJSON (GenesisChainParameters' cpv) where
    parseJSON = case chainParametersVersion @cpv of
        SChainParametersV0 -> parseJSONForGCPV0
        SChainParametersV1 -> parseJSONForGCPV1
        SChainParametersV2 -> parseJSONForGCPV2

-- |Parse 'GenesisChainParameters' from JSON for 'ChainParametersV0'.
parseJSONForGCPV0 :: Value -> Parser (GenesisChainParameters' 'ChainParametersV0)
parseJSONForGCPV0 =
    withObject "GenesisChainParameters" $ \v -> do
        gcpConsensusParameters <- ConsensusParametersV0 <$> v .: "electionDifficulty"
        _erEuroPerEnergy <- v .: "euroPerEnergy"
        _erMicroGTUPerEuro <- v .: "microGTUPerEuro"
        _cpBakerExtraCooldownEpochs <- v .: "bakerCooldownEpochs"
        gcpAccountCreationLimit <- v .: "accountCreationLimit"
        gcpRewardParameters <- v .: "rewardParameters"
        gcpFoundationAccount <- v .: "foundationAccount"
        _ppBakerStakeThreshold <- v .: "minimumThresholdForBaking"
        let gcpCooldownParameters = CooldownParametersV0{..}
            gcpTimeParameters = NoParam
            gcpPoolParameters = PoolParametersV0{..}
            gcpExchangeRates = makeExchangeRates _erEuroPerEnergy _erMicroGTUPerEuro
            gcpFinalizationCommitteeParameters = NoParam
        return GenesisChainParameters{..}

-- |Parse 'GenesisChainParameters' from JSON for 'ChainParametersV1'.
parseJSONForGCPV1 :: Value -> Parser (GenesisChainParameters' 'ChainParametersV1)
parseJSONForGCPV1 =
    withObject "GenesisChainParametersV1" $ \v -> do
        gcpConsensusParameters <- ConsensusParametersV0 <$> v .: "electionDifficulty"
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
            gcpTimeParameters = SomeParam TimeParametersV1{..}
            gcpPoolParameters = PoolParametersV1{..}
            gcpExchangeRates = makeExchangeRates _erEuroPerEnergy _erMicroGTUPerEuro
            _ppPassiveCommissions = CommissionRates{..}
            _ppCommissionBounds = CommissionRanges{..}
            gcpFinalizationCommitteeParameters = NoParam
        return GenesisChainParameters{..}

-- |Parse 'GenesisChainParameters' from JSON for 'ChainParametersV2'.
parseJSONForGCPV2 :: Value -> Parser (GenesisChainParameters' 'ChainParametersV2)
parseJSONForGCPV2 =
    withObject "GenesisChainParametersV2" $ \v -> do
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
        _tpTimeoutBase <- v .: "timeoutBase"
        _tpTimeoutIncrease <- v .: "timeoutIncrease"
        _tpTimeoutDecrease <- v .: "timeoutDecrease"
        _cpMinBlockTime <- v .: "minBlockTime"
        _cpBlockEnergyLimit <- v .: "blockEnergyLimit"
        _fcpMinFinalizers <- v .: "minimumFinalizers"
        _fcpMaxFinalizers <- v .: "maximumFinalizers"
        _fcpFinalizerRelativeStakeThreshold <- v .: "finalizerRelativeStakeThreshold"
        let gcpCooldownParameters = CooldownParametersV1{..}
            gcpTimeParameters = SomeParam TimeParametersV1{..}
            gcpPoolParameters = PoolParametersV1{..}
            gcpExchangeRates = makeExchangeRates _erEuroPerEnergy _erMicroGTUPerEuro
            _ppPassiveCommissions = CommissionRates{..}
            _ppCommissionBounds = CommissionRanges{..}
            _cpTimeoutParameters = TimeoutParameters{..}
            gcpFinalizationCommitteeParameters = SomeParam FinalizationCommitteeParameters{..}
            gcpConsensusParameters = ConsensusParametersV1{..}
        return GenesisChainParameters{..}

instance ToJSON (GenesisChainParameters' 'ChainParametersV0) where
    toJSON GenesisChainParameters{..} =
        object
            [ "electionDifficulty" AE..= _cpElectionDifficulty gcpConsensusParameters,
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
            [ "electionDifficulty" AE..= _cpElectionDifficulty gcpConsensusParameters,
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
              "rewardPeriodLength" AE..= _tpRewardPeriodLength (unOParam gcpTimeParameters),
              "mintPerPayday" AE..= _tpMintPerPayday (unOParam gcpTimeParameters)
            ]

instance ToJSON (GenesisChainParameters' 'ChainParametersV2) where
    toJSON GenesisChainParameters{..} =
        object
            [ "euroPerEnergy" AE..= _erEuroPerEnergy gcpExchangeRates,
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
              "rewardPeriodLength" AE..= _tpRewardPeriodLength (unOParam gcpTimeParameters),
              "mintPerPayday" AE..= _tpMintPerPayday (unOParam gcpTimeParameters),
              "timeoutBase" AE..= _tpTimeoutBase (_cpTimeoutParameters gcpConsensusParameters),
              "timeoutIncrease" AE..= _tpTimeoutIncrease (_cpTimeoutParameters gcpConsensusParameters),
              "timeoutDecrease" AE..= _tpTimeoutDecrease (_cpTimeoutParameters gcpConsensusParameters),
              "minBlockTime" AE..= _cpMinBlockTime gcpConsensusParameters,
              "blockEnergyLimit" AE..= _cpBlockEnergyLimit gcpConsensusParameters,
              "minimumFinalizers" AE..= _fcpMinFinalizers (unOParam gcpFinalizationCommitteeParameters),
              "maximumFinalizers" AE..= _fcpMaxFinalizers (unOParam gcpFinalizationCommitteeParameters),
              "finalizerRelativeStakeThreshold" AE..= _fcpFinalizerRelativeStakeThreshold (unOParam gcpFinalizationCommitteeParameters)
            ]

-- | 'GenesisParametersV2' provides a convenient abstraction for
-- constructing 'GenesisData'. The following invariants are
-- required to hold:
--
-- * There must be at least one baker account in 'gpInitialAccounts'.
-- * Each baker in 'gpInitialAccounts' must have the correct baker id,
--   corresponding to its index in the list.
-- * The foundation account specified in 'gpChainParameters' must
--   correspond to an account in 'gpInitialAccounts'.
--
-- This version is used for consensus version 0.
data GenesisParametersV2 pv = GenesisParametersV2
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
      gpUpdateKeys :: UpdateKeysCollection (AuthorizationsVersionFor (ChainParametersVersionFor pv)),
      -- |The initial (updatable) chain parameters
      gpChainParameters :: GenesisChainParameters pv
    }

instance forall pv. IsProtocolVersion pv => FromJSON (GenesisParametersV2 pv) where
    parseJSON = withObject "GenesisParametersV2" $ \v -> do
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
        let validateBaker (bid, GenesisAccount{gaBaker = Just bkr}) =
                unless (gbBakerId bkr == bid) $ fail $ "Expected baker id " ++ show bid ++ " but was " ++ show (gbBakerId bkr)
            validateBaker _ = return ()
        mapM_ validateBaker (zip [0 ..] gpInitialAccounts)
        gpMaxBlockEnergy <- v .: "maxBlockEnergy"
        gpUpdateKeys <-
            withIsAuthorizationsVersionForPV (protocolVersion @pv) $
                v .: "updateKeys"
        gpChainParameters <- v .: "chainParameters"
        let facct = gcpFoundationAccount gpChainParameters
        unless (any ((facct ==) . gaAddress) gpInitialAccounts) $
            fail $
                "Foundation account (" ++ show facct ++ ") is not in initialAccounts"
        return GenesisParametersV2{..}
