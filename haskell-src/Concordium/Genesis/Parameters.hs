{-# LANGUAGE OverloadedStrings, KindSignatures, DataKinds, ScopedTypeVariables, TypeApplications, GADTs #-}

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

data GenesisChainParameters' (cpv :: ChainParametersVersion) = GenesisChainParameters
    { -- |Election difficulty parameter.
      gcpElectionDifficulty :: !ElectionDifficulty,
      -- |Exchange rates.
      gcpExchangeRates :: !ExchangeRates,
      -- |Cooldown parameters.
      gcpCooldownParameters :: !(CooldownParameters cpv),
      -- |Time parameters.
      gcpTimeParameters :: !(TimeParameters cpv)
    , -- |LimitAccountCreation: the maximum number of accounts
      -- that may be created in one block.
      gcpAccountCreationLimit :: !CredentialsPerBlockLimit
    , -- |Reward parameters.
      gcpRewardParameters :: !(RewardParameters cpv)
    , -- |Foundation account address.
      gcpFoundationAccount :: !AccountAddress
    , -- |Minimum threshold required for registering as a baker.
      gcpPoolParameters :: !(PoolParameters cpv)
    }
    deriving (Eq, Show)

type GenesisChainParameters pv = GenesisChainParameters' (ChainParametersVersionFor pv)

-- |Constructor for chain parameters.
makeGenesisChainParametersV0 :: 
    -- |Election difficulty
    ElectionDifficulty ->
    -- |Euro:Energy rate
    ExchangeRate ->
    -- |uGTU:Euro rate
    ExchangeRate ->
    -- |Baker cooldown
    Epoch ->
    -- |Account creation limit
    CredentialsPerBlockLimit ->
    -- |Reward parameters
    RewardParameters 'ChainParametersV0 ->
    -- |Foundation account
    AccountAddress ->
    -- |Minimum threshold required for registering as a baker
    Amount ->
    GenesisChainParameters' 'ChainParametersV0
makeGenesisChainParametersV0
    gcpElectionDifficulty
    _erEuroPerEnergy
    _erMicroGTUPerEuro
    _cpBakerExtraCooldownEpochs
    gcpAccountCreationLimit
    gcpRewardParameters
    gcpFoundationAccount
    _ppBakerStakeThreshold = GenesisChainParameters{..}
      where
        gcpCooldownParameters = CooldownParametersV0{..}
        gcpTimeParameters = TimeParametersV0
        gcpPoolParameters = PoolParametersV0{..}
        gcpExchangeRates = makeExchangeRates _erEuroPerEnergy _erMicroGTUPerEuro

makeGenesisChainParametersV1 ::
    -- |Election difficulty
    ElectionDifficulty ->
    -- |Euro:Energy rate
    ExchangeRate ->
    -- |uGTU:Euro rate
    ExchangeRate ->
    -- |Number of reward periods that pool owners must cooldown
    -- when reducing their equity capital or closing the pool.
    RewardPeriod ->
    -- |Number of reward periods that a delegator must cooldown
    -- when reducing their delegated stake.
    RewardPeriod ->
    -- |Account creation limit
    CredentialsPerBlockLimit ->
    -- |Reward parameters
    RewardParameters 'ChainParametersV1 ->
    -- |Foundation account
    AccountAddress ->
    -- |Fraction of finalization rewards charged by the L-Pool.
    RewardFraction ->
    -- |Fraction of baking rewards charged by the L-pool.
    RewardFraction ->
    -- |Fraction of transaction rewards charged by the L-pool.
    RewardFraction ->
    -- |Bounds on the commission rates that may be charged by bakers.
    -- TODO: Document these
    InclusiveRange RewardFraction ->
    InclusiveRange RewardFraction ->
    InclusiveRange RewardFraction ->
    -- |Minimum equity capital required for a new baker.
    Amount -> 
    -- |Minimum fraction of the total supply required for a baker to qualify
    -- as a finalizer.
    RewardFraction -> 
    -- |Maximum fraction of the total supply of that a new baker can have.
    RewardFraction ->
    -- |The maximum leverage that a baker can have as a ratio of total stake
    -- to equity capital.
    LeverageFactor ->
    -- |Length of a payday in epochs.
    RewardPeriodLength ->
    GenesisChainParameters' 'ChainParametersV1
makeGenesisChainParametersV1 
    gcpElectionDifficulty
    _erEuroPerEnergy
    _erMicroGTUPerEuro
    _cpPoolOwnerCooldown
    _cpDelegatorCooldown
    gcpAccountCreationLimit
    gcpRewardParameters
    gcpFoundationAccount
    _finalizationCommission
    _bakingCommission
    _transactionCommission
    _finalizationCommissionRange
    _bakingCommissionRange
    _transactionCommissionRange
    _ppMinimumEquityCapital
    _ppMinimumFinalizationCapital
    _ppCapitalBound
    _ppLeverageBound
    _tpRewardPeriodLength = GenesisChainParameters{..}
      where
        gcpCooldownParameters = CooldownParametersV1{..}
        gcpTimeParameters = TimeParametersV1{..}
        gcpPoolParameters = PoolParametersV1{..}
        gcpExchangeRates = makeExchangeRates _erEuroPerEnergy _erMicroGTUPerEuro
        _ppLPoolCommissions = CommissionRates{..}
        _ppCommissionBounds = CommissionRanges{..}

instance IsChainParametersVersion cpv => FromJSON (GenesisChainParameters' cpv) where
    parseJSON = case chainParametersVersion @cpv of 
      SCPV0 -> parseJSONForGCPV0
      SCPV1 -> parseJSONForGCPV1


parseJSONForGCPV0 :: Value -> Parser (GenesisChainParameters' 'ChainParametersV0)
parseJSONForGCPV0 = 
    withObject "GenesisChainParameters" $ \v ->
        makeGenesisChainParametersV0
            <$> v .: "electionDifficulty"
            <*> v .: "euroPerEnergy"
            <*> v .: "microGTUPerEuro"
            <*> v .: "bakerCooldownEpochs"
            <*> v .: "accountCreationLimit"
            <*> v .: "rewardParameters"
            <*> v .: "foundationAccount"
            <*> v .: "minimumThresholdForBaking"

parseJSONForGCPV1 :: Value -> Parser (GenesisChainParameters' 'ChainParametersV1)
parseJSONForGCPV1 = 
    withObject "GenesisChainParametersV1" $ \v ->
        makeGenesisChainParametersV1
            <$> v .: "electionDifficulty"
            <*> v .: "euroPerEnergy"
            <*> v .: "microGTUPerEuro"
            <*> v .: "poolOwnerCooldown"
            <*> v .: "delegatorCooldown"
            <*> v .: "accountCreationLimit"
            <*> v .: "rewardParameters"
            <*> v .: "foundationAccount"
            <*> v .: "finalizationCommissionLPool"
            <*> v .: "bakingCommissionLPool"
            <*> v .: "transactionCommissionLPool"
            <*> v .: "finalizationCommissionRange"
            <*> v .: "bakingCommissionRange"
            <*> v .: "transactionCommissionRange"
            <*> v .: "minimumEquityCapital"
            <*> v .: "minimumFinalizationCapital"
            <*> v .: "capitalBound"
            <*> v .: "leverageBound"
            <*> v .: "rewardPeriodLength"

instance ToJSON (GenesisChainParameters' 'ChainParametersV0) where
    toJSON GenesisChainParameters{..} =
        object
            [ "electionDifficulty" AE..= gcpElectionDifficulty
            , "euroPerEnergy" AE..= _erEuroPerEnergy gcpExchangeRates
            , "microGTUPerEuro" AE..= _erMicroGTUPerEuro gcpExchangeRates
            , "bakerCooldownEpochs" AE..= _cpBakerExtraCooldownEpochs gcpCooldownParameters
            , "accountCreationLimit" AE..= gcpAccountCreationLimit
            , "rewardParameters" AE..= gcpRewardParameters
            , "foundationAccount" AE..= gcpFoundationAccount
            , "minimumThresholdForBaking" AE..= _ppBakerStakeThreshold gcpPoolParameters
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
              "finalizationCommissionLPool" AE..= _finalizationCommission (_ppLPoolCommissions gcpPoolParameters),
              "bakingCommissionLPool" AE..= _bakingCommission (_ppLPoolCommissions gcpPoolParameters),
              "transactionCommissionLPool" AE..= _transactionCommission (_ppLPoolCommissions gcpPoolParameters),
              "finalizationCommissionRange" AE..= _finalizationCommissionRange (_ppCommissionBounds gcpPoolParameters),
              "bakingCommissionRange" AE..= _bakingCommissionRange (_ppCommissionBounds gcpPoolParameters),
              "transactionCommissionRange" AE..= _transactionCommissionRange (_ppCommissionBounds gcpPoolParameters),
              "minimumEquityCapital" AE..= _ppMinimumEquityCapital gcpPoolParameters,
              "minimumFinalizationCapital" AE..= _ppMinimumFinalizationCapital gcpPoolParameters,
              "capitalBound" AE..= _ppCapitalBound gcpPoolParameters,
              "leverageBound" AE..= _ppLeverageBound gcpPoolParameters,
              "rewardPeriodLength" AE..= _tpRewardPeriodLength gcpTimeParameters
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
    , -- |The collection of update keys for performing updates
      gpUpdateKeys :: UpdateKeysCollection (ChainParametersVersionFor pv)
    , -- |The initial (updatable) chain parameters
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
            validateBaker (bid, GenesisAccount{gaBaker = Just bkr})
              = unless (gbBakerId bkr == bid) $ fail $ "Expected baker id " ++ show bid ++ " but was " ++ show (gbBakerId bkr)
            validateBaker _ = return ()
        mapM_ validateBaker (zip [0..] gpInitialAccounts)
        gpMaxBlockEnergy <- v .: "maxBlockEnergy"
        gpUpdateKeys <- v .: "updateKeys"
        gpChainParameters <- v .: "chainParameters"
        let facct = gcpFoundationAccount gpChainParameters
        unless (any ((facct ==) . gaAddress) gpInitialAccounts) $
            fail $ "Foundation account (" ++ show facct ++ ") is not in initialAccounts"
        return GenesisParameters{..}

-- |Alias for the current version of the genesis parameter format.
-- type GenesisParameters = GenesisParametersV2

-- |Version number identifying the current version of the genesis parameter format.
genesisParametersVersion :: Version
genesisParametersVersion = 2
