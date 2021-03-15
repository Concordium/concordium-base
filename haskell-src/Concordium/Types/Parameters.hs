{-# LANGUAGE OverloadedStrings #-}

module Concordium.Types.Parameters where

import Control.Monad
import qualified Data.Aeson as AE
import Data.Aeson.Types
import Data.Ratio
import Data.Serialize
import Data.Word
import Lens.Micro.Platform

import qualified Concordium.Crypto.SHA256 as Hash
import Concordium.ID.Parameters
import Concordium.Types
import Concordium.Types.HashableTo
import Concordium.Types.Updates
    ( HasRewardParameters(rewardParameters), RewardParameters )

-- |Chain cryptographic parameters.
type CryptographicParameters = GlobalContext

-- |Updatable chain parameters.
data ChainParameters = ChainParameters
    { -- |Election difficulty parameter.
      _cpElectionDifficulty :: !ElectionDifficulty,
      -- |Euro:Energy rate.
      _cpEuroPerEnergy :: !ExchangeRate,
      -- |uGTU:Euro rate.
      _cpMicroGTUPerEuro :: !ExchangeRate,
      -- |uGTU:Energy rate.
      -- This is derived, but will be computed when the other
      -- rates are updated since it is more useful.
      _cpEnergyRate :: !EnergyRate,
      -- |Number of additional epochs that bakers must cool down when
      -- removing stake. The cool-down will effectively be 2 epochs
      -- longer than this value, since at any given time, the bakers
      -- (and stakes) for the current and next epochs have already
      -- been determined.
      _cpBakerExtraCooldownEpochs :: !Epoch,
      -- |LimitAccountCreation: the maximum number of accounts
      -- that may be created in one block.
      _cpAccountCreationLimit :: !CredentialsPerBlockLimit,
      -- |Reward parameters.
      _cpRewardParameters :: !RewardParameters,
      -- |Foundation account index.
      _cpFoundationAccount :: !AccountIndex
    , -- |Minimum threshold required for registering as a baker.
      _cpBakerStakeThreshold :: !Amount
    }
    deriving (Eq, Show)

-- |Constructor for chain parameters.
makeChainParameters ::
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
    RewardParameters ->
    -- |Foundation account
    AccountIndex ->
    -- |Minimum threshold required for registering as a baker
    Amount ->
    ChainParameters
makeChainParameters
    _cpElectionDifficulty
    _cpEuroPerEnergy
    _cpMicroGTUPerEuro
    _cpBakerExtraCooldownEpochs
    _cpAccountCreationLimit
    _cpRewardParameters
    _cpFoundationAccount
    _cpBakerStakeThreshold =
        ChainParameters{..}
      where
        _cpEnergyRate = computeEnergyRate _cpMicroGTUPerEuro _cpEuroPerEnergy

-- |Election difficulty chain parameter.
{-# INLINE cpElectionDifficulty #-}
cpElectionDifficulty :: Lens' ChainParameters ElectionDifficulty
cpElectionDifficulty = lens _cpElectionDifficulty (\cp ed -> cp{_cpElectionDifficulty = ed})

-- |Euro:Energy rate parameter.
{-# INLINE cpEuroPerEnergy #-}
cpEuroPerEnergy :: Lens' ChainParameters ExchangeRate
cpEuroPerEnergy = lens _cpEuroPerEnergy (\cp epe -> cp{_cpEuroPerEnergy = epe, _cpEnergyRate = computeEnergyRate (_cpMicroGTUPerEuro cp) epe})

-- |uGTU:Euro rate parameter.
{-# INLINE cpMicroGTUPerEuro #-}
cpMicroGTUPerEuro :: Lens' ChainParameters ExchangeRate
cpMicroGTUPerEuro = lens _cpMicroGTUPerEuro (\cp mgtupe -> cp{_cpMicroGTUPerEuro = mgtupe, _cpEnergyRate = computeEnergyRate mgtupe (_cpEuroPerEnergy cp)})

-- |uGTU:Energy rate parameter (derived).
{-# INLINE cpEnergyRate #-}
cpEnergyRate :: SimpleGetter ChainParameters EnergyRate
cpEnergyRate = to _cpEnergyRate

-- |Additional cooldown epochs on changes that reduce a baker's stake.
{-# INLINE cpBakerExtraCooldownEpochs #-}
cpBakerExtraCooldownEpochs :: Lens' ChainParameters Epoch
cpBakerExtraCooldownEpochs = lens _cpBakerExtraCooldownEpochs (\cp bce -> cp{_cpBakerExtraCooldownEpochs = bce})

-- |Foundation account chain parameter.
{-# INLINE cpFoundationAccount #-}
cpFoundationAccount :: Lens' ChainParameters AccountIndex
cpFoundationAccount = lens _cpFoundationAccount (\cp fa -> cp{_cpFoundationAccount = fa})

-- |LimitAccountCreation parameter.
{-# INLINE cpAccountCreationLimit #-}
cpAccountCreationLimit :: Lens' ChainParameters CredentialsPerBlockLimit
cpAccountCreationLimit = lens _cpAccountCreationLimit (\cp acl -> cp{_cpAccountCreationLimit = acl})

-- |Minimum baker threshold parameter.
{-# INLINE cpBakerStakeThreshold #-}
cpBakerStakeThreshold :: Lens' ChainParameters Amount
cpBakerStakeThreshold = lens _cpBakerStakeThreshold (\cp bmt -> cp{_cpBakerStakeThreshold = bmt})

instance HasRewardParameters ChainParameters where
    rewardParameters = lens _cpRewardParameters (\cp rp -> cp{_cpRewardParameters = rp})

instance Serialize ChainParameters where
    put ChainParameters{..} = do
        put _cpElectionDifficulty
        put _cpEuroPerEnergy
        put _cpMicroGTUPerEuro
        put _cpBakerExtraCooldownEpochs
        put _cpAccountCreationLimit
        put _cpRewardParameters
        put _cpFoundationAccount
        put _cpBakerStakeThreshold
    get = makeChainParameters <$> get <*> get <*> get <*> get <*> get <*> get <*> get <*> get

instance HashableTo Hash.Hash ChainParameters where
    getHash = Hash.hash . encode

instance Monad m => MHashableTo m Hash.Hash ChainParameters

instance FromJSON ChainParameters where
    parseJSON = withObject "ChainParameters" $ \v ->
        makeChainParameters
            <$> v .: "electionDifficulty"
            <*> v .: "euroPerEnergy"
            <*> v .: "microGTUPerEuro"
            <*> v .: "bakerCooldownEpochs"
            <*> v .: "accountCreationLimit"
            <*> v .: "rewardParameters"
            <*> v .: "foundationAccountIndex"
            <*> v .: "minimumThresholdForBaking"

instance ToJSON ChainParameters where
    toJSON ChainParameters{..} =
        object
            [ "electionDifficulty" AE..= _cpElectionDifficulty,
              "euroPerEnergy" AE..= _cpEuroPerEnergy,
              "microGTUPerEuro" AE..= _cpMicroGTUPerEuro,
              "bakerCooldownEpochs" AE..= _cpBakerExtraCooldownEpochs,
              "accountCreationLimit" AE..= _cpAccountCreationLimit,
              "rewardParameters" AE..= _cpRewardParameters,
              "foundationAccountIndex" AE..= _cpFoundationAccount
            , "minimumThresholdForBaking" AE..= _cpBakerStakeThreshold
            ]

-- |Parameters that affect finalization.
data FinalizationParameters = FinalizationParameters
    { -- |Number of levels to skip between finalizations.
      finalizationMinimumSkip :: BlockHeight,
      -- |Maximum size of the finalization committee; determines the minimum stake
      -- required to join the committee as @totalGTU / finalizationCommitteeMaxSize@.
      finalizationCommitteeMaxSize :: FinalizationCommitteeSize,
      -- |Base delay time used in finalization.
      finalizationWaitingTime :: Duration,
      -- |Factor used to shrink the finalization gap. Must be strictly between 0 and 1.
      finalizationSkipShrinkFactor :: Ratio Word64,
      -- |Factor used to grow the finalization gap. Must be strictly greater than 1.
      finalizationSkipGrowFactor :: Ratio Word64,
      -- |Factor for shrinking the finalization delay (i.e. number of descendent blocks
      -- required to be eligible as a finalization target).
      finalizationDelayShrinkFactor :: Ratio Word64,
      -- |Factor for growing the finalization delay when it takes more than one round
      -- to finalize a block.
      finalizationDelayGrowFactor :: Ratio Word64,
      -- |Whether to allow the delay to be 0. (This allows a block to be finalized as soon
      -- as it is baked.)
      finalizationAllowZeroDelay :: Bool
    }
    deriving (Eq, Show)

-- |Serialize 'FinalizationParameters' in the V2 GenesisData
-- format.
putFinalizationParametersGD2 :: Putter FinalizationParameters
putFinalizationParametersGD2 FinalizationParameters{..} = do
    put finalizationMinimumSkip
    put finalizationCommitteeMaxSize
    put finalizationWaitingTime
    put True -- finalizationIgnoreFirstWait
    put False -- finalizationOldStyleSkip
    put finalizationSkipShrinkFactor
    put finalizationSkipGrowFactor
    put finalizationDelayShrinkFactor
    put finalizationDelayGrowFactor
    put finalizationAllowZeroDelay

-- |Deserialize 'FinalizationParameters' in the V2 GenesisData
-- format.
getFinalizationParametersGD2 :: Get FinalizationParameters
getFinalizationParametersGD2 = label "FinalizationParameters" $ do
    finalizationMinimumSkip <- get
    finalizationCommitteeMaxSize <- get
    finalizationWaitingTime <- get
    finalizationIgnoreFirstWait <- get
    unless finalizationIgnoreFirstWait $
        fail "finalizationIgnoreFirstWait must be True"
    finalizationOldStyleSkip <- get
    when finalizationOldStyleSkip $
        fail "finalizationOldStyleSkip must be False"
    finalizationSkipShrinkFactor <- get
    unless (finalizationSkipShrinkFactor > 0 && finalizationSkipShrinkFactor < 1) $
        fail "skipShrinkFactor must be strictly between 0 and 1"
    finalizationSkipGrowFactor <- get
    unless (finalizationSkipGrowFactor > 1) $
        fail "skipGrowFactor must be strictly greater than 1"
    finalizationDelayShrinkFactor <- get
    unless (finalizationDelayShrinkFactor > 0 && finalizationDelayShrinkFactor < 1) $
        fail "delayShrinkFactor must be strictly between 0 and 1"
    finalizationDelayGrowFactor <- get
    unless (finalizationDelayGrowFactor > 1) $
        fail "delayGrowFactor must be strictly greater than 1"
    finalizationAllowZeroDelay <- get
    return FinalizationParameters{..}

-- |Serialize 'FinalizationParameters' in the V3 GenesisData
-- format.
putFinalizationParametersGD3 :: Putter FinalizationParameters
putFinalizationParametersGD3 FinalizationParameters{..} = do
    put finalizationMinimumSkip
    put finalizationCommitteeMaxSize
    put finalizationWaitingTime
    put finalizationSkipShrinkFactor
    put finalizationSkipGrowFactor
    put finalizationDelayShrinkFactor
    put finalizationDelayGrowFactor
    put finalizationAllowZeroDelay

-- |Deserialize 'FinalizationParameters' in the V3 GenesisData
-- format
getFinalizationParametersGD3 :: Get FinalizationParameters
getFinalizationParametersGD3 = label "FinalizationParameters" $ do
    finalizationMinimumSkip <- get
    finalizationCommitteeMaxSize <- get
    finalizationWaitingTime <- get
    finalizationSkipShrinkFactor <- get
    unless (finalizationSkipShrinkFactor > 0 && finalizationSkipShrinkFactor < 1) $
        fail "skipShrinkFactor must be strictly between 0 and 1"
    finalizationSkipGrowFactor <- get
    unless (finalizationSkipGrowFactor > 1) $
        fail "skipGrowFactor must be strictly greater than 1"
    finalizationDelayShrinkFactor <- get
    unless (finalizationDelayShrinkFactor > 0 && finalizationDelayShrinkFactor < 1) $
        fail "delayShrinkFactor must be strictly between 0 and 1"
    finalizationDelayGrowFactor <- get
    unless (finalizationDelayGrowFactor > 1) $
        fail "delayGrowFactor must be strictly greater than 1"
    finalizationAllowZeroDelay <- get
    return FinalizationParameters{..}

instance FromJSON FinalizationParameters where
    parseJSON = withObject "FinalizationParameters" $ \v -> do
        finalizationMinimumSkip <- BlockHeight <$> v .: "minimumSkip"
        finalizationCommitteeMaxSize <- v .: "committeeMaxSize"
        finalizationWaitingTime <- v .: "waitingTime"
        finalizationIgnoreFirstWait <- v .:? "ignoreFirstWait" .!= True
        unless finalizationIgnoreFirstWait $
            fail "ignoreFirstWait must be true (or not specified)"
        finalizationOldStyleSkip <- v .:? "oldStyleSkip" .!= False
        when finalizationOldStyleSkip $
            fail "oldStyleSkip must be false (or not specified)"
        finalizationSkipShrinkFactor <- v .: "skipShrinkFactor"
        unless (finalizationSkipShrinkFactor > 0 && finalizationSkipShrinkFactor < 1) $
            fail "skipShrinkFactor must be strictly between 0 and 1"
        finalizationSkipGrowFactor <- v .: "skipGrowFactor"
        unless (finalizationSkipGrowFactor > 1) $
            fail "skipGrowFactor must be strictly greater than 1"
        finalizationDelayShrinkFactor <- v .: "delayShrinkFactor"
        unless (finalizationDelayShrinkFactor > 0 && finalizationDelayShrinkFactor < 1) $
            fail "delayShrinkFactor must be strictly between 0 and 1"
        finalizationDelayGrowFactor <- v .: "delayGrowFactor"
        unless (finalizationDelayGrowFactor > 1) $
            fail "delayGrowFactor must be strictly greater than 1"
        finalizationAllowZeroDelay <- v .:? "allowZeroDelay" .!= False
        return FinalizationParameters{..}
