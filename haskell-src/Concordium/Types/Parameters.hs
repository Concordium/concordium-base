{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE StandaloneDeriving #-}

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
import Concordium.Types.Updates (
    HasRewardParameters (rewardParameters),
    RewardParameters,
 )

data ChainParametersVersion = ChainParametersV0 | ChainParametersV1
    deriving (Show)

type family ChainParametersVersionFor (pv :: ProtocolVersion) :: ChainParametersVersion where
    ChainParametersVersionFor 'P1 = 'ChainParametersV0
    ChainParametersVersionFor 'P2 = 'ChainParametersV0
    ChainParametersVersionFor 'P3 = 'ChainParametersV0
    ChainParametersVersionFor 'P4 = 'ChainParametersV1

data SChainParametersVersion (cpv :: ChainParametersVersion) where
    SCPV0 :: SChainParametersVersion 'ChainParametersV0
    SCPV1 :: SChainParametersVersion 'ChainParametersV1

chainParametersVersionFor :: SProtocolVersion pv -> SChainParametersVersion (ChainParametersVersionFor pv)
chainParametersVersionFor spv = case spv of 
    SP1 -> SCPV0
    SP2 -> SCPV0
    SP3 -> SCPV0
    SP4 -> SCPV1


-- |Chain cryptographic parameters.
type CryptographicParameters = GlobalContext

data ExchangeRates = ExchangeRates
    { -- |Euro:Energy rate.
      _erEuroPerEnergy :: !ExchangeRate,
      -- |uGTU:Euro rate.
      _erMicroGTUPerEuro :: !ExchangeRate,
      -- |uGTU:Energy rate.
      -- This is derived, but will be computed when the other
      -- rates are updated since it is more useful.
      _erEnergyRate :: !EnergyRate
    }
    deriving (Eq, Show)

instance Serialize ExchangeRates where
    put ExchangeRates{..} = do
        put _erEuroPerEnergy
        put _erMicroGTUPerEuro
    get = makeExchangeRates <$> get <*> get

makeExchangeRates ::
    -- |Euro:Energy rate
    ExchangeRate ->
    -- |uGTU:Euro rate
    ExchangeRate ->
    ExchangeRates
makeExchangeRates _erEuroPerEnergy _erMicroGTUPerEuro = ExchangeRates{..}
  where
    _erEnergyRate = computeEnergyRate _erMicroGTUPerEuro _erEuroPerEnergy

class HasExchangeRates t where
    exchangeRates :: Lens' t ExchangeRates
    euroPerEnergy :: Lens' t ExchangeRate
    euroPerEnergy = exchangeRates . lens _erEuroPerEnergy (\er epe -> er{_erEuroPerEnergy = epe, _erEnergyRate = computeEnergyRate (_erMicroGTUPerEuro er) epe})
    microGTUPerEuro :: Lens' t ExchangeRate
    microGTUPerEuro = exchangeRates . lens _erMicroGTUPerEuro (\er mgtupe -> er{_erMicroGTUPerEuro = mgtupe, _erEnergyRate = computeEnergyRate mgtupe (_erEuroPerEnergy er)})
    energyRate :: SimpleGetter t EnergyRate
    energyRate = exchangeRates . to _erEnergyRate

instance HasExchangeRates ExchangeRates where
    exchangeRates = id
    euroPerEnergy = lens _erEuroPerEnergy (\er epe -> er{_erEuroPerEnergy = epe, _erEnergyRate = computeEnergyRate (_erMicroGTUPerEuro er) epe})
    microGTUPerEuro = lens _erMicroGTUPerEuro (\er mgtupe -> er{_erMicroGTUPerEuro = mgtupe, _erEnergyRate = computeEnergyRate mgtupe (_erEuroPerEnergy er)})
    energyRate = to _erEnergyRate

-- |Euro:Energy rate parameter.
{-# INLINE erEuroPerEnergy #-}
erEuroPerEnergy :: Lens' ExchangeRates ExchangeRate
erEuroPerEnergy = lens _erEuroPerEnergy (\er epe -> er{_erEuroPerEnergy = epe, _erEnergyRate = computeEnergyRate (_erMicroGTUPerEuro er) epe})

-- |uGTU:Euro rate parameter.
{-# INLINE erMicroGTUPerEuro #-}
erMicroGTUPerEuro :: Lens' ExchangeRates ExchangeRate
erMicroGTUPerEuro = lens _erMicroGTUPerEuro (\er mgtupe -> er{_erMicroGTUPerEuro = mgtupe, _erEnergyRate = computeEnergyRate mgtupe (_erEuroPerEnergy er)})

-- |uGTU:Energy rate parameter (derived).
{-# INLINE erEnergyRate #-}
erEnergyRate :: SimpleGetter ExchangeRates EnergyRate
erEnergyRate = to _erEnergyRate

-- |Version-indexed type of cooldown parameters.
-- This is a newtype to provide instances of 'Eq' and 'Show'.
data CooldownParameters cpv where
    CooldownParametersV0 :: { -- |Number of additional epochs that bakers must cool down when
      -- removing stake. The cool-down will effectively be 2 epochs
      -- longer than this value, since at any given time, the bakers
      -- (and stakes) for the current and next epochs have already
      -- been determined.
      _cpBakerExtraCooldownEpochs :: Epoch
    } -> CooldownParameters 'ChainParametersV0
    CooldownParametersV1 :: { -- |Number of reward periods that pool owners must cooldown
      -- when reducing their equity capital or closing the pool.
      _cpPoolOwnerCooldown :: !RewardPeriod,
      -- |Number of reward periods that a delegator must cooldown
      -- when reducing their delegated stake.
      _cpDelegatorCooldown :: !RewardPeriod
    } -> CooldownParameters 'ChainParametersV1

-- |Lens for '_cpBakerExtraCooldownEpochs'
{-# INLINE cpBakerExtraCooldownEpochs #-}
cpBakerExtraCooldownEpochs :: Lens' (CooldownParameters 'ChainParametersV0) Epoch
cpBakerExtraCooldownEpochs =
  lens _cpBakerExtraCooldownEpochs (\cp x -> cp{_cpBakerExtraCooldownEpochs = x})

-- |Lens for '_cpPoolOwnerCooldown'
{-# INLINE cpPoolOwnerCooldown #-}
cpPoolOwnerCooldown :: Lens' (CooldownParameters 'ChainParametersV1) RewardPeriod
cpPoolOwnerCooldown =
  lens _cpPoolOwnerCooldown (\cp x -> cp{_cpPoolOwnerCooldown = x})

-- |Lens for '_cpDelegatorCooldown'
{-# INLINE cpDelegatorCooldown #-}
cpDelegatorCooldown :: Lens' (CooldownParameters 'ChainParametersV1) RewardPeriod
cpDelegatorCooldown =
  lens _cpDelegatorCooldown (\cp x -> cp{_cpDelegatorCooldown = x})
    
deriving instance Eq (CooldownParameters cpv)
deriving instance Show (CooldownParameters cpv)

putCooldownParameters :: Putter (CooldownParameters cpv)
putCooldownParameters CooldownParametersV0{..} = do
        put _cpBakerExtraCooldownEpochs
putCooldownParameters CooldownParametersV1{..} = do
        put _cpPoolOwnerCooldown
        put _cpDelegatorCooldown

getCooldownParameters :: SChainParametersVersion cpv -> Get (CooldownParameters cpv)
getCooldownParameters scpv = case scpv of
    SCPV0 -> CooldownParametersV0 <$> get
    SCPV1 -> CooldownParametersV1 <$> get <*> get

data TimeParameters cpv where
    TimeParametersV0 :: TimeParameters 'ChainParametersV0
    TimeParametersV1 :: {
         _tpRewardPeriodLength :: RewardPeriodLength
    } -> TimeParameters 'ChainParametersV1

-- |Lens for '_tpRewardPeriodLength'
{-# INLINE tpRewardPeriodLength #-}
tpRewardPeriodLength :: Lens' (TimeParameters 'ChainParametersV1) RewardPeriodLength
tpRewardPeriodLength =
  lens _tpRewardPeriodLength (\tp x -> tp{_tpRewardPeriodLength = x})

putTimeParameters :: Putter (TimeParameters cpv)
putTimeParameters TimeParametersV0 = return ()
putTimeParameters TimeParametersV1{..} = do
        put _tpRewardPeriodLength

getTimeParameters :: SChainParametersVersion cpv -> Get (TimeParameters cpv)
getTimeParameters scpv = case scpv of
    SCPV0 -> return TimeParametersV0
    SCPV1 -> TimeParametersV1 <$> get

deriving instance Eq (TimeParameters cpv)
deriving instance Show (TimeParameters cpv)

-- |The commission rates charged by a pool owner.
data CommissionRates = CommissionRates
    { -- |Fraction of finalization rewards charged by the pool owner.
      _finalizationCommission :: RewardFraction,
      -- |Fraction of baking rewards charged by the pool owner.
      _bakingCommission :: RewardFraction,
      -- |Fraction of transaction rewards charged by the pool owner.
      _transactionCommission :: RewardFraction
    }
    deriving (Eq, Show)

makeLenses ''CommissionRates

instance Serialize CommissionRates where
    put CommissionRates{..} = do
        put _finalizationCommission
        put _bakingCommission
        put _transactionCommission
    get = CommissionRates <$> get <*> get <*> get

-- |A range that includes both endpoints.
data InclusiveRange a = InclusiveRange {irMin :: !a, irMax :: !a}
    deriving (Eq, Show)

instance ToJSON a => ToJSON (InclusiveRange a) where
    toJSON InclusiveRange{..} = 
        object [
            "min" AE..= irMin,
            "max" AE..= irMax
        ]

instance FromJSON a => FromJSON (InclusiveRange a) where
    parseJSON = withObject "InclusiveRange" $ \v -> InclusiveRange <$> v .: "min" <*> v .: "max"

instance (Serialize a, Ord a) => Serialize (InclusiveRange a) where
    put InclusiveRange{..} = do
        put irMin
        put irMax
    get = do
        irMin <- get
        irMax <- get
        when (irMin > irMax) $ fail "Invalid interval. Left endpoint cannot be bigger than right endpoint."
        return InclusiveRange{..}

-- |Determine if a value is in a given 'InclusiveRange'.
isInRange :: (Ord a) => a -> InclusiveRange a -> Bool
isInRange v InclusiveRange{..} = irMin <= v && v <= irMax

-- |Ranges of allowed commision values that pools may choose from.
data CommissionRanges = CommissionRanges
    { -- |The range of allowed finalization commisions.
      _finalizationCommissionRange :: !(InclusiveRange RewardFraction),
      -- |The range of allowed baker commisions.
      _bakingCommissionRange :: !(InclusiveRange RewardFraction),
      -- |The range of allowed transaction commisions.
      _transactionCommissionRange :: !(InclusiveRange RewardFraction)
    }
    deriving (Eq, Show)
makeLenses ''CommissionRanges

instance Serialize (CommissionRanges) where
    put CommissionRanges{..} = do
        put _finalizationCommissionRange
        put _bakingCommissionRange
        put _transactionCommissionRange
    get = CommissionRanges <$> get <*> get <*> get

type LeverageFactor = Ratio Word64

data PoolParameters cpv where
    PoolParametersV0 :: { -- |Minimum threshold required for registering as a baker.
      _ppBakerStakeThreshold :: Amount
    } -> PoolParameters 'ChainParametersV0
    PoolParametersV1 :: { -- |Commission rates charged by the L-pool.
      _ppLPoolCommissions :: !CommissionRates,
      -- |Bounds on the commission rates that may be charged by bakers.
      _ppCommissionBounds :: !CommissionRanges,
      -- |Minimum equity capital required for a new baker.
      _ppMinimumEquityCapital :: !Amount,
      -- |Minimum fraction of the total supply required for a baker to qualify
      -- as a finalizer.
      _ppMinimumFinalizationCapital :: !RewardFraction,
      -- |Maximum fraction of the total supply of that a new baker can have.
      _ppCapitalBound :: !RewardFraction,
      -- |The maximum leverage that a baker can have as a ratio of total stake
      -- to equity capital.
      _ppLeverageBound :: !LeverageFactor
    } -> PoolParameters 'ChainParametersV1

-- |Lens for '_ppBakerStakeThreshold'
{-# INLINE ppBakerStakeThreshold #-}
ppBakerStakeThreshold :: Lens' (PoolParameters 'ChainParametersV0) Amount
ppBakerStakeThreshold =
  lens _ppBakerStakeThreshold (\pp x -> pp{_ppBakerStakeThreshold = x})

-- |Lens for '_ppLPoolCommissions'
{-# INLINE ppLPoolCommissions #-}
ppLPoolCommissions :: Lens' (PoolParameters 'ChainParametersV1) CommissionRates
ppLPoolCommissions =
  lens _ppLPoolCommissions (\pp x -> pp{_ppLPoolCommissions = x})

-- |Lens for '_ppCommissionBounds'
{-# INLINE ppCommissionBounds #-}
ppCommissionBounds :: Lens' (PoolParameters 'ChainParametersV1) CommissionRanges
ppCommissionBounds =
  lens _ppCommissionBounds (\pp x -> pp{_ppCommissionBounds = x})

-- |Lens for '_ppMinimumEquityCapital'
{-# INLINE ppMinimumEquityCapital #-}
ppMinimumEquityCapital :: Lens' (PoolParameters 'ChainParametersV1) Amount
ppMinimumEquityCapital =
  lens _ppMinimumEquityCapital (\pp x -> pp{_ppMinimumEquityCapital = x})

-- |Lens for '_ppMinimumFinalizationCapital'
{-# INLINE ppMinimumFinalizationCapital #-}
ppMinimumFinalizationCapital :: Lens' (PoolParameters 'ChainParametersV1) RewardFraction
ppMinimumFinalizationCapital =
  lens _ppMinimumFinalizationCapital (\pp x -> pp{_ppMinimumFinalizationCapital = x})

-- |Lens for '_ppCapitalBound'
{-# INLINE ppCapitalBound #-}
ppCapitalBound :: Lens' (PoolParameters 'ChainParametersV1) RewardFraction
ppCapitalBound =
  lens _ppCapitalBound (\pp x -> pp{_ppCapitalBound = x})

-- |Lens for '_ppLeverageBound'
{-# INLINE ppLeverageBound #-}
ppLeverageBound :: Lens' (PoolParameters 'ChainParametersV1) LeverageFactor
ppLeverageBound =
  lens _ppLeverageBound (\pp x -> pp{_ppLeverageBound = x})

putPoolParameters :: Putter (PoolParameters cpv)
putPoolParameters PoolParametersV0{..} = do
    put _ppBakerStakeThreshold
putPoolParameters PoolParametersV1{..} = do
        put _ppLPoolCommissions
        put _ppCommissionBounds
        put _ppMinimumEquityCapital
        put _ppMinimumFinalizationCapital
        put _ppCapitalBound
        put _ppLeverageBound

getPoolParameters :: SChainParametersVersion cpv -> Get (PoolParameters cpv)
getPoolParameters scpv = case scpv of
    SCPV0 -> PoolParametersV0 <$> get
    SCPV1 -> PoolParametersV1 <$> get <*> get <*> get <*> get <*> get <*> get

deriving instance Eq (PoolParameters cpv)
deriving instance Show (PoolParameters cpv)

-- |Updatable chain parameters.
data ChainParameters' (cpv :: ChainParametersVersion) = ChainParameters
    { -- |Election difficulty parameter.
      _cpElectionDifficulty :: !ElectionDifficulty,
      -- |Exchange rates.
      _cpExchangeRates :: !ExchangeRates,
      -- |Cooldown parameters.
      _cpCooldownParameters :: !(CooldownParameters cpv),
      -- |Time parameters.
      _cpTimeParameters :: !(TimeParameters cpv),
      -- |LimitAccountCreation: the maximum number of accounts
      -- that may be created in one block.
      _cpAccountCreationLimit :: !CredentialsPerBlockLimit,
      -- |Reward parameters.
      _cpRewardParameters :: !RewardParameters,
      -- |Foundation account index.
      _cpFoundationAccount :: !AccountIndex,
      -- |Minimum threshold required for registering as a baker.
      _cpPoolParameters :: !(PoolParameters cpv)
    }
    deriving (Eq, Show)

makeLenses ''ChainParameters'

type ChainParameters pv = ChainParameters' (ChainParametersVersionFor pv)

-- |Constructor for chain parameters.
makeChainParametersV0 :: 
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
    ChainParameters' 'ChainParametersV0
makeChainParametersV0
    _cpElectionDifficulty
    _cpEuroPerEnergy
    _cpMicroGTUPerEuro
    _cpBakerExtraCooldownEpochs
    _cpAccountCreationLimit
    _cpRewardParameters
    _cpFoundationAccount
    _ppBakerStakeThreshold = ChainParameters{..}
      where
        _cpCooldownParameters = CooldownParametersV0{..}
        _cpTimeParameters = TimeParametersV0
        _cpPoolParameters = PoolParametersV0{..}
        _cpExchangeRates = makeExchangeRates _cpEuroPerEnergy _cpMicroGTUPerEuro

makeChainParametersV1 ::
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
    RewardParameters ->
    -- |Foundation account
    AccountIndex ->
    -- |Fraction of finalization rewards charged by the L-Pool.
    RewardFraction ->
    -- |Fraction of baking rewards charged by the L-pool.
    RewardFraction ->
    -- |Fraction of transaction rewards charged by the L-pool.
    RewardFraction ->
    -- |The range of allowed finalization commisions for normal pools.
    InclusiveRange RewardFraction ->
    -- |The range of allowed baker commisions for normal pools.
    InclusiveRange RewardFraction ->
    -- |The range of allowed transaction commisions for normal pools.
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
    ChainParameters' 'ChainParametersV1
makeChainParametersV1 
    _cpElectionDifficulty
    _cpEuroPerEnergy
    _cpMicroGTUPerEuro
    _cpPoolOwnerCooldown
    _cpDelegatorCooldown
    _cpAccountCreationLimit
    _cpRewardParameters
    _cpFoundationAccount
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
    _tpRewardPeriodLength = ChainParameters{..}
      where
        _cpCooldownParameters = CooldownParametersV1{..}
        _cpTimeParameters = TimeParametersV1{..}
        _cpPoolParameters = PoolParametersV1{..}
        _cpExchangeRates = makeExchangeRates _cpEuroPerEnergy _cpMicroGTUPerEuro
        _ppLPoolCommissions = CommissionRates{..}
        _ppCommissionBounds = CommissionRanges{..}
        

instance HasExchangeRates (ChainParameters' cpv) where
    exchangeRates = cpExchangeRates

instance HasRewardParameters (ChainParameters' cpv) where
    rewardParameters = cpRewardParameters

putChainParameters :: Putter (ChainParameters' cpv)
putChainParameters ChainParameters{..} = do
    put _cpElectionDifficulty
    put _cpExchangeRates
    putCooldownParameters _cpCooldownParameters
    putTimeParameters _cpTimeParameters
    put _cpAccountCreationLimit
    put _cpRewardParameters
    put _cpFoundationAccount
    putPoolParameters _cpPoolParameters

getChainParameters :: SChainParametersVersion cpv -> Get (ChainParameters' cpv)
getChainParameters scpv = ChainParameters <$> get <*> get <*> (getCooldownParameters scpv) <*> (getTimeParameters scpv) <*> get <*> get <*> get <*> (getPoolParameters scpv)

instance HashableTo Hash.Hash (ChainParameters' cpv) where
    getHash = Hash.hash . runPut . putChainParameters

instance Monad m => MHashableTo m Hash.Hash (ChainParameters' cpv)

parseJSONForCPV0 :: Value -> Parser (ChainParameters' 'ChainParametersV0)
parseJSONForCPV0 = 
    withObject "ChainParameters" $ \v ->
        makeChainParametersV0
            <$> v .: "electionDifficulty"
            <*> v .: "euroPerEnergy"
            <*> v .: "microGTUPerEuro"
            <*> v .: "bakerCooldownEpochs"
            <*> v .: "accountCreationLimit"
            <*> v .: "rewardParameters"
            <*> v .: "foundationAccountIndex"
            <*> v .: "minimumThresholdForBaking"

parseJSONForCPV1 :: Value -> Parser (ChainParameters' 'ChainParametersV1)
parseJSONForCPV1 = 
    withObject "ChainParametersV1" $ \v ->
        makeChainParametersV1
            <$> v .: "electionDifficulty"
            <*> v .: "euroPerEnergy"
            <*> v .: "microGTUPerEuro"
            <*> v .: "poolOwnerCooldown"
            <*> v .: "delegatorCooldown"
            <*> v .: "accountCreationLimit"
            <*> v .: "rewardParameters"
            <*> v .: "foundationAccountIndex"
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

instance FromJSON (ChainParameters' 'ChainParametersV0) where
    parseJSON = parseJSONForCPV0

instance FromJSON (ChainParameters' 'ChainParametersV1) where
    parseJSON = parseJSONForCPV1

instance ToJSON (ChainParameters' 'ChainParametersV0) where
    toJSON ChainParameters{..} =
        object
            [ "electionDifficulty" AE..= _cpElectionDifficulty,
              "euroPerEnergy" AE..= _erEuroPerEnergy _cpExchangeRates,
              "microGTUPerEuro" AE..= _erMicroGTUPerEuro _cpExchangeRates,
              "bakerCooldownEpochs" AE..= _cpBakerExtraCooldownEpochs _cpCooldownParameters,
              "accountCreationLimit" AE..= _cpAccountCreationLimit,
              "rewardParameters" AE..= _cpRewardParameters,
              "foundationAccountIndex" AE..= _cpFoundationAccount,
              "minimumThresholdForBaking" AE..= _ppBakerStakeThreshold _cpPoolParameters
            ]

instance ToJSON (ChainParameters' 'ChainParametersV1) where
    toJSON ChainParameters{..} =
        object
            [ "electionDifficulty" AE..= _cpElectionDifficulty,
              "euroPerEnergy" AE..= _erEuroPerEnergy _cpExchangeRates,
              "microGTUPerEuro" AE..= _erMicroGTUPerEuro _cpExchangeRates,
              "poolOwnerCooldown" AE..= _cpPoolOwnerCooldown _cpCooldownParameters,
              "delegatorCooldown" AE..= _cpDelegatorCooldown _cpCooldownParameters,
              "accountCreationLimit" AE..= _cpAccountCreationLimit,
              "rewardParameters" AE..= _cpRewardParameters,
              "foundationAccountIndex" AE..= _cpFoundationAccount,
              "finalizationCommissionLPool" AE..= _finalizationCommission (_ppLPoolCommissions _cpPoolParameters),
              "bakingCommissionLPool" AE..= _bakingCommission (_ppLPoolCommissions _cpPoolParameters),
              "transactionCommissionLPool" AE..= _transactionCommission (_ppLPoolCommissions _cpPoolParameters),
              "finalizationCommissionRange" AE..= _finalizationCommissionRange (_ppCommissionBounds _cpPoolParameters),
              "bakingCommissionRange" AE..= _bakingCommissionRange (_ppCommissionBounds _cpPoolParameters),
              "transactionCommissionRange" AE..= _transactionCommissionRange (_ppCommissionBounds _cpPoolParameters),
              "minimumEquityCapital" AE..= _ppMinimumEquityCapital _cpPoolParameters,
              "minimumFinalizationCapital" AE..= _ppMinimumFinalizationCapital _cpPoolParameters,
              "capitalBound" AE..= _ppCapitalBound _cpPoolParameters,
              "leverageBound" AE..= _ppLeverageBound _cpPoolParameters,
              "rewardPeriodLength" AE..= _tpRewardPeriodLength _cpTimeParameters
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

