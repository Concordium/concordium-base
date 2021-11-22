{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE GADTs #-}

module Concordium.Types.Parameters where

import Control.Monad
import qualified Data.Aeson as AE
import Data.Aeson.Types
import Data.Ratio
import Data.Serialize
import Data.Word
import GHC.TypeNats
import Lens.Micro.Platform

import qualified Concordium.Crypto.SHA256 as Hash
import Concordium.ID.Parameters
import Concordium.Types
import Concordium.Types.HashableTo
import Concordium.Types.ProtocolVersion.TH
import Concordium.Types.Updates (
    HasRewardParameters (rewardParameters),
    RewardParameters,
 )
import Data.Function

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

-- |Cooldown parameters for protocol versions P1, P2 and P3.
newtype CooldownParametersP1 = CooldownParametersP1
    { -- |Number of additional epochs that bakers must cool down when
      -- removing stake. The cool-down will effectively be 2 epochs
      -- longer than this value, since at any given time, the bakers
      -- (and stakes) for the current and next epochs have already
      -- been determined.
      _cpBakerExtraCooldownEpochs :: Epoch
    }
    deriving (Eq, Show)

-- |Cooldown parameters for protocol version P4.
data CooldownParametersP4 = CooldownParameterP4
    { -- |Number of reward periods that pool owners must cooldown
      -- when reducing their equity capital or closing the pool.
      _cpPoolOwnerCooldown :: !RewardPeriod,
      -- |Number of reward periods that a delegator must cooldown
      -- when reducing their delegated stake.
      _cpDelegatorCooldown :: !RewardPeriod
    }
    deriving (Eq, Show)

-- |Type family for cooldown parameters.
type family CooldownParametersType (pv :: ProtocolVersion) where
    CooldownParametersType 'P1 = CooldownParametersP1
    CooldownParametersType 'P2 = CooldownParametersP1
    CooldownParametersType 'P3 = CooldownParametersP1
    CooldownParametersType 'P4 = CooldownParametersP4

-- |Version-indexed type of cooldown parameters.
-- This is a newtype to provide instances of 'Eq' and 'Show'.
newtype CooldownParameters pv = CooldownParameters {theCooldownParameters :: CooldownParametersType pv}

instance forall pv. (IsProtocolVersion pv) => Eq (CooldownParameters pv) where
    (==) = $(casePV [t|pv|] [|(==)|]) `on` theCooldownParameters

instance forall pv. (IsProtocolVersion pv) => Show (CooldownParameters pv) where
    show = $(casePV [t|pv|] [|show|]) . theCooldownParameters

newtype TimeParametersP4 = TimeParametersP4
    { _tpRewardPeriodLength :: RewardPeriodLength
    }
    deriving (Eq, Show)

type family TimeParametersType (pv :: ProtocolVersion) where
    TimeParametersType 'P1 = ()
    TimeParametersType 'P2 = ()
    TimeParametersType 'P3 = ()
    TimeParametersType 'P4 = TimeParametersP4

newtype TimeParameters (pv :: ProtocolVersion) = TimeParameters
    { theTimeParameters :: TimeParametersType pv
    }

instance forall pv. (IsProtocolVersion pv) => Eq (TimeParameters pv) where
    (==) = $(casePV [t|pv|] [|(==)|]) `on` theTimeParameters

instance forall pv. (IsProtocolVersion pv) => Show (TimeParameters pv) where
    show = $(casePV [t|pv|] [|show|]) . theTimeParameters

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

-- |A range that includes both endpoints.
data InclusiveRange a = InclusiveRange {irMin :: !a, irMax :: !a}
    deriving (Eq, Show)

-- |Determine if a value is in a given 'InclusiveRange'.
isInRange :: (Ord a) => a -> InclusiveRange a -> Bool
isInRange v InclusiveRange{..} = irMin <= v && v <= irMax

data CommissionRanges = CommissionRanges
    { _finalizationCommissionRange :: !(InclusiveRange RewardFraction),
      _bakingCommissionRange :: !(InclusiveRange RewardFraction),
      _transactionCommissionRange :: !(InclusiveRange RewardFraction)
    }
    deriving (Eq, Show)
makeLenses ''CommissionRanges

type LeverageFactor = Ratio Word64

newtype PoolParametersP1 = PoolParametersP1
    { -- |Minimum threshold required for registering as a baker.
      _ppBakerStakeThreshold :: Amount
    }
    deriving (Eq, Show)

data PoolParametersP4 = PoolParametersP4
    { -- |Commission rates charged by the L-pool.
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
    }
    deriving (Eq, Show)

type family PoolParametersType pv where
    PoolParametersType 'P1 = PoolParametersP1
    PoolParametersType 'P2 = PoolParametersP1
    PoolParametersType 'P3 = PoolParametersP1
    PoolParametersType 'P4 = PoolParametersP4

newtype PoolParameters pv = PoolParameters {thePoolParameters :: PoolParametersType pv}

instance forall pv. (IsProtocolVersion pv) => Eq (PoolParameters pv) where
    (==) = $(casePV [t|pv|] [|(==)|]) `on` thePoolParameters

instance forall pv. (IsProtocolVersion pv) => Show (PoolParameters pv) where
    show = $(casePV [t|pv|] [|show|]) . thePoolParameters

-- |Updatable chain parameters.
data ChainParameters (pv :: ProtocolVersion) = ChainParameters
    { -- |Election difficulty parameter.
      _cpElectionDifficulty :: !ElectionDifficulty,
      -- |Exchange rates.
      _cpExchangeRates :: !ExchangeRates,
      -- |Cooldown parameters.
      _cpCooldownParameters :: !(CooldownParameters pv),
      -- |Time parameters.
      _cpTimeParameters :: !(TimeParameters pv),
      -- |LimitAccountCreation: the maximum number of accounts
      -- that may be created in one block.
      _cpAccountCreationLimit :: !CredentialsPerBlockLimit,
      -- |Reward parameters.
      _cpRewardParameters :: !RewardParameters,
      -- |Foundation account index.
      _cpFoundationAccount :: !AccountIndex,
      -- |Minimum threshold required for registering as a baker.
      _cpBakerStakeThreshold :: !Amount
    }
    deriving (Eq, Show)

makeLenses ''ChainParameters

data Foo pv where
    LeftFoo :: (PVNat pv <= 3) => Foo pv
    RightFoo :: (4 <= PVNat pv) => Foo pv

foo :: forall pv. (IsProtocolVersion pv) => Foo pv
foo = case protocolVersion @pv of
    SP1 -> LeftFoo
    SP2 -> LeftFoo
    SP3 -> LeftFoo
    SP4 -> RightFoo

-- |Constructor for chain parameters.
makeChainParametersP1 :: forall pv. (IsProtocolVersion pv, PVNat pv <= 3) =>
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
    ChainParameters pv
makeChainParametersP1
    _cpElectionDifficulty
    _cpEuroPerEnergy
    _cpMicroGTUPerEuro
    _cpBakerExtraCooldownEpochs
    _cpAccountCreationLimit
    _cpRewardParameters
    _cpFoundationAccount
    _cpBakerStakeThreshold = ChainParameters{..}
      where
        _cpCooldownParameters = -- $(casePV [t|pv|] [|CooldownParameters (CooldownParametersP1{..})|])
            case protocolVersion @pv of
                SP1 -> CooldownParameters (CooldownParametersP1{..})
                SP2 -> CooldownParameters (CooldownParametersP1{..})
                SP3 -> CooldownParameters (CooldownParametersP1{..})
        _cpTimeParameters = undefined -- $(casePV [t|pv|] [|TimeParameters ()|])
        _cpExchangeRates = makeExchangeRates _cpMicroGTUPerEuro _cpEuroPerEnergy

instance HasExchangeRates (ChainParameters pv) where
    exchangeRates = cpExchangeRates

instance HasRewardParameters (ChainParameters pv) where
    rewardParameters = cpRewardParameters

putChainParametersP1 :: (PVNat pv <= 3) => Putter (ChainParameters pv)
putChainParametersP1 = undefined

putChainParametersP4 :: (4 <= PVNat pv) => Putter (ChainParameters pv)
putChainParametersP4 = undefined


instance forall pv. (IsProtocolVersion pv) => Serialize (ChainParameters pv) where
    put cp = case foo @pv of
        LeftFoo -> putChainParametersP1 cp
        RightFoo -> putChainParametersP4 cp
    get = undefined

{-}
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
              "foundationAccountIndex" AE..= _cpFoundationAccount,
              "minimumThresholdForBaking" AE..= _cpBakerStakeThreshold
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
-}
