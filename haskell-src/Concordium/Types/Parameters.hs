{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE PolyKinds #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE StandaloneKindSignatures #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE UndecidableInstances #-}
-- We suppress redundant constraint warnings since GHC does not detect when a constraint is used
-- for pattern matching. (See: https://gitlab.haskell.org/ghc/ghc/-/issues/20896)
{-# OPTIONS_GHC -Wno-redundant-constraints #-}

module Concordium.Types.Parameters where

import Control.Monad
import qualified Data.Aeson as AE
import Data.Aeson.TH
import Data.Aeson.Types
import Data.Bool.Singletons
import Data.Maybe
import Data.Ratio
import Data.Serialize
import Data.Singletons.TH
import Data.Word
import Lens.Micro.Platform
import Test.QuickCheck.Arbitrary
import Test.QuickCheck.Gen

import qualified Concordium.Crypto.SHA256 as Hash
import Concordium.ID.Parameters
import Concordium.Types
import Concordium.Types.HashableTo
import Concordium.Utils

$( singletons
    [d|
        data ParameterType
            = PTElectionDifficulty
            | PTTimeParameters
            | PTMintPerSlot
            | PTTimeoutParameters
            | PTMinBlockTime
            | PTBlockEnergyLimit
            | PTCooldownParametersAccessStructure
            | PTFinalizationProof

        isSupported :: ParameterType -> ChainParametersVersion -> Bool
        isSupported PTElectionDifficulty ChainParametersV0 = True
        isSupported PTElectionDifficulty ChainParametersV1 = True
        isSupported PTElectionDifficulty ChainParametersV2 = False
        isSupported PTTimeParameters ChainParametersV0 = False
        isSupported PTTimeParameters ChainParametersV1 = True
        isSupported PTTimeParameters ChainParametersV2 = True
        isSupported PTMintPerSlot ChainParametersV0 = True
        isSupported PTMintPerSlot ChainParametersV1 = False
        isSupported PTMintPerSlot ChainParametersV2 = False
        isSupported PTTimeoutParameters ChainParametersV0 = False
        isSupported PTTimeoutParameters ChainParametersV1 = False
        isSupported PTTimeoutParameters ChainParametersV2 = True
        isSupported PTMinBlockTime ChainParametersV0 = False
        isSupported PTMinBlockTime ChainParametersV1 = False
        isSupported PTMinBlockTime ChainParametersV2 = True
        isSupported PTBlockEnergyLimit ChainParametersV0 = False
        isSupported PTBlockEnergyLimit ChainParametersV1 = False
        isSupported PTBlockEnergyLimit ChainParametersV2 = True
        isSupported PTCooldownParametersAccessStructure ChainParametersV0 = False
        isSupported PTCooldownParametersAccessStructure ChainParametersV1 = True
        isSupported PTCooldownParametersAccessStructure ChainParametersV2 = True
        isSupported PTFinalizationProof ChainParametersV0 = True
        isSupported PTFinalizationProof ChainParametersV1 = True
        isSupported PTFinalizationProof ChainParametersV2 = False
        |]
 )

type IsParameterType (pt :: ParameterType) = SingI pt

-- |An @OParam pt cpv a@ is an @a@ if the parameter type @pt@ is supported at @cpv@, and @()@
-- otherwise.
data OParam (pt :: ParameterType) (cpv :: ChainParametersVersion) a where
    NoParam :: (IsSupported pt cpv ~ 'False) => OParam pt cpv a
    SomeParam :: (IsSupported pt cpv ~ 'True) => !a -> OParam pt cpv a

-- |Unwrap the 'OParam' when the parameter is supported.
unOParam :: (IsSupported pt cpv ~ 'True) => OParam pt cpv a -> a
unOParam (SomeParam a) = a

instance Functor (OParam pt cpv) where
    fmap _ NoParam = NoParam
    fmap f (SomeParam v) = SomeParam (f v)

instance Foldable (OParam pt cpv) where
    foldr _ b NoParam = b
    foldr f b (SomeParam a) = f a b

    foldl _ b NoParam = b
    foldl f b (SomeParam a) = f b a

    foldMap _ NoParam = mempty
    foldMap f (SomeParam a) = f a

instance Traversable (OParam pt cpv) where
    traverse _ NoParam = pure NoParam
    traverse f (SomeParam a) = SomeParam <$> f a

instance (Eq a) => Eq (OParam pt cpv a) where
    NoParam == NoParam = True
    SomeParam a == SomeParam b = a == b

instance (Ord a) => Ord (OParam pt cpv a) where
    compare NoParam NoParam = EQ
    compare (SomeParam a) (SomeParam b) = compare a b

instance (Show a) => Show (OParam pt cpv a) where
    show NoParam = "<parameter type unsupported>"
    show (SomeParam a) = show a

instance (Serialize a, SingI pt, IsChainParametersVersion cpv) => Serialize (OParam pt cpv a) where
    put NoParam = return ()
    put (SomeParam a) = put a

    get = whenSupported get

whenSupported :: forall pt cpv f a. (Applicative f, SingI pt, IsChainParametersVersion cpv) => f a -> f (OParam pt cpv a)
whenSupported m = case sIsSupported (sing @pt) (chainParametersVersion @cpv) of
    SFalse -> pure NoParam
    STrue -> SomeParam <$> m

pureWhenSupported :: forall pt cpv a. (SingI pt, IsChainParametersVersion cpv) => a -> OParam pt cpv a
pureWhenSupported v = case sIsSupported (sing @pt) (chainParametersVersion @cpv) of
    SFalse -> NoParam
    STrue -> SomeParam v

maybeWhenSupported :: b -> (a -> b) -> OParam pt cpv a -> b
maybeWhenSupported b _ NoParam = b
maybeWhenSupported _ f (SomeParam a) = f a

-- |Chain cryptographic parameters.
type CryptographicParameters = GlobalContext

-- |The minting rate and the distribution of newly-minted GTU
-- among bakers, finalizers, and the foundation account.
-- It must be the case that
-- @_mdBakingReward + _mdFinalizationReward <= 1@.
-- The remaining amount is the platform development charge.
data MintDistribution cpv = MintDistribution
    { -- |Mint rate per slot
      _mdMintPerSlot :: !(OParam 'PTMintPerSlot cpv MintRate),
      -- |BakingRewMintFrac: the fraction allocated to baker rewards
      _mdBakingReward :: !AmountFraction,
      -- |FinRewMintFrac: the fraction allocated to finalization rewards
      _mdFinalizationReward :: !AmountFraction
    }
    deriving (Eq, Show)

-- Define 'HasMintDistribution' class with accessor lenses, and instance for 'MintDistribution'.
makeClassy ''MintDistribution

instance ToJSON (MintDistribution cpv) where
    toJSON MintDistribution{..} =
        object
            ( mintPerSlot
                ++ [ "bakingReward" AE..= _mdBakingReward,
                     "finalizationReward" AE..= _mdFinalizationReward
                   ]
            )
      where
        mintPerSlot = foldMap (\mintRate -> ["mintPerSlot" AE..= mintRate]) _mdMintPerSlot

instance IsChainParametersVersion cpv => FromJSON (MintDistribution cpv) where
    parseJSON = withObject "MintDistribution" $ \v -> do
        _mdMintPerSlot <- whenSupported (v .: "mintPerSlot")
        _mdBakingReward <- v .: "bakingReward"
        _mdFinalizationReward <- v .: "finalizationReward"
        unless (isJust (_mdBakingReward `addAmountFraction` _mdFinalizationReward)) $ fail "Amount fractions exceed 100%"
        return MintDistribution{..}

instance IsChainParametersVersion cpv => Serialize (MintDistribution cpv) where
    put MintDistribution{..} = put _mdMintPerSlot >> put _mdBakingReward >> put _mdFinalizationReward
    get = do
        _mdMintPerSlot <- get
        _mdBakingReward <- get
        _mdFinalizationReward <- get
        unless (isJust (_mdBakingReward `addAmountFraction` _mdFinalizationReward)) $ fail "Amount fractions exceed 100%"
        return MintDistribution{..}

instance IsChainParametersVersion cpv => HashableTo Hash.Hash (MintDistribution cpv) where
    getHash = Hash.hash . encode

instance Arbitrary (MintDistribution 'ChainParametersV1) where
    arbitrary = do
        (x, y) <- arbitrary `suchThat` (\(x, y) -> isJust $ addAmountFraction x y)
        return $ MintDistribution NoParam x y

instance (Monad m, IsChainParametersVersion cpv) => MHashableTo m Hash.Hash (MintDistribution cpv)

-- |The distribution of block transaction fees among the block
-- baker, the GAS account, and the foundation account.  It
-- must be the case that @_tfdBaker + _tfdGASAccount <= 1@.
-- The remaining amount is the TransChargeFrac (paid to the
-- foundation account).
data TransactionFeeDistribution = TransactionFeeDistribution
    { -- |BakerTransFrac: the fraction allocated to the baker
      _tfdBaker :: !AmountFraction,
      -- |The fraction allocated to the GAS account
      _tfdGASAccount :: !AmountFraction
    }
    deriving (Eq, Show)

-- Define 'HasTransactionFeeDistribution' class with accessor lenses, and instance for 'TransactionFeeDistribution'.
makeClassy ''TransactionFeeDistribution

instance ToJSON TransactionFeeDistribution where
    toJSON TransactionFeeDistribution{..} =
        object
            [ "baker" AE..= _tfdBaker,
              "gasAccount" AE..= _tfdGASAccount
            ]
instance FromJSON TransactionFeeDistribution where
    parseJSON = withObject "TransactionFeeDistribution" $ \v -> do
        _tfdBaker <- v .: "baker"
        _tfdGASAccount <- v .: "gasAccount"
        unless (isJust (_tfdBaker `addAmountFraction` _tfdGASAccount)) $ fail "Transaction fee fractions exceed 100%"
        return TransactionFeeDistribution{..}

instance Serialize TransactionFeeDistribution where
    put TransactionFeeDistribution{..} = put _tfdBaker >> put _tfdGASAccount
    get = do
        _tfdBaker <- get
        _tfdGASAccount <- get
        unless (isJust (_tfdBaker `addAmountFraction` _tfdGASAccount)) $ fail "Transaction fee fractions exceed 100%"
        return TransactionFeeDistribution{..}

instance HashableTo Hash.Hash TransactionFeeDistribution where
    getHash = Hash.hash . encode

instance Monad m => MHashableTo m Hash.Hash TransactionFeeDistribution

-- |Parameters that determine the proportion of the GAS account that is paid to the baker (pool)
-- under various circumstances.
data GASRewards cpv = GASRewards
    { -- |BakerPrevTransFrac: fraction paid to baker
      _gasBaker :: !AmountFraction,
      -- |FeeAddFinalisationProof: fraction paid for including a
      -- finalization proof in a block.
      _gasFinalizationProof :: !(OParam 'PTFinalizationProof cpv AmountFraction),
      -- |FeeAccountCreation: fraction paid for including each
      -- account creation transaction in a block.
      _gasAccountCreation :: !AmountFraction,
      -- |FeeUpdate: fraction paid for including an update
      -- transaction in a block.
      _gasChainUpdate :: !AmountFraction
    }
    deriving (Eq, Show)

makeClassy ''GASRewards

instance AE.ToJSON (GASRewards cpv) where
    toJSON GASRewards{..} =
        object
            ( "baker" AE..= _gasBaker : finalizationProof
                ++ [
                     "accountCreation" AE..= _gasAccountCreation,
                     "chainUpdate" AE..= _gasChainUpdate
                   ]
            )
      where
        finalizationProof = foldMap (\finProof -> ["finalizationProof" AE..= finProof]) _gasFinalizationProof

instance IsChainParametersVersion cpv => AE.FromJSON (GASRewards cpv) where
    parseJSON = withObject "RewardParameters" $ \v -> do
        _gasBaker <- v .: "baker"
        _gasFinalizationProof <- whenSupported $ v .: "finalizationProof"
        _gasAccountCreation <- v .: "accountCreation"
        _gasChainUpdate <- v .: "chainUpdate"
        return GASRewards{..}

-- JSON serialization for the GASRewards structure with fields "baker", "finalizationProof",
-- "accountCreation" and "chainUpdate".
-- $(deriveJSON AE.defaultOptions{AE.fieldLabelModifier = firstLower . drop 4} ''GASRewards)

instance IsChainParametersVersion cpv => Serialize (GASRewards cpv) where
    put GASRewards{..} = do
        put _gasBaker
        put _gasFinalizationProof
        put _gasAccountCreation
        put _gasChainUpdate
    get = do
        _gasBaker <- get
        _gasFinalizationProof <- get
        _gasAccountCreation <- get
        _gasChainUpdate <- get
        return GASRewards{..}

instance IsChainParametersVersion cpv => HashableTo Hash.Hash (GASRewards cpv) where
    getHash = Hash.hash . encode

instance (Monad m, IsChainParametersVersion cpv) => MHashableTo m Hash.Hash (GASRewards cpv)

-- |Parameters affecting rewards.
-- It must be that @rpBakingRewMintFrac + rpFinRewMintFrac < 1@
data RewardParameters cpv = RewardParameters
    { -- |Distribution of newly-minted GTUs.
      _rpMintDistribution :: !(MintDistribution cpv),
      -- |Distribution of transaction fees.
      _rpTransactionFeeDistribution :: !TransactionFeeDistribution,
      -- |Rewards paid from the GAS account.
      _rpGASRewards :: !(GASRewards cpv)
    }
    deriving (Eq, Show)

makeClassy ''RewardParameters

instance HasMintDistribution (RewardParameters cpv) cpv where
    mintDistribution = rpMintDistribution

instance HasTransactionFeeDistribution (RewardParameters cpv) where
    transactionFeeDistribution = rpTransactionFeeDistribution

instance HasGASRewards (RewardParameters cpv) cpv where
    gASRewards = rpGASRewards

instance AE.ToJSON (RewardParameters cpv) where
    toJSON RewardParameters{..} =
        object
            [ "mintDistribution" AE..= _rpMintDistribution,
              "transactionFeeDistribution" AE..= _rpTransactionFeeDistribution,
              "gASRewards" AE..= _rpGASRewards
            ]

instance IsChainParametersVersion cpv => AE.FromJSON (RewardParameters cpv) where
    parseJSON = withObject "RewardParameters" $ \v -> do
        _rpMintDistribution <- v .: "mintDistribution"
        _rpTransactionFeeDistribution <- v .: "transactionFeeDistribution"
        _rpGASRewards <- v .: "gASRewards"
        return RewardParameters{..}

instance IsChainParametersVersion cpv => Serialize (RewardParameters cpv) where
    put RewardParameters{..} = do
        put _rpMintDistribution
        put _rpTransactionFeeDistribution
        put _rpGASRewards
    get = do
        _rpMintDistribution <- get
        _rpTransactionFeeDistribution <- get
        _rpGASRewards <- get
        return RewardParameters{..}

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

-- |Lenses (and a getter) for accessing the 'ExchangeRates' fields.
-- Note that 'energyRate' is a getter, since it should not be updated directly, but only as a
-- result of changes to the 'euroPerEnergy' or 'microGTUPerEuro' updates.
class HasExchangeRates t where
    -- |Access the 'ExchangeRates' structure.
    exchangeRates :: Lens' t ExchangeRates

    -- |Access the Euro per energy rate.
    -- Updating this also affects the energy rate.
    euroPerEnergy :: Lens' t ExchangeRate
    euroPerEnergy = exchangeRates . lens _erEuroPerEnergy (\er epe -> er{_erEuroPerEnergy = epe, _erEnergyRate = computeEnergyRate (_erMicroGTUPerEuro er) epe})

    -- |Access the microGTU [microCCD] per Euro rate.
    -- Updating this also affects the energy rate.
    microGTUPerEuro :: Lens' t ExchangeRate
    microGTUPerEuro = exchangeRates . lens _erMicroGTUPerEuro (\er mgtupe -> er{_erMicroGTUPerEuro = mgtupe, _erEnergyRate = computeEnergyRate mgtupe (_erEuroPerEnergy er)})

    -- |Getter for the energy to GTU [CCD] rate.
    energyRate :: SimpleGetter t EnergyRate
    energyRate = exchangeRates . to _erEnergyRate

instance HasExchangeRates ExchangeRates where
    {-# INLINE exchangeRates #-}
    exchangeRates = id
    {-# INLINE euroPerEnergy #-}
    euroPerEnergy = lens _erEuroPerEnergy (\er epe -> er{_erEuroPerEnergy = epe, _erEnergyRate = computeEnergyRate (_erMicroGTUPerEuro er) epe})
    {-# INLINE microGTUPerEuro #-}
    microGTUPerEuro = lens _erMicroGTUPerEuro (\er mgtupe -> er{_erMicroGTUPerEuro = mgtupe, _erEnergyRate = computeEnergyRate mgtupe (_erEuroPerEnergy er)})
    {-# INLINE energyRate #-}
    energyRate = to _erEnergyRate

$( singletons
    [d|
        data CooldownParametersVersion = CooldownParametersVersion0 | CooldownParametersVersion1

        cooldownParametersVersionFor :: ChainParametersVersion -> CooldownParametersVersion
        cooldownParametersVersionFor ChainParametersV0 = CooldownParametersVersion0
        cooldownParametersVersionFor ChainParametersV1 = CooldownParametersVersion1
        cooldownParametersVersionFor ChainParametersV2 = CooldownParametersVersion1
        |]
 )

-- |Version-indexed type of cooldown parameters.
-- This is a GADT to provide instances of 'Eq' and 'Show'.
data CooldownParameters (cpv :: ChainParametersVersion) where
    CooldownParametersV0 ::
        (CooldownParametersVersionFor cpv ~ 'CooldownParametersVersion0) =>
        { -- |Number of additional epochs that bakers must cool down when
          -- removing stake. The cool-down will effectively be 2 epochs
          -- longer than this value, since at any given time, the bakers
          -- (and stakes) for the current and next epochs have already
          -- been determined.
          _cpBakerExtraCooldownEpochs :: Epoch
        } ->
        CooldownParameters cpv
    CooldownParametersV1 ::
        (CooldownParametersVersionFor cpv ~ 'CooldownParametersVersion1) =>
        { -- |Number of seconds that pool owners must cooldown
          -- when reducing their equity capital or closing the pool.
          _cpPoolOwnerCooldown :: !DurationSeconds,
          -- |Number of seconds that a delegator must cooldown
          -- when reducing their delegated stake.
          _cpDelegatorCooldown :: !DurationSeconds
        } ->
        CooldownParameters cpv

instance ToJSON (CooldownParameters cpv) where
    toJSON CooldownParametersV0{..} =
        object
            [ "bakerCooldownEpochs" AE..= _cpBakerExtraCooldownEpochs
            ]
    toJSON CooldownParametersV1{..} =
        object
            [ "poolOwnerCooldown" AE..= _cpPoolOwnerCooldown,
              "delegatorCooldown" AE..= _cpDelegatorCooldown
            ]

parseCooldownParametersJSON :: forall cpv. IsChainParametersVersion cpv => Value -> Parser (CooldownParameters cpv)
parseCooldownParametersJSON = case sCooldownParametersVersionFor (chainParametersVersion @cpv) of
    SCooldownParametersVersion0 -> withObject "CooldownParametersV0" $ \v -> CooldownParametersV0 <$> v .: "bakerCooldownEpochs"
    SCooldownParametersVersion1 -> withObject "CooldownParametersV1" $ \v ->
        CooldownParametersV1
            <$> v
                .: "poolOwnerCooldown"
            <*> v
                .: "delegatorCooldown"

instance IsChainParametersVersion cpv => FromJSON (CooldownParameters cpv) where
    parseJSON = parseCooldownParametersJSON

-- |Lens for '_cpBakerExtraCooldownEpochs'
{-# INLINE cpBakerExtraCooldownEpochs #-}
cpBakerExtraCooldownEpochs ::
    (CooldownParametersVersionFor cpv ~ 'CooldownParametersVersion0) =>
    Lens' (CooldownParameters cpv) Epoch
cpBakerExtraCooldownEpochs =
    lens _cpBakerExtraCooldownEpochs (\cp x -> cp{_cpBakerExtraCooldownEpochs = x})

-- |Lens for '_cpPoolOwnerCooldown'
{-# INLINE cpPoolOwnerCooldown #-}
cpPoolOwnerCooldown ::
    (CooldownParametersVersionFor cpv ~ 'CooldownParametersVersion1) =>
    Lens' (CooldownParameters cpv) DurationSeconds
cpPoolOwnerCooldown =
    lens _cpPoolOwnerCooldown (\cp x -> cp{_cpPoolOwnerCooldown = x})

-- |Lens for '_cpDelegatorCooldown'
{-# INLINE cpDelegatorCooldown #-}
cpDelegatorCooldown ::
    (CooldownParametersVersionFor cpv ~ 'CooldownParametersVersion1) =>
    Lens' (CooldownParameters cpv) DurationSeconds
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

instance HashableTo Hash.Hash (CooldownParameters cpv) where
    getHash = Hash.hash . runPut . putCooldownParameters

instance Monad m => MHashableTo m Hash.Hash (CooldownParameters cpv)

getCooldownParameters :: forall cpv. IsChainParametersVersion cpv => Get (CooldownParameters cpv)
getCooldownParameters = case sCooldownParametersVersionFor (chainParametersVersion @cpv) of
    SCooldownParametersVersion0 -> CooldownParametersV0 <$> get
    SCooldownParametersVersion1 -> CooldownParametersV1 <$> get <*> get

instance IsChainParametersVersion cpv => Serialize (CooldownParameters cpv) where
    put = putCooldownParameters
    get = getCooldownParameters

-- |The time parameters are introduced as of 'ChainParametersV1', and consist of the reward period
-- length and the mint rate per payday.  These are coupled as a change to either affects the
-- overall rate of minting.
data TimeParameters (cpv :: ChainParametersVersion) where
    -- |For 'ChainParametersV1', the time parameters are the reward period length and mint rate per
    -- payday.
    TimeParametersV1 ::
        { -- |Length of a reward period (a number of epochs).
          _tpRewardPeriodLength :: RewardPeriodLength,
          -- |Mint rate per payday (as a proportion of the extant supply).
          _tpMintPerPayday :: !MintRate
        } ->
        TimeParameters cpv

-- |Lens for '_tpRewardPeriodLength'
{-# INLINE tpRewardPeriodLength #-}
tpRewardPeriodLength :: Lens' (TimeParameters cpv) RewardPeriodLength
tpRewardPeriodLength =
    lens _tpRewardPeriodLength (\tp x -> tp{_tpRewardPeriodLength = x})

-- |Lens for '_tpMintPerPayday'
{-# INLINE tpMintPerPayday #-}
tpMintPerPayday :: Lens' (TimeParameters cpv) MintRate
tpMintPerPayday =
    lens _tpMintPerPayday (\tp x -> tp{_tpMintPerPayday = x})

deriving instance Eq (TimeParameters cpv)
deriving instance Show (TimeParameters cpv)

-- |Serialize 'TimeParameters'.
-- (This dispatches on the GADT, and so does not require @IsChainParameters cpv@.)
putTimeParameters :: Putter (TimeParameters cpv)
putTimeParameters TimeParametersV1{..} = do
    put _tpRewardPeriodLength
    put _tpMintPerPayday

-- |Deserialize 'TimeParameters'.
getTimeParameters :: forall cpv. Get (TimeParameters cpv)
getTimeParameters = TimeParametersV1 <$> get <*> get

instance Serialize (TimeParameters cpv) where
    put = putTimeParameters
    get = getTimeParameters

instance ToJSON (TimeParameters cpv) where
    toJSON TimeParametersV1{..} =
        object
            [ "rewardPeriodLength" AE..= _tpRewardPeriodLength,
              "mintPerPayday" AE..= _tpMintPerPayday
            ]

instance FromJSON (TimeParameters cpv) where
    parseJSON = withObject "TimeParametersV1" $ \v ->
        TimeParametersV1 <$> v .: "rewardPeriodLength" <*> v .: "mintPerPayday"

-- |The 'HashableTo' instance for 'TimeParameters' is used in hashing the state for queued updates.
-- It is not necessary to include the version in the hash computation, as it is implicit from the
-- context.
instance HashableTo Hash.Hash (TimeParameters cpv) where
    getHash = Hash.hash . runPut . putTimeParameters

instance Monad m => MHashableTo m Hash.Hash (TimeParameters cpv)

-- |A range that includes both endpoints.
data InclusiveRange a = InclusiveRange {irMin :: !a, irMax :: !a}
    deriving (Eq, Show)

instance ToJSON a => ToJSON (InclusiveRange a) where
    toJSON InclusiveRange{..} =
        object
            [ "min" AE..= irMin,
              "max" AE..= irMax
            ]

instance (FromJSON a, Ord a) => FromJSON (InclusiveRange a) where
    parseJSON = withObject "InclusiveRange" $ \v -> do
        irMin <- v .: "min"
        irMax <- v .: "max"
        when (irMin > irMax) $ fail "Invalid interval. Left endpoint cannot be bigger than right endpoint."
        return InclusiveRange{..}

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
isInRange :: Ord a => a -> InclusiveRange a -> Bool
isInRange v InclusiveRange{..} = irMin <= v && v <= irMax

-- |Determine the closest value to a target within the given 'InclusiveRange'.
closestInRange :: Ord a => a -> InclusiveRange a -> a
closestInRange v r
    | isInRange v r = v
    | v < irMin r = irMin r
    | otherwise = irMax r

-- |Ranges of allowed commission values that pools may choose from.
data CommissionRanges = CommissionRanges
    { -- |The range of allowed finalization commissions.
      _finalizationCommissionRange :: !(InclusiveRange AmountFraction),
      -- |The range of allowed baker commissions.
      _bakingCommissionRange :: !(InclusiveRange AmountFraction),
      -- |The range of allowed transaction commissions.
      _transactionCommissionRange :: !(InclusiveRange AmountFraction)
    }
    deriving (Eq, Show)

makeLenses ''CommissionRanges

instance Serialize CommissionRanges where
    put CommissionRanges{..} = do
        put _finalizationCommissionRange
        put _bakingCommissionRange
        put _transactionCommissionRange
    get = CommissionRanges <$> get <*> get <*> get

-- |Compute the maximum commission rates from commission ranges.
maximumCommissionRates :: CommissionRanges -> CommissionRates
maximumCommissionRates CommissionRanges{..} =
    CommissionRates
        { _finalizationCommission = irMax _finalizationCommissionRange,
          _bakingCommission = irMax _bakingCommissionRange,
          _transactionCommission = irMax _transactionCommissionRange
        }

-- |A leverage factor, which determines the maximum ratio of a baker's effective stake to its
-- equity capital. This is cannot be less than 1.
-- This is mostly a thin wrapper around @Ratio Word64@, except deserialization checks
-- that the denominator is non-zero and the value is at least 1.
newtype LeverageFactor = LeverageFactor {theLeverageFactor :: Ratio Word64}
    deriving newtype (Eq, Ord, Show, Num, Real, Fractional, RealFrac, ToJSON)

instance Serialize LeverageFactor where
    put (LeverageFactor l) = put (numerator l) >> put (denominator l)
    get = do
        num <- get
        den <- get
        when (den == 0) $ fail "0 denominator"
        when (gcd num den /= 1) $ fail "non-normalized ratio"
        when (den > num) $ fail "leverage factor < 1"
        return $ LeverageFactor $ num % den

instance FromJSON LeverageFactor where
    parseJSON v = do
        r <- parseJSON v
        when (r < 1) $ fail "leverage factor < 1"
        return $ LeverageFactor r

-- |Apply a leverage factor to a capital amount.
-- If the computed amount would be larger than the maximum amount, this returns 'maxBound'.
applyLeverageFactor :: LeverageFactor -> Amount -> Amount
applyLeverageFactor (LeverageFactor leverage) (Amount amt)
    | preAmount > toInteger (maxBound :: Amount) = maxBound
    | otherwise = fromInteger preAmount
  where
    preAmount = (toInteger (numerator leverage) * toInteger amt) `div` toInteger (denominator leverage)

-- |A bound on the relative share of the total staked capital that a baker can have as its stake.
-- This is required to be greater than 0.
newtype CapitalBound = CapitalBound {theCapitalBound :: AmountFraction}
    deriving newtype (Eq, Ord, Show, ToJSON)

instance Serialize CapitalBound where
    put = put . theCapitalBound
    get = do
        cb <- get
        when (cb == AmountFraction 0) $ fail "zero-valued capital bound"
        return $ CapitalBound cb

instance FromJSON CapitalBound where
    parseJSON v = do
        cb <- parseJSON v
        when (cb == AmountFraction 0) $ fail "zero-valued capital bound"
        return $ CapitalBound cb

$( singletons
    [d|
        data PoolParametersVersion = PoolParametersVersion0 | PoolParametersVersion1

        poolParametersVersionFor :: ChainParametersVersion -> PoolParametersVersion
        poolParametersVersionFor ChainParametersV0 = PoolParametersVersion0
        poolParametersVersionFor ChainParametersV1 = PoolParametersVersion1
        poolParametersVersionFor ChainParametersV2 = PoolParametersVersion1
        |]
 )

deriving instance Eq PoolParametersVersion
deriving instance Show PoolParametersVersion

-- |The 'PoolParameters' abstracts the parameters that affect baking pools. Prior to P4, there
-- is no concept of a baking pool as such, so the pool parameters are considered just to be the
-- baker stake threshold. From P4 onwards, a broader range of parameters is included.
data PoolParameters cpv where
    PoolParametersV0 ::
        (PoolParametersVersionFor cpv ~ 'PoolParametersVersion0) =>
        { -- |Minimum threshold required for registering as a baker.
          _ppBakerStakeThreshold :: Amount
        } ->
        PoolParameters cpv
    PoolParametersV1 ::
        (PoolParametersVersionFor cpv ~ 'PoolParametersVersion1) =>
        { -- |Commission rates charged for passive delegation.
          _ppPassiveCommissions :: !CommissionRates,
          -- |Bounds on the commission rates that may be charged by bakers.
          _ppCommissionBounds :: !CommissionRanges,
          -- |Minimum equity capital required for a new baker.
          _ppMinimumEquityCapital :: !Amount,
          -- |Maximum fraction of the total staked capital of that a new baker can have.
          _ppCapitalBound :: !CapitalBound,
          -- |The maximum leverage that a baker can have as a ratio of total stake
          -- to equity capital.
          _ppLeverageBound :: !LeverageFactor
        } ->
        PoolParameters cpv

instance ToJSON (PoolParameters cpv) where
    toJSON PoolParametersV0{..} =
        object
            [ "minimumThresholdForBaking" AE..= _ppBakerStakeThreshold
            ]
    toJSON PoolParametersV1{..} =
        object
            [ "passiveFinalizationCommission" AE..= _finalizationCommission _ppPassiveCommissions,
              "passiveBakingCommission" AE..= _bakingCommission _ppPassiveCommissions,
              "passiveTransactionCommission" AE..= _transactionCommission _ppPassiveCommissions,
              "finalizationCommissionRange" AE..= _finalizationCommissionRange _ppCommissionBounds,
              "bakingCommissionRange" AE..= _bakingCommissionRange _ppCommissionBounds,
              "transactionCommissionRange" AE..= _transactionCommissionRange _ppCommissionBounds,
              "minimumEquityCapital" AE..= _ppMinimumEquityCapital,
              "capitalBound" AE..= _ppCapitalBound,
              "leverageBound" AE..= _ppLeverageBound
            ]

parsePoolParametersJSON :: forall cpv. IsChainParametersVersion cpv => Value -> Parser (PoolParameters cpv)
parsePoolParametersJSON = case sPoolParametersVersionFor (chainParametersVersion @cpv) of
    SPoolParametersVersion0 -> withObject "PoolParametersV0" $ \v -> PoolParametersV0 <$> v .: "minimumThresholdForBaking"
    SPoolParametersVersion1 -> withObject "PoolParametersV1" $ \v -> do
        _finalizationCommission <- v .: "passiveFinalizationCommission"
        _bakingCommission <- v .: "passiveBakingCommission"
        _transactionCommission <- v .: "passiveTransactionCommission"
        _finalizationCommissionRange <- v .: "finalizationCommissionRange"
        _bakingCommissionRange <- v .: "bakingCommissionRange"
        _transactionCommissionRange <- v .: "transactionCommissionRange"
        _ppMinimumEquityCapital <- v .: "minimumEquityCapital"
        _ppCapitalBound <- v .: "capitalBound"
        _ppLeverageBound <- v .: "leverageBound"
        let _ppPassiveCommissions = CommissionRates{..}
        let _ppCommissionBounds = CommissionRanges{..}
        return PoolParametersV1{..}

instance IsChainParametersVersion cpv => FromJSON (PoolParameters cpv) where
    parseJSON = parsePoolParametersJSON

-- |Lens for '_ppBakerStakeThreshold'
{-# INLINE ppBakerStakeThreshold #-}
ppBakerStakeThreshold ::
    (PoolParametersVersionFor cpv ~ 'PoolParametersVersion0) =>
    Lens' (PoolParameters cpv) Amount
ppBakerStakeThreshold =
    lens _ppBakerStakeThreshold (\pp x -> pp{_ppBakerStakeThreshold = x})

-- |Lens for '_ppPassiveCommissions'
{-# INLINE ppPassiveCommissions #-}
ppPassiveCommissions ::
    (PoolParametersVersionFor cpv ~ 'PoolParametersVersion1) =>
    Lens' (PoolParameters cpv) CommissionRates
ppPassiveCommissions =
    lens _ppPassiveCommissions (\pp x -> pp{_ppPassiveCommissions = x})

-- |Lens for '_ppCommissionBounds'
{-# INLINE ppCommissionBounds #-}
ppCommissionBounds ::
    (PoolParametersVersionFor cpv ~ 'PoolParametersVersion1) =>
    Lens' (PoolParameters cpv) CommissionRanges
ppCommissionBounds =
    lens _ppCommissionBounds (\pp x -> pp{_ppCommissionBounds = x})

-- |Lens for '_ppMinimumEquityCapital'
{-# INLINE ppMinimumEquityCapital #-}
ppMinimumEquityCapital ::
    (PoolParametersVersionFor cpv ~ 'PoolParametersVersion1) =>
    Lens' (PoolParameters cpv) Amount
ppMinimumEquityCapital =
    lens _ppMinimumEquityCapital (\pp x -> pp{_ppMinimumEquityCapital = x})

-- |Lens for '_ppCapitalBound'
{-# INLINE ppCapitalBound #-}
ppCapitalBound ::
    (PoolParametersVersionFor cpv ~ 'PoolParametersVersion1) =>
    Lens' (PoolParameters cpv) CapitalBound
ppCapitalBound =
    lens _ppCapitalBound (\pp x -> pp{_ppCapitalBound = x})

-- |Lens for '_ppLeverageBound'
{-# INLINE ppLeverageBound #-}
ppLeverageBound ::
    (PoolParametersVersionFor cpv ~ 'PoolParametersVersion1) =>
    Lens' (PoolParameters cpv) LeverageFactor
ppLeverageBound =
    lens _ppLeverageBound (\pp x -> pp{_ppLeverageBound = x})

putPoolParameters :: Putter (PoolParameters cpv)
putPoolParameters PoolParametersV0{..} = do
    put _ppBakerStakeThreshold
putPoolParameters PoolParametersV1{..} = do
    put _ppPassiveCommissions
    put _ppCommissionBounds
    put _ppMinimumEquityCapital
    put _ppCapitalBound
    put _ppLeverageBound

instance HashableTo Hash.Hash (PoolParameters cpv) where
    getHash = Hash.hash . runPut . putPoolParameters

instance Monad m => MHashableTo m Hash.Hash (PoolParameters cpv)

getPoolParameters :: forall cpv. IsChainParametersVersion cpv => Get (PoolParameters cpv)
getPoolParameters = case sPoolParametersVersionFor (chainParametersVersion @cpv) of
    SPoolParametersVersion0 -> PoolParametersV0 <$> get
    SPoolParametersVersion1 -> PoolParametersV1 <$> get <*> get <*> get <*> get <*> get

instance IsChainParametersVersion cpv => Serialize (PoolParameters cpv) where
    put = putPoolParameters
    get = getPoolParameters

deriving instance Eq (PoolParameters cpv)
deriving instance Show (PoolParameters cpv)

-- |Parameters controlling consensus timeouts for the consensus protocol version 2.
data TimeoutParameters = TimeoutParameters
    { -- |The base value for triggering a timeout.
      tpTimeoutBase :: Duration,
      -- |Factor for increasing the timeout. Must be greater than 1.
      tpTimeoutIncrease :: Ratio Word64,
      -- |Factor for decreasing the timeout. Must be between 0 and 1.
      tpTimeoutDecrease :: Ratio Word64
    }
    deriving (Eq, Show)

instance Serialize TimeoutParameters where
    put TimeoutParameters{..} = do
        put tpTimeoutBase
        put tpTimeoutIncrease
        put tpTimeoutDecrease
    get = do
        tpTimeoutBase <- get
        tpTimeoutIncrease <- get
        unless (tpTimeoutIncrease > 1) $ fail "timeoutIncrease must be greater than 1."
        tpTimeoutDecrease <- get
        unless (tpTimeoutDecrease > 0) $ fail "timeoutDecrease must be greater than 0."
        unless (tpTimeoutDecrease < 1) $ fail "timeoutDecrease must be less than 1."
        return TimeoutParameters{..}

instance ToJSON TimeoutParameters where
    toJSON TimeoutParameters{..} =
        object
            [ "timeoutBase" AE..= tpTimeoutBase,
              "timeoutIncrease" AE..= tpTimeoutIncrease,
              "timeoutDecrease" AE..= tpTimeoutDecrease
            ]

instance FromJSON TimeoutParameters where
    parseJSON = withObject "TimeoutParameters" $ \o -> do
        tpTimeoutBase <- o .: "timeoutBase"
        tpTimeoutIncrease <- o .: "timeoutIncrease"
        unless (tpTimeoutIncrease > 1) $ fail "timeoutIncrease must be greater than 1."
        tpTimeoutDecrease <- o .: "timeoutDecrease"
        unless (tpTimeoutDecrease > 0) $ fail "timeoutDecrease must be greater than 0."
        unless (tpTimeoutDecrease < 1) $ fail "timeoutDecrease must be less than 1."
        return TimeoutParameters{..}

instance HashableTo Hash.Hash TimeoutParameters where
    getHash = Hash.hash . encode

instance (Monad m) => MHashableTo m Hash.Hash TimeoutParameters

$( singletons
    [d|
        -- \|Consensus parameters
        data ConsensusParametersVersion
            = ConsensusParametersVersion0 -- \^Election difficulty
            | ConsensusParametersVersion1 -- \^Timeout parameters, block energy limit, min block time

        consensusParametersVersionFor :: ChainParametersVersion -> ConsensusParametersVersion
        consensusParametersVersionFor ChainParametersV0 = ConsensusParametersVersion0
        consensusParametersVersionFor ChainParametersV1 = ConsensusParametersVersion0
        consensusParametersVersionFor ChainParametersV2 = ConsensusParametersVersion1
        |]
 )

data ConsensusParameters (cpv :: ChainParametersVersion) where
    ConsensusParametersV0 ::
        (ConsensusParametersVersionFor cpv ~ 'ConsensusParametersVersion0) =>
        { -- |Election difficulty parameter.
          _cpElectionDifficulty :: !ElectionDifficulty
        } ->
        ConsensusParameters cpv
    ConsensusParametersV1 ::
        (ConsensusParametersVersionFor cpv ~ 'ConsensusParametersVersion1) =>
        { -- |Parameters controlling round timeouts.
          _cpTimeoutParameters :: !TimeoutParameters,
          -- |Minimum time interval between blocks.
          _cpMinBlockTime :: !Duration,
          -- |Maximum energy allowed per block.
          _cpBlockEnergyLimit :: !Energy
        } ->
        ConsensusParameters cpv

-- |Lens for '_cpElectionDifficulty'
{-# INLINE cpElectionDifficulty #-}
cpElectionDifficulty ::
    (ConsensusParametersVersionFor cpv ~ 'ConsensusParametersVersion0) =>
    Lens' (ConsensusParameters cpv) ElectionDifficulty
cpElectionDifficulty =
    lens _cpElectionDifficulty (\cp x -> cp{_cpElectionDifficulty = x})

-- |Lens for '_cpTimeoutParameters'
{-# INLINE cpTimeoutParameters #-}
cpTimeoutParameters ::
    (ConsensusParametersVersionFor cpv ~ 'ConsensusParametersVersion1) =>
    Lens' (ConsensusParameters cpv) TimeoutParameters
cpTimeoutParameters =
    lens _cpTimeoutParameters (\cp x -> cp{_cpTimeoutParameters = x})

-- |Lens for '_cpMinBlockTime'
{-# INLINE cpMinBlockTime #-}
cpMinBlockTime ::
    (ConsensusParametersVersionFor cpv ~ 'ConsensusParametersVersion1) =>
    Lens' (ConsensusParameters cpv) Duration
cpMinBlockTime =
    lens _cpMinBlockTime (\cp x -> cp{_cpMinBlockTime = x})

-- |Lens for '_cpBlockEnergyLimit'
{-# INLINE cpBlockEnergyLimit #-}
cpBlockEnergyLimit ::
    (ConsensusParametersVersionFor cpv ~ 'ConsensusParametersVersion1) =>
    Lens' (ConsensusParameters cpv) Energy
cpBlockEnergyLimit =
    lens _cpBlockEnergyLimit (\cp x -> cp{_cpBlockEnergyLimit = x})

coerceConsensusParameters ::
    (ConsensusParametersVersionFor cpv1 ~ ConsensusParametersVersionFor cpv2) =>
    ConsensusParameters cpv1 ->
    ConsensusParameters cpv2
coerceConsensusParameters ConsensusParametersV0{..} = ConsensusParametersV0{..}
coerceConsensusParameters ConsensusParametersV1{..} = ConsensusParametersV1{..}

deriving instance Eq (ConsensusParameters cpv)

deriving instance Show (ConsensusParameters cpv)

instance IsChainParametersVersion cpv => Serialize (ConsensusParameters cpv) where
    put ConsensusParametersV0{..} = put _cpElectionDifficulty
    put ConsensusParametersV1{..} = do
        put _cpTimeoutParameters
        put _cpMinBlockTime
        put _cpBlockEnergyLimit
    get = case sConsensusParametersVersionFor (chainParametersVersion @cpv) of
        SConsensusParametersVersion0 -> ConsensusParametersV0 <$> get
        SConsensusParametersVersion1 -> do
            _cpTimeoutParameters <- get
            _cpMinBlockTime <- get
            _cpBlockEnergyLimit <- get
            return ConsensusParametersV1{..}

-- |Updatable chain parameters.  This type is parametrised by a 'ChainParametersVersion' that
-- reflects changes to the chain parameters across different protocol versions.
data ChainParameters' (cpv :: ChainParametersVersion) = ChainParameters
    { -- |Consensus parameters.
      _cpConsensusParameters :: !(ConsensusParameters cpv),
      -- |Exchange rates.
      _cpExchangeRates :: !ExchangeRates,
      -- |Cooldown parameters.
      _cpCooldownParameters :: !(CooldownParameters cpv),
      -- |Time parameters.
      _cpTimeParameters :: !(OParam 'PTTimeParameters cpv (TimeParameters cpv)),
      -- |LimitAccountCreation: the maximum number of accounts
      -- that may be created in one block.
      _cpAccountCreationLimit :: !CredentialsPerBlockLimit,
      -- |Reward parameters.
      _cpRewardParameters :: !(RewardParameters cpv),
      -- |Foundation account index.
      _cpFoundationAccount :: !AccountIndex,
      -- |Parameters for baker pools. Prior to P4, this is just the minimum stake threshold
      -- for becoming a baker.
      _cpPoolParameters :: !(PoolParameters cpv)
    }
    deriving (Eq, Show)

makeLenses ''ChainParameters'

-- |An existentially qualified chain parameters variant that is useful where we
-- need to return chain parameters in queries.
data EChainParameters = forall (cpv :: ChainParametersVersion). IsChainParametersVersion cpv => EChainParameters (ChainParameters' cpv)

-- |Chain parameters for a specific 'ProtocolVersion'.
type ChainParameters (pv :: ProtocolVersion) = ChainParameters' (ChainParametersVersionFor pv)

instance HasExchangeRates (ChainParameters' cpv) where
    {-# INLINE exchangeRates #-}
    exchangeRates = cpExchangeRates

instance HasRewardParameters (ChainParameters' cpv) cpv where
    rewardParameters = cpRewardParameters

putChainParameters :: IsChainParametersVersion cpv => Putter (ChainParameters' cpv)
putChainParameters ChainParameters{..} = do
    put _cpConsensusParameters
    put _cpExchangeRates
    putCooldownParameters _cpCooldownParameters
    put _cpTimeParameters
    put _cpAccountCreationLimit
    put _cpRewardParameters
    put _cpFoundationAccount
    putPoolParameters _cpPoolParameters

getChainParameters :: forall cpv. IsChainParametersVersion cpv => Get (ChainParameters' cpv)
getChainParameters = ChainParameters <$> get <*> get <*> getCooldownParameters <*> get <*> get <*> get <*> get <*> getPoolParameters

instance IsChainParametersVersion cpv => Serialize (ChainParameters' cpv) where
    put = putChainParameters
    get = getChainParameters

instance IsChainParametersVersion cpv => HashableTo Hash.Hash (ChainParameters' cpv) where
    getHash = Hash.hash . runPut . putChainParameters

instance (Monad m, IsChainParametersVersion cpv) => MHashableTo m Hash.Hash (ChainParameters' cpv)

parseJSONForCPV0 :: Value -> Parser (ChainParameters' 'ChainParametersV0)
parseJSONForCPV0 =
    withObject "ChainParameters" $ \v -> do
        _cpElectionDifficulty <- v .: "electionDifficulty"
        let _cpConsensusParameters = ConsensusParametersV0{..}
        _cpExchangeRates <-
            makeExchangeRates
                <$> v
                    .: "euroPerEnergy"
                <*> v
                    .: "microGTUPerEuro"
        _cpCooldownParameters <-
            CooldownParametersV0
                <$> v
                    .: "bakerCooldownEpochs"
        _cpAccountCreationLimit <- v .: "accountCreationLimit"
        _cpRewardParameters <- v .: "rewardParameters"
        _cpFoundationAccount <- v .: "foundationAccountIndex"
        _cpPoolParameters <-
            PoolParametersV0
                <$> v
                    .: "minimumThresholdForBaking"
        let _cpTimeParameters = NoParam
        return ChainParameters{..}

parseJSONForCPV1 :: Value -> Parser (ChainParameters' 'ChainParametersV1)
parseJSONForCPV1 =
    withObject "ChainParametersV1" $ \v -> do
        _cpElectionDifficulty <- v .: "electionDifficulty"
        let _cpConsensusParameters = ConsensusParametersV0{..}
        _cpEuroPerEnergy <- v .: "euroPerEnergy"
        _cpMicroGTUPerEuro <- v .: "microGTUPerEuro"
        _cpPoolOwnerCooldown <- v .: "poolOwnerCooldown"
        _cpDelegatorCooldown <- v .: "delegatorCooldown"
        _cpAccountCreationLimit <- v .: "accountCreationLimit"
        _cpRewardParameters <- v .: "rewardParameters"
        _cpFoundationAccount <- v .: "foundationAccountIndex"
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
        let _cpCooldownParameters = CooldownParametersV1{..}
            _cpTimeParameters = SomeParam TimeParametersV1{..}
            _cpPoolParameters = PoolParametersV1{..}
            _cpExchangeRates = makeExchangeRates _cpEuroPerEnergy _cpMicroGTUPerEuro
            _ppPassiveCommissions = CommissionRates{..}
            _ppCommissionBounds = CommissionRanges{..}
        return ChainParameters{..}

parseJSONForCPV2 :: Value -> Parser (ChainParameters' 'ChainParametersV2)
parseJSONForCPV2 =
    withObject "ChainParametersV2" $ \v -> do
        _cpEuroPerEnergy <- v .: "euroPerEnergy"
        _cpMicroGTUPerEuro <- v .: "microGTUPerEuro"
        _cpPoolOwnerCooldown <- v .: "poolOwnerCooldown"
        _cpDelegatorCooldown <- v .: "delegatorCooldown"
        _cpAccountCreationLimit <- v .: "accountCreationLimit"
        _cpRewardParameters <- v .: "rewardParameters"
        _cpFoundationAccount <- v .: "foundationAccountIndex"
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
        tpTimeoutBase <- v .: "timeoutBase"
        tpTimeoutIncrease <- v .: "timeoutIncrease"
        tpTimeoutDecrease <- v .: "timeoutDecrease"
        let _cpTimeoutParameters = TimeoutParameters{..}
        _cpMinBlockTime <- v .: "minBlockTime"
        _cpBlockEnergyLimit <- v .: "blockEnergyLimit"
        let _cpCooldownParameters = CooldownParametersV1{..}
            _cpTimeParameters = SomeParam TimeParametersV1{..}
            _cpPoolParameters = PoolParametersV1{..}
            _cpExchangeRates = makeExchangeRates _cpEuroPerEnergy _cpMicroGTUPerEuro
            _ppPassiveCommissions = CommissionRates{..}
            _ppCommissionBounds = CommissionRanges{..}
            _cpConsensusParameters = ConsensusParametersV1{..}
        return ChainParameters{..}

instance forall cpv. IsChainParametersVersion cpv => FromJSON (ChainParameters' cpv) where
    parseJSON = case chainParametersVersion @cpv of
        SChainParametersV0 -> parseJSONForCPV0
        SChainParametersV1 -> parseJSONForCPV1
        SChainParametersV2 -> parseJSONForCPV2

instance forall cpv. IsChainParametersVersion cpv => ToJSON (ChainParameters' cpv) where
    toJSON ChainParameters{..} = case chainParametersVersion @cpv of
        SChainParametersV0 ->
            object
                [ "electionDifficulty" AE..= _cpElectionDifficulty _cpConsensusParameters,
                  "euroPerEnergy" AE..= _erEuroPerEnergy _cpExchangeRates,
                  "microGTUPerEuro" AE..= _erMicroGTUPerEuro _cpExchangeRates,
                  "bakerCooldownEpochs" AE..= _cpBakerExtraCooldownEpochs _cpCooldownParameters,
                  "accountCreationLimit" AE..= _cpAccountCreationLimit,
                  "rewardParameters" AE..= _cpRewardParameters,
                  "foundationAccountIndex" AE..= _cpFoundationAccount,
                  "minimumThresholdForBaking" AE..= _ppBakerStakeThreshold _cpPoolParameters
                ]
        SChainParametersV1 ->
            object
                [ "electionDifficulty" AE..= _cpElectionDifficulty _cpConsensusParameters,
                  "euroPerEnergy" AE..= _erEuroPerEnergy _cpExchangeRates,
                  "microGTUPerEuro" AE..= _erMicroGTUPerEuro _cpExchangeRates,
                  "poolOwnerCooldown" AE..= _cpPoolOwnerCooldown _cpCooldownParameters,
                  "delegatorCooldown" AE..= _cpDelegatorCooldown _cpCooldownParameters,
                  "accountCreationLimit" AE..= _cpAccountCreationLimit,
                  "rewardParameters" AE..= _cpRewardParameters,
                  "foundationAccountIndex" AE..= _cpFoundationAccount,
                  "passiveFinalizationCommission" AE..= _finalizationCommission (_ppPassiveCommissions _cpPoolParameters),
                  "passiveBakingCommission" AE..= _bakingCommission (_ppPassiveCommissions _cpPoolParameters),
                  "passiveTransactionCommission" AE..= _transactionCommission (_ppPassiveCommissions _cpPoolParameters),
                  "finalizationCommissionRange" AE..= _finalizationCommissionRange (_ppCommissionBounds _cpPoolParameters),
                  "bakingCommissionRange" AE..= _bakingCommissionRange (_ppCommissionBounds _cpPoolParameters),
                  "transactionCommissionRange" AE..= _transactionCommissionRange (_ppCommissionBounds _cpPoolParameters),
                  "minimumEquityCapital" AE..= _ppMinimumEquityCapital _cpPoolParameters,
                  "capitalBound" AE..= _ppCapitalBound _cpPoolParameters,
                  "leverageBound" AE..= _ppLeverageBound _cpPoolParameters,
                  "rewardPeriodLength" AE..= _tpRewardPeriodLength (unOParam _cpTimeParameters),
                  "mintPerPayday" AE..= _tpMintPerPayday (unOParam _cpTimeParameters)
                ]
        SChainParametersV2 ->
            object
                [ "euroPerEnergy" AE..= _erEuroPerEnergy _cpExchangeRates,
                  "microGTUPerEuro" AE..= _erMicroGTUPerEuro _cpExchangeRates,
                  "poolOwnerCooldown" AE..= _cpPoolOwnerCooldown _cpCooldownParameters,
                  "delegatorCooldown" AE..= _cpDelegatorCooldown _cpCooldownParameters,
                  "accountCreationLimit" AE..= _cpAccountCreationLimit,
                  "rewardParameters" AE..= _cpRewardParameters,
                  "foundationAccountIndex" AE..= _cpFoundationAccount,
                  "passiveFinalizationCommission" AE..= _finalizationCommission (_ppPassiveCommissions _cpPoolParameters),
                  "passiveBakingCommission" AE..= _bakingCommission (_ppPassiveCommissions _cpPoolParameters),
                  "passiveTransactionCommission" AE..= _transactionCommission (_ppPassiveCommissions _cpPoolParameters),
                  "finalizationCommissionRange" AE..= _finalizationCommissionRange (_ppCommissionBounds _cpPoolParameters),
                  "bakingCommissionRange" AE..= _bakingCommissionRange (_ppCommissionBounds _cpPoolParameters),
                  "transactionCommissionRange" AE..= _transactionCommissionRange (_ppCommissionBounds _cpPoolParameters),
                  "minimumEquityCapital" AE..= _ppMinimumEquityCapital _cpPoolParameters,
                  "capitalBound" AE..= _ppCapitalBound _cpPoolParameters,
                  "leverageBound" AE..= _ppLeverageBound _cpPoolParameters,
                  "rewardPeriodLength" AE..= _tpRewardPeriodLength (unOParam _cpTimeParameters),
                  "mintPerPayday" AE..= _tpMintPerPayday (unOParam _cpTimeParameters),
                  "timeoutBase" AE..= tpTimeoutBase (_cpTimeoutParameters _cpConsensusParameters),
                  "timeoutIncrease" AE..= tpTimeoutIncrease (_cpTimeoutParameters _cpConsensusParameters),
                  "timeoutDecrease" AE..= tpTimeoutDecrease (_cpTimeoutParameters _cpConsensusParameters),
                  "minBlockTime" AE..= _cpMinBlockTime _cpConsensusParameters,
                  "blockEnergyLimit" AE..= _cpBlockEnergyLimit _cpConsensusParameters
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
