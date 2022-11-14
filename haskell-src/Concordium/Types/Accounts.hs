{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}
-- We suppress redundant constraint warnings since GHC does not detect when a constraint is used
-- for pattern matching. (See: https://gitlab.haskell.org/ghc/ghc/-/issues/20896)
{-# OPTIONS_GHC -Wno-redundant-constraints #-}

-- |Types for representing the results of consensus queries.
module Concordium.Types.Accounts (
    AccountVersion (..),
    SAccountVersion (..),
    AccountVersionFor,
    accountVersionFor,
    BakerPoolInfo (..),
    HasBakerPoolInfo,
    -- |Whether the pool allows delegators.
    poolOpenStatus,
    -- |The URL that links to the metadata about the pool.
    poolMetadataUrl,
    -- |The commission rates charged by the pool owner.
    poolCommissionRates,
    BakerInfo (..),
    HasBakerInfo,
    bakerInfo,
    -- |Identity of the baker. This is actually the account index of
    -- the account controlling the baker.
    bakerIdentity,
    -- |The baker's public VRF key
    bakerElectionVerifyKey,
    -- |The baker's public signature key
    bakerSignatureVerifyKey,
    -- |The baker's public key for finalization record aggregation
    bakerAggregationVerifyKey,
    -- |The details of the pool associated with a baker
    bakerPoolInfo,
    BakerInfoEx (..),
    bieBakerInfo,
    bieBakerPoolInfo,
    PendingChangeEffective (..),
    pendingChangeEffectiveTimestamp,
    coercePendingChangeEffectiveV1,
    StakePendingChange' (..),
    StakePendingChange,
    AccountBaker (..),
    -- |The amount staked by the baker.
    stakedAmount,
    -- |Whether baker and finalizer rewards are added to the stake.
    stakeEarnings,
    -- |The baker's keys and identity.
    accountBakerInfo,
    -- |The pending change (if any) to the baker's status.
    bakerPendingChange,
    serializeAccountBaker,
    deserializeAccountBaker,
    AccountDelegation (..),
    delegationIdentity,
    delegationStakedAmount,
    delegationStakeEarnings,
    delegationTarget,
    delegationPendingChange,
    AccountStake (..),
    serializeAccountStake,
    deserializeAccountStake,
    AccountStakeHash (..),
    getAccountStakeHash,
    AccountInfo (..),
    AccountStakingInfo (..),
    toAccountStakingInfo,

    -- * Account structure version
    AccountStructureVersion (..),
    AccountStructureVersionFor,
) where

import Data.Aeson
import Data.Aeson.Types (Parser)
import qualified Data.Map as Map
import Data.Serialize
import Data.Time
import Lens.Micro.Platform (Lens', lens, makeClassy, makeLenses, (^.))

import Concordium.Common.Version
import qualified Concordium.Crypto.SHA256 as Hash
import Concordium.ID.Types
import Concordium.Types
import Concordium.Types.Accounts.Releases
import Concordium.Types.Execution (DelegationTarget, OpenStatus)
import Concordium.Types.HashableTo

-- |The version of the account structure. This is used to index types that vary the account
-- structure.
data AccountStructureVersion
    = -- |Account structure used prior to P5
      AccountStructureV0
    | -- |Account structure used from P5
      AccountStructureV1

-- |The account structure version associated with an account version.
type family AccountStructureVersionFor (av :: AccountVersion) :: AccountStructureVersion where
    AccountStructureVersionFor 'AccountV0 = 'AccountStructureV0
    AccountStructureVersionFor 'AccountV1 = 'AccountStructureV0
    AccountStructureVersionFor 'AccountV2 = 'AccountStructureV1

-- |The 'BakerId' of a baker and its public keys.
data BakerInfo = BakerInfo
    { -- |Identity of the baker. This is actually the account index of
      -- the account controlling the baker.
      _bakerIdentity :: !BakerId,
      -- |The baker's public VRF key
      _bakerElectionVerifyKey :: !BakerElectionVerifyKey,
      -- |The baker's public signature key
      _bakerSignatureVerifyKey :: !BakerSignVerifyKey,
      -- |The baker's public key for finalization record aggregation
      _bakerAggregationVerifyKey :: !BakerAggregationVerifyKey
    }
    deriving (Eq, Show)

instance Serialize BakerInfo where
    put BakerInfo{..} = do
        put _bakerIdentity
        put _bakerElectionVerifyKey
        put _bakerSignatureVerifyKey
        put _bakerAggregationVerifyKey
    get = do
        _bakerIdentity <- get
        _bakerElectionVerifyKey <- get
        _bakerSignatureVerifyKey <- get
        _bakerAggregationVerifyKey <- get
        return BakerInfo{..}

-- Define the class 'HasBakerInfo' with accessor lenses and an instance for 'BakerInfo'.
makeClassy ''BakerInfo

-- |Additional information about a baking pool.
-- This information is added with the introduction of delegation.
data BakerPoolInfo
    = -- |The introduction of delegation requires information about the pool.
      BakerPoolInfo
      { -- |Whether the pool allows delegators.
        _poolOpenStatus :: !OpenStatus,
        -- |The URL that links to the metadata about the pool.
        _poolMetadataUrl :: !UrlText,
        -- |The commission rates charged by the pool owner.
        _poolCommissionRates :: !CommissionRates
      }
    deriving (Eq, Show)

instance Serialize BakerPoolInfo where
    put BakerPoolInfo{..} = do
        put _poolOpenStatus
        put _poolMetadataUrl
        put _poolCommissionRates
    get = do
        _poolOpenStatus <- get
        _poolMetadataUrl <- get
        _poolCommissionRates <- get
        return BakerPoolInfo{..}

-- Define the class 'HasBakerPoolInfo' with accessor lenses and an instance for 'BakerPoolInfo'.
makeClassy ''BakerPoolInfo

-- |Helper function for defining 'ToJSON'.
bakerPoolInfoV1Pairs :: (KeyValue kv) => BakerPoolInfo -> [kv]
bakerPoolInfoV1Pairs BakerPoolInfo{..} =
    [ "openStatus" .= _poolOpenStatus,
      "metadataUrl" .= _poolMetadataUrl,
      "commissionRates" .= _poolCommissionRates
    ]

instance ToJSON BakerPoolInfo where
    toJSON bpi = object $ bakerPoolInfoV1Pairs bpi
    toEncoding bpi = pairs $ mconcat $ bakerPoolInfoV1Pairs bpi

instance FromJSON BakerPoolInfo where
    parseJSON = withObject "BakerPoolInfo" $ \o -> do
        _poolOpenStatus <- o .: "openStatus"
        _poolMetadataUrl <- o .: "metadataUrl"
        _poolCommissionRates <- o .: "commissionRates"
        return BakerPoolInfo{..}

-- |Extended baker information. Protocol version 4 introduces baking pools that allow delegation.
-- Thus, for 'P4' onwards, the baker info is extended with 'BakerPoolInfo' that describes the
-- pool.
data BakerInfoEx (av :: AccountVersion) where
    BakerInfoExV0 :: !BakerInfo -> BakerInfoEx 'AccountV0
    BakerInfoExV1 ::
        AVSupportsDelegation av =>
        { -- |The baker ID and keys.
          _bieBakerInfo :: !BakerInfo,
          -- |The baker pool info.
          _bieBakerPoolInfo :: !BakerPoolInfo
        } ->
        BakerInfoEx av

deriving instance Eq (BakerInfoEx av)
deriving instance Show (BakerInfoEx av)

-- |Lens for '_bieBakerInfo'
{-# INLINE bieBakerInfo #-}
bieBakerInfo :: AVSupportsDelegation av => Lens' (BakerInfoEx av) BakerInfo
bieBakerInfo =
    lens _bieBakerInfo (\bie x -> bie{_bieBakerInfo = x})

-- |Lens for '_bieBakerPoolInfo'
{-# INLINE bieBakerPoolInfo #-}
bieBakerPoolInfo :: AVSupportsDelegation av => Lens' (BakerInfoEx av) BakerPoolInfo
bieBakerPoolInfo =
    lens _bieBakerPoolInfo (\bie x -> bie{_bieBakerPoolInfo = x})

-- |Note that the serialization of 'BakerInfoEx' matches exactly
-- the serialization of 'BakerInfo' for 'AccountV0'. This is needed to preserve
-- compatibility between versions, allowing 'BakerInfoEx' to be used where
-- 'BakerInfo' was used.
instance forall av. IsAccountVersion av => Serialize (BakerInfoEx av) where
    put (BakerInfoExV0 bi) = put bi
    put BakerInfoExV1{..} = put _bieBakerInfo >> put _bieBakerPoolInfo
    get = case delegationSupport @av of
        SAVDelegationNotSupported -> BakerInfoExV0 <$> get
        SAVDelegationSupported -> do
            _bieBakerInfo <- get
            _bieBakerPoolInfo <- get
            return BakerInfoExV1{..}

instance HasBakerInfo (BakerInfoEx av) where
    bakerInfo upd (BakerInfoExV0 bi) = BakerInfoExV0 <$> upd bi
    bakerInfo upd bie@BakerInfoExV1{..} = (\bi' -> bie{_bieBakerInfo = bi'}) <$> upd _bieBakerInfo

instance (AVSupportsDelegation av) => HasBakerPoolInfo (BakerInfoEx av) where
    bakerPoolInfo upd bie@BakerInfoExV1{..} =
        (\bpi' -> bie{_bieBakerPoolInfo = bpi'})
            <$> upd _bieBakerPoolInfo

-- |The time at which a pending change to a baker or delegator's capital becomes effective from
-- the perspective of determining stakes.  (This will have effect on baker stakes two epochs after
-- this time.)
--
-- For 'AccountV0', this is specified as an 'Epoch', which is an absolute number of epochs since
-- the latest genesis.  For 'AccountV1' (onwards), this is an absolute timestamp. This latter choice
-- is preferable, as it does not need to be changed on a protocol update to account for the
-- resetting of the Epoch counter.
data PendingChangeEffective (av :: AccountVersion) where
    PendingChangeEffectiveV0 :: !Epoch -> PendingChangeEffective 'AccountV0
    PendingChangeEffectiveV1 :: AVSupportsDelegation av => !Timestamp -> PendingChangeEffective av

deriving instance Eq (PendingChangeEffective av)
deriving instance Ord (PendingChangeEffective av)
deriving instance Show (PendingChangeEffective av)

instance IsAccountVersion av => Serialize (PendingChangeEffective av) where
    put (PendingChangeEffectiveV0 epoch) = put epoch
    put (PendingChangeEffectiveV1 timestamp) = put timestamp
    get = case delegationSupport @av of
        SAVDelegationNotSupported -> PendingChangeEffectiveV0 <$> get
        SAVDelegationSupported -> PendingChangeEffectiveV1 <$> get

-- |Get the 'Timestamp' from a 'PendingChangeEffective' if the account version supports delegation.
pendingChangeEffectiveTimestamp :: (AVSupportsDelegation av) => PendingChangeEffective av -> Timestamp
{-# INLINE pendingChangeEffectiveTimestamp #-}
pendingChangeEffectiveTimestamp (PendingChangeEffectiveV1 ts) = ts

-- |Convert a 'PendingChangeEffective' between account versions that support delegation.
coercePendingChangeEffectiveV1 :: (AVSupportsDelegation av1, AVSupportsDelegation av2) => PendingChangeEffective av1 -> PendingChangeEffective av2
coercePendingChangeEffectiveV1 (PendingChangeEffectiveV1 ts) = PendingChangeEffectiveV1 ts

-- |Pending changes to the baker or delegation associated with an account.
data StakePendingChange' effectiveTime
    = -- |There is no change pending to the baker.
      NoChange
    | -- |The stake will be decreased to the given amount.
      ReduceStake !Amount !effectiveTime
    | -- |The baker will be removed.
      RemoveStake !effectiveTime
    deriving (Eq, Ord, Show, Functor)

instance Serialize effectiveTime => Serialize (StakePendingChange' effectiveTime) where
    put NoChange = putWord8 0
    put (ReduceStake amt et) = putWord8 1 >> put amt >> put et
    put (RemoveStake et) = putWord8 2 >> put et

    get =
        getWord8 >>= \case
            0 -> return NoChange
            1 -> ReduceStake <$> get <*> get
            2 -> RemoveStake <$> get
            _ -> fail "Invalid StakePendingChange"

type StakePendingChange (av :: AccountVersion) = StakePendingChange' (PendingChangeEffective av)

-- |A baker associated with an account.
data AccountBaker (av :: AccountVersion) = AccountBaker
    { -- |The amount staked by the baker.
      _stakedAmount :: !Amount,
      -- |Whether baker and finalizer rewards are added to the stake.
      _stakeEarnings :: !Bool,
      -- |The baker's keys, identity, and pool info (V1).
      _accountBakerInfo :: !(BakerInfoEx av),
      -- |The pending change (if any) to the baker's status.
      _bakerPendingChange :: !(StakePendingChange av)
    }
    deriving (Eq, Show)

makeLenses ''AccountBaker

instance HasBakerInfo (AccountBaker av) where
    bakerInfo = accountBakerInfo . bakerInfo

instance (AVSupportsDelegation av) => HasBakerPoolInfo (AccountBaker av) where
    bakerPoolInfo = accountBakerInfo . bakerPoolInfo

-- |Serialize an 'AccountBaker'
serializeAccountBaker :: IsAccountVersion av => Putter (AccountBaker av)
serializeAccountBaker AccountBaker{..} = do
    put _stakedAmount
    put _stakeEarnings
    put _accountBakerInfo
    put _bakerPendingChange

-- |Deserialize an 'AccountBaker'.
deserializeAccountBaker :: IsAccountVersion av => Get (AccountBaker av)
deserializeAccountBaker = do
    _stakedAmount <- get
    _stakeEarnings <- get
    _accountBakerInfo <- get
    _bakerPendingChange <- get
    -- If there is a pending reduction, check that it is actually a reduction.
    case _bakerPendingChange of
        ReduceStake amt _
            | amt > _stakedAmount -> fail "Pending stake reduction is not a reduction in stake"
        _ -> return ()
    return AccountBaker{..}

data AccountDelegation (av :: AccountVersion) where
    AccountDelegationV1 ::
        (AVSupportsDelegation av) =>
        { _delegationIdentity :: !DelegatorId,
          _delegationStakedAmount :: !Amount,
          _delegationStakeEarnings :: !Bool,
          _delegationTarget :: !DelegationTarget,
          _delegationPendingChange :: !(StakePendingChange av)
        } ->
        AccountDelegation av

deriving instance Eq (AccountDelegation av)
deriving instance Show (AccountDelegation av)

-- |Lens for '_delegationIdentity'
{-# INLINE delegationIdentity #-}
delegationIdentity :: Lens' (AccountDelegation av) DelegatorId
delegationIdentity = lens _delegationIdentity (\ad x -> ad{_delegationIdentity = x})

-- |Lens for '_delegationStakedAmount'
{-# INLINE delegationStakedAmount #-}
delegationStakedAmount :: Lens' (AccountDelegation av) Amount
delegationStakedAmount = lens _delegationStakedAmount (\ad x -> ad{_delegationStakedAmount = x})

-- |Lens for '_delegationStakeEarnings'
{-# INLINE delegationStakeEarnings #-}
delegationStakeEarnings :: Lens' (AccountDelegation av) Bool
delegationStakeEarnings = lens _delegationStakeEarnings (\ad x -> ad{_delegationStakeEarnings = x})

-- |Lens for '_delegationTarget'
{-# INLINE delegationTarget #-}
delegationTarget :: Lens' (AccountDelegation av) DelegationTarget
delegationTarget = lens _delegationTarget (\ad x -> ad{_delegationTarget = x})

-- |Lens for '_delegationPendingChange'
{-# INLINE delegationPendingChange #-}
delegationPendingChange :: Lens' (AccountDelegation av) (StakePendingChange av)
delegationPendingChange = lens _delegationPendingChange (\ad x -> ad{_delegationPendingChange = x})

instance forall av. (IsAccountVersion av, AVSupportsDelegation av) => Serialize (AccountDelegation av) where
    put AccountDelegationV1{..} = do
        put _delegationIdentity
        put _delegationStakedAmount
        put _delegationStakeEarnings
        put _delegationTarget
        put _delegationPendingChange
    get = do
        _delegationIdentity <- get
        _delegationStakedAmount <- get
        _delegationStakeEarnings <- get
        _delegationTarget <- get
        _delegationPendingChange <- get
        return AccountDelegationV1{..}

-- |Whether an account stakes as a baker, delegates to a baker, or neither.
data AccountStake (av :: AccountVersion) where
    AccountStakeNone :: AccountStake av
    AccountStakeBaker :: !(AccountBaker av) -> AccountStake av
    AccountStakeDelegate :: !(AccountDelegation av) -> AccountStake av
    deriving (Eq, Show)

-- |Serialize an 'AccountStake', depending on the account version.
-- Note that it should be recorded earlier in the serialization whether the stake is
-- 'AccountStakeNone', since in that case nothing is written.  This function is thus intended
-- to be used in the context of a broader account serialization function.
--
-- For 'AccountV0', the baker is simply serialized. (Delegation is not possible.)
--
-- For 'AccountV1', a byte is written that records whether the stake is as a baker (0) or
-- delegated (1).  Following this, the baker or delegation is simply serialized.
serializeAccountStake :: forall av. IsAccountVersion av => Putter (AccountStake av)
serializeAccountStake AccountStakeNone = return ()
serializeAccountStake (AccountStakeBaker bkr) = case delegationSupport @av of
    SAVDelegationNotSupported -> serializeAccountBaker bkr
    SAVDelegationSupported -> do
        putWord8 0
        serializeAccountBaker bkr
serializeAccountStake (AccountStakeDelegate dlg@AccountDelegationV1{}) = do
    -- Only applies for AccountV1
    putWord8 1
    put dlg

-- |Deserialize an 'AccountStake', depending on the account version.
-- This cannot deserialize the 'AccountStakeNone' case, so should be used in a context where it is
-- already determined that that is not the case.
--
-- For 'AccountV0', the baker is simply deserialized. (Delegation is not possible.)
--
-- For 'AccountV1', the first byte indicates whether a baker (0) or a delegation (1) is read.
deserializeAccountStake :: forall av. IsAccountVersion av => Get (AccountStake av)
deserializeAccountStake = case delegationSupport @av of
    SAVDelegationNotSupported -> AccountStakeBaker <$> deserializeAccountBaker
    SAVDelegationSupported ->
        getWord8 >>= \case
            0 -> AccountStakeBaker <$> deserializeAccountBaker
            1 -> AccountStakeDelegate <$> get
            _ -> fail "Invalid stake type"

newtype AccountStakeHash (av :: AccountVersion) = AccountStakeHash {theAccountStakeHash :: Hash.Hash}
    deriving (Eq, Ord, Show, Serialize, ToJSON, FromJSON) via Hash.Hash

-- |Hash of 'AccountStakeNone' in 'AccountV0'.
accountStakeNoneHashV0 :: AccountStakeHash 'AccountV0
{-# NOINLINE accountStakeNoneHashV0 #-}
accountStakeNoneHashV0 = AccountStakeHash $ Hash.hash ""

instance HashableTo (AccountStakeHash 'AccountV0) (AccountStake 'AccountV0) where
    getHash AccountStakeNone = accountStakeNoneHashV0
    getHash (AccountStakeBaker AccountBaker{..}) =
        AccountStakeHash $
            Hash.hashLazy $
                runPutLazy $ do
                    put _stakedAmount
                    put _stakeEarnings
                    put _accountBakerInfo
                    put _bakerPendingChange

-- |Hash of 'AccountStakeNone' in 'AccountV1'.
accountStakeNoneHashV1 :: AccountStakeHash 'AccountV1
{-# NOINLINE accountStakeNoneHashV1 #-}
accountStakeNoneHashV1 = AccountStakeHash $ Hash.hash "NoStake"

-- |The 'AccountV1' hashing of 'AccountStake' uses tags to enforce distinction between the cases.
instance HashableTo (AccountStakeHash 'AccountV1) (AccountStake 'AccountV1) where
    getHash AccountStakeNone = accountStakeNoneHashV1
    getHash (AccountStakeBaker AccountBaker{..}) =
        AccountStakeHash $
            Hash.hashLazy $
                "Baker"
                    <> runPutLazy
                        ( do
                            put _stakedAmount
                            put _stakeEarnings
                            put _accountBakerInfo
                            put _bakerPendingChange
                        )
    getHash (AccountStakeDelegate AccountDelegationV1{..}) =
        AccountStakeHash $
            Hash.hashLazy $
                "Delegation"
                    <> runPutLazy
                        ( do
                            put _delegationStakedAmount
                            put _delegationStakeEarnings
                            put _delegationTarget
                        )

-- |Hash of 'AccountStakeNone' in 'AccountV2'.
accountStakeNoneHashV2 :: AccountStakeHash 'AccountV2
{-# NOINLINE accountStakeNoneHashV2 #-}
accountStakeNoneHashV2 = AccountStakeHash $ Hash.hash "A2NoStake"

-- |The 'AccountV2' hashing of 'AccountStake' DOES NOT INCLUDE the staked amount.
-- This is since the stake is accounted for separately in the @AccountHash@.
instance HashableTo (AccountStakeHash 'AccountV2) (AccountStake 'AccountV2) where
    getHash AccountStakeNone = accountStakeNoneHashV2
    getHash (AccountStakeBaker AccountBaker{..}) =
        AccountStakeHash $
            Hash.hashLazy $
                "A2Baker"
                    <> runPutLazy
                        ( do
                            put _stakeEarnings
                            put _accountBakerInfo
                            put _bakerPendingChange
                        )
    getHash (AccountStakeDelegate AccountDelegationV1{..}) =
        AccountStakeHash $
            Hash.hashLazy $
                "A2Delegation"
                    <> runPutLazy
                        ( do
                            put _delegationIdentity
                            put _delegationStakeEarnings
                            put _delegationTarget
                            put _delegationPendingChange
                        )

-- |Get the 'AccountStakeHash' from an 'AccountStake' for any account version.
getAccountStakeHash :: forall av. IsAccountVersion av => AccountStake av -> AccountStakeHash av
getAccountStakeHash = case accountVersion @av of
    SAccountV0 -> getHash
    SAccountV1 -> getHash
    SAccountV2 -> getHash

-- |A representation type (used for queries) for the staking status of an account.
-- This representation is agnostic to the protocol version and represents pending change times
-- as UTCTime.
data AccountStakingInfo
    = -- |The account is not a baker or delegator.
      AccountStakingNone
    | -- |The account is a baker.
      AccountStakingBaker
        { asiStakedAmount :: !Amount,
          asiStakeEarnings :: !Bool,
          asiBakerInfo :: !BakerInfo,
          asiPendingChange :: !(StakePendingChange' UTCTime),
          asiPoolInfo :: !(Maybe BakerPoolInfo)
        }
    | -- |The account is delegating stake to a baker.
      AccountStakingDelegated
        { asiStakedAmount :: !Amount,
          asiStakeEarnings :: !Bool,
          asiDelegationTarget :: !DelegationTarget,
          asiDelegationPendingChange :: !(StakePendingChange' UTCTime)
        }
    deriving (Eq, Show)

-- |Convert an 'AccountStake' to an 'AccountStakingInfo'.
-- This takes a function for converting an epoch time to a 'UTCTime' (of the start of the epoch).
-- (This is used for rendering cooldowns prior to 'P4'.)
toAccountStakingInfo :: forall av. IsAccountVersion av => (Epoch -> UTCTime) -> AccountStake av -> AccountStakingInfo
toAccountStakingInfo _ AccountStakeNone = AccountStakingNone
toAccountStakingInfo epochConv (AccountStakeBaker AccountBaker{..}) =
    AccountStakingBaker
        { asiStakedAmount = _stakedAmount,
          asiStakeEarnings = _stakeEarnings,
          asiBakerInfo = _accountBakerInfo ^. bakerInfo,
          asiPendingChange = pcTime <$> _bakerPendingChange,
          asiPoolInfo = case _accountBakerInfo of
            BakerInfoExV0{} -> Nothing
            BakerInfoExV1{..} -> Just _bieBakerPoolInfo
        }
  where
    pcTime (PendingChangeEffectiveV0 e) = epochConv e
    pcTime (PendingChangeEffectiveV1 t) = timestampToUTCTime t
toAccountStakingInfo _ (AccountStakeDelegate AccountDelegationV1{..}) =
    AccountStakingDelegated
        { asiStakedAmount = _delegationStakedAmount,
          asiStakeEarnings = _delegationStakeEarnings,
          asiDelegationTarget = _delegationTarget,
          asiDelegationPendingChange = pcTime <$> _delegationPendingChange
        }
  where
    pcTime :: AVSupportsDelegation av => PendingChangeEffective av -> UTCTime
    pcTime (PendingChangeEffectiveV1 t) = timestampToUTCTime t

pendingChangeToJSON :: KeyValue kv => StakePendingChange' UTCTime -> [kv]
pendingChangeToJSON NoChange = []
pendingChangeToJSON (ReduceStake amt eff) =
    [ "pendingChange"
        .= object
            ["change" .= String "ReduceStake", "newStake" .= amt, "effectiveTime" .= eff]
    ]
pendingChangeToJSON (RemoveStake eff) =
    [ "pendingChange"
        .= object
            ["change" .= String "RemoveStake", "effectiveTime" .= eff]
    ]

pendingChangeFromJSON :: Object -> Parser (StakePendingChange' UTCTime)
pendingChangeFromJSON obj = do
    pc <- obj .:? "pendingChange"
    case pc of
        Just pco -> do
            pco .: "change" >>= \case
                (String "ReduceStake") -> ReduceStake <$> pco .: "newStake" <*> pco .: "effectiveTime"
                (String "RemoveStake") -> RemoveStake <$> pco .: "effectiveTime"
                _ -> fail "Invalid pendingChange"
        Nothing -> return NoChange

accountStakingInfoToJSON :: KeyValue kv => AccountStakingInfo -> [kv]
accountStakingInfoToJSON AccountStakingNone = []
accountStakingInfoToJSON AccountStakingBaker{..} = ["accountBaker" .= bi]
  where
    bi =
        object $
            [ "stakedAmount" .= asiStakedAmount,
              "restakeEarnings" .= asiStakeEarnings,
              "bakerId" .= (asiBakerInfo ^. bakerIdentity),
              "bakerElectionVerifyKey" .= (asiBakerInfo ^. bakerElectionVerifyKey),
              "bakerSignatureVerifyKey" .= (asiBakerInfo ^. bakerSignatureVerifyKey),
              "bakerAggregationVerifyKey" .= (asiBakerInfo ^. bakerAggregationVerifyKey)
            ]
                <> pendingChangeToJSON asiPendingChange
                <> maybe [] (\bpi -> ["bakerPoolInfo" .= bpi]) asiPoolInfo
accountStakingInfoToJSON AccountStakingDelegated{..} = ["accountDelegation" .= di]
  where
    di =
        object $
            [ "stakedAmount" .= asiStakedAmount,
              "restakeEarnings" .= asiStakeEarnings,
              "delegationTarget" .= asiDelegationTarget
            ]
                <> pendingChangeToJSON asiDelegationPendingChange

accountStakingInfoFromJSON :: Object -> Parser AccountStakingInfo
accountStakingInfoFromJSON obj = do
    baker <- obj .:? "accountBaker"
    delegation <- obj .:? "accountDelegation"
    case (baker, delegation) of
        (Nothing, Nothing) -> return AccountStakingNone
        (Just bkr, Nothing) -> do
            asiStakedAmount <- bkr .: "stakedAmount"
            asiStakeEarnings <- bkr .: "restakeEarnings"
            _bakerIdentity <- bkr .: "bakerId"
            _bakerElectionVerifyKey <- bkr .: "bakerElectionVerifyKey"
            _bakerSignatureVerifyKey <- bkr .: "bakerSignatureVerifyKey"
            _bakerAggregationVerifyKey <- bkr .: "bakerAggregationVerifyKey"
            let asiBakerInfo = BakerInfo{..}
            asiPendingChange <- pendingChangeFromJSON bkr
            asiPoolInfo <- bkr .:? "bakerPoolInfo"
            return AccountStakingBaker{..}
        (Nothing, Just dlg) -> do
            asiStakedAmount <- dlg .: "stakedAmount"
            asiStakeEarnings <- dlg .: "restakeEarnings"
            asiDelegationTarget <- dlg .: "delegationTarget"
            asiDelegationPendingChange <- pendingChangeFromJSON dlg
            return AccountStakingDelegated{..}
        (_, _) -> fail "Account must not have both accountBaker and accountDelegation."

-- |The details of the state of an account on the chain, as may be returned by a
-- query. At present the account credentials map must always contain credential
-- at index 0.
data AccountInfo = AccountInfo
    { -- |The next nonce for the account
      aiAccountNonce :: !Nonce,
      -- |The total non-encrypted balance on the account
      aiAccountAmount :: !Amount,
      -- |The release schedule for locked amounts on the account
      aiAccountReleaseSchedule :: !AccountReleaseSummary,
      -- |The credentials on the account. This map must always contain a
      -- credential at credential index 0.
      aiAccountCredentials :: !(Map.Map CredentialIndex (Versioned RawAccountCredential)),
      -- |Number of credentials required to sign a valid transaction
      aiAccountThreshold :: !AccountThreshold,
      -- |The encrypted amount on the account
      aiAccountEncryptedAmount :: !AccountEncryptedAmount,
      -- |The encryption key for the account
      aiAccountEncryptionKey :: !AccountEncryptionKey,
      -- |The account index
      aiAccountIndex :: !AccountIndex,
      -- |The baker associated with the account (if any)
      aiStakingInfo :: !AccountStakingInfo,
      -- |The canonical address of the account, derived from the first
      -- credential. While this is not necessary, since it is derived from
      -- another field of this type, it is convenient for consumers to have it.
      aiAccountAddress :: !AccountAddress
    }
    deriving (Eq, Show)

-- |Helper function for 'ToJSON' instance for 'AccountInfo'.
accountInfoPairs :: (KeyValue kv) => AccountInfo -> [kv]
{-# INLINE accountInfoPairs #-}
accountInfoPairs AccountInfo{..} =
    [ "accountNonce" .= aiAccountNonce,
      "accountAmount" .= aiAccountAmount,
      "accountReleaseSchedule" .= aiAccountReleaseSchedule,
      "accountCredentials" .= aiAccountCredentials,
      "accountThreshold" .= aiAccountThreshold,
      "accountEncryptedAmount" .= aiAccountEncryptedAmount,
      "accountEncryptionKey" .= aiAccountEncryptionKey,
      "accountIndex" .= aiAccountIndex,
      "accountAddress" .= aiAccountAddress
    ]
        <> accountStakingInfoToJSON aiStakingInfo

instance ToJSON AccountInfo where
    toJSON ai = object $ accountInfoPairs ai
    toEncoding ai = pairs $ mconcat $ accountInfoPairs ai

-- Due to the inconsistent naming of the AccountInfo fields we have to write the fromJSON instance manually.
instance FromJSON AccountInfo where
    parseJSON = withObject "Account info" $ \obj -> do
        aiAccountNonce <- obj .: "accountNonce"
        aiAccountAmount <- obj .: "accountAmount"
        aiAccountReleaseSchedule <- obj .: "accountReleaseSchedule"
        aiAccountCredentials <- obj .: "accountCredentials"
        creatingCredential <-
            case Map.lookup (CredentialIndex 0) aiAccountCredentials of
                Nothing -> fail "Accounts must have a credential with index 0."
                Just ac -> return ac
        aiAccountThreshold <- obj .: "accountThreshold"
        aiAccountEncryptedAmount <- obj .: "accountEncryptedAmount"
        aiAccountEncryptionKey <- obj .: "accountEncryptionKey"
        aiAccountIndex <- obj .: "accountIndex"
        -- For backwards compatibility we retrieve the account address from the
        -- credential.
        aiAccountAddress <-
            obj .:! "accountAddress" >>= \case
                Nothing -> return (addressFromRegIdRaw (credId (vValue creatingCredential)))
                Just addr -> return addr
        aiStakingInfo <- accountStakingInfoFromJSON obj
        return AccountInfo{..}
