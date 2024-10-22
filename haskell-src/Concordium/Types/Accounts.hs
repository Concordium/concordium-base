{-# LANGUAGE BinaryLiterals #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE InstanceSigs #-}
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

-- | Types for representing the results of consensus queries.
module Concordium.Types.Accounts (
    AccountVersion (..),
    SAccountVersion (..),
    AccountVersionFor,
    accountVersionFor,
    BakerPoolInfo (..),
    HasBakerPoolInfo,
    -- | Whether the pool allows delegators.
    poolOpenStatus,
    -- | The URL that links to the metadata about the pool.
    poolMetadataUrl,
    -- | The commission rates charged by the pool owner.
    poolCommissionRates,
    BakerInfo (..),
    HasBakerInfo,
    bakerInfo,
    -- | Identity of the baker. This is actually the account index of
    --  the account controlling the baker.
    bakerIdentity,
    -- | The baker's public VRF key
    bakerElectionVerifyKey,
    -- | The baker's public signature key
    bakerSignatureVerifyKey,
    -- | The baker's public key for finalization record aggregation
    bakerAggregationVerifyKey,
    -- | The details of the pool associated with a baker
    bakerPoolInfo,
    BakerInfoEx (..),
    bieBakerInfo,
    bieBakerPoolInfo,
    bieAccountIsSuspended,
    coerceBakerInfoExV1,
    PendingChangeEffective (..),
    pendingChangeEffectiveTimestamp,
    coercePendingChangeEffectiveV1,
    StakePendingChange' (..),
    StakePendingChange,
    AccountBaker (..),
    -- | The amount staked by the baker.
    stakedAmount,
    -- | Whether baker and finalizer rewards are added to the stake.
    stakeEarnings,
    -- | The baker's keys and identity.
    accountBakerInfo,
    -- | The pending change (if any) to the baker's status.
    bakerPendingChange,
    AccountDelegation (..),
    delegationIdentity,
    delegationStakedAmount,
    delegationStakeEarnings,
    delegationTarget,
    delegationPendingChange,
    AccountStake (..),
    AccountStakeHash (..),
    getAccountStakeHash,
    AccountInfo (..),
    AccountStakingInfo (..),
    toAccountStakingInfo,
    toAccountStakingInfoP4,
    CooldownStatus (..),
    Cooldown (..),

    -- * Account structure version
    AccountStructureVersion (..),
    AccountStructureVersionFor,
) where

import Data.Aeson
import Data.Bool.Singletons
import qualified Data.Map as Map
import Data.Serialize
import Data.Singletons
import Data.Time
import Lens.Micro.Platform (Lens', lens, makeClassy, makeLenses, (^.))

import Concordium.Common.Version
import qualified Concordium.Crypto.SHA256 as Hash
import Concordium.ID.Types
import Concordium.Types
import Concordium.Types.Accounts.Releases
import Concordium.Types.Conditionally
import Concordium.Types.Execution (DelegationTarget, OpenStatus)
import Concordium.Types.HashableTo

-- | The version of the account structure. This is used to index types that vary the account
--  structure.
data AccountStructureVersion
    = -- | Account structure used prior to P5
      AccountStructureV0
    | -- | Account structure used from P5
      AccountStructureV1

-- | The account structure version associated with an account version.
type family AccountStructureVersionFor (av :: AccountVersion) :: AccountStructureVersion where
    AccountStructureVersionFor 'AccountV0 = 'AccountStructureV0
    AccountStructureVersionFor 'AccountV1 = 'AccountStructureV0
    AccountStructureVersionFor 'AccountV2 = 'AccountStructureV1
    AccountStructureVersionFor 'AccountV3 = 'AccountStructureV1
    AccountStructureVersionFor 'AccountV4 = 'AccountStructureV1

-- | The 'BakerId' of a baker and its public keys.
data BakerInfo = BakerInfo
    { -- | Identity of the baker. This is actually the account index of
      --  the account controlling the baker.
      _bakerIdentity :: !BakerId,
      -- | The baker's public VRF key
      _bakerElectionVerifyKey :: !BakerElectionVerifyKey,
      -- | The baker's public signature key
      _bakerSignatureVerifyKey :: !BakerSignVerifyKey,
      -- | The baker's public key for finalization record aggregation
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

instance ToJSON BakerInfo where
    toJSON BakerInfo{..} =
        object
            [ "bakerId" .= _bakerIdentity,
              "bakerElectionVerifyKey" .= _bakerElectionVerifyKey,
              "bakerSignatureVerifyKey" .= _bakerSignatureVerifyKey,
              "bakerAggregationVerifyKey" .= _bakerAggregationVerifyKey
            ]

-- Define the class 'HasBakerInfo' with accessor lenses and an instance for 'BakerInfo'.
makeClassy ''BakerInfo

-- | Additional information about a baking pool.
--  This information is added with the introduction of delegation.
data BakerPoolInfo
    = -- | The introduction of delegation requires information about the pool.
      BakerPoolInfo
      { -- | Whether the pool allows delegators.
        _poolOpenStatus :: !OpenStatus,
        -- | The URL that links to the metadata about the pool.
        _poolMetadataUrl :: !UrlText,
        -- | The commission rates charged by the pool owner.
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

-- | Helper function for defining 'ToJSON'.
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

-- | Extended baker information. Protocol version 4 introduces baking pools that allow delegation.
--  Thus, for 'P4' onwards, the baker info is extended with 'BakerPoolInfo' that describes the
--  pool.
data BakerInfoEx (av :: AccountVersion) where
    BakerInfoExV0 :: !BakerInfo -> BakerInfoEx 'AccountV0
    BakerInfoExV1 ::
        forall av.
        (AVSupportsDelegation av) =>
        { -- | The baker ID and keys.
          _bieBakerInfo :: !BakerInfo,
          -- | The baker pool info.
          _bieBakerPoolInfo :: !BakerPoolInfo,
          _bieAccountIsSuspended :: !(Conditionally (SupportsValidatorSuspension av) Bool)
        } ->
        BakerInfoEx av

deriving instance Eq (BakerInfoEx av)
deriving instance Show (BakerInfoEx av)

-- | Lens for '_bieBakerInfo'
{-# INLINE bieBakerInfo #-}
bieBakerInfo :: (AVSupportsDelegation av) => Lens' (BakerInfoEx av) BakerInfo
bieBakerInfo =
    lens _bieBakerInfo (\bie x -> bie{_bieBakerInfo = x})

-- | Lens for '_bieBakerPoolInfo'
{-# INLINE bieBakerPoolInfo #-}
bieBakerPoolInfo :: (AVSupportsDelegation av) => Lens' (BakerInfoEx av) BakerPoolInfo
bieBakerPoolInfo =
    lens _bieBakerPoolInfo (\bie x -> bie{_bieBakerPoolInfo = x})

-- | Lens for '_bieBakerIsSuspended'
{-# INLINE bieAccountIsSuspended #-}
bieAccountIsSuspended ::
    (AVSupportsDelegation av, AVSupportsValidatorSuspension av) =>
    Lens' (BakerInfoEx av) Bool
bieAccountIsSuspended =
    lens (uncond . _bieAccountIsSuspended) (\bie x -> bie{_bieAccountIsSuspended = CTrue x})

-- | Coerce a 'BakerInfoEx' between two account versions that support delegation.
coerceBakerInfoExV1 ::
    ( AVSupportsDelegation av1,
      AVSupportsDelegation av2,
      AVSupportsValidatorSuspension av1 ~ AVSupportsValidatorSuspension av2
    ) =>
    BakerInfoEx av1 ->
    BakerInfoEx av2
coerceBakerInfoExV1 BakerInfoExV1{..} = BakerInfoExV1{..}

-- | Note that the serialization of 'BakerInfoEx' matches exactly
--  the serialization of 'BakerInfo' for 'AccountV0'. This is needed to preserve
--  compatibility between versions, allowing 'BakerInfoEx' to be used where
--  'BakerInfo' was used.
instance forall av. (IsAccountVersion av) => Serialize (BakerInfoEx av) where
    put (BakerInfoExV0 bi) = put bi
    put BakerInfoExV1{..} = do
        put _bieBakerInfo
        put _bieBakerPoolInfo
        mapM_ put _bieAccountIsSuspended
    get = case delegationSupport @av of
        SAVDelegationNotSupported -> BakerInfoExV0 <$> get
        SAVDelegationSupported -> do
            _bieBakerInfo <- get
            _bieBakerPoolInfo <- get
            _bieAccountIsSuspended <-
                conditionallyA (sSupportsValidatorSuspension (accountVersion @av)) get
            return BakerInfoExV1{..}

instance HasBakerInfo (BakerInfoEx av) where
    bakerInfo upd (BakerInfoExV0 bi) = BakerInfoExV0 <$> upd bi
    bakerInfo upd bie@BakerInfoExV1{..} = (\bi' -> bie{_bieBakerInfo = bi'}) <$> upd _bieBakerInfo

instance (AVSupportsDelegation av) => HasBakerPoolInfo (BakerInfoEx av) where
    bakerPoolInfo upd bie@BakerInfoExV1{..} =
        (\bpi' -> bie{_bieBakerPoolInfo = bpi'})
            <$> upd _bieBakerPoolInfo

-- | The time at which a pending change to a baker or delegator's capital becomes effective from
--  the perspective of determining stakes.  (This will have effect on baker stakes two epochs after
--  this time.)
--
--  For 'AccountV0', this is specified as an 'Epoch', which is an absolute number of epochs since
--  the latest genesis.  For 'AccountV1' and 'AccountV2', this is an absolute timestamp. This latter
--  choice is preferable, as it does not need to be changed on a protocol update to account for the
--  resetting of the Epoch counter.  For 'AccountV3' (onwards) the type has no values, as pending
--  changes are replaced by inactive stake.
data PendingChangeEffective (av :: AccountVersion) where
    PendingChangeEffectiveV0 :: !Epoch -> PendingChangeEffective 'AccountV0
    PendingChangeEffectiveV1 ::
        (AVSupportsDelegation av, SupportsFlexibleCooldown av ~ 'False) =>
        !Timestamp ->
        PendingChangeEffective av

deriving instance Eq (PendingChangeEffective av)
deriving instance Ord (PendingChangeEffective av)
deriving instance Show (PendingChangeEffective av)

instance (IsAccountVersion av) => Serialize (PendingChangeEffective av) where
    put :: (IsAccountVersion av) => Putter (PendingChangeEffective av)
    put (PendingChangeEffectiveV0 epoch) = put epoch
    put (PendingChangeEffectiveV1 timestamp) = put timestamp
    get = case delegationSupport @av of
        SAVDelegationNotSupported -> PendingChangeEffectiveV0 <$> get
        SAVDelegationSupported -> case sSupportsFlexibleCooldown (sing @av) of
            SFalse -> PendingChangeEffectiveV1 <$> get
            STrue -> fail "PendingChangeEffective is not compatible with flexible cooldown"

-- | Get the 'Timestamp' from a 'PendingChangeEffective' if the account version supports delegation.
pendingChangeEffectiveTimestamp :: (AVSupportsDelegation av) => PendingChangeEffective av -> Timestamp
{-# INLINE pendingChangeEffectiveTimestamp #-}
pendingChangeEffectiveTimestamp (PendingChangeEffectiveV1 ts) = ts

-- | Convert a 'PendingChangeEffective' between account versions that support delegation.
coercePendingChangeEffectiveV1 ::
    (AVSupportsDelegation av1, AVSupportsDelegation av2, SupportsFlexibleCooldown av2 ~ 'False) =>
    PendingChangeEffective av1 ->
    PendingChangeEffective av2
coercePendingChangeEffectiveV1 (PendingChangeEffectiveV1 ts) = PendingChangeEffectiveV1 ts

-- | Pending changes to the baker or delegation associated with an account.
data StakePendingChange' effectiveTime
    = -- | There is no change pending to the baker.
      NoChange
    | -- | The stake will be decreased to the given amount.
      ReduceStake !Amount !effectiveTime
    | -- | The baker will be removed.
      RemoveStake !effectiveTime
    deriving (Eq, Ord, Show, Functor)

instance (Serialize effectiveTime) => Serialize (StakePendingChange' effectiveTime) where
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

-- | A baker associated with an account.
data AccountBaker (av :: AccountVersion) = AccountBaker
    { -- | The amount staked by the baker.
      _stakedAmount :: !Amount,
      -- | Whether baker and finalizer rewards are added to the stake.
      _stakeEarnings :: !Bool,
      -- | The baker's keys, identity, and pool info (V1).
      _accountBakerInfo :: !(BakerInfoEx av),
      -- | The pending change (if any) to the baker's status.
      _bakerPendingChange :: !(StakePendingChange av)
    }
    deriving (Eq, Show)

makeLenses ''AccountBaker

instance HasBakerInfo (AccountBaker av) where
    bakerInfo = accountBakerInfo . bakerInfo

instance (AVSupportsDelegation av) => HasBakerPoolInfo (AccountBaker av) where
    bakerPoolInfo = accountBakerInfo . bakerPoolInfo

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

-- | Lens for '_delegationIdentity'
{-# INLINE delegationIdentity #-}
delegationIdentity :: Lens' (AccountDelegation av) DelegatorId
delegationIdentity = lens _delegationIdentity (\ad x -> ad{_delegationIdentity = x})

-- | Lens for '_delegationStakedAmount'
{-# INLINE delegationStakedAmount #-}
delegationStakedAmount :: Lens' (AccountDelegation av) Amount
delegationStakedAmount = lens _delegationStakedAmount (\ad x -> ad{_delegationStakedAmount = x})

-- | Lens for '_delegationStakeEarnings'
{-# INLINE delegationStakeEarnings #-}
delegationStakeEarnings :: Lens' (AccountDelegation av) Bool
delegationStakeEarnings = lens _delegationStakeEarnings (\ad x -> ad{_delegationStakeEarnings = x})

-- | Lens for '_delegationTarget'
{-# INLINE delegationTarget #-}
delegationTarget :: Lens' (AccountDelegation av) DelegationTarget
delegationTarget = lens _delegationTarget (\ad x -> ad{_delegationTarget = x})

-- | Lens for '_delegationPendingChange'
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

-- | Whether an account stakes as a baker, delegates to a baker, or neither.
data AccountStake (av :: AccountVersion) where
    AccountStakeNone :: AccountStake av
    AccountStakeBaker :: !(AccountBaker av) -> AccountStake av
    AccountStakeDelegate :: !(AccountDelegation av) -> AccountStake av
    deriving (Eq, Show)

newtype AccountStakeHash (av :: AccountVersion) = AccountStakeHash {theAccountStakeHash :: Hash.Hash}
    deriving (Eq, Ord, Show, Serialize, ToJSON, FromJSON) via Hash.Hash

-- | Hash of 'AccountStakeNone' in 'AccountV0'.
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

-- | Hash of 'AccountStakeNone' in 'AccountV1'.
accountStakeNoneHashV1 :: AccountStakeHash 'AccountV1
{-# NOINLINE accountStakeNoneHashV1 #-}
accountStakeNoneHashV1 = AccountStakeHash $ Hash.hash "NoStake"

-- | The 'AccountV1' hashing of 'AccountStake' uses tags to enforce distinction between the cases.
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

-- | Hash of 'AccountStakeNone' in 'AccountV2'.
accountStakeNoneHashV2 :: AccountStakeHash 'AccountV2
{-# NOINLINE accountStakeNoneHashV2 #-}
accountStakeNoneHashV2 = AccountStakeHash $ Hash.hash "A2NoStake"

-- | Hash of 'AccountStakeNone' in 'AccountV3'.
accountStakeNoneHashV3 :: AccountStakeHash 'AccountV3
{-# NOINLINE accountStakeNoneHashV3 #-}
accountStakeNoneHashV3 = AccountStakeHash $ Hash.hash "A3NoStake"

-- | Hash of 'AccountStakeNone' in 'AccountV4'.
accountStakeNoneHashV4 :: AccountStakeHash 'AccountV4
{-# NOINLINE accountStakeNoneHashV4 #-}
accountStakeNoneHashV4 = AccountStakeHash $ Hash.hash "A4NoStake"

-- | The 'AccountV2' hashing of 'AccountStake' DOES NOT INCLUDE the staked amount.
--  This is since the stake is accounted for separately in the @AccountHash@.
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

-- | The 'AccountV3' hashing of 'AccountStake' DOES NOT INCLUDE the staked amount.
--  This is since the stake is accounted for separately in the @AccountHash@.
instance HashableTo (AccountStakeHash 'AccountV3) (AccountStake 'AccountV3) where
    getHash AccountStakeNone = accountStakeNoneHashV3
    getHash (AccountStakeBaker AccountBaker{..}) =
        AccountStakeHash $
            Hash.hashLazy $
                "A3Baker"
                    <> runPutLazy
                        ( do
                            put _stakeEarnings
                            put _accountBakerInfo
                        )
    getHash (AccountStakeDelegate AccountDelegationV1{..}) =
        AccountStakeHash $
            Hash.hashLazy $
                "A3Delegation"
                    <> runPutLazy
                        ( do
                            put _delegationIdentity
                            put _delegationStakeEarnings
                            put _delegationTarget
                        )

-- | The 'AccountV4' hashing of 'AccountStake' DOES NOT INCLUDE the staked amount.
--  This is since the stake is accounted for separately in the @AccountHash@.
instance HashableTo (AccountStakeHash 'AccountV4) (AccountStake 'AccountV4) where
    getHash AccountStakeNone = accountStakeNoneHashV4
    getHash (AccountStakeBaker AccountBaker{..}) =
        AccountStakeHash $
            Hash.hashLazy $
                "A4Baker"
                    <> runPutLazy
                        ( do
                            put _stakeEarnings
                            put _accountBakerInfo
                            put _bakerPendingChange
                        )
    getHash (AccountStakeDelegate AccountDelegationV1{..}) =
        AccountStakeHash $
            Hash.hashLazy $
                "A4Delegation"
                    <> runPutLazy
                        ( do
                            put _delegationIdentity
                            put _delegationStakeEarnings
                            put _delegationTarget
                            put _delegationPendingChange
                        )

-- | Get the 'AccountStakeHash' from an 'AccountStake' for any account version.
getAccountStakeHash :: forall av. (IsAccountVersion av) => AccountStake av -> AccountStakeHash av
getAccountStakeHash = case accountVersion @av of
    SAccountV0 -> getHash
    SAccountV1 -> getHash
    SAccountV2 -> getHash
    SAccountV3 -> getHash
    SAccountV4 -> getHash

-- | A representation type (used for queries) for the staking status of an account.
--  This representation is agnostic to the protocol version and represents pending change times
--  as UTCTime.
data AccountStakingInfo
    = -- | The account is not a baker or delegator.
      AccountStakingNone
    | -- | The account is a baker.
      AccountStakingBaker
        { asiStakedAmount :: !Amount,
          asiStakeEarnings :: !Bool,
          asiBakerInfo :: !BakerInfo,
          asiPendingChange :: !(StakePendingChange' UTCTime),
          asiPoolInfo :: !(Maybe BakerPoolInfo),
          -- | Flag indicating whether the account is currently suspended. A suspended account
          --  is not participating in the consensus protocol. The `asiIsSuspended` flag does not
          --  have any effect on stake or delegators of a validator.
          asiIsSuspended :: !Bool
        }
    | -- | The account is delegating stake to a baker.
      AccountStakingDelegated
        { asiStakedAmount :: !Amount,
          asiStakeEarnings :: !Bool,
          asiDelegationTarget :: !DelegationTarget,
          asiDelegationPendingChange :: !(StakePendingChange' UTCTime)
        }
    deriving (Eq, Show)

-- | Convert an 'AccountStake' to an 'AccountStakingInfo'.
--  This takes a function for converting an epoch time to a 'UTCTime' (of the start of the epoch).
--  (This is used for rendering cooldowns prior to 'P4'.)
toAccountStakingInfo :: forall av. (IsAccountVersion av) => (Epoch -> UTCTime) -> AccountStake av -> AccountStakingInfo
toAccountStakingInfo _ AccountStakeNone = AccountStakingNone
toAccountStakingInfo epochConv (AccountStakeBaker AccountBaker{..}) =
    AccountStakingBaker
        { asiStakedAmount = _stakedAmount,
          asiStakeEarnings = _stakeEarnings,
          asiBakerInfo = _accountBakerInfo ^. bakerInfo,
          asiPendingChange = pcTime <$> _bakerPendingChange,
          asiPoolInfo = case _accountBakerInfo of
            BakerInfoExV0{} -> Nothing
            BakerInfoExV1{..} -> Just _bieBakerPoolInfo,
          asiIsSuspended = case _accountBakerInfo of
            BakerInfoExV0{} -> False
            BakerInfoExV1{..} -> fromCondDef _bieAccountIsSuspended False
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
    pcTime :: (AVSupportsDelegation av) => PendingChangeEffective av -> UTCTime
    pcTime (PendingChangeEffectiveV1 t) = timestampToUTCTime t

-- | Convert an 'AccountStake' to an 'AccountStakingInfo' in protocol versions from 'P4' onwards.
toAccountStakingInfoP4 ::
    forall av.
    (IsAccountVersion av, AVSupportsDelegation av) =>
    AccountStake av ->
    AccountStakingInfo
toAccountStakingInfoP4 =
    toAccountStakingInfo
        (error "Epoch conversion is not used for account staking info in this protocol version")

pendingChangeToJSON :: (KeyValue kv) => StakePendingChange' UTCTime -> [kv]
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

accountStakingInfoToJSON :: (KeyValue kv) => AccountStakingInfo -> [kv]
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
              "bakerAggregationVerifyKey" .= (asiBakerInfo ^. bakerAggregationVerifyKey),
              "bakerIsSuspended" .= asiIsSuspended
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

-- | Tag indicating whether a cooldown amount is:
--   - In cooldown, with a fully-determined expiry time.
--   - In pre-cooldown, and will enter cooldown at the next payday.
--   - In pre-pre-cooldown, and will enter pre-cooldown at the next snapshot epoch.
data CooldownStatus
    = -- | In cooldown
      StatusCooldown
    | -- | In pre-cooldown
      StatusPreCooldown
    | -- | In pre-pre-cooldown
      StatusPrePreCooldown
    deriving (Eq, Show)

instance ToJSON CooldownStatus where
    toJSON StatusCooldown = String "cooldown"
    toJSON StatusPreCooldown = String "precooldown"
    toJSON StatusPrePreCooldown = String "preprecooldown"

-- | A portion of an account's inactive stake that is subject to a cooldown period.
data Cooldown = Cooldown
    { -- | The timestamp at which the cooldown period is projected to end.
      cooldownTimestamp :: !Timestamp,
      -- | The amount of the inactive stake that is subject to the cooldown period.
      cooldownAmount :: !Amount,
      -- | The status of the cooldown period.
      cooldownStatus :: !CooldownStatus
    }
    deriving (Eq, Show)

instance ToJSON Cooldown where
    toJSON Cooldown{..} =
        object
            [ "timestamp" .= cooldownTimestamp,
              "amount" .= cooldownAmount,
              "status" .= cooldownStatus
            ]

-- | The details of the state of an account on the chain, as may be returned by a
--  query. At present the account credentials map must always contain credential
--  at index 0.
data AccountInfo = AccountInfo
    { -- | The next nonce for the account
      aiAccountNonce :: !Nonce,
      -- | The total non-encrypted balance on the account
      aiAccountAmount :: !Amount,
      -- | The release schedule for locked amounts on the account
      aiAccountReleaseSchedule :: !AccountReleaseSummary,
      -- | The credentials on the account. This map must always contain a
      --  credential at credential index 0.
      aiAccountCredentials :: !(Map.Map CredentialIndex (Versioned RawAccountCredential)),
      -- | Number of credentials required to sign a valid transaction
      aiAccountThreshold :: !AccountThreshold,
      -- | The encrypted amount on the account
      aiAccountEncryptedAmount :: !AccountEncryptedAmount,
      -- | The encryption key for the account
      aiAccountEncryptionKey :: !AccountEncryptionKey,
      -- | The account index
      aiAccountIndex :: !AccountIndex,
      -- | The baker associated with the account (if any)
      aiStakingInfo :: !AccountStakingInfo,
      -- | The canonical address of the account, derived from the first
      --  credential. While this is not necessary, since it is derived from
      --  another field of this type, it is convenient for consumers to have it.
      aiAccountAddress :: !AccountAddress,
      -- | The inactive stake of the account (subject to cooldown).
      --  The order of the cooldown amounts is not guaranteed, but is expected to be
      --   - the cooldowns, with the earliest expiration first,
      --   - the pre-cooldown (if any: there can be at most one),
      --   - the pre-pre-cooldown (if any: there can be at most one).
      --  Note that pre-cooldown and pre-pre-cooldown expiry times are not guaranteed to be
      --  accurate. It is also possible to have a cooldown with a later expiry time than a
      --  pre-cooldown or pre-pre-cooldown (e.g. if the cooldown interval has been decreased).
      aiAccountCooldowns :: ![Cooldown],
      -- | The balance of the account that is available for transactions.
      aiAccountAvailableAmount :: !Amount
    }
    deriving (Eq, Show)

-- | Helper function for 'ToJSON' instance for 'AccountInfo'.
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
      "accountAddress" .= aiAccountAddress,
      "accountCooldowns" .= aiAccountCooldowns,
      "accountAvailableAmount" .= aiAccountAvailableAmount
    ]
        <> accountStakingInfoToJSON aiStakingInfo

instance ToJSON AccountInfo where
    toJSON ai = object $ accountInfoPairs ai
    toEncoding ai = pairs $ mconcat $ accountInfoPairs ai
