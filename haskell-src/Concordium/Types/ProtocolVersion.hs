{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}
-- We suppress redundant constraint warnings since GHC does not detect when a constraint is used
-- for pattern matching. (See: https://gitlab.haskell.org/ghc/ghc/-/issues/20896)
{-# OPTIONS_GHC -Wno-redundant-constraints #-}

-- |This module contains the 'ProtocolVersion' datatype, which enumerates the
-- (supported) versions of the protocol for the consensus layer and up.
-- For the most part, 'ProtocolVersion' should be used at the kind level, and
-- its constructors promoted to types (as @'P1@).
--
-- In addition to 'ProtocolVersion' we define the GADT 'SProtocolVersion',
-- which is indexed by the protocol version.
-- i.e. @SProtocolVersion :: ProtocolVersion -> Type@. For each protocol version @pv@,
-- there is a singleton constructor of type @SProtocolVersion pv@, which is named
-- by prepending "S" to the protocol version constructor (e.g. @SP1 :: SProtocolVersion 'P1@).
--
-- The class 'IsProtocolVersion' identifies the singleton for each 'ProtocolVersion',
-- and should have an instance for each constructor of 'ProtocolVersion'.
module Concordium.Types.ProtocolVersion where

import Data.Aeson
import Data.Aeson.Types
import Data.Serialize
import Data.Word

-- |An enumeration of the supported versions of the consensus protocol.
-- Binary and JSON serializations are as Word64 corresponding to the protocol number.
data ProtocolVersion
    = P1
    | P2
    | P3
    | P4
    | P5
    | P6
    deriving (Eq, Show, Ord)

-- |The singleton type associated with 'ProtocolVersion'.
-- There is a unique constructor of 'SProtocolVersion' for
-- each constructor of 'ProtocolVersion'.
data SProtocolVersion (pv :: ProtocolVersion) where
    SP1 :: SProtocolVersion 'P1
    SP2 :: SProtocolVersion 'P2
    SP3 :: SProtocolVersion 'P3
    SP4 :: SProtocolVersion 'P4
    SP5 :: SProtocolVersion 'P5
    SP6 :: SProtocolVersion 'P6

protocolVersionToWord64 :: ProtocolVersion -> Word64
protocolVersionToWord64 P1 = 1
protocolVersionToWord64 P2 = 2
protocolVersionToWord64 P3 = 3
protocolVersionToWord64 P4 = 4
protocolVersionToWord64 P5 = 5
protocolVersionToWord64 P6 = 6

protocolVersionFromWord64 :: MonadFail m => Word64 -> m ProtocolVersion
protocolVersionFromWord64 1 = return P1
protocolVersionFromWord64 2 = return P2
protocolVersionFromWord64 3 = return P3
protocolVersionFromWord64 4 = return P4
protocolVersionFromWord64 5 = return P5
protocolVersionFromWord64 6 = return P6
protocolVersionFromWord64 v = fail $ "Unknown protocol version: " ++ show v

instance Serialize ProtocolVersion where
    put = putWord64be . protocolVersionToWord64
    get = protocolVersionFromWord64 =<< getWord64be

instance ToJSON ProtocolVersion where
    toJSON = toJSON . protocolVersionToWord64

instance FromJSON ProtocolVersion where
    parseJSON v = prependFailure "Protocol version" $ do
        x <- parseJSON v
        protocolVersionFromWord64 x

-- |Type class for relating type-level 'ProtocolVersion's with
-- term level 'SProtocolVersion's.
class
    ( IsChainParametersVersion (ChainParametersVersionFor pv),
      IsAccountVersion (AccountVersionFor pv),
      IsTransactionOutcomesVersion (TransactionOutcomesVersionFor pv)
    ) =>
    IsProtocolVersion (pv :: ProtocolVersion)
    where
    -- |The singleton associated with the protocol version.
    protocolVersion :: SProtocolVersion pv

instance IsProtocolVersion 'P1 where
    protocolVersion = SP1
    {-# INLINE protocolVersion #-}

instance IsProtocolVersion 'P2 where
    protocolVersion = SP2
    {-# INLINE protocolVersion #-}

instance IsProtocolVersion 'P3 where
    protocolVersion = SP3
    {-# INLINE protocolVersion #-}

instance IsProtocolVersion 'P4 where
    protocolVersion = SP4
    {-# INLINE protocolVersion #-}

instance IsProtocolVersion 'P5 where
    protocolVersion = SP5
    {-# INLINE protocolVersion #-}

instance IsProtocolVersion 'P6 where
    protocolVersion = SP6
    {-# INLINE protocolVersion #-}

-- |Demote an 'SProtocolVersion' to a 'ProtocolVersion'.
demoteProtocolVersion :: SProtocolVersion pv -> ProtocolVersion
demoteProtocolVersion SP1 = P1
demoteProtocolVersion SP2 = P2
demoteProtocolVersion SP3 = P3
demoteProtocolVersion SP4 = P4
demoteProtocolVersion SP5 = P5
demoteProtocolVersion SP6 = P6

-- |An existentially quantified protocol version.
data SomeProtocolVersion where
    SomeProtocolVersion :: (IsProtocolVersion pv) => SProtocolVersion pv -> SomeProtocolVersion

-- |Promote a 'ProtocolVersion' to an 'SProtocolVersion'. This is wrapped in the existential
-- type 'SomeProtocolVersion'.
promoteProtocolVersion :: ProtocolVersion -> SomeProtocolVersion
promoteProtocolVersion P1 = SomeProtocolVersion SP1
promoteProtocolVersion P2 = SomeProtocolVersion SP2
promoteProtocolVersion P3 = SomeProtocolVersion SP3
promoteProtocolVersion P4 = SomeProtocolVersion SP4
promoteProtocolVersion P5 = SomeProtocolVersion SP5
promoteProtocolVersion P6 = SomeProtocolVersion SP6

data ChainParametersVersion = ChainParametersV0 | ChainParametersV1
    deriving (Eq, Show)

type family ChainParametersVersionFor (pv :: ProtocolVersion) :: ChainParametersVersion where
    ChainParametersVersionFor 'P1 = 'ChainParametersV0
    ChainParametersVersionFor 'P2 = 'ChainParametersV0
    ChainParametersVersionFor 'P3 = 'ChainParametersV0
    ChainParametersVersionFor 'P4 = 'ChainParametersV1
    ChainParametersVersionFor 'P5 = 'ChainParametersV1
    ChainParametersVersionFor 'P6 = 'ChainParametersV1

data SChainParametersVersion (cpv :: ChainParametersVersion) where
    SCPV0 :: SChainParametersVersion 'ChainParametersV0
    SCPV1 :: SChainParametersVersion 'ChainParametersV1

-- |Type class for relating type-level 'ChainParametersVersion's with
-- term level 'SChainParameters's.
class IsChainParametersVersion (cpv :: ChainParametersVersion) where
    -- |The singleton associated with the protocol version.
    chainParametersVersion :: SChainParametersVersion cpv

instance IsChainParametersVersion 'ChainParametersV0 where
    chainParametersVersion = SCPV0
    {-# INLINE chainParametersVersion #-}

instance IsChainParametersVersion 'ChainParametersV1 where
    chainParametersVersion = SCPV1
    {-# INLINE chainParametersVersion #-}

chainParametersVersionFor :: SProtocolVersion pv -> SChainParametersVersion (ChainParametersVersionFor pv)
chainParametersVersionFor spv = case spv of
    SP1 -> SCPV0
    SP2 -> SCPV0
    SP3 -> SCPV0
    SP4 -> SCPV1
    SP5 -> SCPV1
    SP6 -> SCPV1

demoteChainParameterVersion :: SChainParametersVersion pv -> ChainParametersVersion
demoteChainParameterVersion SCPV0 = ChainParametersV0
demoteChainParameterVersion SCPV1 = ChainParametersV1
-- * Account versions

-- |A data kind used for parametrising account-related types.
-- This is used rather than 'ProtocolVersion' to coalesce cases where different protocol versions
-- share the same account format.
data AccountVersion
    = -- |Account version used in P1, P2, and P3.
      AccountV0
    | -- |Account version used in P4. Adds stake delegation.
      AccountV1
    | -- |Account version used in P5. Modifies hashing.
      AccountV2

-- |A singleton type corresponding to 'SAccountVersion'.
data SAccountVersion (av :: AccountVersion) where
    SAccountV0 :: SAccountVersion 'AccountV0
    SAccountV1 :: SAccountVersion 'AccountV1
    SAccountV2 :: SAccountVersion 'AccountV2

-- |Projection of 'ProtocolVersion' to 'AccountVersion'.
type family AccountVersionFor (pv :: ProtocolVersion) :: AccountVersion where
    AccountVersionFor 'P1 = 'AccountV0
    AccountVersionFor 'P2 = 'AccountV0
    AccountVersionFor 'P3 = 'AccountV0
    AccountVersionFor 'P4 = 'AccountV1
    AccountVersionFor 'P5 = 'AccountV2
    AccountVersionFor 'P6 = 'AccountV2

-- |Projection of 'SProtocolVersion' to 'SAccountVersion'.
accountVersionFor :: SProtocolVersion pv -> SAccountVersion (AccountVersionFor pv)
accountVersionFor SP1 = SAccountV0
accountVersionFor SP2 = SAccountV0
accountVersionFor SP3 = SAccountV0
accountVersionFor SP4 = SAccountV1
accountVersionFor SP5 = SAccountV2
accountVersionFor SP6 = SAccountV2

class IsAccountVersion (av :: AccountVersion) where
    -- |The singleton associated with the account version
    accountVersion :: SAccountVersion av

instance IsAccountVersion 'AccountV0 where
    accountVersion = SAccountV0

instance IsAccountVersion 'AccountV1 where
    accountVersion = SAccountV1

instance IsAccountVersion 'AccountV2 where
    accountVersion = SAccountV2

-- |Transaction outcomes versions.
-- The difference between the two versions are only related
-- to the hashing scheme.
-- * 'TOVO' is used in P1 to P4. The hash is computed as a simple hash list.
-- All the contents of the transaction summaries are used for computing the hash.
-- * 'TOV1' is used in PV5 and onwards. The hash is computed via a merkle tree and the
-- exact reject reasons for failed transactions are omitted from the hash.
data TransactionOutcomesVersion
    = TOV0
    | TOV1

-- |Projection of 'ProtocolVersion' to 'TransactionOutcomesVersion'.
type family TransactionOutcomesVersionFor (pv :: ProtocolVersion) :: TransactionOutcomesVersion where
    TransactionOutcomesVersionFor 'P1 = 'TOV0
    TransactionOutcomesVersionFor 'P2 = 'TOV0
    TransactionOutcomesVersionFor 'P3 = 'TOV0
    TransactionOutcomesVersionFor 'P4 = 'TOV0
    TransactionOutcomesVersionFor 'P5 = 'TOV1
    TransactionOutcomesVersionFor 'P6 = 'TOV1

-- |Supporting type for bringing the 'TransactionOutcomesVersion' to the term level.
data STransactionOutcomesVersion (tov :: TransactionOutcomesVersion) where
    STOV0 :: STransactionOutcomesVersion 'TOV0
    STOV1 :: STransactionOutcomesVersion 'TOV1

class IsTransactionOutcomesVersion (tov :: TransactionOutcomesVersion) where
    -- |The singleton associated with the outcomes version.
    transactionOutcomesVersion :: STransactionOutcomesVersion tov

instance IsTransactionOutcomesVersion 'TOV0 where
    transactionOutcomesVersion = STOV0

instance IsTransactionOutcomesVersion 'TOV1 where
    transactionOutcomesVersion = STOV1

-- |A type used at the kind level to denote that delegation is or is not expected to be supported
-- at an account version. This is intended to give more descriptive type errors in cases where the
-- typechecker simplifies 'AVSupportsDelegationB'. In particular, a required constraint of
-- @AVSupportsDelegation 'AccountV0@ will give a type error:
--
-- @
--   Couldn't match type: 'DelegationNotSupported 'AccountV0
--   with: 'DelegationSupported 'AccountV0
-- @
--
-- This is more meaningful than @Couldn't match type: 'False with: 'True@.
-- From ghc 9.4, @Assert@ and @TypeError@ can be used instead to give even better errors.
data DelegationSupport
    = -- |Delegation is supported at the account version
      DelegationSupported AccountVersion
    | -- |Delegation is not supported at the account version
      DelegationNotSupported AccountVersion

-- |Type-level predicate that determines if an account version supports delegation.
type family AVSupportsDelegationB (av :: AccountVersion) :: DelegationSupport where
    AVSupportsDelegationB 'AccountV0 = 'DelegationNotSupported 'AccountV0
    AVSupportsDelegationB av = 'DelegationSupported av

-- |Constraint that an account version supports delegation.
--
-- TODO: As of ghc 9.4, @Assert@ should be used to give better type errors.
type AVSupportsDelegation (av :: AccountVersion) = AVSupportsDelegationB av ~ 'DelegationSupported av

-- |Constraint that a protocol version supports delegation.
type SupportsDelegation (pv :: ProtocolVersion) = AVSupportsDelegation (AccountVersionFor pv)

-- |A GADT that covers the cases for whether an account version supports delegation or not.
-- The case that it doesn't is limited to 'AccountV0', and in the other case, this provides an
-- instance of 'AVSupportsDelegation'.
data SAVDelegationSupport (av :: AccountVersion) where
    SAVDelegationNotSupported :: SAVDelegationSupport 'AccountV0
    SAVDelegationSupported :: AVSupportsDelegation av => SAVDelegationSupport av

-- |Determine if delegation is supported at the account version.
delegationSupport :: forall av. (IsAccountVersion av) => SAVDelegationSupport av
{-# INLINE delegationSupport #-}
delegationSupport = case accountVersion @av of
    SAccountV0 -> SAVDelegationNotSupported
    SAccountV1 -> SAVDelegationSupported
    SAccountV2 -> SAVDelegationSupported

-- |A GADT that witnesses the chain parameter version for a protocol version that supports delegation.
-- Currently, all protocol versions that support delegation (P4 and P5) have chain parameters
-- version 1.
data DelegationChainParameters (pv :: ProtocolVersion) where
    DelegationChainParametersV1 :: (ChainParametersVersionFor pv ~ 'ChainParametersV1) => DelegationChainParameters pv

-- |Constrain the chain parameters given that the protocol version supports delegation.
-- Currently, all protocol versions that support delegation (P4 and P5) have chain parameters
-- version 1.
--
-- This should be used in a context where @SupportsDelegation pv@ is known and a constraint of
-- @ChainParametersVersionFor pv ~ 'ChainParametersV1@ is required:
--
-- > case delegationChainParameters @pv of
-- >    DelegationChainParametersV1 -> {\- here: ChainParametersVersionFor pv ~ 'ChainParametersV1 -\}
delegationChainParameters :: forall pv. (IsProtocolVersion pv, SupportsDelegation pv) => DelegationChainParameters pv
delegationChainParameters = case protocolVersion @pv of
    SP4 -> DelegationChainParametersV1
    SP5 -> DelegationChainParametersV1
    SP6 -> DelegationChainParametersV1

-- |Whether the protocol version supports memo functionality.
-- (Memos are supported in 'P2' onwards.)
supportsMemo :: SProtocolVersion pv -> Bool
supportsMemo SP1 = False
supportsMemo _ = True

-- |Whether the protocol version supports stake delegation functionality.
-- (Delegation is supported in 'P4' onwards.)
supportsDelegation :: SProtocolVersion pv -> Bool
supportsDelegation SP1 = False
supportsDelegation SP2 = False
supportsDelegation SP3 = False
supportsDelegation SP4 = True
supportsDelegation SP5 = True
supportsDelegation SP6 = True

-- |Whether the protocol version supports V1 smart contracts.
-- (V1 contracts are supported in 'P4' onwards.)
supportsV1Contracts :: SProtocolVersion pv -> Bool
supportsV1Contracts SP1 = False
supportsV1Contracts SP2 = False
supportsV1Contracts SP3 = False
supportsV1Contracts SP4 = True
supportsV1Contracts SP5 = True
supportsV1Contracts SP6 = True

-- |Whether the protocol version supports upgradable smart contracts.
-- (Supported in 'P5' and onwards)
supportsUpgradableContracts :: SProtocolVersion pv -> Bool
supportsUpgradableContracts spv = case spv of
    SP1 -> False
    SP2 -> False
    SP3 -> False
    SP4 -> False
    SP5 -> True
    SP6 -> True

-- |Whether the protocol version supports chain queries in smart contracts.
-- (Supported in 'P5' and onwards)
supportsChainQueryContracts :: SProtocolVersion pv -> Bool
supportsChainQueryContracts spv = case spv of
    SP1 -> False
    SP2 -> False
    SP3 -> False
    SP4 -> False
    SP5 -> True
    SP6 -> True
