{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE EmptyCase #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE StandaloneKindSignatures #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}
-- We suppress redundant constraint warnings since GHC does not detect when a constraint is used
-- for pattern matching. (See: https://gitlab.haskell.org/ghc/ghc/-/issues/20896)
{-# OPTIONS_GHC -Wno-redundant-constraints #-}

-- The class 'IsProtocolVersion' identifies the singleton for each 'ProtocolVersion',
-- and should have an instance for each constructor of 'ProtocolVersion'.
-- In other words the constraint 'IsProtocolVersion' contextualizes the function
-- with the protocol version.

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
-- This is generated from the definition of 'ProtocolVersion' by the singletons library, along
-- with a number of useful typeclass instances.
module Concordium.Types.ProtocolVersion (
    -- * Protocol version

    -- |An enumeration of the supported versions of the consensus protocol.
    -- Binary and JSON serializations are as 'Word64' corresponding to the protocol number.
    ProtocolVersion (..),
    -- |The singleton type associated with 'ProtocolVersion'.
    -- There is a unique constructor of 'SProtocolVersion' for
    -- each constructor of 'ProtocolVersion'.
    SProtocolVersion (..),
    IsProtocolVersion,
    protocolVersion,
    SomeProtocolVersion (..),
    promoteProtocolVersion,
    demoteProtocolVersion,
    MonadProtocolVersion (..),

    -- * Chain parameters version

    -- |The version of the chain parameters.
    --
    -- * 'ChainParametersV0' is used in 'P1', 'P2' and 'P3'.
    --
    -- * 'ChainParametersV1' is used in 'P4' and 'P5'. This has the following changes:
    --
    --     - Mint-per-slot rate is removed from the mint distribution parameters.
    --     - New time parameters are introduced that combine payday length and mint-per-payday rate.
    --       These time parameters are updatable (introducing a new access structure).
    --     - The cooldown parameters are changed to use real time instead of number of epochs.
    --       The cooldown parameters are made updatable (introducing a new access structure).
    --
    -- * 'ChainParametersV2' is used in 'P6', which introduces the new consensus protocol.
    --   This has the following changes:
    --
    --     - Election difficulty is removed as a parameter.
    --     - New consensus parameters are introduced, consisting of three parameter groups that are
    --       separately updatable (using the same access structure as for election difficulty).
    --       These are:
    --
    --         * Timeout parameters: timeout base time, timeout increase factor, timeout decrease factor.
    --         * Minimum block time.
    --         * Block energy limit.
    --
    --     - The finalization proof reward is removed from the GAS rewards.
    ChainParametersVersion (..),
    -- |Singleton type corresponding to 'ChainParametersVersion'.
    SChainParametersVersion (..),
    IsChainParametersVersion,
    chainParametersVersion,
    demoteChainParameterVersion,
    -- |The chain parameters version for a given protocol version.
    chainParametersVersionFor,
    -- |The chain parameters version for a given protocol version (at the type level).
    ChainParametersVersionFor,
    -- |The chain parameters version for a given protocol version (on singletons).
    sChainParametersVersionFor,
    -- |Defunctionalisation symbol for 'ChainParametersVersionFor'.
    ChainParametersVersionForSym0,

    -- * Account version

    -- |A data kind used for parametrising account-related types.
    -- This is used rather than 'ProtocolVersion' to coalesce cases where different protocol versions
    -- share the same account format.
    --
    --   * 'AccountV0' is used in 'P1', 'P2' and 'P3'.
    --
    --   * 'AccountV1' is used in 'P4'. Adds stake delegation.
    --
    --   * 'AccountV2' is used in 'P5' and 'P6'. Modifies the hash calculation.
    AccountVersion (..),
    -- |Singleton type corresponding to 'AccountVersion'.
    SAccountVersion (..),
    IsAccountVersion,
    accountVersion,
    -- |The account version for a given protocol version.
    accountVersionFor,
    -- |The account version for a given protocol version (at the type level).
    AccountVersionFor,
    -- |The account version for a given protocol version (on singletons).
    sAccountVersionFor,

    -- * Transaction outcomes version

    -- |Transaction outcomes versions.
    -- The difference between the two versions are only related
    -- to the hashing scheme.
    --
    --   * 'TOVO' is used in P1 to P4. The hash is computed as a simple hash list.
    --     All the contents of the transaction summaries are used for computing the hash.
    --
    --   * 'TOV1' is used in PV5 and onwards. The hash is computed via a merkle tree and the
    --     exact reject reasons for failed transactions are omitted from the hash.
    TransactionOutcomesVersion (..),
    -- |Singleton type corresponding to 'TransactionOutcomesVersion'.
    STransactionOutcomesVersion (..),
    IsTransactionOutcomesVersion,
    transactionOutcomesVersion,
    -- |The transaction outcomes version for a given protocol version.
    transactionOutcomesVersionFor,
    -- |The transaction outcomes version for a given protocol version (at the type level).
    TransactionOutcomesVersionFor,
    -- |The transaction outcomes version for a given protocol version (on singletons).
    sTransactionOutcomesVersionFor,

    -- * Delegation support

    -- |Whether or not delegation is supported at a particular account version.
    DelegationSupport (..),
    -- Singleton type corresponding to 'DelegationSupport'.
    SDelegationSupport (..),
    -- |Determine whether delegation is supported for a particular account version.
    supportsDelegation,
    -- |Determine whether delegation is supported for a particular account version (at the type level).
    SupportsDelegation,
    -- |Determine whether delegation is supported for a particular account version (on singletons).
    sSupportsDelegation,
    SAVDelegationSupport (..),
    AVSupportsDelegation,
    PVSupportsDelegation,
    delegationSupport,
    protocolSupportsDelegation,

    -- * Feature guards
    supportsMemo,
    supportsV1Contracts,
    supportsUpgradableContracts,
    supportsChainQueryContracts,
    supportsAccountAliases,
    supportsDelegationPV,

    -- * Defunctionalisation symbols
    P1Sym0,
    P2Sym0,
    P3Sym0,
    P4Sym0,
    P5Sym0,
    P6Sym0,
) where

import Control.Monad.Except (ExceptT)
import Control.Monad.Reader (ReaderT)
import Control.Monad.Trans.Maybe (MaybeT)
import Data.Aeson
import Data.Aeson.Types
import Data.Kind
import Data.Serialize
import Data.Singletons.Base.TH
import Data.Word

import Concordium.Utils.Serialization.Put (PutT)

-- See the splice documentation in 'Parameters.hs' for an explanation of what is generated.
$( singletons
    [d|
        -- \|An enumeration of the supported versions of the consensus protocol.
        -- Binary and JSON serializations are as Word64 corresponding to the protocol number.
        data ProtocolVersion
            = P1
            | P2
            | P3
            | P4
            | P5
            | P6
            deriving (Eq, Ord)

        data ChainParametersVersion
            = ChainParametersV0
            | ChainParametersV1
            | ChainParametersV2
            deriving (Eq, Ord)

        chainParametersVersionFor :: ProtocolVersion -> ChainParametersVersion
        chainParametersVersionFor P1 = ChainParametersV0
        chainParametersVersionFor P2 = ChainParametersV0
        chainParametersVersionFor P3 = ChainParametersV0
        chainParametersVersionFor P4 = ChainParametersV1
        chainParametersVersionFor P5 = ChainParametersV1
        chainParametersVersionFor P6 = ChainParametersV2

        -- \* Account versions

        -- \|A data kind used for parametrising account-related types.
        -- This is used rather than 'ProtocolVersion' to coalesce cases where different protocol versions
        -- share the same account format.
        data AccountVersion
            = -- \|Account version used in P1, P2, and P3.
              AccountV0
            | -- \|Account version used in P4. Adds stake delegation.
              AccountV1
            | -- \|Account version used in P5. Modifies hashing.
              AccountV2

        -- \|'AccountVersion' associated with a 'ProtocolVersion'.
        accountVersionFor :: ProtocolVersion -> AccountVersion
        accountVersionFor P1 = AccountV0
        accountVersionFor P2 = AccountV0
        accountVersionFor P3 = AccountV0
        accountVersionFor P4 = AccountV1
        accountVersionFor P5 = AccountV2
        accountVersionFor P6 = AccountV2

        -- \|Transaction outcomes versions.
        -- The difference between the two versions are only related
        -- to the hashing scheme.
        -- \* 'TOVO' is used in P1 to P4. The hash is computed as a simple hash list.
        -- All the contents of the transaction summaries are used for computing the hash.
        -- \* 'TOV1' is used in PV5 and onwards. The hash is computed via a merkle tree and the
        -- exact reject reasons for failed transactions are omitted from the hash.
        data TransactionOutcomesVersion
            = TOV0
            | TOV1

        -- \|Projection of 'ProtocolVersion' to 'TransactionOutcomesVersion'.
        transactionOutcomesVersionFor :: ProtocolVersion -> TransactionOutcomesVersion
        transactionOutcomesVersionFor P1 = TOV0
        transactionOutcomesVersionFor P2 = TOV0
        transactionOutcomesVersionFor P3 = TOV0
        transactionOutcomesVersionFor P4 = TOV0
        transactionOutcomesVersionFor P5 = TOV1
        transactionOutcomesVersionFor P6 = TOV1

        -- \|A type used at the kind level to denote that delegation is or is not expected to be supported
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
            = -- \|Delegation is supported at the account version
              DelegationSupported AccountVersion
            | -- \|Delegation is not supported at the account version
              DelegationNotSupported AccountVersion

        supportsDelegation :: AccountVersion -> DelegationSupport
        supportsDelegation AccountV0 = DelegationNotSupported AccountV0
        supportsDelegation AccountV1 = DelegationSupported AccountV1
        supportsDelegation AccountV2 = DelegationSupported AccountV2
        |]
 )

instance ToJSON ChainParametersVersion where
    toJSON = toJSON . chainParameterVersionToWord64

deriving instance Show ProtocolVersion

deriving instance Show ChainParametersVersion

-- |Convert a protocol version to the corresponding 'Word64'.
protocolVersionToWord64 :: ProtocolVersion -> Word64
protocolVersionToWord64 P1 = 1
protocolVersionToWord64 P2 = 2
protocolVersionToWord64 P3 = 3
protocolVersionToWord64 P4 = 4
protocolVersionToWord64 P5 = 5
protocolVersionToWord64 P6 = 6

-- |Parse a 'Word64' as a 'ProtocolVersion'.
protocolVersionFromWord64 :: MonadFail m => Word64 -> m ProtocolVersion
protocolVersionFromWord64 1 = return P1
protocolVersionFromWord64 2 = return P2
protocolVersionFromWord64 3 = return P3
protocolVersionFromWord64 4 = return P4
protocolVersionFromWord64 5 = return P5
protocolVersionFromWord64 6 = return P6
protocolVersionFromWord64 v = fail $ "Unknown protocol version: " ++ show v

-- |Convert a @ChainParametersVersion@ to the corresponding 'Word64'.
chainParameterVersionToWord64 :: ChainParametersVersion -> Word64
chainParameterVersionToWord64 ChainParametersV0 = 0
chainParameterVersionToWord64 ChainParametersV1 = 1
chainParameterVersionToWord64 ChainParametersV2 = 2

instance Serialize ProtocolVersion where
    put = putWord64be . protocolVersionToWord64
    get = protocolVersionFromWord64 =<< getWord64be

instance ToJSON ProtocolVersion where
    toJSON = toJSON . protocolVersionToWord64

instance FromJSON ProtocolVersion where
    parseJSON v = prependFailure "Protocol version" $ do
        x <- parseJSON v
        protocolVersionFromWord64 x

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

-- |Demote an 'SProtocolVersion' to a 'ProtocolVersion'.
demoteProtocolVersion :: SProtocolVersion pv -> ProtocolVersion
demoteProtocolVersion = fromSing

-- |Constraint on a type level 'AccountVersion' that can be used to get a corresponding
-- 'SAccountVersion' (see 'accountVersion'). (An alias for 'SingI'.)
type IsAccountVersion (av :: AccountVersion) = SingI av

-- |Constraint on a type level 'ChainParametersVersion' that can be used to get a corresponding
-- 'SChainParametersVersion' (see 'chainParametersVersion'). (An alias for 'SingI'.)
type IsChainParametersVersion (cpv :: ChainParametersVersion) = SingI cpv

-- |Constraint on a type level 'TransactionOutcomesVersion' that can be used to get a corresponding
-- 'STransactionOutcomesVersion' (see 'transactionOutcomesVersion'). (An alias for 'SingI'.)
type IsTransactionOutcomesVersion (tov :: TransactionOutcomesVersion) = SingI tov

-- |Constraint on a type level 'ProtocolVersion' that can be used to get a corresponding
-- 'SProtocolVersion' (see 'protocolVersion'). This wraps 'SingI', but also
-- has constraints on the 'ChainParametersVersionFor', 'AccountVersionFor' and
-- 'TransactionOutcomesVersionFor' the protocol version. (This facilitates cases where those
-- constraints are needed.)
--
-- This is implemented as a typeclass (with a single instance) rather than a synonym because
-- otherwise instances that require 'IsProtocolVersion' as a constraint would have "illegal nested
-- constraints", requiring @UndecidableInstances@.
class
    ( SingI pv,
      IsChainParametersVersion (ChainParametersVersionFor pv),
      IsAccountVersion (AccountVersionFor pv),
      IsTransactionOutcomesVersion (TransactionOutcomesVersionFor pv)
    ) =>
    IsProtocolVersion (pv :: ProtocolVersion)

instance
    ( SingI pv,
      IsChainParametersVersion (ChainParametersVersionFor pv),
      IsAccountVersion (AccountVersionFor pv),
      IsTransactionOutcomesVersion (TransactionOutcomesVersionFor pv)
    ) =>
    IsProtocolVersion (pv :: ProtocolVersion)

-- |Produce the singleton 'SProtocolVersion' from an 'IsProtocolVersion' constraint.
protocolVersion :: IsProtocolVersion pv => SProtocolVersion pv
protocolVersion = sing

-- |Type class for monads that have an associated 'ProtocolVersion'.
class (IsProtocolVersion (MPV m)) => MonadProtocolVersion (m :: Type -> Type) where
    type MPV m :: ProtocolVersion

instance MonadProtocolVersion m => MonadProtocolVersion (MaybeT m) where
    type MPV (MaybeT m) = MPV m

instance MonadProtocolVersion m => MonadProtocolVersion (ExceptT e m) where
    type MPV (ExceptT e m) = MPV m

instance MonadProtocolVersion m => MonadProtocolVersion (ReaderT r m) where
    type MPV (ReaderT r m) = MPV m

instance MonadProtocolVersion m => MonadProtocolVersion (PutT m) where
    type MPV (PutT m) = MPV m

-- |Produce the singleton 'SAccountVersion' from an 'IsAccountVersion' constraint.
accountVersion :: IsAccountVersion av => SAccountVersion av
accountVersion = sing

-- |Produce the singleton 'SChainParametersVersion' from an 'IsChainParametersVersion' constraint.
chainParametersVersion :: IsChainParametersVersion cpv => SChainParametersVersion cpv
chainParametersVersion = sing

-- |Produce the singleton 'STransactionOutcomesVersion' from an 'IsTransactionOutcomesVersion' constraint.
transactionOutcomesVersion :: IsTransactionOutcomesVersion tov => STransactionOutcomesVersion tov
transactionOutcomesVersion = sing

-- |Demote a singleton 'SChainParametersVersion' to a 'ChainParametersVersion'.
demoteChainParameterVersion :: SChainParametersVersion cpv -> ChainParametersVersion
demoteChainParameterVersion = fromSing

-- |Constraint that an account version supports delegation.
--
-- TODO: As of ghc 9.4, @Assert@ should be used to give better type errors.
type AVSupportsDelegation (av :: AccountVersion) = SupportsDelegation av ~ 'DelegationSupported av

-- |Constraint that a protocol version supports delegation.
type PVSupportsDelegation (pv :: ProtocolVersion) = AVSupportsDelegation (AccountVersionFor pv)

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

-- |Whether the protocol supports delegation functionality.
protocolSupportsDelegation :: SProtocolVersion pv -> Bool
{-# INLINE protocolSupportsDelegation #-}
protocolSupportsDelegation spv = case sSupportsDelegation (sAccountVersionFor spv) of
    SDelegationSupported{} -> True
    _ -> False

-- |Whether the protocol version supports memo functionality.
-- (Memos are supported in 'P2' onwards.)
supportsMemo :: SProtocolVersion pv -> Bool
supportsMemo SP1 = False
supportsMemo _ = True

-- |Whether the protocol version supports account aliases.
-- (Account aliases are supported in 'P3' onwards.)
supportsAccountAliases :: SProtocolVersion pv -> Bool
supportsAccountAliases SP1 = False
supportsAccountAliases SP2 = False
supportsAccountAliases _ = True

-- |Whether the protocol version supports V1 smart contracts.
-- (V1 contracts are supported in 'P4' onwards.)
supportsV1Contracts :: SProtocolVersion pv -> Bool
supportsV1Contracts SP1 = False
supportsV1Contracts SP2 = False
supportsV1Contracts SP3 = False
supportsV1Contracts SP4 = True
supportsV1Contracts SP5 = True
supportsV1Contracts SP6 = True

-- |Whether the protocol version supports delegation.
-- (Delegation is supported in 'P4' onwards.)
supportsDelegationPV :: SProtocolVersion pv -> Bool
supportsDelegationPV SP1 = False
supportsDelegationPV SP2 = False
supportsDelegationPV SP3 = False
supportsDelegationPV _ = True

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
